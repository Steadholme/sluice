package waf

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/holdfast/sluice/internal/audit"
)

// detonateTimeout bounds the (stub) upload-detonation seam call so it can never
// wedge the request path.
const detonateTimeout = 2 * time.Second

// blockedHTML is the minimal, static block page. It reflects NO request content,
// so the block response itself can never be an injection vector.
const blockedHTML = `<!doctype html><html><head><meta charset="utf-8">` +
	`<title>Request blocked</title></head><body>` +
	`<h1>403 Request blocked</h1>` +
	`<p>This request was blocked by the Aegis web application firewall.</p>` +
	`</body></html>`

// Middleware wraps next with the WAF. On a nil OR disabled engine it returns next
// UNCHANGED — a pure pass-through with zero behavior change, which is the OFF
// default for the whole gateway. When enabled it inspects each request in cheap-
// to-expensive order: rate limit, body size cap, upload allowlist + detonation
// seam, then the rule engine.
func (e *Engine) Middleware(next http.Handler) http.Handler {
	if e == nil || !e.enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		client := e.clientIP(r)

		// 1. Per-client sliding-window rate limit.
		if !e.limiter.Allow(client) {
			e.block(w, r, client, http.StatusTooManyRequests, "rate_limit", "rate limit exceeded")
			return
		}

		// 2. Body size cap. Captures the (bounded) body for inspection and restores
		// it for the downstream proxy.
		body, tooLarge := e.readBody(r)
		if tooLarge {
			e.block(w, r, client, http.StatusRequestEntityTooLarge, "body_too_large", "request body exceeds cap")
			return
		}

		// 3. Upload content-type allowlist + detonation seam.
		if reason, ok := e.checkUpload(r, body); !ok {
			e.block(w, r, client, http.StatusForbidden, "upload_denied", reason)
			return
		}

		// 4. Rule engine.
		det := e.rules.scan(e.buildInputs(r, body))
		if det.Score >= e.threshold {
			e.blockDetection(w, r, client, det)
			return
		}
		if det.Score > 0 {
			e.flag(r, client, det)
		}
		next.ServeHTTP(w, r)
	})
}

// readBody enforces the configured body size cap and returns the captured bytes
// for inspection. Bodyless methods and an unset cap skip reading (returning a nil
// body so the rule engine just does not inspect a body). When a cap is set the
// body is buffered up to the cap and restored on the request so the proxy still
// forwards it intact; an overflow (declared or actual) signals a block.
func (e *Engine) readBody(r *http.Request) (body []byte, tooLarge bool) {
	if r.Body == nil || r.Body == http.NoBody || e.maxBodyBytes <= 0 {
		return nil, false
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodDelete, http.MethodOptions, http.MethodTrace:
		return nil, false
	}
	cap := e.maxBodyBytes
	// Fast reject on a declared Content-Length over the cap.
	if r.ContentLength > cap {
		return nil, true
	}
	// Read up to cap+1 so an undeclared (chunked) overflow is detected.
	buf, err := io.ReadAll(io.LimitReader(r.Body, cap+1))
	_ = r.Body.Close()
	if err != nil {
		// Unreadable body: restore an empty body and let it proceed un-inspected
		// rather than failing the request on a transport hiccup.
		r.Body = io.NopCloser(bytes.NewReader(nil))
		return nil, false
	}
	if int64(len(buf)) > cap {
		return nil, true
	}
	// Restore the consumed body for the downstream reverse proxy.
	r.Body = io.NopCloser(bytes.NewReader(buf))
	r.ContentLength = int64(len(buf))
	return buf, false
}

// checkUpload applies the upload content-type allowlist and the detonation seam.
// It only gates true file uploads (multipart/form-data or application/octet-
// stream); ordinary API bodies (JSON, text, url-encoded forms) are left for the
// rule engine. With an empty allowlist every upload type is permitted (the hook
// is opt-in). The detonation call is a STUB seam (NoopDetonator) today and never
// blocks; a real sandbox can be wired in without changing this flow.
func (e *Engine) checkUpload(r *http.Request, body []byte) (reason string, ok bool) {
	ct := r.Header.Get("Content-Type")
	if ct == "" || len(body) == 0 {
		return "", true
	}
	mt := mediaType(ct)
	if mt != "multipart/form-data" && mt != "application/octet-stream" {
		return "", true
	}
	if !e.uploadAllowed(ct) {
		return "disallowed upload content-type: " + mt, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), detonateTimeout)
	defer cancel()
	if v, err := e.detonator.Detonate(ctx, mt, body); err == nil && v.Malicious {
		return "upload detonation flagged payload: " + v.Detail, false
	}
	return "", true
}

// buildInputs assembles the scannable strings from a request. The query is scanned
// both raw and percent-decoded so an encoded payload cannot slip past a rule.
func (e *Engine) buildInputs(r *http.Request, body []byte) inputs {
	raw := r.URL.RawQuery
	query := raw
	if decoded, err := url.QueryUnescape(raw); err == nil && decoded != raw {
		query = raw + " " + decoded
	}
	bodyStr := string(body)
	// URL-encoded form bodies encode spaces as '+' and metacharacters as %xx, so
	// scan a decoded copy too — otherwise an attack payload hides behind the
	// encoding (e.g. "1+UNION+SELECT" never matching "union\s+select").
	if len(body) > 0 && mediaType(r.Header.Get("Content-Type")) == "application/x-www-form-urlencoded" {
		if dec, err := url.QueryUnescape(bodyStr); err == nil && dec != bodyStr {
			bodyStr = bodyStr + " " + dec
		}
	}
	return inputs{
		path:      r.URL.Path,
		query:     query,
		headers:   headerValues(r.Header),
		userAgent: r.UserAgent(),
		body:      bodyStr,
	}
}

// block emits a waf.block event and writes the block response with the given
// status. code is a short machine label; detail carries the human reason.
func (e *Engine) block(w http.ResponseWriter, r *http.Request, client string, status int, code, detail string) {
	e.emit(audit.ActionWAFBlock, client, r, code+": "+detail)
	e.respond(w, r, status, code)
}

// blockDetection emits a waf.block for a rule-engine over-threshold hit and writes
// the canonical 403. The audit detail lists the firing rule ids and the score.
func (e *Engine) blockDetection(w http.ResponseWriter, r *http.Request, client string, det Detection) {
	e.emit(audit.ActionWAFBlock, client, r, "rule_block score="+strconv.Itoa(det.Score)+" rules="+det.RuleIDs())
	e.respond(w, r, http.StatusForbidden, "rule_block")
}

// flag emits a waf.flag for a below-threshold detection and lets the request
// through. It is fire-and-forget like every other emit.
func (e *Engine) flag(r *http.Request, client string, det Detection) {
	e.emit(audit.ActionWAFFlag, client, r, "score="+strconv.Itoa(det.Score)+" rules="+det.RuleIDs())
}

// emit posts a WAF event to Watchtower via the non-blocking emitter. A nil
// auditor is safe (the emitter's Emit is a no-op), so emission never touches the
// request path.
func (e *Engine) emit(action, actor string, r *http.Request, detail string) {
	e.auditor.Emit(audit.Event{
		Actor:    actor,
		Action:   action,
		Target:   r.Method + " " + r.URL.Path,
		Severity: audit.SeverityWarning,
		Detail:   detail,
		Source:   audit.SourceSluice,
	})
}

// respond writes the block response, negotiating JSON vs HTML from the request.
// The body is minimal and reflects no request content.
func (e *Engine) respond(w http.ResponseWriter, r *http.Request, status int, code string) {
	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":  "blocked",
			"reason": code,
			"by":     "aegis-waf",
		})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, blockedHTML)
}

// wantsJSON reports whether the client prefers a JSON block body (an API/XHR
// caller) over the HTML page.
func wantsJSON(r *http.Request) bool {
	if strings.Contains(strings.ToLower(r.Header.Get("Accept")), "application/json") {
		return true
	}
	if strings.EqualFold(r.Header.Get("X-Requested-With"), "XMLHttpRequest") {
		return true
	}
	return strings.HasPrefix(mediaType(r.Header.Get("Content-Type")), "application/json")
}
