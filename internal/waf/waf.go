package waf

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/holdfast/sluice/internal/audit"
)

// Detonator is the upload-sandbox seam. The WAF can hand an uploaded payload to a
// detonation service for dynamic analysis; this interface is the integration
// point. It is intentionally a STUB now — NoopDetonator returns a clean verdict —
// so a real sandbox (Rikune/CAPE-style) can be wired in later WITHOUT touching the
// middleware. The call is best-effort and must never block the request path.
type Detonator interface {
	// Detonate inspects an uploaded payload. A non-nil error or a Malicious verdict
	// signals the caller to block. Implementations must honor ctx for cancellation.
	Detonate(ctx context.Context, contentType string, payload []byte) (Verdict, error)
}

// Verdict is the result of a detonation.
type Verdict struct {
	Malicious bool
	Detail    string
}

// NoopDetonator is the default seam implementation: it never analyzes and always
// reports clean, so wiring the WAF does not require a sandbox to exist.
type NoopDetonator struct{}

// Detonate always returns a clean verdict.
func (NoopDetonator) Detonate(context.Context, string, []byte) (Verdict, error) {
	return Verdict{}, nil
}

// Config configures an Engine. The zero value with Enabled=false yields a
// pass-through engine (Middleware returns the next handler unchanged).
type Config struct {
	Enabled            bool
	Threshold          int            // block when a request's rule score >= Threshold
	RateBurst          int            // max requests per client per window (<=0 disables rate limiting)
	RateWindow         time.Duration  // sliding rate-limit window
	MaxBodyBytes       int64          // request body inspection/size cap (<=0 disables the cap)
	AllowedUploadTypes []string       // upload content-type allowlist; empty allows all
	TrustForwardedFor  bool           // honor X-Forwarded-For (set by the trusted edge) for the client IP
	RuleSet            *RuleSet       // detection ruleset; defaults to DefaultRuleSet()
	Detonator          Detonator      // upload sandbox seam; defaults to NoopDetonator
	Auditor            *audit.Emitter // non-blocking event sink; nil disables emission
	Log                *slog.Logger   // optional; defaults to slog.Default()
}

// Engine is the assembled WAF: the rule engine, the rate limiter, the body cap,
// and the upload allowlist + detonation seam. A nil *Engine and a disabled Engine
// are both safe: Middleware returns the wrapped handler untouched.
type Engine struct {
	enabled      bool
	threshold    int
	maxBodyBytes int64
	uploadAllow  map[string]struct{}
	trustXFF     bool
	rules        *RuleSet
	limiter      *Limiter
	detonator    Detonator
	auditor      *audit.Emitter
	log          *slog.Logger
}

// New builds an Engine. With cfg.Enabled false it returns a disabled engine that
// is a pure pass-through (no rate limiter goroutine, no inspection). With it
// enabled, defaults are filled in for any unset collaborator so the engine boots
// with zero extra config.
func New(cfg Config) *Engine {
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	if !cfg.Enabled {
		return &Engine{enabled: false, log: log}
	}

	threshold := cfg.Threshold
	if threshold <= 0 {
		threshold = 5
	}
	rules := cfg.RuleSet
	if rules == nil {
		rules = DefaultRuleSet()
	}
	det := cfg.Detonator
	if det == nil {
		det = NoopDetonator{}
	}

	allow := make(map[string]struct{}, len(cfg.AllowedUploadTypes))
	for _, t := range cfg.AllowedUploadTypes {
		if t = strings.ToLower(strings.TrimSpace(t)); t != "" {
			allow[t] = struct{}{}
		}
	}

	e := &Engine{
		enabled:      true,
		threshold:    threshold,
		maxBodyBytes: cfg.MaxBodyBytes,
		uploadAllow:  allow,
		trustXFF:     cfg.TrustForwardedFor,
		rules:        rules,
		limiter:      NewLimiter(cfg.RateBurst, cfg.RateWindow),
		detonator:    det,
		auditor:      cfg.Auditor,
		log:          log,
	}
	log.Info("waf: enabled",
		"rules", rules.Len(),
		"threshold", threshold,
		"rate_burst", cfg.RateBurst,
		"rate_window", cfg.RateWindow.String(),
		"max_body_bytes", cfg.MaxBodyBytes,
		"upload_allowlist", len(allow),
	)
	return e
}

// Close releases engine resources (the rate-limiter sweeper). Safe on nil/disabled.
func (e *Engine) Close() {
	if e == nil || !e.enabled {
		return
	}
	e.limiter.Close()
}

// uploadAllowed reports whether an upload content-type passes the allowlist. An
// empty allowlist allows everything (the hook is opt-in). The match is on the
// media type only, ignoring parameters like "; boundary=...".
func (e *Engine) uploadAllowed(contentType string) bool {
	if len(e.uploadAllow) == 0 {
		return true
	}
	mt := mediaType(contentType)
	if mt == "" {
		return false
	}
	_, ok := e.uploadAllow[mt]
	return ok
}

// mediaType lowercases a Content-Type and strips any parameters.
func mediaType(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}

// clientIP resolves the per-client key for rate limiting. When TrustForwardedFor
// is set (the trusted edge populates X-Forwarded-For), the leftmost entry — the
// original client — is used; otherwise the direct peer address is used. A
// malformed value falls back to RemoteAddr so a spoofed header cannot evade
// limiting by yielding an empty key.
func (e *Engine) clientIP(r *http.Request) string {
	if e.trustXFF {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
			if ip := net.ParseIP(first); ip != nil {
				return ip.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
