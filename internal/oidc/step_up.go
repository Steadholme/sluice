package oidc

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"html"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

const (
	stepUpCSRFTTLSeconds = int64(10 * 60)
	stepUpCSRFDomain     = "holdfast.sluice.step-up-csrf.v1"
	stepUpRequiredACR    = "hf-aal-strong"
	strongFreshness      = int64(300)
)

type stepUpContinuationContextKey struct{}

// StepUpContinuation is derived only from the already validated gateway route table. The
// browser never supplies a host, route, path, or arbitrary return URL.
type StepUpContinuation struct {
	Route      string
	Host       string
	PathPrefix string
}

func ContextWithStepUpContinuation(ctx context.Context, value StepUpContinuation) context.Context {
	return context.WithValue(ctx, stepUpContinuationContextKey{}, value)
}

func stepUpContinuationFromContext(ctx context.Context) (StepUpContinuation, bool) {
	value, ok := ctx.Value(stepUpContinuationContextKey{}).(StepUpContinuation)
	return value, ok && validStepUpContinuation(value)
}

func validStepUpContinuation(value StepUpContinuation) bool {
	return validOpaqueIdentifier(value.Route, 128, false) && validStepUpHost(value.Host) &&
		strings.HasPrefix(value.PathPrefix, "/") &&
		!strings.HasPrefix(value.PathPrefix, "//") &&
		strings.HasSuffix(value.PathPrefix, "/") &&
		!strings.ContainsAny(value.PathPrefix, "\\?#") &&
		strings.IndexFunc(value.PathPrefix, unicode.IsControl) < 0
}

func validStepUpHost(host string) bool {
	if host == "" || len(host) > 253 || host != strings.ToLower(host) ||
		strings.ContainsAny(host, "/@\\?#") {
		return false
	}
	hostname := host
	if strings.Contains(host, ":") {
		var port string
		var err error
		hostname, port, err = net.SplitHostPort(host)
		if err != nil {
			return false
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return false
		}
	}
	if net.ParseIP(hostname) != nil {
		return true
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			b := label[i]
			if (b < 'a' || b > 'z') && (b < '0' || b > '9') && b != '-' {
				return false
			}
		}
	}
	return true
}

func validStepUpRef(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func exactStepUpRef(r *http.Request) (string, bool) {
	query := r.URL.Query()
	values, ok := query["ref"]
	if !ok || len(query) != 1 || len(values) != 1 || !validStepUpRef(values[0]) {
		return "", false
	}
	return values[0], true
}

func (p *Provider) handleStepUp(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "private, no-store")
	// Preserve the same-origin POST's exact Origin while withholding the step-up path and
	// reference from cross-origin referrers.
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	continuation, ok := stepUpContinuationFromContext(r.Context())
	if !ok || continuation.Host != r.Host {
		http.NotFound(w, r)
		return
	}
	ref, ok := exactStepUpRef(r)
	if !ok {
		http.Error(w, "invalid step-up reference", http.StatusBadRequest)
		return
	}
	_, session, authenticated, err := p.sessionIdentity(r)
	if err != nil {
		w.Header().Set("Retry-After", "5")
		http.Error(w, "session authority unavailable", http.StatusServiceUnavailable)
		return
	}
	if !authenticated {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodGet:
		p.renderStepUp(w, session, continuation, ref)
	case http.MethodPost:
		p.startStepUp(w, r, session, continuation, ref)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (p *Provider) renderStepUp(
	w http.ResponseWriter,
	session Session,
	continuation StepUpContinuation,
	ref string,
) {
	expiresAt := p.now().Unix() + stepUpCSRFTTLSeconds
	token := p.mintStepUpCSRF(session, continuation, ref, expiresAt)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>Confirm identity</title></head><body><main aria-labelledby="step-up-title"><h1 id="step-up-title">Confirm your identity</h1><p>This action requires a recent strong multi-factor confirmation. The exact action you started is saved and has not run.</p><p>Continue to verification to confirm your identity, or safely close this page. The saved action will not run unless you continue and successfully finish verification.</p><form method="post" action="%s?ref=%s"><input type="hidden" name="ref" value="%s"><input type="hidden" name="csrf_token" value="%s"><button type="submit">Continue to verification</button></form></main></body></html>`,
		html.EscapeString(StepUpPath),
		html.EscapeString(ref),
		html.EscapeString(ref),
		html.EscapeString(token),
	)
}

func (p *Provider) startStepUp(
	w http.ResponseWriter,
	r *http.Request,
	session Session,
	continuation StepUpContinuation,
	ref string,
) {
	if !sameOriginStepUp(r, continuation.Host) {
		http.Error(w, "invalid step-up origin", http.StatusForbidden)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		http.Error(w, "invalid step-up content type", http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := r.ParseForm(); err != nil || len(r.PostForm) != 2 || len(r.PostForm["ref"]) != 1 ||
		len(r.PostForm["csrf_token"]) != 1 || r.PostForm.Get("ref") != ref {
		http.Error(w, "invalid step-up form", http.StatusBadRequest)
		return
	}
	if !p.verifyStepUpCSRF(session, continuation, ref, r.PostForm.Get("csrf_token")) {
		http.Error(w, "invalid step-up form token", http.StatusForbidden)
		return
	}
	returnURL := stepUpReturnURL(continuation, ref)
	state := p.token()
	nonce := p.token()
	verifier := p.token()
	st := OAuthState{
		State:                  state,
		Nonce:                  nonce,
		CodeVerifier:           verifier,
		OriginalURL:            returnURL,
		ExpiresAt:              p.now().Add(stateTTL).Unix(),
		Flow:                   OAuthFlowStepUp,
		ExpectedSub:            session.Sub,
		PreviousSessionID:      session.ID,
		PreviousSessionBinding: session.SessionBinding,
		StepUpRef:              ref,
		ContinuationRoute:      continuation.Route,
		ContinuationHost:       continuation.Host,
		ContinuationPath:       continuation.PathPrefix,
	}
	if err := p.states.PutState(r.Context(), st); err != nil {
		p.log.Error("oidc: persist step-up state", "error", err)
		w.Header().Set("Retry-After", "5")
		http.Error(w, "step-up temporarily unavailable", http.StatusServiceUnavailable)
		return
	}

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", p.cfg.RedirectURI)
	q.Set("scope", requestedScope)
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", pkceChallengeS256(verifier))
	q.Set("code_challenge_method", "S256")
	q.Set("acr_values", stepUpRequiredACR)
	http.Redirect(w, r, p.authorizeURL+"?"+q.Encode(), http.StatusSeeOther)
}

func sameOriginStepUp(r *http.Request, host string) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	wantScheme := "http"
	if r.TLS != nil {
		wantScheme = "https"
	}
	return subtle.ConstantTimeCompare([]byte(origin), []byte(wantScheme+"://"+host)) == 1
}

func stepUpReturnURL(continuation StepUpContinuation, ref string) string {
	return (&url.URL{
		Scheme: "https",
		Host:   continuation.Host,
		Path:   continuation.PathPrefix + ref,
	}).String()
}

func validStepUpOAuthState(state OAuthState) bool {
	continuation := StepUpContinuation{
		Route:      state.ContinuationRoute,
		Host:       state.ContinuationHost,
		PathPrefix: state.ContinuationPath,
	}
	return state.Flow == OAuthFlowStepUp && validStepUpContinuation(continuation) &&
		validStepUpRef(state.StepUpRef) && validSubject(state.ExpectedSub) &&
		state.PreviousSessionID != "" &&
		(state.PreviousSessionBinding == "" || validLowerHex64(state.PreviousSessionBinding)) &&
		state.OriginalURL == stepUpReturnURL(continuation, state.StepUpRef)
}

func (p *Provider) stepUpSourceSession(r *http.Request, state OAuthState) (Session, error) {
	cookie, err := r.Cookie(p.cfg.CookieName)
	if err != nil {
		return Session{}, ErrSessionReplacementConflict
	}
	id, ok := p.signer.verify(cookie.Value)
	if !ok || id != state.PreviousSessionID {
		return Session{}, ErrSessionReplacementConflict
	}
	session, ok, err := p.sessions.GetSession(r.Context(), id)
	if err != nil {
		return Session{}, err
	}
	if !ok || session.Sub != state.ExpectedSub ||
		session.SessionBinding != state.PreviousSessionBinding {
		return Session{}, ErrSessionReplacementConflict
	}
	return session, nil
}

func freshStrongAssurance(assurance idTokenAssurance, now int64) bool {
	return assurance.AAL == SessionMFAStrong && assurance.UV &&
		validLowerHex64(assurance.SessionBinding) && assurance.AuthTime > 0 &&
		assurance.AuthTime <= now && now-assurance.AuthTime <= strongFreshness
}

func (p *Provider) mintStepUpCSRF(
	session Session,
	continuation StepUpContinuation,
	ref string,
	expiresAt int64,
) string {
	preimage := stepUpCSRFPreimage(session, continuation, ref, expiresAt)
	mac := hmac.New(sha256.New, p.signer.key)
	_, _ = mac.Write([]byte(preimage))
	return strconv.FormatInt(expiresAt, 10) + "." + hex.EncodeToString(mac.Sum(nil))
}

func (p *Provider) verifyStepUpCSRF(
	session Session,
	continuation StepUpContinuation,
	ref string,
	token string,
) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 2 || len(parts[1]) != 64 {
		return false
	}
	expiresAt, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || expiresAt < p.now().Unix() || expiresAt > p.now().Unix()+stepUpCSRFTTLSeconds {
		return false
	}
	expected := p.mintStepUpCSRF(session, continuation, ref, expiresAt)
	return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}

func stepUpCSRFPreimage(
	session Session,
	continuation StepUpContinuation,
	ref string,
	expiresAt int64,
) string {
	return strings.Join([]string{
		stepUpCSRFDomain,
		session.ID,
		session.Sub,
		continuation.Route,
		continuation.Host,
		continuation.PathPrefix,
		ref,
		strconv.FormatInt(expiresAt, 10),
	}, "\n")
}
