// Package oidc makes Sluice an OIDC BROWSER-SSO relying party.
//
// It is the mechanism by which every public base-service UI is gated behind
// Keystone SSO: a route flagged auth="sso" runs requests through Middleware,
// which either injects the verified identity (X-Auth-*) from a valid gateway
// session cookie (__Secure-gw) and proxies, or 302-redirects the browser through
// Keystone's PUBLIC /authorize. The authorization-code + PKCE callback is served
// by Sluice itself at /_gw/auth/callback: it exchanges the code at the INTERNAL
// token endpoint (optionally over mTLS), validates the id_token (signature via
// the shared JWKS cache, iss/aud/nonce/exp), creates a session, and returns the
// browser to where it started.
//
// The session cookie is DOMAIN-SCOPED (Domain=COOKIE_DOMAIN, default .w33d.xyz)
// so a single login covers every *.w33d.xyz subdomain (true cross-subdomain SSO):
// the callback runs on id.w33d.xyz, sets the domain cookie, and 302s back to the
// FULL original subdomain URL (e.g. https://vitals.w33d.xyz/...), where the same
// cookie is then sent.
//
// The package is wired only when GW_OIDC=on. With it off, the gateway keeps its
// pure bearer/public behavior and this code is never reached.
package oidc

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/holdfast/sluice/internal/accesslog"
	"github.com/holdfast/sluice/internal/audit"
	"github.com/holdfast/sluice/internal/auth"
)

// Gateway-owned paths (served by Sluice, never proxied) and the session cookie.
const (
	GatewayPrefix = "/_gw/"
	CallbackPath  = "/_gw/auth/callback"
	LogoutPath    = "/_gw/auth/logout"
	LangPath      = "/_gw/lang"
	ThemePath     = "/_gw/theme"

	// DefaultCookieName uses the __Secure- prefix (NOT __Host-): __Secure- still
	// REQUIRES Secure + HTTPS but — unlike __Host- — PERMITS a Domain attribute, so
	// the cookie can be scoped to the parent COOKIE_DOMAIN (.w33d.xyz) for
	// cross-subdomain SSO. Host-locking is intentionally traded for one session
	// across every *.w33d.xyz service.
	DefaultCookieName = "__Secure-gw"
	LangCookieName    = "__Secure-lang"
	ThemeCookieName   = "__Secure-theme"

	// DefaultCookieDomain scopes the session cookie to the parent registrable
	// domain so one gateway login is sent to every subdomain. A leading dot is the
	// classic "all subdomains" form. An empty CookieDomain (e.g. in unit tests)
	// keeps the cookie host-only, preserving the pre-subdomain behavior.
	DefaultCookieDomain = ".w33d.xyz"

	// stateTTL bounds how long an in-flight authorization may take from the
	// authorize redirect to the callback.
	stateTTL = 10 * time.Minute

	// requestedScope is the fixed scope set the gateway asks for.
	requestedScope = "openid email profile"

	// langCookieMaxAge is roughly one year.
	langCookieMaxAge = 365 * 24 * 60 * 60
)

// Config is the relying-party configuration. Issuer + the derived authorize URL
// are PUBLIC (browser-facing); TokenURL is INTERNAL (server-to-server, optionally
// mTLS). SessionSecret signs the opaque cookie id.
type Config struct {
	Issuer        string        // PUBLIC issuer; also the id_token `iss` and the authorize-endpoint base
	TokenURL      string        // INTERNAL token endpoint (e.g. https://keystone:8443/token)
	ClientID      string        // gateway client_id (= expected id_token `aud`)
	ClientSecret  string        // client_secret_post credential
	RedirectURI   string        // PUBLIC redirect_uri (= CallbackPath on the public host)
	SessionTTL    time.Duration // gateway session lifetime
	SessionSecret string        // HMAC key for the signed cookie id
	CookieName    string        // defaults to DefaultCookieName
	CookieDomain  string        // Domain attribute for the session cookie (e.g. .w33d.xyz); empty = host-only

	// Auditor is the non-blocking audit emitter. When nil, the relying party
	// emits no audit events (and behaves exactly as before).
	Auditor *audit.Emitter
}

// keyResolver supplies RSA public keys by kid for id_token signature validation.
// *auth.JWKSCache satisfies it, so the SSO path reuses the very same key cache as
// the bearer path (one source of Keystone signing keys).
type keyResolver interface {
	KeyByKID(ctx context.Context, kid string) (*rsa.PublicKey, error)
}

// Provider is the assembled relying party. It is an http.Handler for the
// gateway-owned /_gw/* endpoints and exposes Middleware for sso routes.
type Provider struct {
	cfg          Config
	authorizeURL string
	keys         keyResolver
	client       *http.Client
	sessions     SessionStore
	states       StateStore
	signer       signer
	parser       *jwt.Parser
	log          *slog.Logger
	audit        *audit.Emitter

	// Overridable seams for deterministic tests.
	now  func() time.Time
	rand io.Reader
}

// NewProvider validates the configuration and assembles a Provider. A missing
// required field is a hard error returned to the caller (main), which logs it and
// runs WITHOUT SSO (sso routes then fail closed) rather than crashing the gateway.
func NewProvider(cfg Config, keys keyResolver, client *http.Client, sessions SessionStore, states StateStore, log *slog.Logger) (*Provider, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("oidc: empty issuer")
	}
	if cfg.TokenURL == "" {
		return nil, fmt.Errorf("oidc: empty token url")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("oidc: empty client_id")
	}
	if cfg.RedirectURI == "" {
		return nil, fmt.Errorf("oidc: empty redirect_uri")
	}
	if keys == nil {
		return nil, fmt.Errorf("oidc: nil key resolver")
	}
	if sessions == nil || states == nil {
		return nil, fmt.Errorf("oidc: nil session/state store")
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 8 * time.Hour
	}
	if cfg.CookieName == "" {
		cfg.CookieName = DefaultCookieName
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if log == nil {
		log = slog.Default()
	}

	secret := []byte(cfg.SessionSecret)
	if len(secret) == 0 {
		// Degrade safely: an ephemeral random key keeps SSO working within this
		// process; sessions just don't survive a restart / span instances.
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("oidc: generate ephemeral session secret: %w", err)
		}
		log.Warn("oidc: GW_SESSION_SECRET unset; using an ephemeral cookie key (sessions won't survive restart)")
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(cfg.Issuer),
		jwt.WithAudience(cfg.ClientID),
		jwt.WithExpirationRequired(),
	)

	return &Provider{
		cfg:          cfg,
		authorizeURL: strings.TrimRight(cfg.Issuer, "/") + "/authorize",
		keys:         keys,
		client:       client,
		sessions:     sessions,
		states:       states,
		signer:       signer{key: secret},
		parser:       parser,
		log:          log,
		audit:        cfg.Auditor,
		now:          time.Now,
		rand:         rand.Reader,
	}, nil
}

// ServeHTTP dispatches the gateway-owned endpoints. The gateway routes any
// request under GatewayPrefix here BEFORE its proxy router, so these paths are
// never forwarded to an upstream.
func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case CallbackPath:
		p.handleCallback(w, r)
	case LogoutPath:
		p.handleLogout(w, r)
	case LangPath:
		p.handleLang(w, r)
	case ThemePath:
		p.handleTheme(w, r)
	default:
		http.NotFound(w, r)
	}
}

// Middleware gates an sso route. A valid gateway session injects the verified
// identity into the request context (the proxy turns it into X-Auth-* headers)
// and proxies; otherwise the browser is sent through Keystone login.
func (p *Provider) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, ok := p.sessionIdentity(r); ok {
			accesslog.SetSubject(r.Context(), id.Subject)
			ctx := auth.ContextWithIdentity(r.Context(), id)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		p.beginAuth(w, r)
	})
}

// OptionalMiddleware is a non-gating SSO middleware: it injects the verified
// identity when a valid gateway session exists, and otherwise passes the request
// through ANONYMOUSLY (no login redirect). Upstreams must enforce their own auth
// for writes; the proxy still strips any client-supplied X-Auth-* on this path,
// so anonymous requests reach the upstream with no identity.
func (p *Provider) OptionalMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, ok := p.sessionIdentity(r); ok {
			accesslog.SetSubject(r.Context(), id.Subject)
			ctx := auth.ContextWithIdentity(r.Context(), id)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sessionIdentity resolves the __Secure-gw cookie to a live session identity. Any
// failure (no cookie, bad signature, unknown/expired session) returns ok=false
// so the caller starts a fresh login.
func (p *Provider) sessionIdentity(r *http.Request) (*auth.Identity, bool) {
	c, err := r.Cookie(p.cfg.CookieName)
	if err != nil {
		return nil, false
	}
	id, ok := p.signer.verify(c.Value)
	if !ok {
		return nil, false
	}
	sess, ok, err := p.sessions.GetSession(r.Context(), id)
	if err != nil {
		p.log.Warn("oidc: session lookup failed", "error", err)
		return nil, false
	}
	if !ok {
		return nil, false
	}
	return &auth.Identity{Subject: sess.Sub, Email: sess.Email, Scope: sess.Scope}, true
}

// beginAuth starts an authorization-code + PKCE flow: it persists fresh
// state/nonce/verifier + the original URL, then 302s the browser to Keystone's
// PUBLIC authorize endpoint.
func (p *Provider) beginAuth(w http.ResponseWriter, r *http.Request) {
	state := p.token()
	nonce := p.token()
	verifier := p.token()
	st := OAuthState{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: verifier,
		OriginalURL:  originalURL(r),
		ExpiresAt:    p.now().Add(stateTTL).Unix(),
	}
	if err := p.states.PutState(r.Context(), st); err != nil {
		p.log.Error("oidc: persist oauth state", "error", err)
		http.Error(w, "auth temporarily unavailable", http.StatusServiceUnavailable)
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
	http.Redirect(w, r, p.authorizeURL+"?"+q.Encode(), http.StatusFound)
}

// handleCallback completes the flow: verify state, exchange the code, validate
// the id_token, mint a session, set __Secure-gw, and return to the original URL.
func (p *Provider) handleCallback(w http.ResponseWriter, r *http.Request) {
	qs := r.URL.Query()
	if e := qs.Get("error"); e != "" {
		p.auditDeny("authorization error")
		http.Error(w, "authorization failed: "+sanitize(e), http.StatusUnauthorized)
		return
	}
	state := qs.Get("state")
	code := qs.Get("code")
	if state == "" || code == "" {
		p.auditDeny("missing state or code")
		http.Error(w, "missing state or code", http.StatusBadRequest)
		return
	}
	st, ok, err := p.states.TakeState(r.Context(), state)
	if err != nil {
		p.log.Error("oidc: take oauth state", "error", err)
		http.Error(w, "auth temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	if !ok {
		// Unknown or already-redeemed state == CSRF/replay; fail closed.
		p.auditDeny("invalid state")
		http.Error(w, "invalid or expired authorization state", http.StatusBadRequest)
		return
	}

	tok, err := p.exchangeCode(r.Context(), code, st.CodeVerifier)
	if err != nil {
		p.log.Warn("oidc: code exchange failed", "error", err)
		p.auditDeny("code exchange failed")
		http.Error(w, "authorization code exchange failed", http.StatusBadGateway)
		return
	}

	claims, err := p.validateIDToken(r.Context(), tok.IDToken, st.Nonce)
	if err != nil {
		p.log.Warn("oidc: id_token validation failed", "error", err)
		p.auditDeny("invalid id_token")
		http.Error(w, "invalid id_token", http.StatusBadGateway)
		return
	}

	scope := tok.Scope
	if scope == "" {
		scope = requestedScope
	}
	now := p.now().Unix()
	id := p.token()
	sess := Session{
		ID:        id,
		Sub:       claims.Subject,
		Email:     claims.Email,
		Scope:     scope,
		CreatedAt: now,
		ExpiresAt: now + int64(p.cfg.SessionTTL.Seconds()),
	}
	if err := p.sessions.CreateSession(r.Context(), sess); err != nil {
		p.log.Error("oidc: create session", "error", err)
		http.Error(w, "auth temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	p.audit.Emit(audit.Event{
		Actor:    actorOr(claims.Subject, claims.Email),
		Action:   audit.ActionSSOEstablish,
		Target:   p.cfg.ClientID,
		Severity: audit.SeverityInfo,
	})
	p.setCookie(w, p.signer.sign(id), int(p.cfg.SessionTTL.Seconds()))
	http.Redirect(w, r, p.safeReturn(st.OriginalURL), http.StatusFound)
}

// handleLogout clears the session (best-effort) and the cookie, then returns the
// browser to root.
func (p *Provider) handleLogout(w http.ResponseWriter, r *http.Request) {
	sub := ""
	if c, err := r.Cookie(p.cfg.CookieName); err == nil {
		if id, ok := p.signer.verify(c.Value); ok {
			// Best-effort identity lookup so the audit event names the subject.
			if sess, found, _ := p.sessions.GetSession(r.Context(), id); found {
				sub = sess.Sub
			}
			_ = p.sessions.DeleteSession(r.Context(), id)
		}
	}
	p.audit.Emit(audit.Event{
		Actor:    actorOr(sub, "anonymous"),
		Action:   audit.ActionSSOLogout,
		Target:   p.cfg.ClientID,
		Severity: audit.SeverityInfo,
	})
	p.setCookie(w, "", -1)
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleLang sets the estate-wide display locale cookie and redirects back to a
// validated same-domain return target.
func (p *Provider) handleLang(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if to := r.URL.Query().Get("to"); validLang(to) {
		p.setLangCookie(w, to, langCookieMaxAge)
	}
	http.Redirect(w, r, p.langReturn(r), http.StatusFound)
}

// handleTheme sets the estate-wide display theme cookie and redirects back to a
// validated same-domain return target.
func (p *Provider) handleTheme(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if to := r.URL.Query().Get("to"); validTheme(to) {
		p.setThemeCookie(w, to, langCookieMaxAge)
	}
	http.Redirect(w, r, p.langReturn(r), http.StatusFound)
}

func validLang(code string) bool {
	switch code {
	case "en", "zh", "ja":
		return true
	default:
		return false
	}
}

func validTheme(code string) bool {
	switch code {
	case "light", "dark", "auto":
		return true
	default:
		return false
	}
}

func (p *Provider) langReturn(r *http.Request) string {
	q := r.URL.Query()
	if _, ok := q["return"]; ok {
		return p.safeReturn(q.Get("return"))
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		return p.safeReturn(ref)
	}
	return "/"
}

// auditDeny emits an sso.session.deny with a short, safe reason. The actor is
// anonymous because a failed callback never established an identity, and detail
// never carries token/code/secret material.
func (p *Provider) auditDeny(reason string) {
	p.audit.Emit(audit.Event{
		Actor:    "anonymous",
		Action:   audit.ActionSSODeny,
		Target:   p.cfg.ClientID,
		Severity: audit.SeverityWarning,
		Detail:   reason,
	})
}

// actorOr returns primary if non-empty, else the fallback. Used so an event
// names sub when known and degrades to email/"anonymous" otherwise.
func actorOr(primary, fallback string) string {
	if primary != "" {
		return primary
	}
	return fallback
}

// exchangeCode performs the client_secret_post token request against the INTERNAL
// token endpoint (over the provider's http.Client, which carries the mTLS
// transport when INTERNAL_MTLS=on).
func (p *Provider) exchangeCode(ctx context.Context, code, verifier string) (*tokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", p.cfg.RedirectURI)
	form.Set("client_id", p.cfg.ClientID)
	if p.cfg.ClientSecret != "" {
		form.Set("client_secret", p.cfg.ClientSecret)
	}
	form.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint status %d", resp.StatusCode)
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	if tr.IDToken == "" {
		return nil, fmt.Errorf("token response missing id_token")
	}
	return &tr, nil
}

// validateIDToken verifies the RS256 signature (via the shared JWKS cache),
// iss/aud/exp (via the parser), and the nonce binding.
func (p *Provider) validateIDToken(ctx context.Context, raw, wantNonce string) (*idTokenClaims, error) {
	claims := &idTokenClaims{}
	keyfunc := func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method %q", t.Header["alg"])
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("id_token missing kid")
		}
		return p.keys.KeyByKID(ctx, kid)
	}
	if _, err := p.parser.ParseWithClaims(raw, claims, keyfunc); err != nil {
		return nil, fmt.Errorf("parse id_token: %w", err)
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("id_token missing sub")
	}
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(wantNonce)) != 1 {
		return nil, fmt.Errorf("id_token nonce mismatch")
	}
	return claims, nil
}

// setCookie writes (or clears, when maxAge<0) the __Secure-gw session cookie. The
// Domain attribute (when CookieDomain is set) scopes it to the parent domain so a
// single login is presented across every *.w33d.xyz subdomain; an empty
// CookieDomain leaves it host-only. SameSite=Lax keeps it sent on the top-level
// navigation that returns from Keystone login.
func (p *Provider) setCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     p.cfg.CookieName,
		Value:    value,
		Path:     "/",
		Domain:   p.cfg.CookieDomain,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

// __Secure-lang is display-only and deliberately outside the gateway HMAC signature.
func (p *Provider) setLangCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     LangCookieName,
		Value:    value,
		Path:     "/",
		Domain:   p.cfg.CookieDomain,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

// __Secure-theme is display-only and deliberately outside the gateway HMAC signature.
func (p *Provider) setThemeCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     ThemeCookieName,
		Value:    value,
		Path:     "/",
		Domain:   p.cfg.CookieDomain,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

// token returns a fresh 256-bit base64url random token (state/nonce/verifier/id).
func (p *Provider) token() string {
	b := make([]byte, 32)
	if _, err := io.ReadFull(p.rand, b); err != nil {
		// rand.Reader does not fail in practice; panic surfaces a broken CSPRNG.
		panic("oidc: read random: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// tokenResponse is the subset of the token endpoint JSON the gateway consumes.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope"`
}

// idTokenClaims is the subset of id_token claims validated/consumed. iss/aud/exp
// are enforced by the parser; email/nonce are application claims.
type idTokenClaims struct {
	Email string `json:"email"`
	Nonce string `json:"nonce"`
	jwt.RegisteredClaims
}

// signer signs/verifies an opaque cookie value with HMAC-SHA256: "value.sig".
type signer struct{ key []byte }

func (s signer) sign(value string) string {
	return value + "." + base64.RawURLEncoding.EncodeToString(s.mac(value))
}

// verify returns the value iff the appended signature is valid (constant time).
func (s signer) verify(signed string) (string, bool) {
	i := strings.LastIndexByte(signed, '.')
	if i <= 0 || i == len(signed)-1 {
		return "", false
	}
	value, sig := signed[:i], signed[i+1:]
	want, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return "", false
	}
	if !hmac.Equal(want, s.mac(value)) {
		return "", false
	}
	return value, true
}

func (s signer) mac(value string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(value))
	return m.Sum(nil)
}

// pkceChallengeS256 derives base64url(sha256(verifier)) per RFC 7636.
func pkceChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// originalURL captures the ABSOLUTE URL the browser was trying to reach so the
// callback — which runs on the id.w33d.xyz host — can return the browser to the
// ORIGINAL subdomain (e.g. https://vitals.w33d.xyz/dashboard). The scheme is
// derived from the inbound connection (Sluice terminates TLS, so r.TLS is set for
// real public traffic); a request with no Host degrades to the relative path so
// the callback returns same-origin.
func originalURL(r *http.Request) string {
	uri := r.URL.RequestURI()
	if uri == "" {
		uri = "/"
	}
	if r.Host == "" {
		return uri
	}
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host + uri
}

// safeReturn validates the post-login redirect target before 302-ing the browser
// to it. To support cross-subdomain SSO an ABSOLUTE https URL is allowed, but ONLY
// when its host is within the configured cookie domain (e.g. *.w33d.xyz); any
// other absolute target (open-redirect attempt, foreign or non-https host) is
// downgraded to its path on the callback host, never followed to a foreign origin.
// A same-origin relative path is always safe. An empty/odd target falls back to
// root.
func (p *Provider) safeReturn(target string) string {
	if target == "" {
		return "/"
	}
	// Same-origin relative path ("/...", but not the protocol-relative "//host").
	if strings.HasPrefix(target, "/") && !strings.HasPrefix(target, "//") {
		return target
	}
	u, err := url.Parse(target)
	if err != nil {
		return "/"
	}
	if u.Scheme == "https" && u.Host != "" && p.hostInCookieDomain(u.Hostname()) {
		return target
	}
	// Not a trusted absolute target: keep only the (safe) path+query so we never
	// emit an open redirect to a foreign origin.
	rel := u.EscapedPath()
	if rel == "" {
		return "/"
	}
	if u.RawQuery != "" {
		rel += "?" + u.RawQuery
	}
	return rel
}

// hostInCookieDomain reports whether host is the cookie-domain apex or one of its
// subdomains. With CookieDomain unset (host-only cookie) nothing qualifies, so
// safeReturn admits relative paths only — the pre-subdomain behavior.
func (p *Provider) hostInCookieDomain(host string) bool {
	d := strings.TrimPrefix(p.cfg.CookieDomain, ".")
	if d == "" {
		return false
	}
	host = strings.ToLower(host)
	d = strings.ToLower(d)
	return host == d || strings.HasSuffix(host, "."+d)
}

// sanitize trims a provider-supplied error code to a short, safe echo.
func sanitize(s string) string {
	if len(s) > 64 {
		s = s[:64]
	}
	return strings.Map(func(r rune) rune {
		if r >= 0x20 && r < 0x7f {
			return r
		}
		return '?'
	}, s)
}

// nowUnix is the package default clock for the memory store.
func nowUnix() int64 { return time.Now().Unix() }
