package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/holdfast/sluice/internal/auth"
)

const (
	testKID      = "kid-oidc-test"
	testClientID = "gw-sluice"
	testSub      = "u_admin"
	testEmail    = "admin@steadholme.local"
)

// fakeIssuer is an httptest OIDC provider: /authorize auto-approves (simulating an
// already-logged-in browser) and /token exchanges the code after verifying PKCE,
// minting an RS256 id_token bound to the request's nonce.
type fakeIssuer struct {
	server *httptest.Server
	priv   *rsa.PrivateKey
	url    string
	// stepUpMode lets negative callback tests model an IdP that returns a token
	// which does not satisfy the requested strong assurance. Empty is canonical.
	stepUpMode string

	mu    sync.Mutex
	codes map[string]codeRec
}

type codeRec struct {
	challenge, nonce, redirectURI, clientID, scope, acr string
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	fi := &fakeIssuer{priv: priv, codes: map[string]codeRec{}}

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		pub := &priv.PublicKey
		var eBuf [4]byte
		binary.BigEndian.PutUint32(eBuf[:], uint32(pub.E))
		eBytes := eBuf[:]
		for len(eBytes) > 1 && eBytes[0] == 0 {
			eBytes = eBytes[1:]
		}
		writeJSON(w, map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": testKID,
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(eBytes),
		}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" ||
			q.Get("code_challenge") == "" || q.Get("client_id") != testClientID {
			http.Error(w, "bad authorize request", http.StatusBadRequest)
			return
		}
		code := "code-" + q.Get("state")
		fi.mu.Lock()
		fi.codes[code] = codeRec{
			challenge:   q.Get("code_challenge"),
			nonce:       q.Get("nonce"),
			redirectURI: q.Get("redirect_uri"),
			clientID:    q.Get("client_id"),
			scope:       q.Get("scope"),
			acr:         q.Get("acr_values"),
		}
		fi.mu.Unlock()
		loc := q.Get("redirect_uri") + "?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(q.Get("state"))
		http.Redirect(w, r, loc, http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "authorization_code" {
			http.Error(w, "bad grant", http.StatusBadRequest)
			return
		}
		code := r.Form.Get("code")
		fi.mu.Lock()
		rec, ok := fi.codes[code]
		delete(fi.codes, code)
		fi.mu.Unlock()
		if !ok {
			http.Error(w, "invalid_grant", http.StatusBadRequest)
			return
		}
		// PKCE S256 + binding checks.
		if pkceChallengeS256(r.Form.Get("code_verifier")) != rec.challenge ||
			r.Form.Get("redirect_uri") != rec.redirectURI ||
			r.Form.Get("client_id") != rec.clientID {
			http.Error(w, "invalid_grant", http.StatusBadRequest)
			return
		}
		idToken := fi.signID(t, rec.nonce, time.Now().Add(time.Hour))
		if rec.acr == stepUpRequiredACR {
			switch fi.stepUpMode {
			case "weak":
			case "stale":
				idToken = fi.signStrongID(t, rec.nonce, testSub, time.Now().Unix()-301, time.Now().Add(time.Hour))
			case "future":
				idToken = fi.signStrongID(t, rec.nonce, testSub, time.Now().Unix()+60, time.Now().Add(time.Hour))
			case "wrong-sub":
				idToken = fi.signStrongID(t, rec.nonce, "u_other", time.Now().Unix(), time.Now().Add(time.Hour))
			default:
				idToken = fi.signStrongID(t, rec.nonce, testSub, time.Now().Unix(), time.Now().Add(time.Hour))
			}
		}
		writeJSON(w, map[string]any{
			"access_token": "at-" + code,
			"id_token":     idToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        rec.scope,
		})
	})

	fi.server = httptest.NewServer(mux)
	fi.url = fi.server.URL
	t.Cleanup(fi.server.Close)
	return fi
}

// signID mints an RS256 id_token (iss/sub/aud/exp/email/nonce).
func (fi *fakeIssuer) signID(t *testing.T, nonce string, exp time.Time) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss":   fi.url,
		"sub":   testSub,
		"aud":   testClientID,
		"exp":   exp.Unix(),
		"iat":   time.Now().Add(-time.Minute).Unix(),
		"email": testEmail,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = testKID
	signed, err := tok.SignedString(fi.priv)
	if err != nil {
		t.Fatalf("sign id_token: %v", err)
	}
	return signed
}

func (fi *fakeIssuer) signStrongID(
	t *testing.T,
	nonce string,
	subject string,
	authTime int64,
	exp time.Time,
) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss":       fi.url,
		"sub":       subject,
		"aud":       testClientID,
		"exp":       exp.Unix(),
		"iat":       time.Now().Add(-time.Minute).Unix(),
		"email":     testEmail,
		"nonce":     nonce,
		"auth_time": authTime,
		"acr":       stepUpRequiredACR,
		"amr":       []string{"pwd", "otp"},
		"hf_mfa": map[string]any{
			"aal": SessionMFAStrong,
			"uv":  true,
			"sb":  strings.Repeat("a", 64),
			"fe":  7,
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = testKID
	signed, err := tok.SignedString(fi.priv)
	if err != nil {
		t.Fatalf("sign strong id_token: %v", err)
	}
	return signed
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// newTestProvider wires a Provider against the fake issuer with in-memory stores.
// RedirectURI is left empty; callers set it after the gateway TLS server starts.
func newTestProvider(t *testing.T, fi *fakeIssuer) *Provider {
	t.Helper()
	keys := auth.NewJWKSCache(fi.url+"/.well-known/openid-configuration",
		&http.Client{Timeout: 5 * time.Second}, time.Second,
		auth.WithJWKSURI(fi.url+"/jwks.json"))
	p, err := NewProvider(Config{
		Issuer:       fi.url,
		TokenURL:     fi.url + "/token",
		ClientID:     testClientID,
		ClientSecret: "shh",
		// Placeholder so NewProvider validates; gatewayServer overwrites it with the
		// real TLS server URL once it is known.
		RedirectURI:   "https://placeholder.invalid" + CallbackPath,
		SessionTTL:    time.Hour,
		SessionSecret: "unit-test-secret",
	}, keys, &http.Client{Timeout: 5 * time.Second}, NewMemoryStore(), NewMemoryStore(), nil)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return p
}

// gatewayServer mounts the provider's /_gw/* endpoints and an sso-gated echo
// route on a TLS server (required for the __Host-/Secure cookie), and returns the
// running server with RedirectURI wired back into the provider.
func gatewayServer(t *testing.T, p *Provider) *httptest.Server {
	t.Helper()
	echo := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := auth.IdentityFromContext(r.Context())
		if !ok {
			http.Error(w, "no identity", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"sub": id.Subject, "email": id.Email, "scope": id.Scope, "path": r.URL.RequestURI()})
	}))
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, GatewayPrefix) {
			p.ServeHTTP(w, r)
			return
		}
		echo.ServeHTTP(w, r)
	})
	srv := httptest.NewTLSServer(h)
	p.cfg.RedirectURI = srv.URL + CallbackPath
	t.Cleanup(srv.Close)
	return srv
}

func jarClient(t *testing.T, srv *httptest.Server) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	c := srv.Client()
	c.Jar = jar
	c.Timeout = 10 * time.Second
	return c
}

// TestSSOFullFlow drives the end-to-end browser SSO: protected GET -> authorize
// redirect -> callback (code exchange + id_token validation + session) -> back to
// the original URL with the verified identity available to the upstream.
func TestSSOFullFlow(t *testing.T) {
	fi := newFakeIssuer(t)
	p := newTestProvider(t, fi)
	srv := gatewayServer(t, p)
	client := jarClient(t, srv)

	resp, err := client.Get(srv.URL + "/app/dashboard?x=1")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("final status = %d, want 200", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["sub"] != testSub || body["email"] != testEmail {
		t.Errorf("identity = %v, want sub=%s email=%s", body, testSub, testEmail)
	}
	if body["path"] != "/app/dashboard?x=1" {
		t.Errorf("returned to %q, want original /app/dashboard?x=1", body["path"])
	}
	// A __Host-gw session cookie must now exist for the gateway origin.
	u, _ := url.Parse(srv.URL)
	var found bool
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == DefaultCookieName {
			found = true
		}
	}
	if !found {
		t.Error("expected __Host-gw session cookie to be set")
	}

	// With the session established, a second request is served WITHOUT bouncing to
	// the authorize endpoint (no redirect).
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	r2, err := client.Get(srv.URL + "/app/again")
	if err != nil {
		t.Fatalf("GET again: %v", err)
	}
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusOK {
		t.Errorf("session-backed status = %d, want 200 (no redirect)", r2.StatusCode)
	}
}

// TestBeginAuthRedirectParams asserts the authorize redirect carries every
// required OIDC + PKCE parameter.
func TestBeginAuthRedirectParams(t *testing.T) {
	fi := newFakeIssuer(t)
	p := newTestProvider(t, fi)
	srv := gatewayServer(t, p)
	nc := srv.Client()
	nc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	resp, err := nc.Get(srv.URL + "/app/secret")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if got := strings.TrimSuffix(loc.Scheme+"://"+loc.Host+loc.Path, "/authorize"); got != fi.url {
		t.Errorf("authorize base = %q, want %q", got, fi.url)
	}
	q := loc.Query()
	checks := map[string]string{
		"response_type":         "code",
		"client_id":             testClientID,
		"redirect_uri":          p.cfg.RedirectURI,
		"scope":                 requestedScope,
		"code_challenge_method": "S256",
	}
	for k, want := range checks {
		if q.Get(k) != want {
			t.Errorf("authorize param %s = %q, want %q", k, q.Get(k), want)
		}
	}
	for _, k := range []string{"state", "nonce", "code_challenge"} {
		if q.Get(k) == "" {
			t.Errorf("authorize missing %s", k)
		}
	}
	if got := q.Get("acr_values"); got != "" {
		t.Errorf("ordinary login unexpectedly requested acr_values=%q", got)
	}
}

// TestCallbackUnknownStateRejected proves an unknown/forged state is rejected
// (CSRF/replay), failing closed without minting a session.
func TestCallbackUnknownStateRejected(t *testing.T) {
	fi := newFakeIssuer(t)
	p := newTestProvider(t, fi)
	srv := gatewayServer(t, p)
	nc := srv.Client()
	nc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	resp, err := nc.Get(srv.URL + CallbackPath + "?state=forged&code=whatever")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for unknown state", resp.StatusCode)
	}
}

func TestCallbackRejectsAmbiguousStateWithoutConsumingEitherValue(t *testing.T) {
	fi := newFakeIssuer(t)
	p := newTestProvider(t, fi)
	stored := OAuthState{
		State: "legitimate-state", Nonce: "nonce", CodeVerifier: "verifier",
		ExpiresAt: time.Now().Add(time.Minute).Unix(), Flow: OAuthFlowLogin,
	}
	if err := p.states.PutState(context.Background(), stored); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodGet,
		"https://id.example"+CallbackPath+"?state=legitimate-state&state=attacker&code=unused",
		nil,
	)
	recorder := httptest.NewRecorder()
	p.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("ambiguous state status = %d, want 400", recorder.Code)
	}
	if _, ok, err := p.states.TakeState(context.Background(), stored.State); err != nil || !ok {
		t.Fatalf("ambiguous callback consumed legitimate state: ok=%t err=%v", ok, err)
	}
}

// TestTamperedCookieStartsLogin confirms a forged/garbage session cookie is
// treated as no session and restarts login (302 to authorize), never as a valid
// identity.
func TestTamperedCookieStartsLogin(t *testing.T) {
	fi := newFakeIssuer(t)
	p := newTestProvider(t, fi)
	srv := gatewayServer(t, p)
	nc := srv.Client()
	nc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/app", nil)
	req.Header.Set("Cookie", DefaultCookieName+"=forged.deadbeef")
	resp, err := nc.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302 (restart login)", resp.StatusCode)
	}
	if !strings.HasPrefix(resp.Header.Get("Location"), fi.url+"/authorize") {
		t.Errorf("Location = %q, want authorize redirect", resp.Header.Get("Location"))
	}
}

func TestOptionalMiddlewareInjectsSessionOrPassesAnonymous(t *testing.T) {
	fi := newFakeIssuer(t)
	p := newTestProvider(t, fi)

	now := time.Now().Unix()
	const sessionID = "session-optional"
	if err := p.sessions.CreateSession(context.Background(), Session{
		ID:        sessionID,
		Sub:       testSub,
		Email:     testEmail,
		Scope:     requestedScope,
		CreatedAt: now,
		ExpiresAt: now + 3600,
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	cases := []struct {
		name         string
		cookie       *http.Cookie
		wantIdentity bool
	}{
		{
			name: "valid session injects identity",
			cookie: &http.Cookie{
				Name:  DefaultCookieName,
				Value: p.signer.sign(sessionID),
			},
			wantIdentity: true,
		},
		{
			name: "missing cookie passes anonymously",
		},
		{
			name: "invalid cookie passes anonymously",
			cookie: &http.Cookie{
				Name:  DefaultCookieName,
				Value: "forged.deadbeef",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			var got *auth.Identity
			var ok bool
			h := p.OptionalMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				got, ok = auth.IdentityFromContext(r.Context())
				w.WriteHeader(http.StatusNoContent)
			}))

			req := httptest.NewRequest(http.MethodGet, "/app", nil)
			if tc.cookie != nil {
				req.AddCookie(tc.cookie)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if !called {
				t.Fatal("wrapped handler was not called")
			}
			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want 204", rec.Code)
			}
			if loc := rec.Header().Get("Location"); loc != "" {
				t.Fatalf("unexpected redirect Location = %q", loc)
			}
			if tc.wantIdentity {
				if !ok {
					t.Fatal("identity missing from context")
				}
				if got.Subject != testSub || got.Email != testEmail || got.Scope != requestedScope {
					t.Fatalf("identity = %#v, want sub=%s email=%s scope=%s", got, testSub, testEmail, requestedScope)
				}
				return
			}
			if ok {
				t.Fatalf("anonymous request had identity: %#v", got)
			}
		})
	}
}

// TestValidateIDTokenNonceBinding checks the nonce binding directly: a token whose
// nonce differs from the stored value is rejected.
func TestValidateIDTokenNonceBinding(t *testing.T) {
	fi := newFakeIssuer(t)
	p := newTestProvider(t, fi)

	good := fi.signID(t, "nonce-A", time.Now().Add(time.Hour))
	if _, err := p.validateIDToken(context.Background(), good, "nonce-A"); err != nil {
		t.Fatalf("valid nonce rejected: %v", err)
	}
	if _, err := p.validateIDToken(context.Background(), good, "nonce-B"); err == nil {
		t.Error("expected nonce mismatch to be rejected")
	}
	expired := fi.signID(t, "nonce-A", time.Now().Add(-time.Hour))
	if _, err := p.validateIDToken(context.Background(), expired, "nonce-A"); err == nil {
		t.Error("expected expired id_token to be rejected")
	}
}

// TestCookieSignerRoundTrip covers the opaque-cookie signer: round-trip succeeds,
// tampering fails.
func TestCookieSignerRoundTrip(t *testing.T) {
	s := signer{key: []byte("k")}
	signed := s.sign("session-123")
	if v, ok := s.verify(signed); !ok || v != "session-123" {
		t.Fatalf("verify = (%q,%v), want (session-123,true)", v, ok)
	}
	if _, ok := s.verify(signed + "x"); ok {
		t.Error("tampered signature accepted")
	}
	if _, ok := s.verify("no-dot"); ok {
		t.Error("malformed value accepted")
	}
	other := signer{key: []byte("different")}
	if _, ok := other.verify(signed); ok {
		t.Error("signature from a different key accepted")
	}
}

// TestSafeReturnCrossSubdomain covers the post-login redirect target validation:
// a relative path is kept; an absolute https URL within the cookie domain (apex or
// any subdomain) is allowed so login returns to the ORIGINAL subdomain; every
// other absolute target (foreign host, non-https, look-alike domain,
// protocol-relative) is downgraded to its path so we never emit an open redirect.
func TestSafeReturnCrossSubdomain(t *testing.T) {
	p := &Provider{cfg: Config{CookieDomain: ".w33d.xyz"}}
	cases := []struct{ in, want string }{
		{"/dashboard?x=1", "/dashboard?x=1"},
		{"https://vitals.w33d.xyz/dashboard?x=1", "https://vitals.w33d.xyz/dashboard?x=1"},
		{"https://w33d.xyz/", "https://w33d.xyz/"},
		{"https://evil.com/phish", "/phish"},
		{"http://vitals.w33d.xyz/x", "/x"},
		{"https://notw33d.xyz/x", "/x"},
		{"//evil.com/x", "/x"},
		{`/\\evil.com/x`, "/"},
		{"/safe\nunsafe", "/"},
		{"https://user@vitals.w33d.xyz/x", "/"},
		{"", "/"},
	}
	for _, tc := range cases {
		if got := p.safeReturn(tc.in); got != tc.want {
			t.Errorf("safeReturn(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	// With no cookie domain (host-only cookie) absolute URLs are never trusted and
	// downgrade to their path; relative paths still pass.
	hostOnly := &Provider{cfg: Config{CookieDomain: ""}}
	if got := hostOnly.safeReturn("https://vitals.w33d.xyz/x"); got != "/x" {
		t.Errorf("host-only safeReturn(absolute) = %q, want /x", got)
	}
	if got := hostOnly.safeReturn("/x?y=1"); got != "/x?y=1" {
		t.Errorf("host-only safeReturn(relative) = %q, want /x?y=1", got)
	}
}

func TestLangHandlerSetsCookieAndRedirectsSafely(t *testing.T) {
	p := &Provider{cfg: Config{CookieDomain: ".w33d.xyz"}}
	cases := []struct {
		name      string
		target    string
		referer   string
		wantLoc   string
		wantValue string
	}{
		{
			name:      "trusted return parameter",
			target:    "https://id.w33d.xyz" + LangPath + "?to=ja&return=" + url.QueryEscape("https://people.w33d.xyz/u/u_alice?tab=profile"),
			wantLoc:   "https://people.w33d.xyz/u/u_alice?tab=profile",
			wantValue: "ja",
		},
		{
			name:      "referer fallback is sanitized",
			target:    "https://id.w33d.xyz" + LangPath + "?to=zh",
			referer:   "https://evil.com/phish?x=1",
			wantLoc:   "/phish?x=1",
			wantValue: "zh",
		},
		{
			name:      "return parameter takes precedence over referer and is sanitized",
			target:    "https://id.w33d.xyz" + LangPath + "?to=en&return=" + url.QueryEscape("https://evil.com/return"),
			referer:   "https://people.w33d.xyz/safe",
			wantLoc:   "/return",
			wantValue: "en",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)
			if tc.referer != "" {
				req.Header.Set("Referer", tc.referer)
			}
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, req)
			resp := rec.Result()
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusFound {
				t.Fatalf("status = %d, want 302", resp.StatusCode)
			}
			if got := resp.Header.Get("Location"); got != tc.wantLoc {
				t.Fatalf("Location = %q, want %q", got, tc.wantLoc)
			}
			c := findCookie(resp.Cookies(), LangCookieName)
			if c == nil {
				t.Fatalf("missing %s Set-Cookie", LangCookieName)
			}
			if c.Value != tc.wantValue {
				t.Errorf("cookie value = %q, want %q", c.Value, tc.wantValue)
			}
			if c.Domain != "w33d.xyz" || c.Path != "/" || !c.Secure || !c.HttpOnly ||
				c.SameSite != http.SameSiteLaxMode || c.MaxAge != langCookieMaxAge {
				t.Errorf("cookie attributes = %#v, want __Secure-gw shape", c)
			}
		})
	}
}

func TestLangHandlerIgnoresInvalidLocale(t *testing.T) {
	p := &Provider{cfg: Config{CookieDomain: ".w33d.xyz"}}
	target := "https://id.w33d.xyz" + LangPath + "?to=fr&return=" + url.QueryEscape("https://evil.com/phish")
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "/phish" {
		t.Fatalf("Location = %q, want sanitized /phish", got)
	}
	if c := findCookie(resp.Cookies(), LangCookieName); c != nil {
		t.Fatalf("invalid locale set cookie: %#v", c)
	}
}

func TestThemeHandlerSetsCookieAndRedirectsSafely(t *testing.T) {
	p := &Provider{cfg: Config{CookieDomain: ".w33d.xyz"}}
	cases := []struct {
		name      string
		target    string
		referer   string
		wantLoc   string
		wantValue string
	}{
		{
			name:      "trusted return parameter",
			target:    "https://id.w33d.xyz" + ThemePath + "?to=dark&return=" + url.QueryEscape("https://people.w33d.xyz/u/u_alice?tab=profile"),
			wantLoc:   "https://people.w33d.xyz/u/u_alice?tab=profile",
			wantValue: "dark",
		},
		{
			name:      "referer fallback is sanitized",
			target:    "https://id.w33d.xyz" + ThemePath + "?to=auto",
			referer:   "https://evil.com/phish?x=1",
			wantLoc:   "/phish?x=1",
			wantValue: "auto",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)
			if tc.referer != "" {
				req.Header.Set("Referer", tc.referer)
			}
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, req)
			resp := rec.Result()
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusFound {
				t.Fatalf("status = %d, want 302", resp.StatusCode)
			}
			if got := resp.Header.Get("Location"); got != tc.wantLoc {
				t.Fatalf("Location = %q, want %q", got, tc.wantLoc)
			}
			c := findCookie(resp.Cookies(), ThemeCookieName)
			if c == nil {
				t.Fatalf("missing %s Set-Cookie", ThemeCookieName)
			}
			if c.Value != tc.wantValue {
				t.Errorf("cookie value = %q, want %q", c.Value, tc.wantValue)
			}
			if c.Domain != "w33d.xyz" || c.Path != "/" || !c.Secure || !c.HttpOnly ||
				c.SameSite != http.SameSiteLaxMode || c.MaxAge != langCookieMaxAge {
				t.Errorf("cookie attributes = %#v, want __Secure-gw shape", c)
			}
		})
	}
}

func TestThemeHandlerIgnoresInvalidTheme(t *testing.T) {
	p := &Provider{cfg: Config{CookieDomain: ".w33d.xyz"}}
	target := "https://id.w33d.xyz" + ThemePath + "?to=blues&return=" + url.QueryEscape("https://evil.com/path")
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "/path" {
		t.Fatalf("Location = %q, want sanitized /path", got)
	}
	if c := findCookie(resp.Cookies(), ThemeCookieName); c != nil {
		t.Fatalf("invalid theme set cookie: %#v", c)
	}
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// TestMemoryStateSingleUse asserts TakeState is single-use.
func TestMemoryStateSingleUse(t *testing.T) {
	m := NewMemoryStore()
	ctx := context.Background()
	st := OAuthState{State: "s1", Nonce: "n", CodeVerifier: "v", ExpiresAt: time.Now().Add(time.Minute).Unix()}
	if err := m.PutState(ctx, st); err != nil {
		t.Fatalf("PutState: %v", err)
	}
	if _, ok, _ := m.TakeState(ctx, "s1"); !ok {
		t.Fatal("first TakeState should succeed")
	}
	if _, ok, _ := m.TakeState(ctx, "s1"); ok {
		t.Error("second TakeState should fail (single-use)")
	}
}

func TestSubjectWideSessionRevocationEndpoint(t *testing.T) {
	store := NewMemoryStore()
	now := time.Now().Unix()
	for _, session := range []Session{
		{ID: "target-1", Sub: testSub, CreatedAt: now, ExpiresAt: now + 3600},
		{ID: "target-2", Sub: testSub, CreatedAt: now, ExpiresAt: now + 3600},
		{ID: "other", Sub: "u_other", CreatedAt: now, ExpiresAt: now + 3600},
	} {
		if err := store.CreateSession(context.Background(), session); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
	}

	p := &Provider{
		cfg:      Config{SessionRevocationToken: "dedicated-jml-token"},
		sessions: store,
		log:      slog.Default(),
	}

	request := func(method, authorization, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, SessionRevocationPath, strings.NewReader(body))
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
		recorder := httptest.NewRecorder()
		p.ServeHTTP(recorder, req)
		return recorder
	}

	if got := request(http.MethodGet, "Bearer dedicated-jml-token", ""); got.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d, want 405", got.Code)
	}
	if got := request(http.MethodPost, "Bearer wrong", `{"subject":"u_admin"}`); got.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token status = %d, want 401", got.Code)
	}
	if got := request(http.MethodPost, "Bearer dedicated-jml-token", `{"subject":" u_admin","state":"terminated","source_event_id":"event-42","source_version":42}`); got.Code != http.StatusBadRequest {
		t.Fatalf("non-canonical subject status = %d, want 400", got.Code)
	}
	if _, ok, _ := store.GetSession(context.Background(), "target-1"); !ok {
		t.Fatal("rejected request revoked a session")
	}

	const terminated = `{"subject":"u_admin","state":"terminated","source_event_id":"event-42","source_version":42,"correlation_id":"jml-42"}`
	got := request(http.MethodPost, "Bearer dedicated-jml-token", terminated)
	if got.Code != http.StatusOK {
		t.Fatalf("valid revoke status = %d body=%s", got.Code, got.Body.String())
	}
	if got.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got.Header().Get("Cache-Control"))
	}
	var response struct {
		Subject         string              `json:"subject"`
		State           SubjectSessionState `json:"state"`
		SourceVersion   int64               `json:"source_version"`
		Revoked         int64               `json:"revoked"`
		RevokedSessions int64               `json:"revoked_sessions"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Subject != testSub || response.State != SubjectSessionTerminated || response.SourceVersion != 42 {
		t.Fatalf("acknowledgement = %+v, want subject/state/version echo", response)
	}
	if response.Revoked != 2 || response.RevokedSessions != 2 {
		t.Fatalf("revoked = %d/%d, want 2/2", response.Revoked, response.RevokedSessions)
	}
	for _, id := range []string{"target-1", "target-2"} {
		if _, ok, _ := store.GetSession(context.Background(), id); ok {
			t.Fatalf("session %q survived subject revocation", id)
		}
	}
	if _, ok, _ := store.GetSession(context.Background(), "other"); !ok {
		t.Fatal("different subject session was revoked")
	}
	if err := store.CreateSession(context.Background(), Session{ID: "late", Sub: testSub, ExpiresAt: now + 3600}); !errors.Is(err, ErrSubjectSessionBlocked) {
		t.Fatalf("late session creation error = %v, want blocked", err)
	}

	// Replays are epoch/version-stable; conflicting or stale updates fail closed.
	if replay := request(http.MethodPost, "Bearer dedicated-jml-token", terminated); replay.Code != http.StatusOK || !strings.Contains(replay.Body.String(), `"replayed":true`) {
		t.Fatalf("replay = status %d body %q", replay.Code, replay.Body.String())
	}
	if conflict := request(http.MethodPost, "Bearer dedicated-jml-token", `{"subject":"u_admin","state":"active","source_event_id":"conflict","source_version":42}`); conflict.Code != http.StatusConflict {
		t.Fatalf("conflict status = %d, want 409", conflict.Code)
	}
	if active := request(http.MethodPost, "Bearer dedicated-jml-token", `{"subject":"u_admin","state":"active","source_event_id":"event-43","source_version":43}`); active.Code != http.StatusOK {
		t.Fatalf("active status = %d body=%q", active.Code, active.Body.String())
	}
	if err := store.CreateSession(context.Background(), Session{ID: "rehire", Sub: testSub, ExpiresAt: now + 3600}); err != nil {
		t.Fatalf("active subject could not create session: %v", err)
	}

	p.cfg.SessionRevocationToken = ""
	if disabled := request(http.MethodPost, "Bearer dedicated-jml-token", `{"subject":"u_other"}`); disabled.Code != http.StatusNotFound {
		t.Fatalf("disabled endpoint status = %d, want 404", disabled.Code)
	}
}

// TestNewProviderRequiresConfig confirms missing required fields are rejected so
// main degrades to no-SSO instead of running a half-built relying party.
func TestNewProviderRequiresConfig(t *testing.T) {
	keys := auth.NewJWKSCache("http://x/d", nil, time.Second, auth.WithJWKSURI("http://x/jwks"))
	base := Config{Issuer: "https://id", TokenURL: "https://k/token", ClientID: "c", RedirectURI: "https://id/_gw/auth/callback"}
	if _, err := NewProvider(base, keys, nil, NewMemoryStore(), NewMemoryStore(), nil); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	bad := base
	bad.ClientID = ""
	if _, err := NewProvider(bad, keys, nil, NewMemoryStore(), NewMemoryStore(), nil); err == nil {
		t.Error("expected error for empty client_id")
	}
	if _, err := NewProvider(base, nil, nil, NewMemoryStore(), NewMemoryStore(), nil); err == nil {
		t.Error("expected error for nil key resolver")
	}
}
