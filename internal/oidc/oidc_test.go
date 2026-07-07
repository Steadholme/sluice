package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
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
	testEmail    = "admin@holdfast.local"
)

// fakeIssuer is an httptest OIDC provider: /authorize auto-approves (simulating an
// already-logged-in browser) and /token exchanges the code after verifying PKCE,
// minting an RS256 id_token bound to the request's nonce.
type fakeIssuer struct {
	server *httptest.Server
	priv   *rsa.PrivateKey
	url    string

	mu    sync.Mutex
	codes map[string]codeRec
}

type codeRec struct {
	challenge, nonce, redirectURI, clientID, scope string
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
