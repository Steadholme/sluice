package test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/holdfast/sluice/internal/accesslog"
	"github.com/holdfast/sluice/internal/auth"
	"github.com/holdfast/sluice/internal/config"
	"github.com/holdfast/sluice/internal/gateway"
	"github.com/holdfast/sluice/internal/oidc"
	"github.com/holdfast/sluice/internal/store"
)

const ssoKID = "kid-sso-1"

// fakeOIDC is a one-server stand-in for Keystone used by the gateway-level SSO
// test: discovery + JWKS, an /authorize that auto-approves (the user is treated
// as already logged in), a /token that verifies PKCE and mints an id_token bound
// to the request nonce, and a mintAccess helper for the bearer route.
type fakeOIDC struct {
	server   *httptest.Server
	priv     *rsa.PrivateKey
	url      string
	clientID string

	mu    sync.Mutex
	codes map[string]map[string]string // code -> {challenge,nonce,redirect_uri,client_id,scope}
}

func newFakeOIDC(t *testing.T, clientID string) *fakeOIDC {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	fo := &fakeOIDC{priv: priv, clientID: clientID, codes: map[string]map[string]string{}}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                 fo.url,
			"jwks_uri":               fo.url + "/jwks.json",
			"authorization_endpoint": fo.url + "/authorize",
			"token_endpoint":         fo.url + "/token",
		})
	})
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		pub := &priv.PublicKey
		var eBuf [4]byte
		binary.BigEndian.PutUint32(eBuf[:], uint32(pub.E))
		eBytes := eBuf[:]
		for len(eBytes) > 1 && eBytes[0] == 0 {
			eBytes = eBytes[1:]
		}
		writeJSON(w, map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": ssoKID,
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(eBytes),
		}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := "code-" + q.Get("state")
		fo.mu.Lock()
		fo.codes[code] = map[string]string{
			"challenge":    q.Get("code_challenge"),
			"nonce":        q.Get("nonce"),
			"redirect_uri": q.Get("redirect_uri"),
			"client_id":    q.Get("client_id"),
			"scope":        q.Get("scope"),
		}
		fo.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		fo.mu.Lock()
		rec, ok := fo.codes[r.Form.Get("code")]
		delete(fo.codes, r.Form.Get("code"))
		fo.mu.Unlock()
		if !ok || pkceS256(r.Form.Get("code_verifier")) != rec["challenge"] ||
			r.Form.Get("redirect_uri") != rec["redirect_uri"] || r.Form.Get("client_id") != rec["client_id"] {
			http.Error(w, "invalid_grant", http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{
			"access_token": "at",
			"id_token":     fo.signID(t, rec["nonce"]),
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        rec["scope"],
		})
	})

	fo.server = httptest.NewServer(mux)
	fo.url = fo.server.URL
	t.Cleanup(fo.server.Close)
	return fo
}

func (fo *fakeOIDC) signID(t *testing.T, nonce string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": fo.url, "sub": "u_admin", "aud": fo.clientID,
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Add(-time.Minute).Unix(),
		"email": "admin@steadholme.local", "nonce": nonce,
	}
	return fo.sign(t, claims)
}

// mintAccess mints an RS256 access token for the bearer route (iss = this issuer).
func (fo *fakeOIDC) mintAccess(t *testing.T) string {
	t.Helper()
	return fo.sign(t, jwt.MapClaims{
		"iss": fo.url, "sub": "u_admin", "aud": fo.clientID,
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Add(-time.Minute).Unix(),
		"scope": "openid profile email",
	})
}

func (fo *fakeOIDC) sign(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = ssoKID
	signed, err := tok.SignedString(fo.priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func pkceS256(verifier string) string {
	// Mirror of oidc.pkceChallengeS256 for the fake token endpoint.
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// TestGatewaySSOEndToEnd drives the full gateway.Server over real TLS: an sso
// route browser-redirects through Keystone and ends up with X-Auth-* identity
// injected at the upstream, while the bearer + public paths are unchanged.
func TestGatewaySSOEndToEnd(t *testing.T) {
	accesslog.SetLogger(slog.New(slog.NewJSONHandler(io.Discard, nil)))

	const clientID = "gw-sluice"
	fo := newFakeOIDC(t, clientID)
	upstream := newEchoUpstream(t)

	// Reserve the public TLS address up front so the redirect_uri is known before
	// the provider (which validates it) is constructed.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	base := "https://" + ln.Addr().String()

	cfg := &config.Config{
		KeystoneIssuer: fo.url,
		JWKSFetchURL:   fo.url + "/jwks.json",
		Routes: []config.Route{
			{Name: "app", Match: config.Match{PathPrefix: "/app"}, Upstream: upstream.server.URL, Auth: "sso"},
			{Name: "api", Match: config.Match{PathPrefix: "/api"}, Upstream: upstream.server.URL, Auth: "bearer"},
			{Name: "pub", Match: config.Match{PathPrefix: "/public"}, Upstream: upstream.server.URL, Auth: "public"},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	jwks := auth.NewJWKSCache(cfg.DiscoveryURL, &http.Client{Timeout: 5 * time.Second}, time.Second,
		auth.WithJWKSURI(cfg.JWKSFetchURL))
	verifier := auth.NewVerifier(jwks, cfg.KeystoneIssuer)

	provider, err := oidc.NewProvider(oidc.Config{
		Issuer:        fo.url,
		TokenURL:      fo.url + "/token",
		ClientID:      clientID,
		ClientSecret:  "gw-secret",
		RedirectURI:   base + oidc.CallbackPath,
		SessionTTL:    time.Hour,
		SessionSecret: "sso-test-secret",
	}, jwks, &http.Client{Timeout: 5 * time.Second}, oidc.NewMemoryStore(), oidc.NewMemoryStore(), nil)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	handler := gateway.NewServer(store.NewStaticStore(cfg.Routes),
		gateway.Options{Verifier: verifier, Provider: provider}).Handler()

	certFile, keyFile, pool := genSelfSigned(t, t.TempDir())
	tlsCfg, err := gateway.FileTLSConfig(&config.Config{TLSMode: config.TLSModeFile, TLSCertFile: certFile, TLSKeyFile: keyFile})
	if err != nil {
		t.Fatalf("FileTLSConfig: %v", err)
	}
	srv := &http.Server{Handler: handler, TLSConfig: tlsCfg}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Timeout:   10 * time.Second,
		Jar:       jar,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
	}

	// (a) sso route, unauthenticated -> 302 to the authorize endpoint with the
	//     full OIDC + PKCE parameter set.
	t.Run("sso_unauthenticated_redirects_to_authorize", func(t *testing.T) {
		nc := &http.Client{
			Timeout:       10 * time.Second,
			Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		resp, err := nc.Get(base + "/app/dashboard")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("status = %d, want 302", resp.StatusCode)
		}
		loc, _ := url.Parse(resp.Header.Get("Location"))
		if !strings.HasPrefix(resp.Header.Get("Location"), fo.url+"/authorize") {
			t.Fatalf("Location = %q, want authorize redirect", resp.Header.Get("Location"))
		}
		q := loc.Query()
		for k, want := range map[string]string{
			"response_type": "code", "client_id": clientID,
			"redirect_uri": base + oidc.CallbackPath, "scope": "openid email profile",
			"code_challenge_method": "S256",
		} {
			if q.Get(k) != want {
				t.Errorf("authorize %s = %q, want %q", k, q.Get(k), want)
			}
		}
		for _, k := range []string{"state", "nonce", "code_challenge"} {
			if q.Get(k) == "" {
				t.Errorf("authorize missing %s", k)
			}
		}
	})

	// (b) full SSO flow -> identity injected as X-Auth-* at the upstream.
	t.Run("sso_full_flow_injects_identity", func(t *testing.T) {
		resp, err := client.Get(base + "/app/dashboard?x=1")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		h := decodeReflected(t, resp.Body)
		if got := first(h["X-Auth-Subject"]); got != "u_admin" {
			t.Errorf("X-Auth-Subject = %q, want u_admin", got)
		}
		if got := first(h["X-Auth-Email"]); got != "admin@steadholme.local" {
			t.Errorf("X-Auth-Email = %q, want admin@steadholme.local", got)
		}
		if got := first(h["X-Auth-Scope"]); got == "" {
			t.Error("X-Auth-Scope not injected")
		}
	})

	// (c) bearer route is unchanged: no token -> 401; valid token -> 200 + subject.
	t.Run("bearer_route_unchanged", func(t *testing.T) {
		noTok := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
		resp, err := noTok.Get(base + "/api/secret")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("no-token status = %d, want 401", resp.StatusCode)
		}

		req, _ := http.NewRequest(http.MethodGet, base+"/api/secret", nil)
		req.Header.Set("Authorization", "Bearer "+fo.mintAccess(t))
		resp2, err := noTok.Do(req)
		if err != nil {
			t.Fatalf("GET with token: %v", err)
		}
		defer resp2.Body.Close()
		if resp2.StatusCode != http.StatusOK {
			t.Fatalf("token status = %d, want 200", resp2.StatusCode)
		}
		if got := first(decodeReflected(t, resp2.Body)["X-Auth-Subject"]); got != "u_admin" {
			t.Errorf("bearer X-Auth-Subject = %q, want u_admin", got)
		}
	})

	// (d) public route still serves without any auth.
	t.Run("public_route_unchanged", func(t *testing.T) {
		noTok := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
		resp, err := noTok.Get(base + "/public/x")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("public status = %d, want 200", resp.StatusCode)
		}
	})
}

// TestGatewaySSOCrossSubdomainCookie proves the cutover to DOMAIN-SCOPED SSO: a
// login started on vitals.w33d.xyz mints a __Secure-gw cookie scoped to .w33d.xyz,
// the callback returns the browser to the FULL original subdomain URL, and the
// SAME cookie is accepted on a DIFFERENT subdomain (audit.w33d.xyz) — one login,
// every subdomain. Host-based vhost routing selects the per-subdomain upstream.
func TestGatewaySSOCrossSubdomainCookie(t *testing.T) {
	accesslog.SetLogger(slog.New(slog.NewJSONHandler(io.Discard, nil)))

	const clientID = "gw-sluice"
	fo := newFakeOIDC(t, clientID)
	upstream := newEchoUpstream(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	base := "https://" + ln.Addr().String()

	cfg := &config.Config{
		KeystoneIssuer: fo.url,
		JWKSFetchURL:   fo.url + "/jwks.json",
		Routes: []config.Route{
			{Name: "vitals", Match: config.Match{Host: "vitals.w33d.xyz", PathPrefix: "/"}, Upstream: upstream.server.URL, Auth: "sso"},
			{Name: "audit", Match: config.Match{Host: "audit.w33d.xyz", PathPrefix: "/"}, Upstream: upstream.server.URL, Auth: "sso"},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	jwks := auth.NewJWKSCache(cfg.DiscoveryURL, &http.Client{Timeout: 5 * time.Second}, time.Second,
		auth.WithJWKSURI(cfg.JWKSFetchURL))
	verifier := auth.NewVerifier(jwks, cfg.KeystoneIssuer)

	provider, err := oidc.NewProvider(oidc.Config{
		Issuer:        fo.url,
		TokenURL:      fo.url + "/token",
		ClientID:      clientID,
		ClientSecret:  "gw-secret",
		RedirectURI:   base + oidc.CallbackPath,
		SessionTTL:    time.Hour,
		SessionSecret: "cross-sub-secret",
		CookieDomain:  ".w33d.xyz",
	}, jwks, &http.Client{Timeout: 5 * time.Second}, oidc.NewMemoryStore(), oidc.NewMemoryStore(), nil)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	handler := gateway.NewServer(store.NewStaticStore(cfg.Routes),
		gateway.Options{Verifier: verifier, Provider: provider}).Handler()

	certFile, keyFile, pool := genSelfSigned(t, t.TempDir())
	tlsCfg, err := gateway.FileTLSConfig(&config.Config{TLSMode: config.TLSModeFile, TLSCertFile: certFile, TLSKeyFile: keyFile})
	if err != nil {
		t.Fatalf("FileTLSConfig: %v", err)
	}
	srv := &http.Server{Handler: handler, TLSConfig: tlsCfg}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	// Manual redirect chaining (no cookie jar): a Domain=.w33d.xyz cookie cannot be
	// stored by a jar keyed on the 127.0.0.1 dial host, so we thread the cookie by
	// hand and drive each subdomain via an explicit Host header (TLS SNI stays the
	// dialed 127.0.0.1, which the self-signed cert covers).
	nc := &http.Client{
		Timeout:       10 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	// (1) sso route on vitals.w33d.xyz, unauthenticated -> 302 to authorize.
	req1, _ := http.NewRequest(http.MethodGet, base+"/dashboard?x=1", nil)
	req1.Host = "vitals.w33d.xyz"
	resp1, err := nc.Do(req1)
	if err != nil {
		t.Fatalf("vitals GET: %v", err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusFound {
		t.Fatalf("vitals status = %d, want 302", resp1.StatusCode)
	}
	authorizeURL := resp1.Header.Get("Location")
	if !strings.HasPrefix(authorizeURL, fo.url+"/authorize") {
		t.Fatalf("Location = %q, want authorize redirect", authorizeURL)
	}

	// (2) follow to the fake Keystone authorize -> 302 back to the callback.
	resp2, err := nc.Get(authorizeURL)
	if err != nil {
		t.Fatalf("authorize GET: %v", err)
	}
	resp2.Body.Close()
	callbackURL := resp2.Header.Get("Location")

	// (3) callback mints the session, sets the DOMAIN cookie, and returns the
	//     browser to the FULL original vitals URL (cross-subdomain return).
	resp3, err := nc.Get(callbackURL)
	if err != nil {
		t.Fatalf("callback GET: %v", err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusFound {
		t.Fatalf("callback status = %d, want 302", resp3.StatusCode)
	}
	if got := resp3.Header.Get("Location"); got != "https://vitals.w33d.xyz/dashboard?x=1" {
		t.Errorf("callback returned to %q, want full original subdomain URL https://vitals.w33d.xyz/dashboard?x=1", got)
	}

	// The session cookie is the domain-scoped __Secure-gw (Domain attr present,
	// SameSite=Lax, Secure, HttpOnly).
	var gw *http.Cookie
	for _, c := range resp3.Cookies() {
		if c.Name == oidc.DefaultCookieName {
			gw = c
		}
	}
	if gw == nil {
		t.Fatalf("no %s cookie set on callback", oidc.DefaultCookieName)
	}
	if strings.TrimPrefix(gw.Domain, ".") != "w33d.xyz" {
		t.Errorf("cookie Domain = %q, want a .w33d.xyz domain scope", gw.Domain)
	}
	if gw.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie SameSite = %v, want Lax", gw.SameSite)
	}
	if !gw.Secure || !gw.HttpOnly {
		t.Errorf("cookie Secure=%v HttpOnly=%v, want both true", gw.Secure, gw.HttpOnly)
	}

	// (4) cross-subdomain: present the SAME cookie to a DIFFERENT subdomain
	//     (audit.w33d.xyz). The session is accepted with NO re-login and the
	//     verified identity is injected upstream.
	req4, _ := http.NewRequest(http.MethodGet, base+"/incidents", nil)
	req4.Host = "audit.w33d.xyz"
	req4.AddCookie(&http.Cookie{Name: gw.Name, Value: gw.Value})
	resp4, err := nc.Do(req4)
	if err != nil {
		t.Fatalf("audit GET: %v", err)
	}
	defer resp4.Body.Close()
	if resp4.StatusCode != http.StatusOK {
		t.Fatalf("cross-subdomain status = %d, want 200 (session accepted on another subdomain)", resp4.StatusCode)
	}
	h := decodeReflected(t, resp4.Body)
	if got := first(h["X-Auth-Subject"]); got != "u_admin" {
		t.Errorf("cross-subdomain X-Auth-Subject = %q, want u_admin", got)
	}
	if got := first(h["X-Auth-Email"]); got != "admin@steadholme.local" {
		t.Errorf("cross-subdomain X-Auth-Email = %q, want admin@steadholme.local", got)
	}
}
