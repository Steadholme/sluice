package test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/holdfast/sluice/internal/accesslog"
	"github.com/holdfast/sluice/internal/auth"
	"github.com/holdfast/sluice/internal/config"
	"github.com/holdfast/sluice/internal/gateway"
	"github.com/holdfast/sluice/internal/store"
)

const testKID = "kid-keystone-1"

// fakeKeystone is an httptest server that serves OIDC discovery + JWKS for a
// generated RSA key and mints RS256 tokens, matching the shared contract.
type fakeKeystone struct {
	server *httptest.Server
	priv   *rsa.PrivateKey
	issuer string
}

func newFakeKeystone(t *testing.T) *fakeKeystone {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	fk := &fakeKeystone{priv: priv}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                fk.issuer,
			"jwks_uri":                              fk.issuer + "/jwks.json",
			"authorization_endpoint":                fk.issuer + "/authorize",
			"token_endpoint":                        fk.issuer + "/token",
			"userinfo_endpoint":                     fk.issuer + "/userinfo",
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code"},
			"code_challenge_methods_supported":      []string{"S256"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"subject_types_supported":               []string{"public"},
			"scopes_supported":                      []string{"openid", "profile", "email"},
		})
	})
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		pub := &priv.PublicKey
		nStr := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		var eBuf [4]byte
		binary.BigEndian.PutUint32(eBuf[:], uint32(pub.E))
		eBytes := eBuf[:]
		for len(eBytes) > 1 && eBytes[0] == 0 {
			eBytes = eBytes[1:]
		}
		eStr := base64.RawURLEncoding.EncodeToString(eBytes)
		writeJSON(w, map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA", "use": "sig", "alg": "RS256", "kid": testKID,
				"n": nStr, "e": eStr,
			}},
		})
	})

	fk.server = httptest.NewServer(mux)
	fk.issuer = fk.server.URL
	t.Cleanup(fk.server.Close)
	return fk
}

// mint creates an RS256 access token with the given issuer and expiry.
func (fk *fakeKeystone) mint(t *testing.T, issuer string, exp time.Time) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss":   issuer,
		"sub":   "u_admin",
		"aud":   "sluice-dev",
		"exp":   exp.Unix(),
		"iat":   time.Now().Add(-time.Minute).Unix(),
		"scope": "openid profile email",
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = testKID
	signed, err := tok.SignedString(fk.priv)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

// echoUpstream reflects received request headers as a JSON body and counts hits.
type echoUpstream struct {
	server *httptest.Server
	hits   atomic.Int64
}

func newEchoUpstream(t *testing.T) *echoUpstream {
	t.Helper()
	eu := &echoUpstream{}
	eu.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		eu.hits.Add(1)
		writeJSON(w, map[string]any{
			"headers": r.Header,
			"host":    r.Host,
			"path":    r.URL.Path,
		})
	}))
	t.Cleanup(eu.server.Close)
	return eu
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// newSluiceHandler assembles a real Sluice http.Handler with one public and one
// protected route, both pointing at the echo upstream. It is the shared core
// used by both the plain-HTTP integration server and the file-mode TLS test.
func newSluiceHandler(t *testing.T, keystone *fakeKeystone, upstream string) http.Handler {
	t.Helper()
	cfg := &config.Config{
		ListenAddr:     "127.0.0.1:0",
		KeystoneIssuer: keystone.issuer,
		Routes: []config.Route{
			{Name: "public", Match: config.Match{PathPrefix: "/public"}, Upstream: upstream, Protected: false},
			{Name: "protected", Match: config.Match{PathPrefix: "/api"}, Upstream: upstream, Protected: true},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config validate: %v", err)
	}

	jwks := auth.NewJWKSCache(cfg.DiscoveryURL, &http.Client{Timeout: 5 * time.Second}, time.Second)
	if err := jwks.Warm(context.Background()); err != nil {
		t.Fatalf("warm jwks: %v", err)
	}
	verifier := auth.NewVerifier(jwks, cfg.KeystoneIssuer)
	return gateway.NewServer(store.NewStaticStore(cfg.Routes), gateway.Options{Verifier: verifier}).Handler()
}

// buildSluice wraps the shared handler in a plain-HTTP httptest server.
func buildSluice(t *testing.T, keystone *fakeKeystone, upstream string) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(newSluiceHandler(t, keystone, upstream))
	t.Cleanup(s.Close)
	return s
}

func decodeReflected(t *testing.T, body io.Reader) map[string][]string {
	t.Helper()
	var payload struct {
		Headers map[string][]string `json:"headers"`
	}
	if err := json.NewDecoder(body).Decode(&payload); err != nil {
		t.Fatalf("decode reflected headers: %v", err)
	}
	return payload.Headers
}

func TestIntegrationContract(t *testing.T) {
	// Silence access logs during the test.
	accesslog.SetLogger(slog.New(slog.NewJSONHandler(io.Discard, nil)))

	keystone := newFakeKeystone(t)
	upstream := newEchoUpstream(t)
	sluice := buildSluice(t, keystone, upstream.server.URL)
	client := sluice.Client()

	// (a) public route proxies 200 and upstream saw X-Forwarded-*.
	t.Run("public_route_forwards", func(t *testing.T) {
		resp, err := client.Get(sluice.URL + "/public/hello")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		h := decodeReflected(t, resp.Body)
		for _, want := range []string{"X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host"} {
			if len(h[want]) == 0 || h[want][0] == "" {
				t.Errorf("upstream missing %s header: %v", want, h[want])
			}
		}
	})

	// (b) protected route with no token -> 401 + WWW-Authenticate, upstream NOT hit.
	t.Run("protected_no_token", func(t *testing.T) {
		before := upstream.hits.Load()
		resp, err := client.Get(sluice.URL + "/api/secret")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", resp.StatusCode)
		}
		if got := resp.Header.Get("WWW-Authenticate"); got != "Bearer" {
			t.Errorf("WWW-Authenticate = %q, want Bearer", got)
		}
		if after := upstream.hits.Load(); after != before {
			t.Errorf("upstream was hit on unauthenticated request: before=%d after=%d", before, after)
		}
	})

	// (c) protected route with valid token -> 200 and X-Auth-* injected.
	t.Run("protected_valid_token", func(t *testing.T) {
		token := keystone.mint(t, keystone.issuer, time.Now().Add(time.Hour))
		req, _ := http.NewRequest(http.MethodGet, sluice.URL+"/api/secret", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
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
		if got := first(h["X-Auth-Scope"]); got != "openid profile email" {
			t.Errorf("X-Auth-Scope = %q, want 'openid profile email'", got)
		}
	})

	// (d) expired token -> 401.
	t.Run("expired_token", func(t *testing.T) {
		token := keystone.mint(t, keystone.issuer, time.Now().Add(-time.Hour))
		req, _ := http.NewRequest(http.MethodGet, sluice.URL+"/api/secret", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", resp.StatusCode)
		}
	})

	// (e) wrong-issuer token -> 401.
	t.Run("wrong_issuer_token", func(t *testing.T) {
		token := keystone.mint(t, "http://evil.example", time.Now().Add(time.Hour))
		req, _ := http.NewRequest(http.MethodGet, sluice.URL+"/api/secret", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", resp.StatusCode)
		}
	})

	// (f) client-sent X-Auth-Subject is stripped and replaced by verified value.
	t.Run("spoofed_auth_header_stripped", func(t *testing.T) {
		token := keystone.mint(t, keystone.issuer, time.Now().Add(time.Hour))
		req, _ := http.NewRequest(http.MethodGet, sluice.URL+"/api/secret", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Auth-Subject", "attacker")
		req.Header.Set("X-Auth-Scope", "admin:everything")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		h := decodeReflected(t, resp.Body)
		if got := first(h["X-Auth-Subject"]); got != "u_admin" {
			t.Errorf("X-Auth-Subject = %q, want u_admin (spoof must be replaced)", got)
		}
		if got := first(h["X-Auth-Scope"]); got != "openid profile email" {
			t.Errorf("X-Auth-Scope = %q, want verified scope (spoof must be replaced)", got)
		}
	})

	// public route must also strip client X-Auth-* (no auth context to re-inject).
	t.Run("public_route_strips_spoofed_auth", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, sluice.URL+"/public/hello", nil)
		req.Header.Set("X-Auth-Subject", "attacker")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		h := decodeReflected(t, resp.Body)
		if got := first(h["X-Auth-Subject"]); got != "" {
			t.Errorf("public route leaked X-Auth-Subject = %q, want empty", got)
		}
	})
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}
