package gateway

import (
	"context"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/holdfast/sluice/internal/auth"
	"github.com/holdfast/sluice/internal/config"
	"github.com/holdfast/sluice/internal/oidc"
	"github.com/holdfast/sluice/internal/pat"
	"github.com/holdfast/sluice/internal/rbac"
)

type unusedKeyResolver struct{}

type gatewayPATIntrospector struct {
	result pat.Result
	err    error
}

func (i gatewayPATIntrospector) Introspect(context.Context, string) (pat.Result, error) {
	return i.result, i.err
}

func (unusedKeyResolver) KeyByKID(context.Context, string) (*rsa.PublicKey, error) {
	return nil, errors.New("unused key resolver")
}

func newGatewayTestProvider(t *testing.T) *oidc.Provider {
	t.Helper()
	p, err := oidc.NewProvider(oidc.Config{
		Issuer:        "https://id.example",
		TokenURL:      "https://id.example/token",
		ClientID:      "gw-sluice",
		RedirectURI:   "https://id.example/_gw/auth/callback",
		SessionSecret: "unit-test-secret",
	}, unusedKeyResolver{}, nil, oidc.NewMemoryStore(), oidc.NewMemoryStore(), nil)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return p
}

func TestGatewayZoneHeaderOverwritesInbound(t *testing.T) {
	type contextHeaders struct {
		zones []string
		sigs  []string
		unix  int64
	}
	seen := make(chan contextHeaders, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- contextHeaders{
			zones: r.Header.Values(gatewayZoneHeader),
			sigs:  r.Header.Values(auth.HeaderGatewayZoneSig),
			unix:  time.Now().Unix(),
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	store := mustRoutes(t, []config.Route{
		{Name: "public", Match: config.Match{Host: "public.example", PathPrefix: "/"}, Upstream: upstream.URL, Auth: config.AuthPublic},
	})
	handler := NewServer(store, Options{
		GatewayZone:        config.GatewayZoneInternal,
		GatewayZoneHMACKey: "test-key",
	}).Handler()

	req := httptest.NewRequest(http.MethodGet, "http://public.example/", nil)
	req.Host = "public.example"
	req.Header.Add(gatewayZoneHeader, config.GatewayZoneExternal)
	req.Header.Add(gatewayZoneHeader, "spoofed")
	req.Header.Set(auth.HeaderGatewayZoneSig, "spoofed")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	got := <-seen
	if len(got.zones) != 1 {
		t.Fatalf("%s values = %v, want exactly one", gatewayZoneHeader, got.zones)
	}
	if got.zones[0] != config.GatewayZoneInternal {
		t.Errorf("%s = %q, want %q", gatewayZoneHeader, got.zones[0], config.GatewayZoneInternal)
	}
	if len(got.sigs) != 1 || got.sigs[0] == "" || got.sigs[0] == "spoofed" {
		t.Errorf("%s values = %v, want one Sluice-minted signature", auth.HeaderGatewayZoneSig, got.sigs)
	}
	current := auth.SignGatewayZone("test-key", "public", "public.example", config.GatewayZoneInternal, got.unix)
	previous := auth.SignGatewayZone("test-key", "public", "public.example", config.GatewayZoneInternal, got.unix-60)
	if got.sigs[0] != current && got.sigs[0] != previous {
		t.Errorf("%s is not bound to the matched route, host, zone, and current window", auth.HeaderGatewayZoneSig)
	}
}

func TestSSOOptionalWithoutProviderFallsThrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	store := mustRoutes(t, []config.Route{
		{Name: "git", Match: config.Match{Host: "git.example", PathPrefix: "/"}, Upstream: upstream.URL, Auth: config.AuthSSOOptional},
	})
	handler := NewServer(store, Options{}).Handler()

	req := httptest.NewRequest(http.MethodGet, "http://git.example/repos", nil)
	req.Host = "git.example"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
}

func TestSSOOptionalAnonymousRoutePassesThroughWithoutGateOrSpoofedIdentity(t *testing.T) {
	seenSubject := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenSubject <- r.Header.Get(auth.HeaderAuthSubject)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	verdict := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("anonymous optional route should not call Verdict")
	}))
	defer verdict.Close()

	store := mustRoutes(t, []config.Route{
		{
			Name:         "git",
			Match:        config.Match{Host: "git.example", PathPrefix: "/"},
			Upstream:     upstream.URL,
			Auth:         config.AuthSSOOptional,
			RequireGroup: "estate-users",
		},
	})
	handler := NewServer(store, Options{
		Provider: newGatewayTestProvider(t),
		Authz: rbac.New(rbac.Config{
			Enabled:    true,
			VerdictURL: verdict.URL,
			Token:      "verdict-token",
		}),
	}).Handler()

	req := httptest.NewRequest(http.MethodGet, "http://git.example/repos", nil)
	req.Host = "git.example"
	req.Header.Set(auth.HeaderAuthSubject, "forged-user")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if got := <-seenSubject; got != "" {
		t.Fatalf("%s reached upstream as %q, want stripped/empty", auth.HeaderAuthSubject, got)
	}
}

func TestPATRouteTerminatesTokenAndInjectsOnlyVerifiedIdentity(t *testing.T) {
	type observed struct {
		authorization string
		subject       string
		scope         string
		signature     string
	}
	seen := make(chan observed, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- observed{
			authorization: r.Header.Get("Authorization"),
			subject:       r.Header.Get(auth.HeaderAuthSubject),
			scope:         r.Header.Get(auth.HeaderAuthScope),
			signature:     r.Header.Get(auth.HeaderAuthSig),
		}
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("Vary", "Accept-Encoding")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	const requiredScope = "corvid:temp-mail:delete"
	store := mustRoutes(t, []config.Route{{
		Name:         "corvid-delete",
		Match:        config.Match{Host: "mail.example", PathPrefix: "/api/v1/temp-mailboxes/"},
		Upstream:     upstream.URL,
		Auth:         config.AuthPAT,
		RequireScope: requiredScope,
	}})
	handler := NewServer(store, Options{
		PATIntrospector: gatewayPATIntrospector{result: pat.Result{
			Active:  true,
			Subject: "u_test",
			Scope:   "profile " + requiredScope,
		}},
		GatewayHMACKey: "identity-hmac-key",
	}).Handler()

	const rawPAT = "pat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	req := httptest.NewRequest(http.MethodDelete, "http://mail.example/api/v1/temp-mailboxes/opaque-id", nil)
	req.Host = "mail.example"
	req.Header.Set("Authorization", "Bearer "+rawPAT)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	got := <-seen
	if got.authorization != "" {
		t.Fatalf("raw PAT reached upstream in Authorization: %q", got.authorization)
	}
	if got.subject != "u_test" || got.scope != "profile "+requiredScope || got.signature == "" {
		t.Fatalf("upstream identity = %+v", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if !headerHasValue(rec.Header().Values("Vary"), "Accept-Encoding") || !headerHasValue(rec.Header().Values("Vary"), "Authorization") {
		t.Fatalf("Vary = %q", rec.Header().Values("Vary"))
	}
}

func TestPATRouteMissingIntrospectionConfigFailsClosed(t *testing.T) {
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamHit = true
	}))
	defer upstream.Close()
	store := mustRoutes(t, []config.Route{{
		Name:         "corvid-delete",
		Match:        config.Match{Host: "mail.example", PathPrefix: "/api/"},
		Upstream:     upstream.URL,
		Auth:         config.AuthPAT,
		RequireScope: "corvid:temp-mail:delete",
	}})
	handler := NewServer(store, Options{}).Handler()
	req := httptest.NewRequest(http.MethodDelete, "http://mail.example/api/resource", nil)
	req.Host = "mail.example"
	req.Header.Set("Authorization", "Bearer pat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if upstreamHit {
		t.Fatal("PAT route reached upstream without introspection configuration")
	}
	if rec.Header().Get("Cache-Control") != "private, no-store" || !headerHasValue(rec.Header().Values("Vary"), "Authorization") {
		t.Fatalf("privacy headers: Cache-Control=%q Vary=%q", rec.Header().Get("Cache-Control"), rec.Header().Values("Vary"))
	}
}

func TestNonPATRoutePreservesAuthorizationHeader(t *testing.T) {
	seen := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	store := mustRoutes(t, []config.Route{{
		Name: "existing-public", Match: config.Match{Host: "api.example", PathPrefix: "/"},
		Upstream: upstream.URL, Auth: config.AuthPublic,
	}})
	handler := NewServer(store, Options{}).Handler()
	req := httptest.NewRequest(http.MethodGet, "http://api.example/resource", nil)
	req.Host = "api.example"
	req.Header.Set("Authorization", "Bearer existing-non-pat-credential")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if got := <-seen; got != "Bearer existing-non-pat-credential" {
		t.Fatalf("Authorization = %q, existing non-PAT behavior changed", got)
	}
}

func headerHasValue(values []string, want string) bool {
	for _, value := range values {
		for _, field := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(field), want) {
				return true
			}
		}
	}
	return false
}
