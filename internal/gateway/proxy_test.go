package gateway

import (
	"context"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/holdfast/sluice/internal/auth"
	"github.com/holdfast/sluice/internal/config"
	"github.com/holdfast/sluice/internal/oidc"
	"github.com/holdfast/sluice/internal/rbac"
)

type unusedKeyResolver struct{}

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
	seen := make(chan []string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Values(gatewayZoneHeader)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	store := mustRoutes(t, []config.Route{
		{Name: "public", Match: config.Match{Host: "public.example", PathPrefix: "/"}, Upstream: upstream.URL, Auth: config.AuthPublic},
	})
	handler := NewServer(store, Options{GatewayZone: config.GatewayZoneInternal}).Handler()

	req := httptest.NewRequest(http.MethodGet, "http://public.example/", nil)
	req.Host = "public.example"
	req.Header.Add(gatewayZoneHeader, config.GatewayZoneExternal)
	req.Header.Add(gatewayZoneHeader, "spoofed")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	got := <-seen
	if len(got) != 1 {
		t.Fatalf("%s values = %v, want exactly one", gatewayZoneHeader, got)
	}
	if got[0] != config.GatewayZoneInternal {
		t.Errorf("%s = %q, want %q", gatewayZoneHeader, got[0], config.GatewayZoneInternal)
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
