package gateway

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/holdfast/sluice/internal/config"
)

func TestPublicOnlyRejectsInternalNamespaceBeforeRootRoute(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	routes := mustRoutes(t, []config.Route{{
		Name:     "sso-root",
		Match:    config.Match{Host: "id.example", PathPrefix: "/"},
		Upstream: upstream.URL,
		Auth:     config.AuthPublic,
	}})
	handler := NewServer(routes, Options{PublicOnly: true}).Handler()

	for _, target := range []string{
		"http://id.example/internal",
		"http://id.example/internal/",
		"http://id.example/internal/v1/pats/introspect",
		"http://id.example/internal/v1/pats/introspect/",
		"http://id.example/internal/v1/pats/introspect?probe=1",
	} {
		t.Run(target, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, target, nil)
			req.Host = "id.example"
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", rec.Code)
			}
		})
	}
	if got := upstreamHits.Load(); got != 0 {
		t.Fatalf("public /internal request fell through to root upstream %d times", got)
	}
}

func TestInternalInstanceKeepsInternalNamespaceRouting(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	routes := mustRoutes(t, []config.Route{{
		Name:     "root",
		Match:    config.Match{Host: "id.example", PathPrefix: "/"},
		Upstream: upstream.URL,
		Auth:     config.AuthPublic,
	}})
	handler := NewServer(routes, Options{PublicOnly: false}).Handler()
	req := httptest.NewRequest(http.MethodPost, "http://id.example/internal/v1/pats/introspect?probe=1", nil)
	req.Host = "id.example"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if got := upstreamHits.Load(); got != 1 {
		t.Fatalf("internal upstream hits = %d, want 1", got)
	}
}

func TestPublicOnlyInternalBoundaryDoesNotClaimSimilarPaths(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	routes := mustRoutes(t, []config.Route{{
		Name:     "root",
		Match:    config.Match{Host: "id.example", PathPrefix: "/"},
		Upstream: upstream.URL,
		Auth:     config.AuthPublic,
	}})
	handler := NewServer(routes, Options{PublicOnly: true}).Handler()

	for _, path := range []string{"/internal-api", "/internality"} {
		req := httptest.NewRequest(http.MethodGet, "http://id.example"+path, nil)
		req.Host = "id.example"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("%s status = %d, want 204", path, rec.Code)
		}
	}
}
