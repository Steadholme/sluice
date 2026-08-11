package gateway

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/holdfast/sluice/internal/config"
)

func TestRequiredGroupFailsClosedWhenAuthorizerIsUnavailable(t *testing.T) {
	var upstreamHits atomic.Int32
	proxy := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
	route := config.Route{RequireGroup: "infra-admins"}

	rec := httptest.NewRecorder()
	rbacWrap(route, proxy, Options{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://admin.example/", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := upstreamHits.Load(); got != 0 {
		t.Fatalf("upstream hits = %d, want 0", got)
	}
}

func TestUngatedRouteRemainsPassThroughWithoutAuthorizer(t *testing.T) {
	var upstreamHits atomic.Int32
	proxy := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})

	rec := httptest.NewRecorder()
	rbacWrap(config.Route{}, proxy, Options{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://app.example/", nil))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if got := upstreamHits.Load(); got != 1 {
		t.Fatalf("upstream hits = %d, want 1", got)
	}
}
