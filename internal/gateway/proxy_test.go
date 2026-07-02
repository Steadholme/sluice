package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/holdfast/sluice/internal/config"
)

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
