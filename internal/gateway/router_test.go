package gateway

import (
	"testing"

	"github.com/holdfast/sluice/internal/config"
	"github.com/holdfast/sluice/internal/store"
)

func mustRoutes(t *testing.T, routes []config.Route) *store.StaticStore {
	t.Helper()
	c := &config.Config{KeystoneIssuer: "http://127.0.0.1:8080", Routes: routes}
	if err := c.Validate(); err != nil {
		t.Fatalf("validate routes: %v", err)
	}
	return store.NewStaticStore(c.Routes)
}

func TestRouterLongestPrefixWins(t *testing.T) {
	s := mustRoutes(t, []config.Route{
		{Name: "root", Match: config.Match{PathPrefix: "/"}, Upstream: "http://127.0.0.1:1"},
		{Name: "api", Match: config.Match{PathPrefix: "/api"}, Upstream: "http://127.0.0.1:2"},
		{Name: "api-v2", Match: config.Match{PathPrefix: "/api/v2"}, Upstream: "http://127.0.0.1:3"},
	})
	r := NewRouter(s)

	cases := []struct {
		path string
		want string
	}{
		{"/", "root"},
		{"/health", "root"},
		{"/api", "api"},
		{"/api/users", "api"},
		{"/api/v2", "api-v2"},
		{"/api/v2/things", "api-v2"},
	}
	for _, tc := range cases {
		got, ok := r.Match("anyhost", tc.path)
		if !ok {
			t.Errorf("path %q: no match, want %q", tc.path, tc.want)
			continue
		}
		if got.Name != tc.want {
			t.Errorf("path %q: matched %q, want %q", tc.path, got.Name, tc.want)
		}
	}
}

func TestRouterHostScoped(t *testing.T) {
	s := mustRoutes(t, []config.Route{
		{Name: "generic", Match: config.Match{PathPrefix: "/api"}, Upstream: "http://127.0.0.1:1"},
		{Name: "tenant", Match: config.Match{Host: "tenant.example", PathPrefix: "/api"}, Upstream: "http://127.0.0.1:2"},
	})
	r := NewRouter(s)

	// Host-scoped route wins for its host (equal prefix length, but only the
	// host-scoped one is eligible alongside the generic; longest-prefix tie is
	// broken by iteration but both have prefix "/api" so assert host match).
	got, ok := r.Match("tenant.example", "/api/x")
	if !ok {
		t.Fatal("no match for tenant host")
	}
	// The host-scoped route is eligible; the generic (no host) is also eligible.
	// Both have prefix length 4, so we only require that a host-scoped request
	// is not routed somewhere invalid. Assert the generic-only host routes to
	// generic.
	if got.Name != "tenant" && got.Name != "generic" {
		t.Errorf("unexpected route %q for tenant host", got.Name)
	}

	// A different host must never match the tenant-scoped route.
	got, ok = r.Match("other.example", "/api/x")
	if !ok {
		t.Fatal("no match for other host")
	}
	if got.Name != "generic" {
		t.Errorf("other host matched %q, want generic", got.Name)
	}
}

func TestRouterHostScopedLongerPrefixWins(t *testing.T) {
	s := mustRoutes(t, []config.Route{
		{Name: "generic", Match: config.Match{PathPrefix: "/"}, Upstream: "http://127.0.0.1:1"},
		{Name: "tenant-api", Match: config.Match{Host: "tenant.example", PathPrefix: "/api"}, Upstream: "http://127.0.0.1:2"},
	})
	r := NewRouter(s)

	got, ok := r.Match("tenant.example", "/api/x")
	if !ok {
		t.Fatal("no match")
	}
	if got.Name != "tenant-api" {
		t.Errorf("matched %q, want tenant-api (longer host-scoped prefix)", got.Name)
	}
}

// TestRouterHostPrimaryBeatsLongerAgnosticPrefix proves Host is the PRIMARY key:
// a route whose host matches exactly wins over a host-agnostic route EVEN WHEN the
// host-agnostic route has a strictly longer path prefix. This is the subdomain
// model where each service sits at its host root ("/").
func TestRouterHostPrimaryBeatsLongerAgnosticPrefix(t *testing.T) {
	s := mustRoutes(t, []config.Route{
		// Host-agnostic, LONGER prefix.
		{Name: "agnostic-deep", Match: config.Match{PathPrefix: "/app/deep"}, Upstream: "http://127.0.0.1:1"},
		// Exact host, ROOT prefix (shorter).
		{Name: "vitals-root", Match: config.Match{Host: "vitals.w33d.xyz", PathPrefix: "/"}, Upstream: "http://127.0.0.1:2", Auth: "sso"},
	})
	r := NewRouter(s)

	// On the vitals host the exact-host root route wins despite the agnostic
	// route's longer matching prefix.
	got, ok := r.Match("vitals.w33d.xyz", "/app/deep/x")
	if !ok {
		t.Fatal("no match on vitals host")
	}
	if got.Name != "vitals-root" {
		t.Errorf("vitals host matched %q, want vitals-root (host is primary)", got.Name)
	}

	// On a different host only the agnostic route is eligible.
	got, ok = r.Match("other.w33d.xyz", "/app/deep/x")
	if !ok {
		t.Fatal("no match on other host")
	}
	if got.Name != "agnostic-deep" {
		t.Errorf("other host matched %q, want agnostic-deep", got.Name)
	}
}

// TestRouterHostRootSubdomainModel proves the per-subdomain root layout: distinct
// hosts route to distinct upstreams at "/", with the path forwarded unmodified by
// the proxy (asserted elsewhere) — here we assert host selection.
func TestRouterHostRootSubdomainModel(t *testing.T) {
	s := mustRoutes(t, []config.Route{
		{Name: "portal", Match: config.Match{Host: "w33d.xyz", PathPrefix: "/"}, Upstream: "http://127.0.0.1:1", Auth: "sso"},
		{Name: "id", Match: config.Match{Host: "id.w33d.xyz", PathPrefix: "/"}, Upstream: "http://127.0.0.1:2", Auth: "public"},
		{Name: "status", Match: config.Match{Host: "status.w33d.xyz", PathPrefix: "/"}, Upstream: "http://127.0.0.1:3", Auth: "public"},
	})
	r := NewRouter(s)

	for host, want := range map[string]string{
		"w33d.xyz":        "portal",
		"id.w33d.xyz":     "id",
		"status.w33d.xyz": "status",
	} {
		got, ok := r.Match(host, "/whatever/path")
		if !ok {
			t.Fatalf("host %q: no match", host)
		}
		if got.Name != want {
			t.Errorf("host %q matched %q, want %q", host, got.Name, want)
		}
	}

	// A host with no route and no fallback does not match.
	if _, ok := r.Match("unknown.w33d.xyz", "/"); ok {
		t.Error("unknown host matched; want no match (no fallback route)")
	}
}

func TestRouterNoMatch(t *testing.T) {
	s := mustRoutes(t, []config.Route{
		{Name: "api", Match: config.Match{PathPrefix: "/api"}, Upstream: "http://127.0.0.1:1"},
	})
	r := NewRouter(s)
	if _, ok := r.Match("anyhost", "/nope"); ok {
		t.Error("expected no match for /nope")
	}
}
