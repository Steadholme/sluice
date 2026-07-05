package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/holdfast/sluice/internal/config"
)

func TestStripCookie(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string // "" means the Cookie header should be absent
	}{
		{"__Secure-gw", "__Secure-gw=x; a=1; b=2", "a=1; b=2"},
		{"__Secure-gw", "a=1; __Secure-gw=x; b=2", "a=1; b=2"},
		{"__Secure-gw", "a=1; b=2; __Secure-gw=x", "a=1; b=2"},
		{"__Secure-gw", "__Secure-gw=x", ""},                                     // only cookie -> header removed
		{"__Secure-gw", "a=1; b=2", "a=1; b=2"},                                  // absent -> unchanged
		{"", "__Secure-gw=x; a=1", "__Secure-gw=x; a=1"},                         // empty name -> no-op
		{"__Secure-gw", "__Secure-gw2=keep; __Secure-gw=x", "__Secure-gw2=keep"}, // prefix-only must not match
	}
	for _, c := range cases {
		h := http.Header{}
		h.Set("Cookie", c.in)
		stripCookie(h, c.name)
		if got := h.Get("Cookie"); got != c.want {
			t.Errorf("stripCookie(%q, %q) -> Cookie=%q, want %q", c.in, c.name, got, c.want)
		}
	}
}

// TestSessionCookieStrippedOnNonSSORoute is the security-critical one: an
// untrusted public upstream (a deployed site) must never receive the estate SSO
// cookie the browser attaches to *.w33d.xyz hosts, while the site's OWN cookies
// pass through untouched.
func TestSessionCookieStrippedOnNonSSORoute(t *testing.T) {
	seen := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Cookie")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	store := mustRoutes(t, []config.Route{
		{Name: "sfsite-x", Match: config.Match{Host: "app.example", PathPrefix: "/"}, Upstream: upstream.URL, Auth: config.AuthPublic},
	})
	handler := NewServer(store, Options{SessionCookieName: "__Secure-gw"}).Handler()

	req := httptest.NewRequest(http.MethodGet, "http://app.example/", nil)
	req.Host = "app.example"
	req.Header.Set("Cookie", "__Secure-gw=SECRETSESSION; site_pref=dark")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	got := <-seen
	if strings.Contains(got, "__Secure-gw") || strings.Contains(got, "SECRETSESSION") {
		t.Fatalf("estate session cookie leaked to untrusted upstream: %q", got)
	}
	if !strings.Contains(got, "site_pref=dark") {
		t.Fatalf("site's own cookie was dropped: %q", got)
	}
}

// TestSessionCookieKeptWhenStripDisabled locks the backward-compatible default:
// no SessionCookieName configured => no stripping (existing deployments unchanged).
func TestSessionCookieKeptWhenStripDisabled(t *testing.T) {
	seen := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Cookie")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	store := mustRoutes(t, []config.Route{
		{Name: "public", Match: config.Match{Host: "app.example", PathPrefix: "/"}, Upstream: upstream.URL, Auth: config.AuthPublic},
	})
	handler := NewServer(store, Options{}).Handler() // no SessionCookieName

	req := httptest.NewRequest(http.MethodGet, "http://app.example/", nil)
	req.Host = "app.example"
	req.Header.Set("Cookie", "__Secure-gw=SECRETSESSION")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if got := <-seen; !strings.Contains(got, "__Secure-gw=SECRETSESSION") {
		t.Fatalf("cookie unexpectedly stripped when disabled: %q", got)
	}
}

func TestFingerprint(t *testing.T) {
	a := []config.Route{{Name: "r1", Match: config.Match{Host: "a", PathPrefix: "/"}, Upstream: "http://u1", Auth: "public"}}
	b := []config.Route{{Name: "r1", Match: config.Match{Host: "a", PathPrefix: "/"}, Upstream: "http://u1", Auth: "public"}}
	if fingerprint(a) != fingerprint(b) {
		t.Fatal("identical route sets produced different fingerprints")
	}

	r2 := config.Route{Name: "r2", Match: config.Match{Host: "b", PathPrefix: "/"}, Upstream: "http://u2", Auth: "public"}
	two := []config.Route{a[0], r2}
	twoRev := []config.Route{r2, a[0]}
	if fingerprint(two) != fingerprint(twoRev) {
		t.Fatal("reordering routes changed the fingerprint")
	}
	if fingerprint(a) == fingerprint(two) {
		t.Fatal("adding a route did not change the fingerprint")
	}

	changed := []config.Route{{Name: "r1", Match: config.Match{Host: "a", PathPrefix: "/"}, Upstream: "http://CHANGED", Auth: "public"}}
	if fingerprint(a) == fingerprint(changed) {
		t.Fatal("changing an upstream did not change the fingerprint")
	}
}

type mutStore struct {
	mu     sync.Mutex
	routes []config.Route
}

func (m *mutStore) Routes() []config.Route {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.routes
}

func (m *mutStore) set(r []config.Route) {
	m.mu.Lock()
	m.routes = r
	m.mu.Unlock()
}

func TestReloadableHandlerRebuildsOnChange(t *testing.T) {
	ms := &mutStore{routes: []config.Route{{Name: "a", Match: config.Match{Host: "a", PathPrefix: "/"}, Upstream: "http://u", Auth: "public"}}}

	var mu sync.Mutex
	builds := 0
	build := func() http.Handler {
		mu.Lock()
		builds++
		mu.Unlock()
		return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	}
	buildCount := func() int { mu.Lock(); defer mu.Unlock(); return builds }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	NewReloadableHandler(ctx, ms, build, 5*time.Millisecond, nil)

	if buildCount() != 1 {
		t.Fatalf("initial build count = %d, want 1", buildCount())
	}
	time.Sleep(40 * time.Millisecond)
	if buildCount() != 1 {
		t.Fatalf("rebuilt despite no route change: %d", buildCount())
	}

	ms.set([]config.Route{
		{Name: "a", Match: config.Match{Host: "a", PathPrefix: "/"}, Upstream: "http://u", Auth: "public"},
		{Name: "b", Match: config.Match{Host: "b", PathPrefix: "/"}, Upstream: "http://u2", Auth: "public"},
	})
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if buildCount() >= 2 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("handler did not rebuild after route change: builds=%d", buildCount())
}
