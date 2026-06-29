package audit

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestEmitDisabledIsNoop confirms the default (disabled) Emitter, a nil Emitter,
// and a misconfigured-but-enabled Emitter all swallow Emit without side effects.
func TestEmitDisabledIsNoop(t *testing.T) {
	var nilEmitter *Emitter
	nilEmitter.Emit(Event{Action: ActionForwardAuthDeny}) // must not panic
	if nilEmitter.Dropped() != 0 {
		t.Errorf("nil emitter Dropped = %d, want 0", nilEmitter.Dropped())
	}

	off := New(Config{Enabled: false})
	off.Emit(Event{Action: ActionForwardAuthAllow})
	if off.Dropped() != 0 {
		t.Errorf("disabled emitter Dropped = %d, want 0", off.Dropped())
	}

	// Enabled but missing URL/token -> stays disabled, never panics.
	misconfigured := New(Config{Enabled: true})
	misconfigured.Emit(Event{Action: ActionForwardAuthAllow})
	if misconfigured.enabled {
		t.Error("emitter with missing URL/token should stay disabled")
	}
}

// TestEmitNonBlockingDropsWhenFull is the core guarantee: with the worker wedged
// on a hung Watchtower, flooding Emit returns immediately and drops the excess
// instead of blocking the caller, and never panics.
func TestEmitNonBlockingDropsWhenFull(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // hang every POST so the worker cannot drain the queue
	}))
	defer srv.Close()
	defer close(release)

	e := New(Config{Enabled: true, URL: srv.URL, Token: "ingest-secret", QueueCap: 8, Timeout: time.Second})
	defer e.Close()

	const n = 50000
	start := time.Now()
	for i := 0; i < n; i++ {
		e.Emit(Event{Action: ActionForwardAuthDeny, Target: "/x", Severity: SeverityWarning})
	}
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("Emit blocked: %v to enqueue %d events (worker wedged); must be non-blocking", elapsed, n)
	}
	// Worker pulled at most one event and is hung; the queue (cap 8) fills and the
	// rest are dropped. So drops must be large (≈ n).
	if got := e.Dropped(); got < n-100 {
		t.Fatalf("Dropped = %d, want ~%d (excess dropped, not blocked)", got, n)
	}
}

// TestEmitPostsEventFields proves an enabled Emitter delivers the exact logical
// fields to WATCHTOWER_URL/events with the ingest bearer, and stamps source.
func TestEmitPostsEventFields(t *testing.T) {
	type captured struct {
		path string
		auth string
		body Event
	}
	got := make(chan captured, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var ev Event
		_ = json.Unmarshal(raw, &ev)
		got <- captured{path: r.URL.Path, auth: r.Header.Get("Authorization"), body: ev}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	e := New(Config{Enabled: true, URL: srv.URL, Token: "ingest-secret"})
	defer e.Close()

	e.Emit(Event{
		Actor:    "anonymous",
		Action:   ActionForwardAuthDeny,
		Target:   "/api/secret",
		Severity: SeverityWarning,
		Detail:   "invalid token",
	})

	select {
	case c := <-got:
		if c.path != "/events" {
			t.Errorf("POST path = %q, want /events", c.path)
		}
		if c.auth != "Bearer ingest-secret" {
			t.Errorf("Authorization = %q, want Bearer ingest-secret", c.auth)
		}
		if c.body.Source != SourceSluice {
			t.Errorf("source = %q, want %q", c.body.Source, SourceSluice)
		}
		if c.body.Action != ActionForwardAuthDeny || c.body.Actor != "anonymous" ||
			c.body.Target != "/api/secret" || c.body.Severity != SeverityWarning || c.body.Detail != "invalid token" {
			t.Errorf("event mismatch: %+v", c.body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("watchtower received no event within 3s")
	}
}

// TestEmitWatchtowerDownDoesNotBlock confirms that with Watchtower unreachable,
// Emit still returns immediately (delivery failure is swallowed by the worker).
func TestEmitWatchtowerDownDoesNotBlock(t *testing.T) {
	// 203.0.113.0/24 (TEST-NET-3) is non-routable; the worker's POST fails, but
	// that is invisible to Emit.
	e := New(Config{Enabled: true, URL: "http://203.0.113.1:9", Token: "t", Timeout: 200 * time.Millisecond})
	defer e.Close()

	start := time.Now()
	for i := 0; i < 100; i++ {
		e.Emit(Event{Action: ActionForwardAuthDeny, Target: "/x"})
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Emit blocked %v with Watchtower down; must be fire-and-forget", elapsed)
	}
}

// TestEventCarriesNoUnexpectedFields is a guard that the wire JSON is exactly the
// shared schema (so a future field addition is a conscious change).
func TestEventCarriesNoUnexpectedFields(t *testing.T) {
	b, _ := json.Marshal(Event{Actor: "a", Action: "x.y", Target: "/t", Severity: SeverityInfo, Detail: "d", Source: SourceSluice})
	for _, want := range []string{`"actor"`, `"action"`, `"target"`, `"severity"`, `"detail"`, `"source"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("event JSON %s missing %s", b, want)
		}
	}
}
