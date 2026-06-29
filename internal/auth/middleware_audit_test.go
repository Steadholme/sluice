package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/holdfast/sluice/internal/audit"
)

// fakeWatchtower captures the JSON bodies (and raw payloads) POSTed by the audit
// worker so a test can assert the emitted event and the absence of leaks.
type fakeWatchtower struct {
	server *httptest.Server
	events chan audit.Event
	raw    chan string
}

func newFakeWatchtower(t *testing.T) *fakeWatchtower {
	t.Helper()
	fw := &fakeWatchtower{
		events: make(chan audit.Event, 8),
		raw:    make(chan string, 8),
	}
	fw.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/events" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var ev audit.Event
		_ = json.Unmarshal(raw, &ev)
		fw.events <- ev
		fw.raw <- string(raw) // the exact bytes on the wire, for leak scanning
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(fw.server.Close)
	return fw
}

func (fw *fakeWatchtower) await(t *testing.T) (audit.Event, string) {
	t.Helper()
	select {
	case ev := <-fw.events:
		return ev, <-fw.raw
	case <-time.After(3 * time.Second):
		t.Fatal("watchtower received no audit event within 3s")
		return audit.Event{}, ""
	}
}

// TestMiddlewareEmitsForwardAuthDeny is the required check: with AUDIT_ENABLED a
// rejected bearer request POSTs forward_auth.deny to Watchtower with the exact
// logical fields, and the user's bearer token NEVER appears in the payload.
func TestMiddlewareEmitsForwardAuthDeny(t *testing.T) {
	fw := newFakeWatchtower(t)
	em := audit.New(audit.Config{Enabled: true, URL: fw.server.URL, Token: "ingest-secret"})
	defer em.Close()

	v := NewVerifier(failingResolver{}, testIssuer) // every token fails validation
	upstreamHit := false
	h := Middleware(v, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { upstreamHit = true }), WithAuditor(em))

	const userToken = "SUPER_SECRET_USER_TOKEN_DO_NOT_LEAK"
	req := httptest.NewRequest(http.MethodGet, "/api/secret", nil)
	req.Header.Set("Authorization", "Bearer "+userToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if upstreamHit {
		t.Fatal("upstream reached on auth failure")
	}

	ev, raw := fw.await(t)
	if ev.Action != audit.ActionForwardAuthDeny {
		t.Errorf("action = %q, want %q", ev.Action, audit.ActionForwardAuthDeny)
	}
	if ev.Actor != "anonymous" {
		t.Errorf("actor = %q, want anonymous", ev.Actor)
	}
	if ev.Target != "/api/secret" {
		t.Errorf("target = %q, want /api/secret", ev.Target)
	}
	if ev.Severity != audit.SeverityWarning {
		t.Errorf("severity = %q, want warning", ev.Severity)
	}
	if ev.Source != audit.SourceSluice {
		t.Errorf("source = %q, want sluice", ev.Source)
	}
	if ev.Detail != "invalid token" {
		t.Errorf("detail = %q, want 'invalid token'", ev.Detail)
	}
	// The whole point: the raw token must never travel to the audit log.
	if strings.Contains(raw, userToken) {
		t.Fatalf("LEAK: audit payload contains the user bearer token: %s", raw)
	}
	if strings.Contains(raw, "Bearer "+userToken) {
		t.Fatalf("LEAK: audit payload contains the Authorization header value")
	}
}

// TestMiddlewareEmitsForwardAuthAllow confirms a valid token emits
// forward_auth.allow with actor=sub, and that disabling audit emits nothing.
func TestMiddlewareEmitsForwardAuthAllow(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	const kid = "audit-allow-kid"
	resolver := &testKeyResolver{keys: map[string]*rsa.PublicKey{kid: &priv.PublicKey}}
	v := NewVerifier(resolver, testIssuer)
	token := mintRS256(t, priv, kid, testIssuer, time.Now().Add(time.Hour))

	t.Run("allow_emitted", func(t *testing.T) {
		fw := newFakeWatchtower(t)
		em := audit.New(audit.Config{Enabled: true, URL: fw.server.URL, Token: "ingest-secret"})
		defer em.Close()

		h := Middleware(v, okHandler(), WithAuditor(em))
		req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		h.ServeHTTP(httptest.NewRecorder(), req)

		ev, _ := fw.await(t)
		if ev.Action != audit.ActionForwardAuthAllow {
			t.Errorf("action = %q, want %q", ev.Action, audit.ActionForwardAuthAllow)
		}
		if ev.Actor != "u_admin" {
			t.Errorf("actor = %q, want u_admin (sub)", ev.Actor)
		}
		if ev.Severity != audit.SeverityInfo {
			t.Errorf("severity = %q, want info", ev.Severity)
		}
	})

	t.Run("audit_off_emits_nothing", func(t *testing.T) {
		// No WithAuditor option at all -> the request path is identical to before.
		h := Middleware(v, okHandler())
		req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (audit off must not change behavior)", rec.Code)
		}
	})
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}
