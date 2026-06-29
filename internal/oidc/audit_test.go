package oidc

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/holdfast/sluice/internal/audit"
	"github.com/holdfast/sluice/internal/auth"
)

// wtSink is a fake Watchtower capturing audit events POSTed by the worker.
type wtSink struct {
	server *httptest.Server
	events chan audit.Event
}

func newWTSink(t *testing.T) *wtSink {
	t.Helper()
	s := &wtSink{events: make(chan audit.Event, 16)}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var ev audit.Event
		_ = json.Unmarshal(raw, &ev)
		s.events <- ev
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *wtSink) await(t *testing.T) audit.Event {
	t.Helper()
	select {
	case ev := <-s.events:
		return ev
	case <-time.After(3 * time.Second):
		t.Fatal("watchtower received no audit event within 3s")
		return audit.Event{}
	}
}

// auditProvider mirrors newTestProvider but wires a non-blocking audit emitter
// pointed at the fake Watchtower.
func auditProvider(t *testing.T, fi *fakeIssuer, em *audit.Emitter) *Provider {
	t.Helper()
	keys := auth.NewJWKSCache(fi.url+"/.well-known/openid-configuration",
		&http.Client{Timeout: 5 * time.Second}, time.Second,
		auth.WithJWKSURI(fi.url+"/jwks.json"))
	p, err := NewProvider(Config{
		Issuer:        fi.url,
		TokenURL:      fi.url + "/token",
		ClientID:      testClientID,
		ClientSecret:  "shh",
		RedirectURI:   "https://placeholder.invalid" + CallbackPath,
		SessionTTL:    time.Hour,
		SessionSecret: "unit-test-secret",
		Auditor:       em,
	}, keys, &http.Client{Timeout: 5 * time.Second}, NewMemoryStore(), NewMemoryStore(), nil)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return p
}

// TestSSOEstablishAudited drives the full browser SSO flow and asserts a single
// sso.session.establish event naming the subject and the gateway client_id.
func TestSSOEstablishAudited(t *testing.T) {
	fi := newFakeIssuer(t)
	sink := newWTSink(t)
	em := audit.New(audit.Config{Enabled: true, URL: sink.server.URL, Token: "ingest"})
	defer em.Close()
	p := auditProvider(t, fi, em)
	srv := gatewayServer(t, p)
	client := jarClient(t, srv)

	resp, err := client.Get(srv.URL + "/app/dashboard?x=1")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("final status = %d, want 200", resp.StatusCode)
	}

	ev := sink.await(t)
	if ev.Action != audit.ActionSSOEstablish {
		t.Errorf("action = %q, want %q", ev.Action, audit.ActionSSOEstablish)
	}
	if ev.Actor != testSub {
		t.Errorf("actor = %q, want %q", ev.Actor, testSub)
	}
	if ev.Target != testClientID {
		t.Errorf("target = %q, want %q", ev.Target, testClientID)
	}
	if ev.Severity != audit.SeverityInfo {
		t.Errorf("severity = %q, want info", ev.Severity)
	}
	if ev.Source != audit.SourceSluice {
		t.Errorf("source = %q, want sluice", ev.Source)
	}
}

// TestSSODenyAudited proves a forged callback state emits sso.session.deny with a
// short safe reason and no identity.
func TestSSODenyAudited(t *testing.T) {
	fi := newFakeIssuer(t)
	sink := newWTSink(t)
	em := audit.New(audit.Config{Enabled: true, URL: sink.server.URL, Token: "ingest"})
	defer em.Close()
	p := auditProvider(t, fi, em)
	srv := gatewayServer(t, p)
	nc := srv.Client()
	nc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	resp, err := nc.Get(srv.URL + CallbackPath + "?state=forged&code=whatever")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}

	ev := sink.await(t)
	if ev.Action != audit.ActionSSODeny {
		t.Errorf("action = %q, want %q", ev.Action, audit.ActionSSODeny)
	}
	if ev.Actor != "anonymous" {
		t.Errorf("actor = %q, want anonymous", ev.Actor)
	}
	if ev.Severity != audit.SeverityWarning {
		t.Errorf("severity = %q, want warning", ev.Severity)
	}
	if ev.Detail != "invalid state" {
		t.Errorf("detail = %q, want 'invalid state'", ev.Detail)
	}
}

// TestSSOLogoutAudited establishes a session, then logs out and asserts the
// sso.logout event names the subject from the resolved session.
func TestSSOLogoutAudited(t *testing.T) {
	fi := newFakeIssuer(t)
	sink := newWTSink(t)
	em := audit.New(audit.Config{Enabled: true, URL: sink.server.URL, Token: "ingest"})
	defer em.Close()
	p := auditProvider(t, fi, em)
	srv := gatewayServer(t, p)
	client := jarClient(t, srv)

	// Establish a session (drains the establish event).
	resp, err := client.Get(srv.URL + "/app/home")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if est := sink.await(t); est.Action != audit.ActionSSOEstablish {
		t.Fatalf("expected establish first, got %q", est.Action)
	}

	// Now log out.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	lr, err := client.Get(srv.URL + LogoutPath)
	if err != nil {
		t.Fatalf("logout GET: %v", err)
	}
	lr.Body.Close()

	ev := sink.await(t)
	if ev.Action != audit.ActionSSOLogout {
		t.Errorf("action = %q, want %q", ev.Action, audit.ActionSSOLogout)
	}
	if ev.Actor != testSub {
		t.Errorf("actor = %q, want %q (sub from session)", ev.Actor, testSub)
	}
	if ev.Severity != audit.SeverityInfo {
		t.Errorf("severity = %q, want info", ev.Severity)
	}
}
