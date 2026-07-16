package pat

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/holdfast/sluice/internal/accesslog"
	"github.com/holdfast/sluice/internal/auth"
)

type fakeIntrospector struct {
	mu     sync.Mutex
	result Result
	err    error
	calls  int
	tokens []string
}

func (f *fakeIntrospector) Introspect(_ context.Context, token string) (Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.tokens = append(f.tokens, token)
	return f.result, f.err
}

func (f *fakeIntrospector) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestMiddlewareOutcomeMappingAndPrivacyHeaders(t *testing.T) {
	cases := []struct {
		name         string
		introspector Introspector
		header       string
		wantStatus   int
		wantCalls    int
	}{
		{name: "missing-config", introspector: nil, header: "Bearer " + testPAT, wantStatus: http.StatusServiceUnavailable},
		{name: "missing-token", introspector: &fakeIntrospector{}, wantStatus: http.StatusUnauthorized},
		{name: "malformed-scheme", introspector: &fakeIntrospector{}, header: "Basic abc", wantStatus: http.StatusUnauthorized},
		{name: "malformed-pat", introspector: &fakeIntrospector{}, header: "Bearer not-a-pat", wantStatus: http.StatusUnauthorized},
		{name: "inactive-revoked", introspector: &fakeIntrospector{result: Result{Active: false}}, header: "Bearer " + testPAT, wantStatus: http.StatusUnauthorized, wantCalls: 1},
		{name: "keystone-outage", introspector: &fakeIntrospector{err: ErrUnavailable}, header: "Bearer " + testPAT, wantStatus: http.StatusServiceUnavailable, wantCalls: 1},
		{name: "introspector-invalid-token", introspector: &fakeIntrospector{err: ErrInvalidToken}, header: "Bearer " + testPAT, wantStatus: http.StatusUnauthorized, wantCalls: 1},
		{name: "generic-introspector-error", introspector: &fakeIntrospector{err: errors.New("db down")}, header: "Bearer " + testPAT, wantStatus: http.StatusServiceUnavailable, wantCalls: 1},
		{name: "missing-exact-scope", introspector: &fakeIntrospector{result: Result{Active: true, Subject: "u_test", Scope: "corvid:temp-mail:delete-extra"}}, header: "Bearer " + testPAT, wantStatus: http.StatusForbidden, wantCalls: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reached := false
			handler := Middleware(tc.introspector, "corvid:temp-mail:delete", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				reached = true
			}))
			req := httptest.NewRequest(http.MethodDelete, "/api/v1/temp-mailboxes/id", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if reached {
				t.Fatal("upstream reached on PAT denial")
			}
			if got := rec.Header().Get("Cache-Control"); got != "private, no-store" {
				t.Fatalf("Cache-Control = %q", got)
			}
			if !headerContainsToken(rec.Header().Values("Vary"), "Authorization") {
				t.Fatalf("Vary = %q, want Authorization", rec.Header().Values("Vary"))
			}
			if tc.wantStatus == http.StatusUnauthorized && rec.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatalf("WWW-Authenticate = %q", rec.Header().Get("WWW-Authenticate"))
			}
			if strings.Contains(rec.Body.String(), testPAT) {
				t.Fatal("raw PAT leaked in local error response")
			}
			if fake, ok := tc.introspector.(*fakeIntrospector); ok && fake.callCount() != tc.wantCalls {
				t.Fatalf("introspection calls = %d, want %d", fake.callCount(), tc.wantCalls)
			}
		})
	}
}

func TestMiddlewareActiveIdentityAndExactScope(t *testing.T) {
	fake := &fakeIntrospector{result: Result{
		Active:  true,
		Subject: "u_test",
		Scope:   "profile corvid:temp-mail:delete messages:read",
	}}
	handler := Middleware(fake, "corvid:temp-mail:delete", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := auth.IdentityFromContext(r.Context())
		if !ok || id.Subject != "u_test" || id.Scope != fake.result.Scope {
			t.Fatalf("identity = %+v, ok=%v", id, ok)
		}
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("Vary", "Accept-Encoding")
		w.WriteHeader(http.StatusNoContent)
	}))

	for range 2 {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/temp-mailboxes/id", nil)
		req.Header.Set("Authorization", "Bearer "+testPAT)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", rec.Code)
		}
		if got := rec.Header().Get("Cache-Control"); got != "private, no-store" {
			t.Fatalf("Cache-Control = %q", got)
		}
		if !headerContainsToken(rec.Header().Values("Vary"), "Accept-Encoding") || !headerContainsToken(rec.Header().Values("Vary"), "Authorization") {
			t.Fatalf("Vary = %q, want preserved Accept-Encoding + Authorization", rec.Header().Values("Vary"))
		}
	}
	if got := fake.callCount(); got != 2 {
		t.Fatalf("destructive requests introspected %d times, want 2", got)
	}
}

func TestMiddlewareRejectsMultipleAuthorizationValues(t *testing.T) {
	fake := &fakeIntrospector{}
	handler := Middleware(fake, "scope", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("upstream reached")
	}))
	req := httptest.NewRequest(http.MethodDelete, "/resource", nil)
	req.Header.Add("Authorization", "Bearer "+testPAT)
	req.Header.Add("Authorization", "Bearer "+testPAT)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if fake.callCount() != 0 {
		t.Fatal("ambiguous Authorization values reached introspection")
	}
}

type optionalWriter struct {
	header  http.Header
	flushes int
	hijacks int
}

func (w *optionalWriter) Header() http.Header { return w.header }

func (w *optionalWriter) Write(body []byte) (int, error) { return len(body), nil }

func (w *optionalWriter) WriteHeader(int) {}

func (w *optionalWriter) Flush() { w.flushes++ }

func (w *optionalWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.hijacks++
	return nil, nil, nil
}

func TestNoStorePreservesOptionalWriterInterfacesThroughNestedUnwrap(t *testing.T) {
	base := &optionalWriter{header: make(http.Header)}
	terminal := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		controller := http.NewResponseController(w)
		if err := controller.Flush(); err != nil {
			t.Fatalf("Flush through nested wrappers: %v", err)
		}
		if _, _, err := controller.Hijack(); err != nil {
			t.Fatalf("Hijack through nested wrappers: %v", err)
		}
	})

	// This is the production shape: accesslog contributes an Unwrap-only status
	// recorder, while the route-level and middleware-level NoStore guards are
	// intentionally nested.
	handler := accesslog.Wrap(NoStore(NoStore(terminal)))
	handler.ServeHTTP(base, httptest.NewRequest(http.MethodGet, "/", nil))

	if base.flushes != 1 || base.hijacks != 1 {
		t.Fatalf("optional interface calls = flush:%d hijack:%d, want 1 each", base.flushes, base.hijacks)
	}
	if got := base.header.Get("Cache-Control"); got != "private, no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if !headerContainsToken(base.header.Values("Vary"), "Authorization") {
		t.Fatalf("Vary = %q, want Authorization", base.header.Values("Vary"))
	}
}

func headerContainsToken(values []string, want string) bool {
	for _, value := range values {
		for _, field := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(field), want) {
				return true
			}
		}
	}
	return false
}
