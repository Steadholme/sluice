package application

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type stubIntrospector struct {
	calls  int
	result Result
	err    error
}

func (s *stubIntrospector) Introspect(_ context.Context, _, _ string) (Result, error) {
	s.calls++
	return s.result, s.err
}

func TestApplicationMiddlewareMapsFrozenErrorsAndDoesNotDispatchOnOutage(t *testing.T) {
	for _, tc := range []struct {
		name          string
		introspector  Introspector
		authorization string
		status        int
		code          string
	}{
		{name: "inactive", introspector: &stubIntrospector{result: Result{Active: false}}, authorization: "Bearer " + testApplicationToken, status: 401, code: "unauthenticated"},
		{name: "malformed", introspector: &stubIntrospector{}, authorization: "Bearer app_v1_short", status: 401, code: "unauthenticated"},
		{name: "outage", introspector: &stubIntrospector{err: ErrUnavailable}, authorization: "Bearer " + testApplicationToken, status: 503, code: "authentication_unavailable"},
		{name: "missing-config", introspector: nil, authorization: "Bearer " + testApplicationToken, status: 503, code: "authentication_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dispatched := false
			handler := Middleware(tc.introspector, "analyze-facade", "", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { dispatched = true }))
			req := httptest.NewRequest(http.MethodPost, "https://analyze.w33d.xyz/mcp", strings.NewReader("{}"))
			req.Header.Set("Authorization", tc.authorization)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.status || !strings.Contains(rec.Body.String(), `"code":"`+tc.code+`"`) || dispatched {
				t.Fatalf("status=%d body=%q dispatched=%v", rec.Code, rec.Body.String(), dispatched)
			}
			if rec.Header().Get("Cache-Control") != "private, no-store" {
				t.Fatalf("Cache-Control=%q", rec.Header().Get("Cache-Control"))
			}
		})
	}
}

func TestBoundSessionInvalidationUsesInvalidSession(t *testing.T) {
	introspector := &stubIntrospector{err: ErrSessionInvalid}
	handler := Middleware(introspector, "analyze-facade", "", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("dispatched") }))
	req := httptest.NewRequest(http.MethodPost, "https://analyze.w33d.xyz/mcp", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+testApplicationToken)
	req.Header.Set("Mcp-Session-Id", "session_abcdefghijklmnop")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), `"code":"invalid_session"`) {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	if !errors.Is(introspector.err, ErrSessionInvalid) {
		t.Fatal("wrong stub")
	}
}

func TestIntrospectionSessionConflictWithoutClientSessionStillUsesInvalidSession(t *testing.T) {
	introspector := &stubIntrospector{err: ErrSessionInvalid}
	handler := Middleware(introspector, "analyze-facade", "", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("dispatched") }))
	req := httptest.NewRequest(http.MethodPost, "https://analyze.w33d.xyz/mcp", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+testApplicationToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), `"code":"invalid_session"`) {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
}
