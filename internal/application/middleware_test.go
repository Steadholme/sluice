package application

import (
	"context"
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
			req.Header.Set("Mcp-Session-Id", "session_abcdefghijklmnop")
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

func TestSessionConflictRequiresValidInboundMCPSession(t *testing.T) {
	for _, tc := range []struct {
		name       string
		session    *string
		wantStatus int
		wantCode   string
		wantCalls  int
	}{
		{name: "absent", wantStatus: http.StatusUnauthorized, wantCode: "unauthenticated"},
		{name: "empty", session: stringPointer(""), wantStatus: http.StatusUnauthorized, wantCode: "unauthenticated"},
		{name: "malformed", session: stringPointer("contains space"), wantStatus: http.StatusUnauthorized, wantCode: "unauthenticated"},
		{name: "present", session: stringPointer("session_abcdefghijklmnop"), wantStatus: http.StatusNotFound, wantCode: "invalid_session", wantCalls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			introspector := &stubIntrospector{err: ErrSessionInvalid}
			handler := Middleware(introspector, "analyze-facade", "", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("dispatched") }))
			req := httptest.NewRequest(http.MethodPost, "https://analyze.w33d.xyz/mcp", strings.NewReader("{}"))
			req.Header.Set("Authorization", "Bearer "+testApplicationToken)
			if tc.session != nil {
				req.Header.Set("Mcp-Session-Id", *tc.session)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus || !strings.Contains(rec.Body.String(), `"code":"`+tc.wantCode+`"`) || introspector.calls != tc.wantCalls {
				t.Fatalf("status=%d body=%q calls=%d", rec.Code, rec.Body.String(), introspector.calls)
			}
		})
	}
}

func stringPointer(value string) *string { return &value }
