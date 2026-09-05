package application

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type stubIntrospector struct {
	calls         int
	result        Result
	err           error
	sessionDigest string
}

func (s *stubIntrospector) Introspect(_ context.Context, _, sessionDigest string) (Result, error) {
	s.calls++
	s.sessionDigest = sessionDigest
	return s.result, s.err
}

const testInitializeBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"standard-client","version":"1.0"}}}`

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

func TestMcpOriginIsValidatedBeforeCredentialIntrospection(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodDelete} {
		for _, tc := range []struct {
			name    string
			origins []string
			allowed bool
		}{
			{name: "non-browser", allowed: true},
			{name: "same-origin", origins: []string{"https://analyze.w33d.xyz"}, allowed: true},
			{name: "foreign", origins: []string{"https://attacker.example"}},
			{name: "sibling", origins: []string{"https://other.w33d.xyz"}},
			{name: "insecure", origins: []string{"http://analyze.w33d.xyz"}},
			{name: "null", origins: []string{"null"}},
			{name: "empty", origins: []string{""}},
			{name: "duplicate", origins: []string{"https://analyze.w33d.xyz", "https://analyze.w33d.xyz"}},
			{name: "list", origins: []string{"https://analyze.w33d.xyz https://attacker.example"}},
			{name: "userinfo", origins: []string{"https://analyze.w33d.xyz@attacker.example"}},
			{name: "path", origins: []string{"https://analyze.w33d.xyz/path"}},
		} {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				introspector := &stubIntrospector{result: Result{Active: false}}
				handler := MiddlewareWithSigner(introspector, nil, "analyze-mcp", "analyze-facade", "", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					t.Fatal("inactive credential or forbidden origin dispatched")
				}))
				req := httptest.NewRequest(method, "https://analyze.w33d.xyz/mcp", strings.NewReader("{}"))
				req.Header.Set("Authorization", "Bearer "+testApplicationToken)
				req.Header.Set("Mcp-Session-Id", "session_abcdefghijklmnop")
				for _, origin := range tc.origins {
					req.Header.Add("Origin", origin)
				}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				wantStatus, wantCalls := http.StatusForbidden, 0
				if tc.allowed {
					wantStatus, wantCalls = http.StatusUnauthorized, 1
				}
				if rec.Code != wantStatus || introspector.calls != wantCalls {
					t.Fatalf("status=%d introspection_calls=%d; want %d/%d", rec.Code, introspector.calls, wantStatus, wantCalls)
				}
				if rec.Header().Get("Cache-Control") != "private, no-store" {
					t.Fatal("origin response must not be cached")
				}
			})
		}
	}
}

func TestOnlyValidInitializeCanAllocateMissingMcpSession(t *testing.T) {
	for _, tc := range []struct {
		name    string
		method  string
		path    string
		route   string
		body    string
		headers http.Header
	}{
		{name: "not initialize", body: `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`},
		{name: "get", method: http.MethodGet},
		{name: "upload route", path: "/v1/uploads/id/finalize", route: "analyze-uploads"},
		{name: "wrong path", path: "/mcp/"},
		{name: "query", path: "/mcp?initialize=true"},
		{name: "batch", body: "[" + testInitializeBody + "]"},
		{name: "trailing body", body: testInitializeBody + "{}"},
		{name: "duplicate method", body: strings.Replace(testInitializeBody, `"method":"initialize"`, `"method":"tools/list","method":"initialize"`, 1)},
		{name: "missing id", body: strings.Replace(testInitializeBody, `"id":1,`, "", 1)},
		{name: "null id", body: strings.Replace(testInitializeBody, `"id":1`, `"id":null`, 1)},
		{name: "wrong jsonrpc", body: strings.Replace(testInitializeBody, `"jsonrpc":"2.0"`, `"jsonrpc":"1.0"`, 1)},
		{name: "wrong protocol", body: strings.ReplaceAll(testInitializeBody, "2025-11-25", "2025-03-26")},
		{name: "duplicate protocol", body: strings.Replace(testInitializeBody, `"protocolVersion":"2025-11-25"`, `"protocolVersion":"2025-03-26","protocolVersion":"2025-11-25"`, 1)},
		{name: "null capabilities", body: strings.Replace(testInitializeBody, `"capabilities":{}`, `"capabilities":null`, 1)},
		{name: "missing client", body: strings.Replace(testInitializeBody, `"clientInfo":{"name":"standard-client","version":"1.0"}`, `"clientInfo":{}`, 1)},
		{name: "invalid utf8", body: strings.Replace(testInitializeBody, "standard-client", string([]byte{0xff}), 1)},
		{name: "empty header", headers: http.Header{"Mcp-Session-Id": {""}}},
		{name: "duplicate header", headers: http.Header{"Mcp-Session-Id": {"a", "b"}}},
		{name: "bad header", headers: http.Header{"Mcp-Session-Id": {"bad session"}}},
		{name: "wrong content type", headers: http.Header{"Content-Type": {"text/plain"}}},
		{name: "missing stream accept", headers: http.Header{"Accept": {"application/json"}}},
		{name: "wrong protocol header", headers: http.Header{"Mcp-Protocol-Version": {"2025-03-26"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.method == "" {
				tc.method = http.MethodPost
			}
			if tc.path == "" {
				tc.path = "/mcp"
			}
			if tc.route == "" {
				tc.route = "analyze-mcp"
			}
			if tc.body == "" {
				tc.body = testInitializeBody
			}
			introspector := &stubIntrospector{result: Result{Active: false}}
			handler := MiddlewareWithSigner(introspector, nil, tc.route, "analyze-facade", "", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("invalid initialize dispatched") }))
			req := httptest.NewRequest(tc.method, "https://analyze.w33d.xyz"+tc.path, strings.NewReader(tc.body))
			req.Header.Set("Authorization", "Bearer "+testApplicationToken)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			for name, values := range tc.headers {
				req.Header[name] = values
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized || introspector.calls != 0 || rec.Header().Get("Mcp-Session-Id") != "" {
				t.Fatalf("invalid initialize status=%d introspection_calls=%d", rec.Code, introspector.calls)
			}
		})
	}
}

func TestStandardInitializeWithoutSessionReachesAuthenticatedMcpUpstream(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	signer, err := NewContextSigner(SigningKeyring{ActiveKID: "initialize-test", PrivateKeys: map[string]ed25519.PrivateKey{"initialize-test": private}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	introspector := &stubIntrospector{result: Result{
		Active: true, Subject: "application:abcdefghijklmnop", ApplicationSub: "application:abcdefghijklmnop",
		Scopes: []string{"analysis.read"}, ClientID: "app_abcdefghijklmnop", CredentialID: "acr_abcdefghijklmnop",
		GrantID: "grt_abcdefghijklmnop", PackageID: "pkg_analyze_mcp_client", PackageRevisionDigest: strings.Repeat("a", 64),
		Audience: "analyze-facade", CredentialVersion: 1, SubjectVersion: 1, CredentialState: CredentialActive,
		PolicyEpoch: 1, RevocationEpoch: 1,
	}}
	body := testInitializeBody
	dispatched := false
	handler := MiddlewareWithSigner(introspector, signer, "analyze-mcp", "analyze-facade", "", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dispatched = true
		sessionID, ok := applicationSessionIdentifier(r.Header)
		if !ok || !strings.HasPrefix(sessionID, "mcps_") || len(sessionID) != len("mcps_")+32 {
			t.Error("authenticated initialize omitted the internal server session binding")
		}
		signed, ok := SignedRequestFromContext(r.Context())
		if !ok {
			t.Fatal("initialize omitted signed application context")
		}
		hash := sha256.Sum256([]byte(sessionID))
		if signed.Context.MCPSessionDigest != hex.EncodeToString(hash[:]) || introspector.sessionDigest != signed.Context.MCPSessionDigest {
			t.Error("signed session digest does not bind the generated session identifier")
		}
		forwarded, err := io.ReadAll(r.Body)
		if err != nil || string(forwarded) != body {
			t.Error("initialize body changed before forwarding")
		}
		w.Header().Set("Mcp-Session-Id", sessionID)
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "https://analyze.w33d.xyz/mcp", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testApplicationToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || !dispatched || introspector.calls != 1 {
		t.Fatalf("standard initialize failed: status=%d dispatched=%v introspection_calls=%d", rec.Code, dispatched, introspector.calls)
	}
}

func TestAllocatedSessionDoesNotPretendClientHadBoundSession(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
	}{
		{name: "invalid credential", err: ErrInvalidToken, status: http.StatusUnauthorized},
		{name: "conflicting credential binding", err: ErrSessionInvalid, status: http.StatusUnauthorized},
		{name: "introspection unavailable", err: ErrUnavailable, status: http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			introspector := &stubIntrospector{err: tc.err}
			handler := MiddlewareWithSigner(introspector, nil, "analyze-mcp", "analyze-facade", "", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("failed introspection dispatched") }))
			req := httptest.NewRequest(http.MethodPost, "https://analyze.w33d.xyz/mcp", strings.NewReader(testInitializeBody))
			req.Header.Set("Authorization", "Bearer "+testApplicationToken)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.status || introspector.calls != 1 || rec.Header().Get("Mcp-Session-Id") != "" {
				t.Fatalf("status=%d introspection_calls=%d", rec.Code, introspector.calls)
			}
		})
	}
}
