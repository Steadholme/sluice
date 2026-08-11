package rbac

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/holdfast/sluice/internal/auth"
)

func TestPermissionGateAllowsOnlyExplicitVerdictAllow(t *testing.T) {
	verdict := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/check" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("missing Verdict service token")
		}
		var input permissionCheckRequest
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if input.Subject != "user:alice" || input.Permission != "cpa.console.enter" {
			t.Fatalf("unexpected check request: %+v", input)
		}
		if input.Context.MFA || input.Context.BreakGlass || input.Context.Zone != "internal" {
			t.Fatalf("untrusted context widened: %+v", input.Context)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":"Allow","reason":"allow-direct","epoch":42,"evaluated_at":1765000000,"evidence":[]}`))
	}))
	defer verdict.Close()

	authorizer := New(Config{Enabled: true, VerdictURL: verdict.URL, Token: "test-token"})
	authorizer.now = func() time.Time { return time.Unix(1_765_000_001, 0) }
	var hits atomic.Int32
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		decision, ok := auth.AuthorizationFromContext(r.Context())
		if !ok {
			t.Fatal("allow did not attach authorization context")
		}
		if decision.Permission != "cpa.console.enter" || decision.Object != "route:cpa-root" || decision.RevocationEpoch != 42 {
			t.Fatalf("authorization context = %+v", decision)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	handler := authorizer.PermissionGate("cpa.console.enter", "route:cpa-root", "critical", "internal", next)
	req := httptest.NewRequest(http.MethodGet, "https://cpa.w33d.xyz/", nil)
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{Subject: "alice"}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent || hits.Load() != 1 {
		t.Fatalf("status=%d hits=%d, want 204/1", recorder.Code, hits.Load())
	}
}

func TestPermissionGateDistinguishesDenyAndUnavailable(t *testing.T) {
	for _, test := range []struct {
		name       string
		status     int
		body       string
		wantStatus int
	}{
		{
			name:       "explicit deny",
			status:     http.StatusOK,
			body:       `{"decision":"Deny","reason":"no-grant-path","epoch":2,"evaluated_at":1765000000,"evidence":[]}`,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "authority outage",
			status:     http.StatusServiceUnavailable,
			body:       `{"decision":"Indeterminate"}`,
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name:       "malformed authority response",
			status:     http.StatusOK,
			body:       `{"decision":"Allow"}`,
			wantStatus: http.StatusServiceUnavailable,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			verdict := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer verdict.Close()
			authorizer := New(Config{Enabled: true, VerdictURL: verdict.URL, Token: "test-token"})
			var hits atomic.Int32
			handler := authorizer.PermissionGate(
				"cpa.console.enter",
				"route:cpa-root",
				"critical",
				"internal",
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					hits.Add(1)
					w.WriteHeader(http.StatusNoContent)
				}),
			)
			req := httptest.NewRequest(http.MethodGet, "https://cpa.w33d.xyz/", nil)
			req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{Subject: "alice"}))
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			if recorder.Code != test.wantStatus || hits.Load() != 0 {
				t.Fatalf("status=%d hits=%d, want %d/0", recorder.Code, hits.Load(), test.wantStatus)
			}
			if recorder.Header().Get("Cache-Control") == "" {
				t.Fatal("authorization failure is cacheable")
			}
		})
	}
}

func TestDecodePermissionResponseAcceptsBoundedRealEvidence(t *testing.T) {
	body := []byte(`{
		"decision":"Allow",
		"reason":"allow-direct",
		"epoch":42,
		"evaluated_at":1765000000,
		"decision_id":"dec_0123456789abcdef",
		"evidence":[{
			"edge_id":"edge-1",
			"source_grant_id":"grant-1",
			"effect":"allow",
			"path":["group:infra-admins#member@user:alice"],
			"condition_result":"matched"
		}]
	}`)
	decision, err := decodePermissionCheckResponse(body)
	if err != nil {
		t.Fatalf("real Verdict evidence was rejected: %v", err)
	}
	if decision.SourceGrantID != "grant-1" || len(decision.Evidence) != 1 {
		t.Fatalf("safe evidence was not preserved: %+v", decision)
	}
}

func TestDecodePermissionResponseRejectsUnknownAndUnboundedEvidence(t *testing.T) {
	validEvidence := map[string]any{
		"edge_id":          "edge-1",
		"source_grant_id":  "grant-1",
		"effect":           "allow",
		"path":             []string{"group:infra-admins#member@user:alice"},
		"condition_result": "matched",
	}
	build := func(evidence []map[string]any) []byte {
		body, err := json.Marshal(map[string]any{
			"decision":     "Allow",
			"reason":       "allow-direct",
			"epoch":        42,
			"evaluated_at": 1_765_000_000,
			"evidence":     evidence,
		})
		if err != nil {
			t.Fatalf("marshal test body: %v", err)
		}
		return body
	}

	unknown := map[string]any{}
	for key, value := range validEvidence {
		unknown[key] = value
	}
	unknown["raw_policy"] = "must-not-be-accepted"
	oversized := map[string]any{}
	for key, value := range validEvidence {
		oversized[key] = value
	}
	oversized["source_grant_id"] = strings.Repeat("g", maxVerdictEvidenceField+1)
	many := make([]map[string]any, maxVerdictEvidenceItems+1)
	for i := range many {
		many[i] = validEvidence
	}

	for _, body := range [][]byte{
		build([]map[string]any{unknown}),
		build([]map[string]any{oversized}),
		build(many),
		append(build([]map[string]any{validEvidence}), []byte(` {}`)...),
		[]byte(`{"decision":"Allow","reason":"allow-direct","epoch":42,"evaluated_at":1765000000,"evidence":[],"unexpected":true}`),
	} {
		if decision, err := decodePermissionCheckResponse(body); err == nil {
			t.Fatalf("unsafe Verdict response accepted: %+v", decision)
		}
	}
}

func TestDecodePermissionResponseRejectsFalseAllowAndInconsistentEvidence(t *testing.T) {
	bodies := [][]byte{
		[]byte(`{"decision":"Allow","reason":"deny-override","epoch":42,"evaluated_at":1765000000,"evidence":[]}`),
		[]byte(`{"decision":"Allow","reason":"allow-direct","epoch":42,"evaluated_at":1765000000,"evidence":[{"edge_id":"edge-deny","source_grant_id":"grant-deny","effect":"deny","path":[],"condition_result":"matched"}]}`),
		[]byte(`{"decision":"Indeterminate","reason":"store-unavailable","epoch":0,"evaluated_at":1765000000,"evidence":[{"edge_id":"edge-1","source_grant_id":"grant-1","effect":"allow","path":[],"condition_result":"matched"}]}`),
	}
	for _, body := range bodies {
		if decision, err := decodePermissionCheckResponse(body); err == nil {
			t.Fatalf("inconsistent Verdict tuple accepted: %+v", decision)
		}
	}
}

func TestCheckPermissionPreservesSafe503Classification(t *testing.T) {
	for _, test := range []struct {
		name      string
		reason    string
		wantECode string
	}{
		{name: "authority outage", reason: "store-unavailable", wantECode: "E7"},
		{name: "policy drift", reason: "unknown-condition", wantECode: "E10"},
	} {
		t.Run(test.name, func(t *testing.T) {
			verdict := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"decision":"Indeterminate","reason":"` + test.reason + `","epoch":0,"evaluated_at":1765000000,"evidence":[]}`))
			}))
			defer verdict.Close()
			authorizer := New(Config{Enabled: true, VerdictURL: verdict.URL, Token: "test-token"})
			decision, err := authorizer.checkPermission(httptest.NewRequest(http.MethodGet, "https://cpa.w33d.xyz/", nil), permissionCheckRequest{})
			if err == nil {
				t.Fatal("503 authority response unexpectedly allowed")
			}
			typed, ok := err.(*permissionAuthorityError)
			if !ok || typed.ECode != test.wantECode {
				t.Fatalf("error = %#v, want %s classification", err, test.wantECode)
			}
			if decision.Reason != test.reason || decision.EvaluatedAt != 1_765_000_000 {
				t.Fatalf("safe 503 fields were not preserved: %+v", decision)
			}
		})
	}
}

func TestCheckPermissionBoundsBodyAndNeverTreatsHTTP403AsPolicyDeny(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
	}{
		{
			name:   "oversized body",
			status: http.StatusServiceUnavailable,
			body:   strings.Repeat("x", maxVerdictResponseBytes+1),
		},
		{
			name:   "http 403 is dependency failure",
			status: http.StatusForbidden,
			body:   `{"decision":"Deny","reason":"no-grant-path","epoch":42,"evaluated_at":1765000000,"evidence":[]}`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			verdict := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer verdict.Close()
			authorizer := New(Config{Enabled: true, VerdictURL: verdict.URL, Token: "test-token"})
			_, err := authorizer.checkPermission(httptest.NewRequest(http.MethodGet, "https://cpa.w33d.xyz/", nil), permissionCheckRequest{})
			if err == nil {
				t.Fatal("unsafe authority response unexpectedly allowed")
			}
			typed, ok := err.(*permissionAuthorityError)
			if !ok || typed.ECode != "E7" || strings.Contains(err.Error(), strings.Repeat("x", 32)) {
				t.Fatalf("unsafe error classification or raw-body leak: %v", err)
			}
		})
	}
}
