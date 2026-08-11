package rbac

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/holdfast/sluice/internal/auth"
)

func TestPermissionGateUsesOnlyTrustedMFAContext(t *testing.T) {
	seen := make(chan bool, 3)
	verdict := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input permissionCheckRequest
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Fatalf("decode Verdict request: %v", err)
		}
		seen <- input.Context.MFA
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":"Allow","reason":"allow-direct","epoch":9,"evaluated_at":1754400123,"evidence":[]}`))
	}))
	defer verdict.Close()

	authorizer := New(Config{Enabled: true, VerdictURL: verdict.URL, Token: "test-token"})
	authorizationNow := time.Unix(1_754_400_123, 0)
	authorizer.now = func() time.Time { return authorizationNow }
	handler := authorizer.PermissionGate(
		"newapi.channel.write",
		"newapi-channel:42",
		"critical",
		"internal",
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }),
	)

	request := httptest.NewRequest(http.MethodPost, "https://ai.w33d.xyz/console/channels", nil)
	request.Header.Set(auth.HeaderAuthMFAAAL, auth.MFAAALStrong)
	request.Header.Set(auth.HeaderAuthMFAUV, "1")
	request.Header.Set(auth.HeaderAuthMFASig, strings.Repeat("a", 64))
	request = request.WithContext(auth.ContextWithIdentity(request.Context(), &auth.Identity{Subject: "alice"}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent || <-seen {
		t.Fatal("browser-supplied MFA headers influenced the Verdict context")
	}

	assertion := auth.MFAAssertion{
		Subject:        "alice",
		AAL:            auth.MFAAALStrong,
		UV:             true,
		AuthTime:       1_754_400_000,
		SessionBinding: strings.Repeat("b", 64),
		FactorEpoch:    3,
		Route:          "newapi-console",
		Audience:       "new-api",
		Timestamp:      1_754_400_123,
	}
	var err error
	assertion.Evidence, err = auth.MFAEvidenceDigest(assertion)
	if err != nil {
		t.Fatalf("MFAEvidenceDigest: %v", err)
	}
	signature, err := auth.SignMFAAssertion("rbac-mfa-assertion-key-0123456789abcdef", assertion)
	if err != nil {
		t.Fatalf("SignMFAAssertion: %v", err)
	}
	request = httptest.NewRequest(http.MethodPost, "https://ai.w33d.xyz/console/channels", nil)
	ctx := auth.ContextWithIdentity(request.Context(), &auth.Identity{Subject: "alice"})
	ctx = auth.ContextWithMFAAssertion(ctx, assertion, signature)
	request = request.WithContext(ctx)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent || !<-seen {
		t.Fatal("Sluice-minted strong MFA assertion was not forwarded to Verdict")
	}

	authorizationNow = time.Unix(assertion.AuthTime+auth.MFAAssertionFreshnessSeconds+1, 0)
	request = httptest.NewRequest(http.MethodPost, "https://ai.w33d.xyz/console/channels", nil)
	ctx = auth.ContextWithIdentity(request.Context(), &auth.Identity{Subject: "alice"})
	ctx = auth.ContextWithMFAAssertion(ctx, assertion, signature)
	request = request.WithContext(ctx)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent || <-seen {
		t.Fatal("an assertion that crossed the 301-second boundary reached Verdict as mfa=true")
	}
}
