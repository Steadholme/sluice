package auth

import (
	"context"
	"strings"
	"testing"
)

func TestHasStrongMFAAtBindsSubjectAndAuthorizationClock(t *testing.T) {
	assertion := MFAAssertion{
		Subject:        "alice",
		AAL:            MFAAALStrong,
		UV:             true,
		AuthTime:       1_754_400_000,
		SessionBinding: strings.Repeat("a", 64),
		FactorEpoch:    7,
		Route:          "ai-console",
		Audience:       "newapi",
		Timestamp:      1_754_400_100,
	}
	var err error
	assertion.Evidence, err = MFAEvidenceDigest(assertion)
	if err != nil {
		t.Fatalf("MFAEvidenceDigest: %v", err)
	}
	signature, err := SignMFAAssertion("context-mfa-assertion-key-0123456789", assertion)
	if err != nil {
		t.Fatalf("SignMFAAssertion: %v", err)
	}
	ctx := ContextWithMFAAssertion(context.Background(), assertion, signature)
	if !HasStrongMFAAt(ctx, "alice", assertion.AuthTime+MFAAssertionFreshnessSeconds) {
		t.Fatal("300-second boundary was rejected")
	}
	if HasStrongMFAAt(ctx, "alice", assertion.AuthTime+MFAAssertionFreshnessSeconds+1) {
		t.Fatal("301-second assertion was accepted")
	}
	if HasStrongMFAAt(ctx, "mallory", assertion.AuthTime+1) {
		t.Fatal("subject-mismatched assertion was accepted")
	}
	if HasStrongMFAAt(ctx, "alice", assertion.AuthTime-1) {
		t.Fatal("future-dated assertion was accepted")
	}
}
