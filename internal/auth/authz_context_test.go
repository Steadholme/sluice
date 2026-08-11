package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestSignAuthorizationContextCanonicalV1(t *testing.T) {
	value := AuthorizationContext{
		Permission:      "cpa.console.enter",
		Object:          "route:cpa-root",
		Decision:        "Allow",
		DecisionID:      "dec_123",
		RevocationEpoch: 42,
		Timestamp:       1_765_000_000,
	}
	canonical := "v1\ncpa.console.enter\nroute:cpa-root\nAllow\ndec_123\n42\n1765000000"
	mac := hmac.New(sha256.New, []byte("authz-key"))
	_, _ = mac.Write([]byte(canonical))
	want := hex.EncodeToString(mac.Sum(nil))
	if got := SignAuthorizationContext("authz-key", value); got != want {
		t.Fatalf("signature = %q, want %q", got, want)
	}
	value.Object = "route:cpa-root\nforged"
	if got := SignAuthorizationContext("authz-key", value); got != "" {
		t.Fatalf("newline-bearing context was signed: %q", got)
	}
}
