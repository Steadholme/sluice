package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

const (
	HeaderAuthPermission      = "X-Auth-Permission"
	HeaderAuthObject          = "X-Auth-Object"
	HeaderAuthDecision        = "X-Auth-Decision"
	HeaderAuthDecisionID      = "X-Auth-Decision-Id"
	HeaderAuthRevocationEpoch = "X-Auth-Revocation-Epoch"
	HeaderAuthContextTime     = "X-Auth-Context-Timestamp"
	HeaderAuthContextSig      = "X-Auth-Context-Sig"
)

// AuthorizationContext is minted only after Verdict v2 returned Allow. The
// reverse proxy signs and injects it toward the matched upstream.
type AuthorizationContext struct {
	Permission      string
	Object          string
	Decision        string
	DecisionID      string
	RevocationEpoch int64
	Timestamp       int64
	// Subject and Risk are covered only by the v2 context. They intentionally do
	// not alter the frozen v1 preimage above, preserving existing consumers.
	Subject string
	Risk    string
}

func AuthorizationFromContext(ctx context.Context) (AuthorizationContext, bool) {
	value, ok := ctx.Value(authorizationKey).(AuthorizationContext)
	return value, ok
}

func ContextWithAuthorization(ctx context.Context, value AuthorizationContext) context.Context {
	return context.WithValue(ctx, authorizationKey, value)
}

// SignAuthorizationContext implements the frozen newline-delimited canonical
// v1 contract. Newline-bearing values are rejected instead of normalized.
func SignAuthorizationContext(key string, value AuthorizationContext) string {
	if key == "" || value.Decision != "Allow" {
		return ""
	}
	fields := []string{
		"v1",
		value.Permission,
		value.Object,
		value.Decision,
		value.DecisionID,
		strconv.FormatInt(value.RevocationEpoch, 10),
		strconv.FormatInt(value.Timestamp, 10),
	}
	for _, field := range fields {
		if strings.ContainsAny(field, "\r\n") {
			return ""
		}
	}
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(strings.Join(fields, "\n")))
	return hex.EncodeToString(mac.Sum(nil))
}
