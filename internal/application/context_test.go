package application

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestApplicationContextCanonicalEd25519TimingAndCompleteRequestV2(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	signer, err := NewContextSigner(SigningKeyring{
		ActiveKID:   "appctx-2026a",
		PrivateKeys: map[string]ed25519.PrivateKey{"appctx-2026a": private},
	}, func() time.Time { return now }, bytes.NewReader(bytes.Repeat([]byte{9}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	body := sha256.Sum256([]byte(`{"jsonrpc":"2.0"}`))
	overlapUntil := now.Unix() + 120
	value := ContextV1{
		Issuer: "sluice", Audience: "analyze-facade", ApplicationSub: "application:abcdefghijklmnop",
		ClientID: "client_abcdefghijklmnop", CredentialID: "cred_abcdefghijklmnop", CredentialVersion: 3,
		GrantID: "grant_abcdefghijklmnop", PackageID: "pkg_analyze_mcp_client",
		PackageRevisionDigest: hex.EncodeToString(bytes.Repeat([]byte{4}, 32)),
		Scopes:                []string{"analysis.create", "analysis.read"}, Method: http.MethodPost, NormalizedPath: "/mcp",
		Route: "analyze-mcp", BodySHA256: hex.EncodeToString(body[:]), RequestID: "req_abcdefghijklmnop",
		CorrelationID: "corr_abcdefghijklmnop", MCPSessionDigest: hex.EncodeToString(bytes.Repeat([]byte{5}, 32)),
		CredentialState: CredentialOverlap, OverlapUntil: &overlapUntil, PolicyEpoch: 11, RevocationEpoch: 13,
	}
	signed, err := signer.Mint(value)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Context.ExpiresAt-signed.Context.IssuedAt != ContextTTLSeconds || signed.Context.JTI == "" {
		t.Fatalf("context timing/jti = %+v", signed.Context)
	}
	headers := signed.Headers()
	verified, err := VerifyContextHeaders(headers, VerificationKeyring{
		Keys: map[string]VerificationKey{"appctx-2026a": {PublicKey: private.Public().(ed25519.PublicKey)}},
	}, now, ExpectedRequest{
		Audience: "analyze-facade", Route: "analyze-mcp", Method: http.MethodPost,
		NormalizedPath: "/mcp", BodySHA256: value.BodySHA256, RequestID: value.RequestID,
		MCPSessionDigest: value.MCPSessionDigest,
	}, NewMemoryReplayGuard())
	if err != nil {
		t.Fatal(err)
	}
	if verified.ApplicationSub != value.ApplicationSub || verified.CredentialState != CredentialOverlap || verified.OverlapUntil == nil || *verified.OverlapUntil != overlapUntil {
		t.Fatalf("verified = %+v", verified)
	}
	if _, err := VerifyContextHeaders(headers, VerificationKeyring{
		Keys: map[string]VerificationKey{"appctx-2026a": {PublicKey: private.Public().(ed25519.PublicKey)}},
	}, now, ExpectedRequest{Audience: "analyze-facade", Route: "analyze-mcp", Method: http.MethodPost, NormalizedPath: "/mcp", BodySHA256: value.BodySHA256, RequestID: value.RequestID, MCPSessionDigest: value.MCPSessionDigest}, NewMemoryReplayGuard()); err != nil {
		t.Fatalf("fresh replay guard should accept independent verification: %v", err)
	}
}

func TestContextRejectsDuplicateHeadersWrongBindingReplayAndExpiredPreviousKey(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	signer, err := NewContextSigner(SigningKeyring{ActiveKID: "previous", PrivateKeys: map[string]ed25519.PrivateKey{"previous": private}}, func() time.Time { return now }, bytes.NewReader(bytes.Repeat([]byte{3}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	digest := hex.EncodeToString(bytes.Repeat([]byte{1}, 32))
	signed, err := signer.Mint(ContextV1{Issuer: "sluice", Audience: "analyze-facade", ApplicationSub: "application:abcdefghijklmnop", ClientID: "client_abcdefghijklmnop", CredentialID: "cred_abcdefghijklmnop", CredentialVersion: 1, GrantID: "grant_abcdefghijklmnop", PackageID: "pkg_analyze_mcp_client", PackageRevisionDigest: digest, Scopes: []string{"analysis.read"}, Method: "POST", NormalizedPath: "/mcp", Route: "analyze-mcp", BodySHA256: digest, RequestID: "req_abcdefghijklmnop", CorrelationID: "corr_abcdefghijklmnop", MCPSessionDigest: digest, CredentialState: CredentialActive, PolicyEpoch: 1, RevocationEpoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	keys := VerificationKeyring{Keys: map[string]VerificationKey{"previous": {PublicKey: private.Public().(ed25519.PublicKey), RetiredAt: now.Add(-KeyOverlapSeconds * time.Second)}}}
	expected := ExpectedRequest{Audience: "analyze-facade", Route: "analyze-mcp", Method: "POST", NormalizedPath: "/mcp", BodySHA256: digest, RequestID: "req_abcdefghijklmnop", MCPSessionDigest: digest}
	if _, err := VerifyContextHeaders(signed.Headers(), keys, now.Add(time.Second), expected, NewMemoryReplayGuard()); err == nil {
		t.Fatal("expired previous key accepted")
	}
	activeKeys := VerificationKeyring{Keys: map[string]VerificationKey{"previous": {PublicKey: private.Public().(ed25519.PublicKey)}}}
	for _, name := range []string{HeaderKID, HeaderContext, HeaderSig} {
		headers := signed.Headers()
		headers.Add(name, headers.Get(name))
		if _, err := VerifyContextHeaders(headers, activeKeys, now, expected, NewMemoryReplayGuard()); err == nil {
			t.Fatalf("duplicate %s header accepted", name)
		}
	}
	headers := signed.Headers()
	guard := NewMemoryReplayGuard()
	if _, err := VerifyContextHeaders(headers, activeKeys, now, expected, guard); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyContextHeaders(headers, activeKeys, now, expected, guard); err == nil {
		t.Fatal("replayed jti accepted")
	}
	expected.BodySHA256 = hex.EncodeToString(bytes.Repeat([]byte{2}, 32))
	if _, err := VerifyContextHeaders(signed.Headers(), activeKeys, now, expected, NewMemoryReplayGuard()); err == nil {
		t.Fatal("wrong body binding accepted")
	}
}

func TestContextRejectsEveryExpiredOrMismatchedSignedBinding(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	digest := hex.EncodeToString(bytes.Repeat([]byte{1}, 32))
	value := ContextV1{
		Version: 1, KID: "appctx-2026a", Issuer: "sluice", Audience: "analyze-facade",
		ApplicationSub: "application:abcdefghijklmnop", ClientID: "client_abcdefghijklmnop",
		CredentialID: "cred_abcdefghijklmnop", CredentialVersion: 1, GrantID: "grant_abcdefghijklmnop",
		PackageID: "pkg_analyze_mcp_client", PackageRevisionDigest: digest, Scopes: []string{"analysis.read"},
		Method: http.MethodPost, NormalizedPath: "/mcp", Route: "analyze-mcp", BodySHA256: digest,
		RequestID: "req_abcdefghijklmnop", CorrelationID: "corr_abcdefghijklmnop",
		JTI: "AAAAAAAAAAAAAAAAAAAAAA", MCPSessionDigest: digest, CredentialState: CredentialActive,
		PolicyEpoch: 1, RevocationEpoch: 1, IssuedAt: now.Unix(), ExpiresAt: now.Unix() + ContextTTLSeconds,
	}
	keys := VerificationKeyring{Keys: map[string]VerificationKey{"appctx-2026a": {PublicKey: private.Public().(ed25519.PublicKey)}}}
	expected := ExpectedRequest{
		Audience: value.Audience, Route: value.Route, Method: value.Method, NormalizedPath: value.NormalizedPath,
		BodySHA256: value.BodySHA256, RequestID: value.RequestID, MCPSessionDigest: value.MCPSessionDigest,
	}

	for _, tc := range []struct {
		name   string
		at     time.Time
		value  ContextV1
		expect ExpectedRequest
		keys   VerificationKeyring
	}{
		{name: "issued too far in future", at: now.Add(-time.Duration(ClockSkewSeconds+1) * time.Second), value: value, expect: expected, keys: keys},
		{name: "expired beyond skew", at: now.Add(time.Duration(ContextTTLSeconds+ClockSkewSeconds+1) * time.Second), value: value, expect: expected, keys: keys},
		{name: "wrong audience", at: now, value: value, expect: withExpected(expected, func(v *ExpectedRequest) { v.Audience = "other-audience" }), keys: keys},
		{name: "wrong route", at: now, value: value, expect: withExpected(expected, func(v *ExpectedRequest) { v.Route = "other-route" }), keys: keys},
		{name: "wrong method", at: now, value: value, expect: withExpected(expected, func(v *ExpectedRequest) { v.Method = http.MethodGet }), keys: keys},
		{name: "wrong path", at: now, value: value, expect: withExpected(expected, func(v *ExpectedRequest) { v.NormalizedPath = "/other" }), keys: keys},
		{name: "wrong body", at: now, value: value, expect: withExpected(expected, func(v *ExpectedRequest) { v.BodySHA256 = hex.EncodeToString(bytes.Repeat([]byte{2}, 32)) }), keys: keys},
		{name: "wrong request", at: now, value: value, expect: withExpected(expected, func(v *ExpectedRequest) { v.RequestID = "req_differentdifferent" }), keys: keys},
		{name: "wrong session", at: now, value: value, expect: withExpected(expected, func(v *ExpectedRequest) { v.MCPSessionDigest = hex.EncodeToString(bytes.Repeat([]byte{2}, 32)) }), keys: keys},
		{name: "invalid ttl", at: now, value: withContext(value, func(v *ContextV1) { v.ExpiresAt++ }), expect: expected, keys: keys},
		{name: "invalid jti", at: now, value: withContext(value, func(v *ContextV1) { v.JTI = "too-short" }), expect: expected, keys: keys},
		{name: "invalid application subject", at: now, value: withContext(value, func(v *ContextV1) { v.ApplicationSub = "user:abcdefghijklmnop" }), expect: expected, keys: keys},
		{name: "unknown kid", at: now, value: withContext(value, func(v *ContextV1) { v.KID = "missing-key" }), expect: expected, keys: keys},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := rawSignedContextHeaders(t, tc.value, private)
			if _, err := VerifyContextHeaders(headers, tc.keys, tc.at, tc.expect, NewMemoryReplayGuard()); err == nil {
				t.Fatal("invalid context accepted")
			}
		})
	}
}

func rawSignedContextHeaders(t *testing.T, value ContextV1, private ed25519.PrivateKey) http.Header {
	t.Helper()
	canonical, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	headers := make(http.Header)
	headers.Set(HeaderKID, value.KID)
	headers.Set(HeaderContext, base64.RawURLEncoding.EncodeToString(canonical))
	headers.Set(HeaderSig, base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, canonical)))
	return headers
}

func withExpected(value ExpectedRequest, mutate func(*ExpectedRequest)) ExpectedRequest {
	mutate(&value)
	return value
}

func withContext(value ContextV1, mutate func(*ContextV1)) ContextV1 {
	mutate(&value)
	return value
}
