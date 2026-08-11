package auth

import (
	"errors"
	"testing"
)

func goldenAuthorizationContextV2() AuthorizationContextV2 {
	return AuthorizationContextV2{
		Issuer:          AuthorizationContextV2Issuer,
		Subject:         "user:alice",
		Route:           "cpa-root",
		Audience:        "cpa.w33d.xyz",
		Zone:            "internal",
		Permission:      "cpa.console.enter",
		ResourceVersion: "1",
		ResourceType:    "route",
		ResourceID:      "cpa-root",
		Risk:            "critical",
		Decision:        "Allow",
		DecisionID:      "dec_0123456789abcdef0123456789abcdef",
		PolicyEpoch:     42,
		IssuedAt:        1_765_000_000,
		Expiry:          1_765_000_090,
	}
}

func goldenAuthorizationContextV2Keyring() AuthorizationContextV2Keyring {
	return AuthorizationContextV2Keyring{
		Current: AuthorizationContextV2Key{
			KID: "authz2-2026a",
			Key: "authz2-ctx-golden-key-0123456789abcdef",
		},
		Previous: AuthorizationContextV2Key{
			KID: "authz2-2025h",
			Key: "authz2-ctx-golden-prev-0123456789abcdef",
		},
	}
}

func TestMintAuthorizationContextV2GoldenVector(t *testing.T) {
	signed, err := MintAuthorizationContextV2(goldenAuthorizationContextV2Keyring(), goldenAuthorizationContextV2())
	if err != nil {
		t.Fatalf("MintAuthorizationContextV2: %v", err)
	}
	const want = "bc5d6152f44d7c4ca8110e7eac191bce169d9b46a0de7dcfdc67839ddbb03929"
	if signed.Signature != want {
		t.Fatalf("signature = %q, want %q", signed.Signature, want)
	}
	if signed.Context.KID != "authz2-2026a" {
		t.Fatalf("minted KID = %q, want current KID", signed.Context.KID)
	}
	if err := VerifyAuthorizationContextV2(goldenAuthorizationContextV2Keyring(), signed.Context, signed.Signature); err != nil {
		t.Fatalf("current signature did not verify: %v", err)
	}
	headers := signed.Headers()
	if len(headers) != 17 {
		t.Fatalf("header count = %d, want 17", len(headers))
	}
	if headers[HeaderAuthContextV2Subject] != "user:alice" ||
		headers[HeaderAuthContextV2ResourceVersion] != "1" ||
		headers[HeaderAuthContextV2Expiry] != "1765000090" ||
		headers[HeaderAuthContextV2Signature] != want {
		t.Fatalf("unexpected v2 headers: %#v", headers)
	}
}

func TestVerifyAuthorizationContextV2AcceptsPreviousAndClassifiesUnknownKID(t *testing.T) {
	value := goldenAuthorizationContextV2()
	value.KID = "authz2-2025h"
	const previousSignature = "b0b4f0641b14d8d849fd91afa1eea11ea30a8cb460ef0679f80b1714ba690422"
	if err := VerifyAuthorizationContextV2(goldenAuthorizationContextV2Keyring(), value, previousSignature); err != nil {
		t.Fatalf("previous signature did not verify: %v", err)
	}

	value.KID = "authz2-nope"
	if err := VerifyAuthorizationContextV2(goldenAuthorizationContextV2Keyring(), value, previousSignature); !errors.Is(err, ErrAuthorizationContextV2Unavailable) {
		t.Fatalf("unknown KID error = %v, want unavailable/E9", err)
	}
}

func TestAuthorizationContextV2RejectsBadSignatureAndUnsafeFields(t *testing.T) {
	signed, err := MintAuthorizationContextV2(goldenAuthorizationContextV2Keyring(), goldenAuthorizationContextV2())
	if err != nil {
		t.Fatalf("MintAuthorizationContextV2: %v", err)
	}
	badSignature := signed.Signature[:len(signed.Signature)-1] + "0"
	if badSignature == signed.Signature {
		badSignature = signed.Signature[:len(signed.Signature)-1] + "1"
	}
	if err := VerifyAuthorizationContextV2(goldenAuthorizationContextV2Keyring(), signed.Context, badSignature); !errors.Is(err, ErrAuthorizationContextV2Invalid) {
		t.Fatalf("bad signature error = %v, want invalid/E5", err)
	}

	for _, mutate := range []func(*AuthorizationContextV2){
		func(value *AuthorizationContextV2) { value.Subject = "user:álice" },
		func(value *AuthorizationContextV2) { value.ResourceID = "alpha\n.json" },
		func(value *AuthorizationContextV2) { value.DecisionID = "dec_short" },
		func(value *AuthorizationContextV2) { value.Expiry++ },
	} {
		value := goldenAuthorizationContextV2()
		mutate(&value)
		if _, err := MintAuthorizationContextV2(goldenAuthorizationContextV2Keyring(), value); !errors.Is(err, ErrAuthorizationContextV2Invalid) {
			t.Fatalf("unsafe value error = %v, want invalid/E5; value=%+v", err, value)
		}
	}
}

func TestAuthorizationContextV2KeyringRejectsTornOrDuplicateBindings(t *testing.T) {
	valid := goldenAuthorizationContextV2Keyring()
	for _, mutate := range []func(*AuthorizationContextV2Keyring){
		func(keyring *AuthorizationContextV2Keyring) { keyring.Current.KID = "" },
		func(keyring *AuthorizationContextV2Keyring) { keyring.Previous.Key = "" },
		func(keyring *AuthorizationContextV2Keyring) { keyring.Previous.KID = keyring.Current.KID },
		func(keyring *AuthorizationContextV2Keyring) { keyring.Previous.Key = keyring.Current.Key },
	} {
		keyring := valid
		mutate(&keyring)
		if err := ValidateAuthorizationContextV2Keyring(keyring); err == nil {
			t.Fatalf("invalid keyring accepted: %+v", keyring)
		}
	}

	currentOnly := valid
	currentOnly.Previous = AuthorizationContextV2Key{}
	if err := ValidateAuthorizationContextV2Keyring(currentOnly); err != nil {
		t.Fatalf("current-only keyring rejected: %v", err)
	}
}
