package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testIssuer = "http://127.0.0.1:8080"

type testKeyResolver struct {
	keys map[string]*rsa.PublicKey
}

func (r *testKeyResolver) KeyByKID(_ context.Context, kid string) (*rsa.PublicKey, error) {
	k, ok := r.keys[kid]
	if !ok {
		return nil, fmt.Errorf("unknown kid %q", kid)
	}
	return k, nil
}

func mintRS256(t *testing.T, priv *rsa.PrivateKey, kid, iss string, exp time.Time) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss":   iss,
		"sub":   "u_admin",
		"aud":   "sluice-dev",
		"exp":   exp.Unix(),
		"iat":   time.Now().Add(-time.Minute).Unix(),
		"scope": "openid profile",
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign RS256: %v", err)
	}
	return signed
}

func TestVerifierValidate(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const kid = "test-kid-1"
	resolver := &testKeyResolver{keys: map[string]*rsa.PublicKey{kid: &priv.PublicKey}}
	v := NewVerifier(resolver, testIssuer)
	ctx := context.Background()

	validToken := mintRS256(t, priv, kid, testIssuer, time.Now().Add(time.Hour))

	// alg=none token.
	noneTok := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"iss": testIssuer, "sub": "u_admin", "exp": time.Now().Add(time.Hour).Unix(),
	})
	noneTok.Header["kid"] = kid
	noneSigned, err := noneTok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}

	// HS256-signed token (signature confusion attempt).
	hsTok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": testIssuer, "sub": "u_admin", "exp": time.Now().Add(time.Hour).Unix(),
	})
	hsTok.Header["kid"] = kid
	hsSigned, err := hsTok.SignedString([]byte("shared-secret"))
	if err != nil {
		t.Fatalf("sign hs256: %v", err)
	}

	// Tampered signature: flip the last byte region of a valid token.
	tampered := validToken[:len(validToken)-3] + "AAA"

	cases := []struct {
		name      string
		token     string
		wantValid bool
	}{
		{"valid", validToken, true},
		{"expired", mintRS256(t, priv, kid, testIssuer, time.Now().Add(-time.Hour)), false},
		{"wrong-issuer", mintRS256(t, priv, kid, "http://evil.example", time.Now().Add(time.Hour)), false},
		{"alg-none", noneSigned, false},
		{"hs256", hsSigned, false},
		{"unknown-kid", mintRS256(t, priv, "no-such-kid", testIssuer, time.Now().Add(time.Hour)), false},
		{"tampered", tampered, false},
		{"garbage", "not.a.jwt", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := v.Validate(ctx, tc.token)
			if tc.wantValid {
				if err != nil {
					t.Fatalf("expected valid, got error: %v", err)
				}
				if claims.Subject != "u_admin" {
					t.Errorf("Subject = %q, want u_admin", claims.Subject)
				}
				if claims.Scope != "openid profile" {
					t.Errorf("Scope = %q, want 'openid profile'", claims.Scope)
				}
			} else if err == nil {
				t.Fatalf("expected error, got valid claims: %+v", claims)
			}
		})
	}
}

func TestParseJWKSReconstructsKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub := &priv.PublicKey

	// Encode modulus and exponent as base64url per RFC 7518.
	nStr := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	var eBuf [4]byte
	binary.BigEndian.PutUint32(eBuf[:], uint32(pub.E))
	// Trim leading zero bytes from the exponent encoding.
	eBytes := eBuf[:]
	for len(eBytes) > 1 && eBytes[0] == 0 {
		eBytes = eBytes[1:]
	}
	eStr := base64.RawURLEncoding.EncodeToString(eBytes)

	doc := &jwksDocument{Keys: []jwksKey{
		{Kty: "RSA", Kid: "k1", Use: "sig", Alg: "RS256", N: nStr, E: eStr},
		{Kty: "oct", Kid: "ignored"}, // non-RSA must be skipped
	}}

	keys, err := parseJWKS(doc)
	if err != nil {
		t.Fatalf("parseJWKS: %v", err)
	}
	got, ok := keys["k1"]
	if !ok {
		t.Fatal("kid k1 not present after parse")
	}
	if got.N.Cmp(pub.N) != 0 {
		t.Error("reconstructed modulus mismatch")
	}
	if got.E != pub.E {
		t.Errorf("reconstructed exponent = %d, want %d", got.E, pub.E)
	}
	if _, ok := keys["ignored"]; ok {
		t.Error("non-RSA key should have been skipped")
	}
}

func TestRSAPublicKeyFromNEErrors(t *testing.T) {
	if _, err := rsaPublicKeyFromNE("!!!not-base64", "AQAB"); err == nil {
		t.Error("expected error for invalid modulus encoding")
	}
	if _, err := rsaPublicKeyFromNE(base64.RawURLEncoding.EncodeToString(big.NewInt(1).Bytes()), ""); err == nil {
		t.Error("expected error for empty exponent")
	}
}

// D10a: an expected audience, when configured, is enforced; empty keeps v0 (no aud check).
func TestVerifierAudienceEnforcement(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const kid = "test-kid-aud"
	resolver := &testKeyResolver{keys: map[string]*rsa.PublicKey{kid: &priv.PublicKey}}
	ctx := context.Background()
	// mintRS256 stamps aud="sluice-dev".
	token := mintRS256(t, priv, kid, testIssuer, time.Now().Add(time.Hour))

	// Matching expected audience => accepted.
	if _, err := NewVerifierWithAudience(resolver, testIssuer, "sluice-dev").Validate(ctx, token); err != nil {
		t.Fatalf("matching aud should validate, got: %v", err)
	}
	// Different expected audience => rejected (a token minted for another resource server).
	if _, err := NewVerifierWithAudience(resolver, testIssuer, "other-service").Validate(ctx, token); err == nil {
		t.Fatal("mismatched aud should be rejected")
	}
	// Empty audience keeps v0 behavior: aud not checked, any aud accepted.
	if _, err := NewVerifierWithAudience(resolver, testIssuer, "").Validate(ctx, token); err != nil {
		t.Fatalf("empty aud must not enforce, got: %v", err)
	}
}
