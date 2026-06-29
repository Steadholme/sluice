package auth

import (
	"context"
	"crypto/rsa"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// Claims are the subset of token claims Sluice cares about. RegisteredClaims
// supplies iss/aud/exp/iat; Subject and Scope are the application claims that
// get injected downstream.
//
// Note: aud is intentionally NOT enforced in v0. Sluice is a resource server
// that does not yet know the expected client_id/audience. The seam to enforce
// it (jwt.WithAudience) lives in Validate once expected audiences are
// configurable.
type Claims struct {
	Subject string `json:"sub"`
	Scope   string `json:"scope"`
	jwt.RegisteredClaims
}

// keyResolver supplies RSA public keys by kid. JWKSCache satisfies it; tests
// may substitute their own.
type keyResolver interface {
	KeyByKID(ctx context.Context, kid string) (*rsa.PublicKey, error)
}

// Verifier validates Keystone-issued RS256 access tokens.
type Verifier struct {
	keys   keyResolver
	issuer string
	parser *jwt.Parser
}

// NewVerifier builds a Verifier pinned to RS256, requiring exp and the
// configured issuer. Pinning the method defeats alg=none and RS->HS confusion.
func NewVerifier(keys keyResolver, issuer string) *Verifier {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(issuer),
		jwt.WithExpirationRequired(),
	)
	return &Verifier{keys: keys, issuer: issuer, parser: parser}
}

// Validate parses and verifies a raw bearer token, returning the claims on
// success. Any failure (bad signature, expired, wrong issuer, unknown kid,
// disallowed alg) returns an error; callers must map all of them to a single
// 401 response without leaking which check failed.
func (v *Verifier) Validate(ctx context.Context, raw string) (*Claims, error) {
	claims := &Claims{}
	keyfunc := func(token *jwt.Token) (any, error) {
		// WithValidMethods already constrains the alg, but assert the concrete
		// key type as defense in depth.
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method %q", token.Header["alg"])
		}
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("token missing kid header")
		}
		return v.keys.KeyByKID(ctx, kid)
	}

	if _, err := v.parser.ParseWithClaims(raw, claims, keyfunc); err != nil {
		return nil, fmt.Errorf("auth: token validation failed: %w", err)
	}
	return claims, nil
}
