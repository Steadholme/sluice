package application

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"sync"
	"time"
)

const (
	HeaderKID     = "X-Application-Ctx-Kid"
	HeaderContext = "X-Application-Ctx"
	HeaderSig     = "X-Application-Ctx-Sig"

	ContextTTLSeconds = int64(30)
	ClockSkewSeconds  = int64(5)
	KeyOverlapSeconds = 300
)

var (
	ErrContextInvalid     = errors.New("application: invalid signed context")
	ErrContextUnavailable = errors.New("application: context verifier unavailable")
	kidPattern            = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	jtiPattern            = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
)

type ContextV1 struct {
	Version               int             `json:"v"`
	KID                   string          `json:"kid"`
	Issuer                string          `json:"iss"`
	Audience              string          `json:"aud"`
	ApplicationSub        string          `json:"application_sub"`
	ClientID              string          `json:"client_id"`
	CredentialID          string          `json:"credential_id"`
	CredentialVersion     int64           `json:"credential_version"`
	GrantID               string          `json:"grant_id"`
	PackageID             string          `json:"package_id"`
	PackageRevisionDigest string          `json:"package_revision_digest"`
	Scopes                []string        `json:"scopes"`
	Method                string          `json:"method"`
	NormalizedPath        string          `json:"normalized_path"`
	Route                 string          `json:"route"`
	BodySHA256            string          `json:"body_sha256"`
	RequestID             string          `json:"request_id"`
	CorrelationID         string          `json:"correlation_id"`
	JTI                   string          `json:"jti"`
	MCPSessionDigest      string          `json:"mcp_session_digest"`
	CredentialState       CredentialState `json:"credential_state"`
	OverlapUntil          *int64          `json:"overlap_until"`
	PolicyEpoch           int64           `json:"policy_epoch"`
	RevocationEpoch       int64           `json:"revocation_epoch"`
	IssuedAt              int64           `json:"iat"`
	ExpiresAt             int64           `json:"exp"`
}

type SigningKeyring struct {
	ActiveKID   string
	PrivateKeys map[string]ed25519.PrivateKey
}

type ContextSigner struct {
	activeKID string
	private   ed25519.PrivateKey
	now       func() time.Time
	random    io.Reader
}

type SignedContext struct {
	Context   ContextV1
	Canonical []byte
	Signature []byte
}

type signedContextKey struct{}

func ContextWithSignedRequest(ctx context.Context, signed SignedContext) context.Context {
	return context.WithValue(ctx, signedContextKey{}, signed)
}

func SignedRequestFromContext(ctx context.Context) (SignedContext, bool) {
	signed, ok := ctx.Value(signedContextKey{}).(SignedContext)
	return signed, ok
}

func NewContextSigner(keyring SigningKeyring, now func() time.Time, random io.Reader) (*ContextSigner, error) {
	if !kidPattern.MatchString(keyring.ActiveKID) || len(keyring.PrivateKeys) == 0 {
		return nil, ErrContextUnavailable
	}
	private, ok := keyring.PrivateKeys[keyring.ActiveKID]
	if !ok || len(private) != ed25519.PrivateKeySize {
		return nil, ErrContextUnavailable
	}
	if now == nil {
		now = time.Now
	}
	if random == nil {
		random = rand.Reader
	}
	return &ContextSigner{activeKID: keyring.ActiveKID, private: append(ed25519.PrivateKey(nil), private...), now: now, random: random}, nil
}

func (s *ContextSigner) Mint(value ContextV1) (SignedContext, error) {
	if s == nil || len(s.private) != ed25519.PrivateKeySize {
		return SignedContext{}, ErrContextUnavailable
	}
	issuedAt := s.now().Unix()
	jtiBytes := make([]byte, 16)
	if _, err := io.ReadFull(s.random, jtiBytes); err != nil {
		return SignedContext{}, ErrContextUnavailable
	}
	value.Version = 1
	value.KID = s.activeKID
	value.JTI = base64.RawURLEncoding.EncodeToString(jtiBytes)
	value.IssuedAt = issuedAt
	value.ExpiresAt = issuedAt + ContextTTLSeconds
	value.Scopes = append([]string(nil), value.Scopes...)
	sort.Strings(value.Scopes)
	if err := validateContext(value); err != nil {
		return SignedContext{}, err
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return SignedContext{}, ErrContextInvalid
	}
	signature := ed25519.Sign(s.private, canonical)
	return SignedContext{Context: value, Canonical: canonical, Signature: signature}, nil
}

func (s SignedContext) Headers() http.Header {
	h := make(http.Header)
	h.Set(HeaderKID, s.Context.KID)
	h.Set(HeaderContext, base64.RawURLEncoding.EncodeToString(s.Canonical))
	h.Set(HeaderSig, base64.RawURLEncoding.EncodeToString(s.Signature))
	return h
}

type VerificationKey struct {
	PublicKey ed25519.PublicKey
	RetiredAt time.Time
}

type VerificationKeyring struct{ Keys map[string]VerificationKey }

type ExpectedRequest struct {
	Audience, Route, Method, NormalizedPath, BodySHA256, RequestID, MCPSessionDigest string
}

type ReplayGuard interface {
	Consume(issuer, jti string, expiresAt int64) bool
}

type memoryReplayGuard struct {
	mu   sync.Mutex
	seen map[string]int64
}

func NewMemoryReplayGuard() ReplayGuard { return &memoryReplayGuard{seen: make(map[string]int64)} }

func (g *memoryReplayGuard) Consume(issuer, jti string, expiresAt int64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	key := issuer + "\x00" + jti
	if _, exists := g.seen[key]; exists {
		return false
	}
	g.seen[key] = expiresAt
	return true
}

func VerifyContextHeaders(headers http.Header, keyring VerificationKeyring, now time.Time, expected ExpectedRequest, replay ReplayGuard) (ContextV1, error) {
	kid, ok := singleHeader(headers, HeaderKID)
	if !ok {
		return ContextV1{}, ErrContextInvalid
	}
	encoded, ok := singleHeader(headers, HeaderContext)
	if !ok {
		return ContextV1{}, ErrContextInvalid
	}
	encodedSig, ok := singleHeader(headers, HeaderSig)
	if !ok {
		return ContextV1{}, ErrContextInvalid
	}
	canonical, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(canonical) == 0 || len(canonical) > 16<<10 {
		return ContextV1{}, ErrContextInvalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(encodedSig)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ContextV1{}, ErrContextInvalid
	}
	var value ContextV1
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil || requireJSONEOF(decoder) != nil {
		return ContextV1{}, ErrContextInvalid
	}
	reencoded, err := json.Marshal(value)
	if err != nil || !bytes.Equal(reencoded, canonical) || value.KID != kid || validateContext(value) != nil {
		return ContextV1{}, ErrContextInvalid
	}
	key, exists := keyring.Keys[kid]
	if !exists || len(key.PublicKey) != ed25519.PublicKeySize {
		return ContextV1{}, ErrContextUnavailable
	}
	if !key.RetiredAt.IsZero() && now.Unix() > key.RetiredAt.Unix()+KeyOverlapSeconds {
		return ContextV1{}, ErrContextUnavailable
	}
	if now.Unix() < value.IssuedAt-ClockSkewSeconds || now.Unix() > value.ExpiresAt+ClockSkewSeconds || !ed25519.Verify(key.PublicKey, canonical, signature) {
		return ContextV1{}, ErrContextInvalid
	}
	if value.Audience != expected.Audience || value.Route != expected.Route || value.Method != expected.Method || value.NormalizedPath != expected.NormalizedPath || value.BodySHA256 != expected.BodySHA256 || value.RequestID != expected.RequestID || value.MCPSessionDigest != expected.MCPSessionDigest {
		return ContextV1{}, ErrContextInvalid
	}
	if replay == nil || !replay.Consume(value.Issuer, value.JTI, value.ExpiresAt) {
		return ContextV1{}, ErrContextInvalid
	}
	return value, nil
}

func singleHeader(headers http.Header, name string) (string, bool) {
	values := headers.Values(name)
	returnValue := ""
	if len(values) == 1 {
		returnValue = values[0]
	}
	return returnValue, len(values) == 1 && returnValue != ""
}

func validateContext(value ContextV1) error {
	if value.Version != 1 || !kidPattern.MatchString(value.KID) || value.Issuer != "sluice" || value.Audience != "analyze-facade" ||
		!subjectPattern.MatchString(value.ApplicationSub) || !validOpaqueID(value.ClientID) || !validOpaqueID(value.CredentialID) ||
		value.CredentialVersion <= 0 || !validOpaqueID(value.GrantID) || !validOpaqueID(value.PackageID) ||
		!hexDigestPattern.MatchString(value.PackageRevisionDigest) || len(value.Scopes) == 0 ||
		!validVisible(value.Method, 1, 16) || !validVisible(value.NormalizedPath, 1, 4096) || value.NormalizedPath[0] != '/' ||
		!validOpaqueID(value.Route) || !hexDigestPattern.MatchString(value.BodySHA256) || !validOpaqueID(value.RequestID) ||
		!validOpaqueID(value.CorrelationID) || !jtiPattern.MatchString(value.JTI) || !hexDigestPattern.MatchString(value.MCPSessionDigest) ||
		value.PolicyEpoch <= 0 || value.RevocationEpoch <= 0 || value.IssuedAt <= 0 || value.ExpiresAt-value.IssuedAt != ContextTTLSeconds {
		return ErrContextInvalid
	}
	for index, scope := range value.Scopes {
		if !validScope(scope) || (index > 0 && value.Scopes[index-1] >= scope) {
			return ErrContextInvalid
		}
	}
	switch value.CredentialState {
	case CredentialActive:
		if value.OverlapUntil != nil {
			return ErrContextInvalid
		}
	case CredentialOverlap:
		if value.OverlapUntil == nil || *value.OverlapUntil <= value.IssuedAt {
			return ErrContextInvalid
		}
	default:
		return ErrContextInvalid
	}
	return nil
}

func ParseSigningKeyring(activeKID string, raw string) (SigningKeyring, error) {
	var encoded map[string]string
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	if err := decoder.Decode(&encoded); err != nil || requireJSONEOF(decoder) != nil || len(encoded) == 0 || len(encoded) > 2 {
		return SigningKeyring{}, ErrContextUnavailable
	}
	keys := make(map[string]ed25519.PrivateKey, len(encoded))
	for kid, value := range encoded {
		if !kidPattern.MatchString(kid) {
			return SigningKeyring{}, ErrContextUnavailable
		}
		decoded, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil {
			return SigningKeyring{}, ErrContextUnavailable
		}
		switch len(decoded) {
		case ed25519.SeedSize:
			keys[kid] = ed25519.NewKeyFromSeed(decoded)
		case ed25519.PrivateKeySize:
			keys[kid] = ed25519.PrivateKey(append([]byte(nil), decoded...))
		default:
			return SigningKeyring{}, ErrContextUnavailable
		}
	}
	if _, ok := keys[activeKID]; !ok {
		return SigningKeyring{}, fmt.Errorf("%w: active kid missing", ErrContextUnavailable)
	}
	return SigningKeyring{ActiveKID: activeKID, PrivateKeys: keys}, nil
}
