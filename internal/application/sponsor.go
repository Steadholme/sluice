package application

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

const (
	HeaderSponsorKID       = "X-Sponsor-Assertion-Kid"
	HeaderSponsorAssertion = "X-Sponsor-Assertion-Assertion"
	HeaderSponsorSig       = "X-Sponsor-Assertion-Sig"
	SponsorTTLSeconds      = int64(300)
)

var (
	ErrSponsorInvalid = errors.New("application: invalid sponsor assertion")
	requestIDPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
	sponsorJTIPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,200}$`)
)

type SponsorAssertionV1 struct {
	Version        int      `json:"v"`
	KID            string   `json:"kid"`
	Issuer         string   `json:"iss"`
	Audience       string   `json:"aud"`
	Subject        string   `json:"sub"`
	JTI            string   `json:"jti"`
	RequestID      string   `json:"request_id"`
	RequestVersion int64    `json:"request_version"`
	Method         string   `json:"method"`
	NormalizedPath string   `json:"normalized_path"`
	BodySHA256     string   `json:"body_sha256"`
	SessionBinding string   `json:"session_binding"`
	AuthTime       int64    `json:"auth_time"`
	AMR            []string `json:"amr"`
	IssuedAt       int64    `json:"iat"`
	ExpiresAt      int64    `json:"exp"`
}

type SponsorSigner struct {
	activeKID string
	private   ed25519.PrivateKey
	now       func() time.Time
	random    io.Reader
}

type SignedSponsorAssertion struct {
	Assertion SponsorAssertionV1
	Canonical []byte
	Signature []byte
}

func NewSponsorSigner(keyring SigningKeyring, now func() time.Time, random io.Reader) (*SponsorSigner, error) {
	contextSigner, err := NewContextSigner(keyring, now, random)
	if err != nil {
		return nil, err
	}
	return &SponsorSigner{activeKID: contextSigner.activeKID, private: contextSigner.private, now: contextSigner.now, random: contextSigner.random}, nil
}

func (s *SponsorSigner) Mint(value SponsorAssertionV1) (SignedSponsorAssertion, error) {
	if s == nil || len(s.private) != ed25519.PrivateKeySize {
		return SignedSponsorAssertion{}, ErrContextUnavailable
	}
	jti := make([]byte, 16)
	if _, err := io.ReadFull(s.random, jti); err != nil {
		return SignedSponsorAssertion{}, ErrContextUnavailable
	}
	now := s.now().Unix()
	value.Version = 1
	value.KID = s.activeKID
	value.Issuer = "https://id.w33d.xyz"
	value.Audience = "access-governance"
	value.JTI = base64.RawURLEncoding.EncodeToString(jti)
	value.AMR = []string{"passkey", "uv"}
	value.IssuedAt = now
	value.ExpiresAt = now + SponsorTTLSeconds
	if err := validateSponsor(value); err != nil {
		return SignedSponsorAssertion{}, err
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return SignedSponsorAssertion{}, ErrSponsorInvalid
	}
	return SignedSponsorAssertion{Assertion: value, Canonical: canonical, Signature: ed25519.Sign(s.private, canonical)}, nil
}

func (s SignedSponsorAssertion) Headers() http.Header {
	h := make(http.Header)
	h.Set(HeaderSponsorKID, s.Assertion.KID)
	h.Set(HeaderSponsorAssertion, base64.RawURLEncoding.EncodeToString(s.Canonical))
	h.Set(HeaderSponsorSig, base64.RawURLEncoding.EncodeToString(s.Signature))
	return h
}

func VerifySponsorHeaders(headers http.Header, publicKeys map[string]ed25519.PublicKey, now time.Time) (SponsorAssertionV1, error) {
	kid, ok := singleHeader(headers, HeaderSponsorKID)
	if !ok {
		return SponsorAssertionV1{}, ErrSponsorInvalid
	}
	encoded, ok := singleHeader(headers, HeaderSponsorAssertion)
	if !ok {
		return SponsorAssertionV1{}, ErrSponsorInvalid
	}
	encodedSig, ok := singleHeader(headers, HeaderSponsorSig)
	if !ok {
		return SponsorAssertionV1{}, ErrSponsorInvalid
	}
	canonical, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(canonical) > 8<<10 {
		return SponsorAssertionV1{}, ErrSponsorInvalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(encodedSig)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return SponsorAssertionV1{}, ErrSponsorInvalid
	}
	var assertion SponsorAssertionV1
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&assertion); err != nil || requireJSONEOF(decoder) != nil {
		return SponsorAssertionV1{}, ErrSponsorInvalid
	}
	reencoded, err := json.Marshal(assertion)
	key, exists := publicKeys[kid]
	if err != nil || !bytes.Equal(reencoded, canonical) || assertion.KID != kid || !exists || len(key) != ed25519.PublicKeySize || validateSponsor(assertion) != nil || !ed25519.Verify(key, canonical, signature) {
		return SponsorAssertionV1{}, ErrSponsorInvalid
	}
	if now.Unix() < assertion.IssuedAt-ClockSkewSeconds || now.Unix() > assertion.ExpiresAt+ClockSkewSeconds {
		return SponsorAssertionV1{}, ErrSponsorInvalid
	}
	return assertion, nil
}

func validateSponsor(value SponsorAssertionV1) error {
	if value.Version != 1 || !kidPattern.MatchString(value.KID) || value.Issuer != "https://id.w33d.xyz" || value.Audience != "access-governance" ||
		!validVisible(value.Subject, 1, 256) || !sponsorJTIPattern.MatchString(value.JTI) || !requestIDPattern.MatchString(value.RequestID) || value.RequestVersion <= 0 ||
		value.Method != http.MethodPost || !sponsorSubmitPathMatches(value.NormalizedPath, value.RequestID) ||
		!hexDigestPattern.MatchString(value.BodySHA256) || !hexDigestPattern.MatchString(value.SessionBinding) || value.AuthTime <= 0 ||
		len(value.AMR) != 2 || value.AMR[0] != "passkey" || value.AMR[1] != "uv" || value.IssuedAt < value.AuthTime || value.IssuedAt-value.AuthTime > SponsorTTLSeconds || value.ExpiresAt-value.IssuedAt != SponsorTTLSeconds {
		return ErrSponsorInvalid
	}
	return nil
}

type sponsorContextKey struct{}

func ContextWithSponsorAssertion(ctx context.Context, assertion SignedSponsorAssertion) context.Context {
	return context.WithValue(ctx, sponsorContextKey{}, assertion)
}

func SponsorAssertionFromContext(ctx context.Context) (SignedSponsorAssertion, bool) {
	assertion, ok := ctx.Value(sponsorContextKey{}).(SignedSponsorAssertion)
	return assertion, ok
}

type submitBody struct {
	ExpectedVersion int64 `json:"expected_version"`
}

func ParseSponsorSubmit(request *http.Request, maxBytes int64) (SponsorAssertionV1, []byte, error) {
	requestID, surface, ok := sponsorSubmitSurface(request.URL.EscapedPath())
	if request.Method != http.MethodPost || !ok || maxBytes <= 0 {
		return SponsorAssertionV1{}, nil, ErrSponsorInvalid
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxBytes+1))
	if err != nil || int64(len(body)) > maxBytes {
		return SponsorAssertionV1{}, nil, ErrSponsorInvalid
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil {
		return SponsorAssertionV1{}, nil, ErrSponsorInvalid
	}
	var expectedVersion int64
	switch surface {
	case sponsorSubmitJSON:
		if mediaType != "application/json" || !uniqueTopLevelJSONFields(body) {
			return SponsorAssertionV1{}, nil, ErrSponsorInvalid
		}
		var payload submitBody
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&payload); err != nil || requireJSONEOF(decoder) != nil || payload.ExpectedVersion <= 0 {
			return SponsorAssertionV1{}, nil, ErrSponsorInvalid
		}
		expectedVersion = payload.ExpectedVersion
	case sponsorSubmitForm:
		if mediaType != "application/x-www-form-urlencoded" {
			return SponsorAssertionV1{}, nil, ErrSponsorInvalid
		}
		form, err := url.ParseQuery(string(body))
		if err != nil || len(form) != 2 || len(form["expected_version"]) != 1 || len(form["csrf_token"]) != 1 {
			return SponsorAssertionV1{}, nil, ErrSponsorInvalid
		}
		expectedVersion, err = parsePositiveDecimal(form["expected_version"][0])
		if err != nil {
			return SponsorAssertionV1{}, nil, ErrSponsorInvalid
		}
	default:
		return SponsorAssertionV1{}, nil, ErrSponsorInvalid
	}
	digest := sha256.Sum256(body)
	return SponsorAssertionV1{RequestID: requestID, RequestVersion: expectedVersion, Method: http.MethodPost, NormalizedPath: request.URL.EscapedPath(), BodySHA256: hex.EncodeToString(digest[:])}, body, nil
}

type sponsorSubmitKind int

const (
	sponsorSubmitUnknown sponsorSubmitKind = iota
	sponsorSubmitJSON
	sponsorSubmitForm
)

var (
	jsonSubmitPathPattern = regexp.MustCompile(`^/api/v1/application-requests/([A-Za-z0-9_-]{16,128})/submit$`)
	formSubmitPathPattern = regexp.MustCompile(`^/applications/([A-Za-z0-9_-]{16,128})/submit$`)
)

func sponsorSubmitSurface(path string) (string, sponsorSubmitKind, bool) {
	if match := jsonSubmitPathPattern.FindStringSubmatch(path); len(match) == 2 {
		return match[1], sponsorSubmitJSON, true
	}
	if match := formSubmitPathPattern.FindStringSubmatch(path); len(match) == 2 {
		return match[1], sponsorSubmitForm, true
	}
	return "", sponsorSubmitUnknown, false
}

func sponsorSubmitPathMatches(path, requestID string) bool {
	matchedID, _, ok := sponsorSubmitSurface(path)
	return ok && matchedID == requestID
}

func parsePositiveDecimal(value string) (int64, error) {
	if value == "" || value[0] < '1' || value[0] > '9' {
		return 0, ErrSponsorInvalid
	}
	for _, digit := range value[1:] {
		if digit < '0' || digit > '9' {
			return 0, ErrSponsorInvalid
		}
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 || strconv.FormatInt(parsed, 10) != value {
		return 0, ErrSponsorInvalid
	}
	return parsed, nil
}

func IsSponsorSubmitPath(path string) bool {
	_, _, ok := sponsorSubmitSurface(path)
	return ok
}
