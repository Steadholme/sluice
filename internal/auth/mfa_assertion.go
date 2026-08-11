package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	// MFAAssertionDomain separates this signature from every other Sluice HMAC
	// family. In particular, it must never share the X-Auth-Sig canonical form.
	MFAAssertionDomain = "holdfast.mfa-assertion.v1"
	MFAEvidenceDomain  = "holdfast.mfa-assertion.evidence.v1"

	MFAAALNone   = "AAL_NONE"
	MFAAALStrong = "MFA_STRONG"

	// MFAAssertionFreshnessSeconds is the single strong-assurance freshness
	// window. A delta of exactly 300 seconds is valid; 301 is not.
	MFAAssertionFreshnessSeconds int64 = 300
)

// Trusted MFA assertion headers. Sluice's proxy strips all client-supplied
// X-Auth-* headers before injecting this family.
const (
	HeaderAuthMFASubject        = "X-Auth-Mfa-Subject"
	HeaderAuthMFAAAL            = "X-Auth-Mfa-Aal"
	HeaderAuthMFAUV             = "X-Auth-Mfa-Uv"
	HeaderAuthMFAAuthTime       = "X-Auth-Mfa-Auth-Time"
	HeaderAuthMFASessionBinding = "X-Auth-Mfa-Session-Binding"
	HeaderAuthMFAFactorEpoch    = "X-Auth-Mfa-Factor-Epoch"
	HeaderAuthMFARoute          = "X-Auth-Mfa-Route"
	HeaderAuthMFAAudience       = "X-Auth-Mfa-Audience"
	HeaderAuthMFAEvidence       = "X-Auth-Mfa-Evidence"
	HeaderAuthMFATimestamp      = "X-Auth-Mfa-Timestamp"
	HeaderAuthMFASig            = "X-Auth-Mfa-Sig"
)

var (
	ErrMFAAssertionKey       = errors.New("auth: invalid MFA assertion key")
	ErrMFAAssertion          = errors.New("auth: invalid MFA assertion")
	ErrMFAAssertionSignature = errors.New("auth: invalid MFA assertion signature")
	ErrMFAAssertionBinding   = errors.New("auth: MFA assertion binding mismatch")
	ErrMFAAssertionFreshness = errors.New("auth: MFA assertion is not fresh")
)

// MFAAssertion is the typed representation of the frozen X-Auth-Mfa-* wire
// contract. UV is serialized as exactly "0" or "1"; integer fields use base-10
// without padding.
type MFAAssertion struct {
	Subject        string
	AAL            string
	UV             bool
	AuthTime       int64
	SessionBinding string
	FactorEpoch    int64
	Route          string
	Audience       string
	Evidence       string
	Timestamp      int64
}

// ValidateMFAAssertionKey enforces the independent assertion-key contract.
// The key must contain at least 32 bytes and every byte must be visible ASCII.
// This helper deliberately has no relationship to GATEWAY_HMAC_KEY or any
// existing X-Auth-Sig key.
func ValidateMFAAssertionKey(key string) error {
	if len(key) < 32 {
		return fmt.Errorf("%w: must contain at least 32 bytes", ErrMFAAssertionKey)
	}
	for i := 0; i < len(key); i++ {
		if key[i] < 0x21 || key[i] > 0x7e {
			return fmt.Errorf("%w: must contain only visible ASCII bytes", ErrMFAAssertionKey)
		}
	}
	return nil
}

// MFAEvidenceDigest returns the lowercase-hex SHA-256 digest over the frozen
// assurance-only preimage:
//
//	domain "\n" subject "\n" aal "\n" uv "\n" auth_time "\n"
//	session_binding "\n" factor_epoch
//
// Route, audience, evidence, and timestamp are intentionally excluded.
func MFAEvidenceDigest(value MFAAssertion) (string, error) {
	if err := validateMFAEvidenceFields(value); err != nil {
		return "", err
	}
	preimage := strings.Join([]string{
		MFAEvidenceDomain,
		value.Subject,
		value.AAL,
		mfaUVString(value.UV),
		strconv.FormatInt(value.AuthTime, 10),
		value.SessionBinding,
		strconv.FormatInt(value.FactorEpoch, 10),
	}, "\n")
	digest := sha256.Sum256([]byte(preimage))
	return hex.EncodeToString(digest[:]), nil
}

// CanonicalMFAAssertion returns the frozen newline-delimited assertion
// preimage with no trailing newline. It rejects invalid wire combinations and
// requires Evidence to equal MFAEvidenceDigest(value).
func CanonicalMFAAssertion(value MFAAssertion) (string, error) {
	if err := validateMFAAssertion(value); err != nil {
		return "", err
	}
	return canonicalMFAAssertion(value)
}

// SignMFAAssertion returns a lowercase-hex HMAC-SHA256 over the canonical
// assertion. Timestamp is the minting clock for this check: a STRONG assertion
// whose AuthTime is future-dated or already more than 300 seconds old is not
// signed. The caller must pass the dedicated MFA assertion key.
func SignMFAAssertion(key string, value MFAAssertion) (string, error) {
	if err := ValidateMFAAssertionKey(key); err != nil {
		return "", err
	}
	canonical, err := CanonicalMFAAssertion(value)
	if err != nil {
		return "", err
	}
	if err := validateMFAFreshness(value, value.Timestamp); err != nil {
		return "", err
	}
	return signMFAAssertionCanonical(key, canonical), nil
}

// VerifyMFAAssertion authenticates an assertion with the current key and an
// optional previous rotation key, then enforces its trusted subject, route, and
// audience bindings and the 300-second STRONG freshness window. Both configured
// keys are evaluated before the result is selected.
func VerifyMFAAssertion(
	currentKey string,
	previousKey string,
	value MFAAssertion,
	signature string,
	expectedSubject string,
	expectedRoute string,
	expectedAudience string,
	now int64,
) error {
	if err := ValidateMFAAssertionKey(currentKey); err != nil {
		return err
	}
	if previousKey != "" {
		if err := ValidateMFAAssertionKey(previousKey); err != nil {
			return err
		}
	}
	if !isLowerHex64(signature) {
		return ErrMFAAssertionSignature
	}

	// Reject line injection before constructing the signed bytes, but defer all
	// trusted semantic use until after the constant-time MAC comparison.
	canonical, err := canonicalMFAAssertion(value)
	if err != nil {
		return err
	}
	currentMAC := signMFAAssertionCanonical(currentKey, canonical)
	currentOK := hmac.Equal([]byte(signature), []byte(currentMAC))
	previousOK := false
	if previousKey != "" {
		previousMAC := signMFAAssertionCanonical(previousKey, canonical)
		previousOK = hmac.Equal([]byte(signature), []byte(previousMAC))
	}
	if !currentOK && !previousOK {
		return ErrMFAAssertionSignature
	}

	if value.Subject != expectedSubject || value.Route != expectedRoute || value.Audience != expectedAudience {
		return ErrMFAAssertionBinding
	}
	if err := validateMFAAssertion(value); err != nil {
		return err
	}
	return validateMFAFreshness(value, now)
}

func canonicalMFAAssertion(value MFAAssertion) (string, error) {
	fields := []string{
		MFAAssertionDomain,
		value.Subject,
		value.AAL,
		mfaUVString(value.UV),
		strconv.FormatInt(value.AuthTime, 10),
		value.SessionBinding,
		strconv.FormatInt(value.FactorEpoch, 10),
		value.Route,
		value.Audience,
		value.Evidence,
		strconv.FormatInt(value.Timestamp, 10),
	}
	for _, field := range fields {
		if strings.ContainsAny(field, "\r\n") {
			return "", fmt.Errorf("%w: fields must not contain CR or LF", ErrMFAAssertion)
		}
	}
	return strings.Join(fields, "\n"), nil
}

func validateMFAAssertion(value MFAAssertion) error {
	if _, err := canonicalMFAAssertion(value); err != nil {
		return err
	}
	if err := validateMFAEvidenceFields(value); err != nil {
		return err
	}
	if value.Route == "" {
		return fmt.Errorf("%w: route is empty", ErrMFAAssertion)
	}
	if value.Audience == "" {
		return fmt.Errorf("%w: audience is empty", ErrMFAAssertion)
	}
	if value.Timestamp < 0 {
		return fmt.Errorf("%w: timestamp is negative", ErrMFAAssertion)
	}
	if !isLowerHex64(value.Evidence) {
		return fmt.Errorf("%w: evidence must be 64 lowercase hexadecimal characters", ErrMFAAssertion)
	}
	wantEvidence, err := MFAEvidenceDigest(value)
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(value.Evidence), []byte(wantEvidence)) {
		return fmt.Errorf("%w: evidence digest mismatch", ErrMFAAssertion)
	}
	return nil
}

func validateMFAEvidenceFields(value MFAAssertion) error {
	for _, field := range []string{value.Subject, value.AAL, value.SessionBinding} {
		if strings.ContainsAny(field, "\r\n") {
			return fmt.Errorf("%w: evidence fields must not contain CR or LF", ErrMFAAssertion)
		}
	}
	if value.Subject == "" {
		return fmt.Errorf("%w: subject is empty", ErrMFAAssertion)
	}
	switch value.AAL {
	case MFAAALNone:
		if value.UV || value.AuthTime != 0 || value.SessionBinding != "" || value.FactorEpoch != 0 {
			return fmt.Errorf("%w: AAL_NONE wire values are not canonical", ErrMFAAssertion)
		}
	case MFAAALStrong:
		if !value.UV {
			return fmt.Errorf("%w: MFA_STRONG requires uv=1", ErrMFAAssertion)
		}
		if value.AuthTime <= 0 {
			return fmt.Errorf("%w: MFA_STRONG requires a positive auth_time", ErrMFAAssertion)
		}
		if !isLowerHex64(value.SessionBinding) {
			return fmt.Errorf("%w: MFA_STRONG requires a 64-character lowercase-hex session binding", ErrMFAAssertion)
		}
		if value.FactorEpoch < 0 {
			return fmt.Errorf("%w: factor_epoch is negative", ErrMFAAssertion)
		}
	default:
		return fmt.Errorf("%w: unsupported aal", ErrMFAAssertion)
	}
	return nil
}

func validateMFAFreshness(value MFAAssertion, now int64) error {
	if value.AAL != MFAAALStrong {
		return nil
	}
	if value.AuthTime > now {
		return fmt.Errorf("%w: auth_time is in the future", ErrMFAAssertionFreshness)
	}
	if now-value.AuthTime > MFAAssertionFreshnessSeconds {
		return fmt.Errorf("%w: auth_time is older than 300 seconds", ErrMFAAssertionFreshness)
	}
	return nil
}

func signMFAAssertionCanonical(key, canonical string) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

func mfaUVString(uv bool) string {
	if uv {
		return "1"
	}
	return "0"
}

func isLowerHex64(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if (value[i] < '0' || value[i] > '9') && (value[i] < 'a' || value[i] > 'f') {
			return false
		}
	}
	return true
}
