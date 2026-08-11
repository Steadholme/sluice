package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

const mfaGoldenKey = "mfa-assertion-test-key-0123456789abcdef"

func TestMFAAssertionA1GoldenVector(t *testing.T) {
	value := MFAAssertion{
		Subject:        "alice",
		AAL:            MFAAALStrong,
		UV:             true,
		AuthTime:       1_754_400_000,
		SessionBinding: "1e0007c3bba79f5c4f0c6f61e4081ed08ed2e1698268a86eaf96ebe903dd4b7f",
		FactorEpoch:    7,
		Route:          "access-requests",
		Audience:       "access-governance",
		Timestamp:      1_754_400_123,
	}

	const wantEvidence = "fa1456e33d0f2bee5774d28467aafc0e0cd426031cc0782a6f66e7aa10aa5a1e"
	evidence, err := MFAEvidenceDigest(value)
	if err != nil {
		t.Fatalf("MFAEvidenceDigest() error = %v", err)
	}
	if evidence != wantEvidence {
		t.Fatalf("evidence = %q, want A4 E3 %q", evidence, wantEvidence)
	}
	value.Evidence = evidence

	const wantCanonical = "holdfast.mfa-assertion.v1\n" +
		"alice\n" +
		"MFA_STRONG\n" +
		"1\n" +
		"1754400000\n" +
		"1e0007c3bba79f5c4f0c6f61e4081ed08ed2e1698268a86eaf96ebe903dd4b7f\n" +
		"7\n" +
		"access-requests\n" +
		"access-governance\n" +
		"fa1456e33d0f2bee5774d28467aafc0e0cd426031cc0782a6f66e7aa10aa5a1e\n" +
		"1754400123"
	canonical, err := CanonicalMFAAssertion(value)
	if err != nil {
		t.Fatalf("CanonicalMFAAssertion() error = %v", err)
	}
	if canonical != wantCanonical {
		t.Fatalf("canonical bytes differ:\n got %q\nwant %q", canonical, wantCanonical)
	}

	const wantSignature = "7dd077f8e7778694a634ff0f7eb8e07c2747def5d412f65c41d43f827af2d57c"
	if independentlyComputed := testHMAC(mfaGoldenKey, wantCanonical); independentlyComputed != wantSignature {
		t.Fatalf("independent A4 A1 recomputation = %q, want %q", independentlyComputed, wantSignature)
	}
	signature, err := SignMFAAssertion(mfaGoldenKey, value)
	if err != nil {
		t.Fatalf("SignMFAAssertion() error = %v", err)
	}
	if signature != wantSignature {
		t.Fatalf("signature = %q, want A4 A1 %q", signature, wantSignature)
	}
	if err := VerifyMFAAssertion(
		mfaGoldenKey,
		"",
		value,
		signature,
		"alice",
		"access-requests",
		"access-governance",
		value.AuthTime+MFAAssertionFreshnessSeconds,
	); err != nil {
		t.Fatalf("VerifyMFAAssertion() at 300-second boundary error = %v", err)
	}
}

func TestMFAAssertionA2GoldenVector(t *testing.T) {
	value := MFAAssertion{
		Subject:   "alice",
		AAL:       MFAAALNone,
		Route:     "access-requests",
		Audience:  "access-governance",
		Timestamp: 1_754_400_123,
	}

	const wantEvidence = "5ba80549e077c060be37c75303cae3e3062750332ccde7dc4936bf61d37c01f9"
	evidence, err := MFAEvidenceDigest(value)
	if err != nil {
		t.Fatalf("MFAEvidenceDigest() error = %v", err)
	}
	if evidence != wantEvidence {
		t.Fatalf("evidence = %q, want A4 E4 %q", evidence, wantEvidence)
	}
	value.Evidence = evidence

	// The empty line between auth_time and factor_epoch is the exact empty
	// session-binding segment required by the AAL_NONE wire contract.
	const wantCanonical = "holdfast.mfa-assertion.v1\n" +
		"alice\n" +
		"AAL_NONE\n" +
		"0\n" +
		"0\n" +
		"\n" +
		"0\n" +
		"access-requests\n" +
		"access-governance\n" +
		"5ba80549e077c060be37c75303cae3e3062750332ccde7dc4936bf61d37c01f9\n" +
		"1754400123"
	canonical, err := CanonicalMFAAssertion(value)
	if err != nil {
		t.Fatalf("CanonicalMFAAssertion() error = %v", err)
	}
	if canonical != wantCanonical {
		t.Fatalf("canonical bytes differ:\n got %q\nwant %q", canonical, wantCanonical)
	}

	const wantSignature = "8e241551a5a2dc403544719d17ae63eb58ebde04edc9ca63f9efd1731a0df49d"
	if independentlyComputed := testHMAC(mfaGoldenKey, wantCanonical); independentlyComputed != wantSignature {
		t.Fatalf("independent A4 A2 recomputation = %q, want %q", independentlyComputed, wantSignature)
	}
	signature, err := SignMFAAssertion(mfaGoldenKey, value)
	if err != nil {
		t.Fatalf("SignMFAAssertion() error = %v", err)
	}
	if signature != wantSignature {
		t.Fatalf("signature = %q, want A4 A2 %q", signature, wantSignature)
	}
	if err := VerifyMFAAssertion(
		mfaGoldenKey,
		"",
		value,
		signature,
		"alice",
		"access-requests",
		"access-governance",
		value.Timestamp+86_400,
	); err != nil {
		t.Fatalf("AAL_NONE must not use strong-auth freshness: %v", err)
	}
}

func TestMFAAssertionRejectsTampering(t *testing.T) {
	value := testStrongMFAAssertion(t)
	signature, err := SignMFAAssertion(mfaGoldenKey, value)
	if err != nil {
		t.Fatalf("SignMFAAssertion() error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*MFAAssertion)
	}{
		{name: "subject", mutate: func(v *MFAAssertion) { v.Subject = "mallory" }},
		{name: "aal", mutate: func(v *MFAAssertion) { v.AAL = MFAAALNone }},
		{name: "uv", mutate: func(v *MFAAssertion) { v.UV = false }},
		{name: "auth time", mutate: func(v *MFAAssertion) { v.AuthTime++ }},
		{name: "session binding", mutate: func(v *MFAAssertion) { v.SessionBinding = strings.Repeat("b", 64) }},
		{name: "factor epoch", mutate: func(v *MFAAssertion) { v.FactorEpoch++ }},
		{name: "route", mutate: func(v *MFAAssertion) { v.Route = "admin" }},
		{name: "audience", mutate: func(v *MFAAssertion) { v.Audience = "other-service" }},
		{name: "evidence", mutate: func(v *MFAAssertion) { v.Evidence = strings.Repeat("0", 64) }},
		{name: "timestamp", mutate: func(v *MFAAssertion) { v.Timestamp++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tampered := value
			test.mutate(&tampered)
			err := VerifyMFAAssertion(
				mfaGoldenKey,
				"",
				tampered,
				signature,
				"alice",
				"access-requests",
				"access-governance",
				value.AuthTime+100,
			)
			if !errors.Is(err, ErrMFAAssertionSignature) {
				t.Fatalf("tampered assertion error = %v, want signature failure", err)
			}
		})
	}

	upperSignature := strings.ToUpper(signature)
	if err := VerifyMFAAssertion(
		mfaGoldenKey, "", value, upperSignature,
		"alice", "access-requests", "access-governance", value.AuthTime+100,
	); !errors.Is(err, ErrMFAAssertionSignature) {
		t.Fatalf("uppercase signature error = %v, want signature failure", err)
	}
}

func TestMFAAssertionRejectsNewlines(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*MFAAssertion)
	}{
		{name: "subject CR", mutate: func(v *MFAAssertion) { v.Subject += "\rforged" }},
		{name: "aal LF", mutate: func(v *MFAAssertion) { v.AAL += "\nforged" }},
		{name: "session binding LF", mutate: func(v *MFAAssertion) { v.SessionBinding += "\n" }},
		{name: "route CR", mutate: func(v *MFAAssertion) { v.Route += "\rforged" }},
		{name: "audience LF", mutate: func(v *MFAAssertion) { v.Audience += "\nforged" }},
		{name: "evidence CR", mutate: func(v *MFAAssertion) { v.Evidence += "\r" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := testStrongMFAAssertion(t)
			test.mutate(&value)
			if _, err := SignMFAAssertion(mfaGoldenKey, value); !errors.Is(err, ErrMFAAssertion) {
				t.Fatalf("SignMFAAssertion() error = %v, want invalid assertion", err)
			}
		})
	}
}

func TestMFAAssertionBindsExpectedAudienceRouteAndSubject(t *testing.T) {
	value := testStrongMFAAssertion(t)
	signature, err := SignMFAAssertion(mfaGoldenKey, value)
	if err != nil {
		t.Fatalf("SignMFAAssertion() error = %v", err)
	}

	checks := []struct {
		name, subject, route, audience string
	}{
		{name: "subject", subject: "mallory", route: value.Route, audience: value.Audience},
		{name: "route", subject: value.Subject, route: "other-route", audience: value.Audience},
		{name: "audience", subject: value.Subject, route: value.Route, audience: "other-service"},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			err := VerifyMFAAssertion(
				mfaGoldenKey, "", value, signature,
				check.subject, check.route, check.audience, value.AuthTime+100,
			)
			if !errors.Is(err, ErrMFAAssertionBinding) {
				t.Fatalf("VerifyMFAAssertion() error = %v, want binding mismatch", err)
			}
		})
	}
}

func TestMFAAssertionFreshnessBoundary(t *testing.T) {
	value := testStrongMFAAssertion(t)
	signature, err := SignMFAAssertion(mfaGoldenKey, value)
	if err != nil {
		t.Fatalf("SignMFAAssertion() error = %v", err)
	}
	verifyAt := func(now int64) error {
		return VerifyMFAAssertion(
			mfaGoldenKey, "", value, signature,
			value.Subject, value.Route, value.Audience, now,
		)
	}
	if err := verifyAt(value.AuthTime + 300); err != nil {
		t.Fatalf("300-second boundary rejected: %v", err)
	}
	if err := verifyAt(value.AuthTime + 301); !errors.Is(err, ErrMFAAssertionFreshness) {
		t.Fatalf("301-second assertion error = %v, want freshness failure", err)
	}
	if err := verifyAt(value.AuthTime - 1); !errors.Is(err, ErrMFAAssertionFreshness) {
		t.Fatalf("future auth_time error = %v, want freshness failure", err)
	}

	staleAtMint := value
	staleAtMint.Timestamp = value.AuthTime + 301
	if _, err := SignMFAAssertion(mfaGoldenKey, staleAtMint); !errors.Is(err, ErrMFAAssertionFreshness) {
		t.Fatalf("stale mint error = %v, want freshness failure", err)
	}
	futureAtMint := value
	futureAtMint.Timestamp = value.AuthTime - 1
	if _, err := SignMFAAssertion(mfaGoldenKey, futureAtMint); !errors.Is(err, ErrMFAAssertionFreshness) {
		t.Fatalf("future mint error = %v, want freshness failure", err)
	}
}

func TestMFAAssertionPreviousKeyRotation(t *testing.T) {
	const (
		currentKey  = "current-mfa-assertion-key-0123456789"
		previousKey = "previous-mfa-assertion-key-01234567"
	)
	value := testStrongMFAAssertion(t)
	signature, err := SignMFAAssertion(previousKey, value)
	if err != nil {
		t.Fatalf("SignMFAAssertion(previous) error = %v", err)
	}
	if err := VerifyMFAAssertion(
		currentKey, previousKey, value, signature,
		value.Subject, value.Route, value.Audience, value.AuthTime+100,
	); err != nil {
		t.Fatalf("previous rotation key was rejected: %v", err)
	}
	if err := VerifyMFAAssertion(
		currentKey, "", value, signature,
		value.Subject, value.Route, value.Audience, value.AuthTime+100,
	); !errors.Is(err, ErrMFAAssertionSignature) {
		t.Fatalf("signature without previous key error = %v, want signature failure", err)
	}

	currentSignature, err := SignMFAAssertion(currentKey, value)
	if err != nil {
		t.Fatalf("SignMFAAssertion(current) error = %v", err)
	}
	if err := VerifyMFAAssertion(
		currentKey, "too-short", value, currentSignature,
		value.Subject, value.Route, value.Audience, value.AuthTime+100,
	); !errors.Is(err, ErrMFAAssertionKey) {
		t.Fatalf("invalid previous key error = %v, want key failure", err)
	}
}

func TestMFAAssertionRejectsNonCanonicalAALCombinations(t *testing.T) {
	none := testNoneMFAAssertion(t)
	noneTests := []struct {
		name   string
		mutate func(*MFAAssertion)
	}{
		{name: "uv", mutate: func(v *MFAAssertion) { v.UV = true }},
		{name: "auth time", mutate: func(v *MFAAssertion) { v.AuthTime = 1 }},
		{name: "session binding", mutate: func(v *MFAAssertion) { v.SessionBinding = strings.Repeat("a", 64) }},
		{name: "factor epoch", mutate: func(v *MFAAssertion) { v.FactorEpoch = 1 }},
	}
	for _, test := range noneTests {
		t.Run("AAL_NONE/"+test.name, func(t *testing.T) {
			value := none
			test.mutate(&value)
			if _, err := SignMFAAssertion(mfaGoldenKey, value); !errors.Is(err, ErrMFAAssertion) {
				t.Fatalf("SignMFAAssertion() error = %v, want invalid assertion", err)
			}
		})
	}

	strong := testStrongMFAAssertion(t)
	strongTests := []struct {
		name   string
		mutate func(*MFAAssertion)
	}{
		{name: "uv", mutate: func(v *MFAAssertion) { v.UV = false }},
		{name: "zero auth time", mutate: func(v *MFAAssertion) { v.AuthTime = 0 }},
		{name: "empty session binding", mutate: func(v *MFAAssertion) { v.SessionBinding = "" }},
		{name: "short session binding", mutate: func(v *MFAAssertion) { v.SessionBinding = strings.Repeat("a", 63) }},
		{name: "uppercase session binding", mutate: func(v *MFAAssertion) { v.SessionBinding = strings.Repeat("A", 64) }},
		{name: "negative factor epoch", mutate: func(v *MFAAssertion) { v.FactorEpoch = -1 }},
		{name: "unknown aal", mutate: func(v *MFAAssertion) { v.AAL = "AAL2" }},
	}
	for _, test := range strongTests {
		t.Run("MFA_STRONG/"+test.name, func(t *testing.T) {
			value := strong
			test.mutate(&value)
			if _, err := SignMFAAssertion(mfaGoldenKey, value); !errors.Is(err, ErrMFAAssertion) {
				t.Fatalf("SignMFAAssertion() error = %v, want invalid assertion", err)
			}
		})
	}
}

func TestMFAAssertionRejectsBadEvidenceAndRequiredFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*MFAAssertion)
	}{
		{name: "empty subject", mutate: func(v *MFAAssertion) { v.Subject = "" }},
		{name: "empty route", mutate: func(v *MFAAssertion) { v.Route = "" }},
		{name: "empty audience", mutate: func(v *MFAAssertion) { v.Audience = "" }},
		{name: "short evidence", mutate: func(v *MFAAssertion) { v.Evidence = strings.Repeat("a", 63) }},
		{name: "uppercase evidence", mutate: func(v *MFAAssertion) { v.Evidence = strings.Repeat("A", 64) }},
		{name: "mismatched evidence", mutate: func(v *MFAAssertion) { v.Evidence = strings.Repeat("0", 64) }},
		{name: "negative timestamp", mutate: func(v *MFAAssertion) { v.Timestamp = -1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := testStrongMFAAssertion(t)
			test.mutate(&value)
			if _, err := SignMFAAssertion(mfaGoldenKey, value); !errors.Is(err, ErrMFAAssertion) {
				t.Fatalf("SignMFAAssertion() error = %v, want invalid assertion", err)
			}
		})
	}
}

func TestValidateMFAAssertionKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
		ok   bool
	}{
		{name: "minimum", key: strings.Repeat("k", 32), ok: true},
		{name: "golden", key: mfaGoldenKey, ok: true},
		{name: "too short", key: strings.Repeat("k", 31)},
		{name: "space is not visible", key: strings.Repeat("k", 31) + " "},
		{name: "newline", key: strings.Repeat("k", 31) + "\n"},
		{name: "non ASCII", key: strings.Repeat("k", 31) + "é"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateMFAAssertionKey(test.key)
			if test.ok && err != nil {
				t.Fatalf("ValidateMFAAssertionKey() error = %v", err)
			}
			if !test.ok && !errors.Is(err, ErrMFAAssertionKey) {
				t.Fatalf("ValidateMFAAssertionKey() error = %v, want key failure", err)
			}
		})
	}
}

func testStrongMFAAssertion(t *testing.T) MFAAssertion {
	t.Helper()
	value := MFAAssertion{
		Subject:        "alice",
		AAL:            MFAAALStrong,
		UV:             true,
		AuthTime:       1_754_400_000,
		SessionBinding: "1e0007c3bba79f5c4f0c6f61e4081ed08ed2e1698268a86eaf96ebe903dd4b7f",
		FactorEpoch:    7,
		Route:          "access-requests",
		Audience:       "access-governance",
		Timestamp:      1_754_400_123,
	}
	evidence, err := MFAEvidenceDigest(value)
	if err != nil {
		t.Fatalf("MFAEvidenceDigest() error = %v", err)
	}
	value.Evidence = evidence
	return value
}

func testNoneMFAAssertion(t *testing.T) MFAAssertion {
	t.Helper()
	value := MFAAssertion{
		Subject:   "alice",
		AAL:       MFAAALNone,
		Route:     "access-requests",
		Audience:  "access-governance",
		Timestamp: 1_754_400_123,
	}
	evidence, err := MFAEvidenceDigest(value)
	if err != nil {
		t.Fatalf("MFAEvidenceDigest() error = %v", err)
	}
	value.Evidence = evidence
	return value
}

func testHMAC(key, canonical string) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}
