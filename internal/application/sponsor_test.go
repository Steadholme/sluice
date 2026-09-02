package application

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

type sponsorFixtureCase struct {
	ContentType string          `json:"content_type"`
	Body        string          `json:"body"`
	Claims      json.RawMessage `json:"claims"`
}

type sponsorInteropFixture struct {
	HeaderNames []string           `json:"header_names"`
	JSONSubmit  sponsorFixtureCase `json:"json_submit"`
	HTMLSubmit  sponsorFixtureCase `json:"html_submit"`
}

func TestAccessSponsorAssertionSharedKnownVector(t *testing.T) {
	fixtureBytes, err := os.ReadFile("testdata/sponsor_assertion_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(fixtureBytes)
	if got := hex.EncodeToString(digest[:]); got != "c92ee510a4be88e511f62c72256e3ad5cd647df7d4c3ec5c74d9d39c08d010bd" {
		t.Fatalf("fixture digest=%s", got)
	}
	var fixture sponsorInteropFixture
	if err := json.Unmarshal(fixtureBytes, &fixture); err != nil {
		t.Fatal(err)
	}
	wantHeaders := []string{HeaderSponsorAssertion, HeaderSponsorKID, HeaderSponsorSig}
	sort.Strings(fixture.HeaderNames)
	if !reflect.DeepEqual(fixture.HeaderNames, wantHeaders) {
		t.Fatalf("fixture headers=%q want=%q", fixture.HeaderNames, wantHeaders)
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	for _, tc := range []struct {
		name string
		sponsorFixtureCase
	}{
		{name: "json-api", sponsorFixtureCase: fixture.JSONSubmit},
		{name: "html-form", sponsorFixtureCase: fixture.HTMLSubmit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var claims SponsorAssertionV1
			if err := json.Unmarshal(tc.Claims, &claims); err != nil {
				t.Fatal(err)
			}
			canonical, err := json.Marshal(claims)
			if err != nil {
				t.Fatal(err)
			}
			var fixtureCanonical bytes.Buffer
			if err := json.Compact(&fixtureCanonical, tc.Claims); err != nil || !bytes.Equal(fixtureCanonical.Bytes(), canonical) {
				t.Fatalf("canonical=%s fixture=%s err=%v", canonical, fixtureCanonical.Bytes(), err)
			}
			request := httptest.NewRequest(http.MethodPost, "https://analyze.w33d.xyz"+claims.NormalizedPath, strings.NewReader(tc.Body))
			request.Header.Set("Content-Type", tc.ContentType)
			parsed, rawBody, err := ParseSponsorSubmit(request, 64<<10)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.RequestID != claims.RequestID || parsed.RequestVersion != claims.RequestVersion || parsed.Method != claims.Method || parsed.NormalizedPath != claims.NormalizedPath || parsed.BodySHA256 != claims.BodySHA256 || string(rawBody) != tc.Body {
				t.Fatalf("parsed=%+v claims=%+v raw=%q", parsed, claims, rawBody)
			}
			signed := SignedSponsorAssertion{Assertion: claims, Canonical: canonical, Signature: ed25519.Sign(private, canonical)}
			headers := signed.Headers()
			if got := sortedHeaderNames(headers); !reflect.DeepEqual(got, wantHeaders) {
				t.Fatalf("headers=%q want=%q", got, wantHeaders)
			}
			verified, err := VerifySponsorHeaders(headers, map[string]ed25519.PublicKey{claims.KID: private.Public().(ed25519.PublicKey)}, time.Unix(claims.IssuedAt, 0))
			if err != nil || !reflect.DeepEqual(verified, claims) {
				t.Fatalf("verified=%+v err=%v", verified, err)
			}
		})
	}
}

func TestSponsorSubmitSurfacesPreserveRawBodyAndBindPath(t *testing.T) {
	for _, tc := range []struct {
		name        string
		path        string
		contentType string
		body        string
		version     int64
	}{
		{name: "json-api", path: "/api/v1/application-requests/abcdefghijklmnop/submit", contentType: "application/json", body: `{"expected_version":3}`, version: 3},
		{name: "html-form", path: "/applications/abcdefghijklmnop/submit", contentType: "application/x-www-form-urlencoded", body: "csrf_token=csrf-value&expected_version=4", version: 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "https://analyze.w33d.xyz"+tc.path, strings.NewReader(tc.body))
			request.Header.Set("Content-Type", tc.contentType)
			value, rawBody, err := ParseSponsorSubmit(request, 64<<10)
			if err != nil {
				t.Fatal(err)
			}
			preserved, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256([]byte(tc.body))
			if value.RequestID != "abcdefghijklmnop" || value.RequestVersion != tc.version || value.NormalizedPath != tc.path || value.BodySHA256 != hex.EncodeToString(digest[:]) || string(rawBody) != tc.body || string(preserved) != tc.body {
				t.Fatalf("value=%+v raw=%q preserved=%q", value, rawBody, preserved)
			}
		})
	}
}

func TestSponsorSubmitRejectsWrongSurfaceOrAmbiguousExpectedVersion(t *testing.T) {
	for _, tc := range []struct {
		name        string
		path        string
		contentType string
		body        string
	}{
		{name: "json-on-form", path: "/applications/abcdefghijklmnop/submit", contentType: "application/json", body: `{"expected_version":3}`},
		{name: "form-on-json", path: "/api/v1/application-requests/abcdefghijklmnop/submit", contentType: "application/x-www-form-urlencoded", body: "expected_version=3"},
		{name: "duplicate-form-version", path: "/applications/abcdefghijklmnop/submit", contentType: "application/x-www-form-urlencoded", body: "csrf_token=csrf&expected_version=3&expected_version=4"},
		{name: "noncanonical-form-version", path: "/applications/abcdefghijklmnop/submit", contentType: "application/x-www-form-urlencoded", body: "csrf_token=csrf&expected_version=03"},
		{name: "missing-form-csrf", path: "/applications/abcdefghijklmnop/submit", contentType: "application/x-www-form-urlencoded", body: "expected_version=3"},
		{name: "unknown-form-field", path: "/applications/abcdefghijklmnop/submit", contentType: "application/x-www-form-urlencoded", body: "csrf_token=csrf&expected_version=3&extra=value"},
		{name: "duplicate-json-version", path: "/api/v1/application-requests/abcdefghijklmnop/submit", contentType: "application/json", body: `{"expected_version":3,"expected_version":4}`},
		{name: "zero-json-version", path: "/api/v1/application-requests/abcdefghijklmnop/submit", contentType: "application/json", body: `{"expected_version":0}`},
		{name: "unknown-json-field", path: "/api/v1/application-requests/abcdefghijklmnop/submit", contentType: "application/json", body: `{"expected_version":3,"extra":true}`},
		{name: "non-submit", path: "/applications/abcdefghijklmnop/cancel", contentType: "application/x-www-form-urlencoded", body: "csrf_token=csrf&expected_version=3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "https://analyze.w33d.xyz"+tc.path, strings.NewReader(tc.body))
			request.Header.Set("Content-Type", tc.contentType)
			if _, _, err := ParseSponsorSubmit(request, 64<<10); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestSponsorHeadersUseExactTripletAndRejectLegacyMiddleHeader(t *testing.T) {
	fixedNow := time.Unix(1_900_000_000, 0)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, ed25519.SeedSize))
	signer, err := NewSponsorSigner(SigningKeyring{ActiveKID: "appctx-2026a", PrivateKeys: map[string]ed25519.PrivateKey{"appctx-2026a": private}}, func() time.Time { return fixedNow }, bytes.NewReader(bytes.Repeat([]byte{2}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Mint(SponsorAssertionV1{
		Subject: "usr_abcdefghijklmnop", RequestID: "abcdefghijklmnop", RequestVersion: 3,
		Method: http.MethodPost, NormalizedPath: "/applications/abcdefghijklmnop/submit",
		BodySHA256: strings.Repeat("b", 64), SessionBinding: strings.Repeat("a", 64), AuthTime: fixedNow.Unix() - 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	headers := signed.Headers()
	if got, want := sortedHeaderNames(headers), []string{HeaderSponsorAssertion, HeaderSponsorKID, HeaderSponsorSig}; !reflect.DeepEqual(got, want) {
		t.Fatalf("headers=%q want=%q", got, want)
	}
	if headers.Get("X-Sponsor-Assertion") != "" {
		t.Fatal("legacy middle header was emitted")
	}
	if _, err := VerifySponsorHeaders(headers, map[string]ed25519.PublicKey{"appctx-2026a": private.Public().(ed25519.PublicKey)}, fixedNow); err != nil {
		t.Fatal(err)
	}
	legacy := headers.Clone()
	legacy.Set("X-Sponsor-Assertion", legacy.Get(HeaderSponsorAssertion))
	legacy.Del(HeaderSponsorAssertion)
	if _, err := VerifySponsorHeaders(legacy, map[string]ed25519.PublicKey{"appctx-2026a": private.Public().(ed25519.PublicKey)}, fixedNow); err == nil {
		t.Fatal("legacy middle header was accepted")
	}
}

func sortedHeaderNames(headers http.Header) []string {
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
