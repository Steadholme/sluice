package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/holdfast/sluice/internal/auth"
	"github.com/holdfast/sluice/internal/config"
	"github.com/holdfast/sluice/internal/oidc"
)

const (
	trustedMFATestSubject = "u_admin"
	trustedMFATestBinding = "1e0007c3bba79f5c4f0c6f61e4081ed08ed2e1698268a86eaf96ebe903dd4b7f"
	trustedMFATestKey     = "gateway-mfa-assertion-test-key-00000001"
)

var trustedMFATestNow = time.Unix(1_754_400_200, 0)

type recordingAssuranceLookup struct {
	result   oidc.SessionAssurance
	err      error
	calls    int
	subjects []string
	bindings []string
}

type clockAdvancingAssuranceLookup struct {
	recordingAssuranceLookup
	clock *time.Time
}

func (lookup *clockAdvancingAssuranceLookup) LookupSessionAssurance(
	ctx context.Context,
	subject string,
	binding string,
) (oidc.SessionAssurance, error) {
	*lookup.clock = lookup.clock.Add(time.Second)
	lookup.result.AsOf = lookup.clock.Unix()
	return lookup.recordingAssuranceLookup.LookupSessionAssurance(ctx, subject, binding)
}

func (lookup *recordingAssuranceLookup) LookupSessionAssurance(
	_ context.Context,
	subject string,
	binding string,
) (oidc.SessionAssurance, error) {
	lookup.calls++
	lookup.subjects = append(lookup.subjects, subject)
	lookup.bindings = append(lookup.bindings, binding)
	return lookup.result, lookup.err
}

func TestTrustedMFAFeatureOffIsTransparent(t *testing.T) {
	route := trustedMFARoute(t)
	lookup := &recordingAssuranceLookup{err: errors.New("must not be called")}
	nextCalls := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalls++
		if _, _, ok := auth.MFAAssertionFromContext(r.Context()); ok {
			t.Fatal("disabled middleware unexpectedly minted an MFA assertion")
		}
		w.WriteHeader(http.StatusNoContent)
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://ai.w33d.xyz/console", nil)
	trustedMFAWrap(route, next, Options{
		TrustedMFAEnabled:   false,
		AssuranceLookup:     lookup,
		MFAAssertionHMACKey: trustedMFATestKey,
		Now:                 func() time.Time { return trustedMFATestNow },
	}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent || nextCalls != 1 {
		t.Fatalf("disabled middleware status/calls = %d/%d, want 204/1", recorder.Code, nextCalls)
	}
	if lookup.calls != 0 {
		t.Fatalf("disabled middleware lookup calls = %d, want 0", lookup.calls)
	}
}

func TestTrustedMFALegacyAndNoneSessionsMintExactNoneWithoutLookup(t *testing.T) {
	for _, aal := range []string{"", oidc.SessionAALNone} {
		name := "legacy"
		if aal != "" {
			name = "canonical-none"
		}
		t.Run(name, func(t *testing.T) {
			route := trustedMFARoute(t)
			lookup := &recordingAssuranceLookup{err: errors.New("must not be called")}
			session := oidc.Session{Sub: trustedMFATestSubject, AAL: aal}
			var got auth.MFAAssertion
			var signature string
			var present bool
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got, signature, present = auth.MFAAssertionFromContext(r.Context())
				w.WriteHeader(http.StatusNoContent)
			})

			recorder := httptest.NewRecorder()
			trustedMFAWrap(route, next, trustedMFAOptions(lookup)).ServeHTTP(
				recorder,
				trustedMFARequest(&auth.Identity{Subject: trustedMFATestSubject}, &session),
			)

			if recorder.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want 204", recorder.Code)
			}
			if lookup.calls != 0 {
				t.Fatalf("lookup calls = %d, want 0", lookup.calls)
			}
			want := trustedMFANoneAssertion(t, route)
			assertTrustedMFAAssertion(t, got, signature, present, want)
		})
	}
}

func TestTrustedMFAStrongSessionLooksUpEveryRequestAndMintsBoundStrong(t *testing.T) {
	route := trustedMFARoute(t)
	session := trustedMFAStrongSession()
	lookup := &recordingAssuranceLookup{result: trustedMFALiveAssurance()}
	assertions := make([]auth.MFAAssertion, 0, 2)
	signatures := make([]string, 0, 2)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertion, signature, ok := auth.MFAAssertionFromContext(r.Context())
		if !ok {
			t.Fatal("strong request reached next without a trusted MFA assertion")
		}
		assertions = append(assertions, assertion)
		signatures = append(signatures, signature)
		w.WriteHeader(http.StatusNoContent)
	})
	handler := trustedMFAWrap(route, next, trustedMFAOptions(lookup))

	for requestNumber := 0; requestNumber < 2; requestNumber++ {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(
			recorder,
			trustedMFARequest(&auth.Identity{Subject: trustedMFATestSubject}, &session),
		)
		if recorder.Code != http.StatusNoContent {
			t.Fatalf("request %d status = %d, want 204", requestNumber+1, recorder.Code)
		}
	}

	if lookup.calls != 2 {
		t.Fatalf("lookup calls = %d, want one per request (2)", lookup.calls)
	}
	for index := range lookup.subjects {
		if lookup.subjects[index] != trustedMFATestSubject || lookup.bindings[index] != trustedMFATestBinding {
			t.Fatalf("lookup %d tuple = %q/%q, want authoritative session tuple", index+1, lookup.subjects[index], lookup.bindings[index])
		}
	}
	want := trustedMFAStrongAssertion(t, route)
	if want.Route != "cpa-console" || want.Audience != "cpa.service.internal" {
		t.Fatalf("route/audience binding = %q/%q, want cpa-console/cpa.service.internal", want.Route, want.Audience)
	}
	for index := range assertions {
		assertTrustedMFAAssertion(t, assertions[index], signatures[index], true, want)
	}
}

func TestTrustedMFAMintClockIsSampledAfterLookup(t *testing.T) {
	route := trustedMFARoute(t)
	session := trustedMFAStrongSession()
	clock := trustedMFATestNow
	lookup := &clockAdvancingAssuranceLookup{
		recordingAssuranceLookup: recordingAssuranceLookup{result: trustedMFALiveAssurance()},
		clock:                    &clock,
	}
	opts := trustedMFAOptions(lookup)
	opts.Now = func() time.Time { return clock }
	var got auth.MFAAssertion
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _, _ = auth.MFAAssertionFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})

	recorder := httptest.NewRecorder()
	trustedMFAWrap(route, next, opts).ServeHTTP(
		recorder,
		trustedMFARequest(&auth.Identity{Subject: trustedMFATestSubject}, &session),
	)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("cross-second lookup status = %d, want 204", recorder.Code)
	}
	if got.Timestamp != trustedMFATestNow.Add(time.Second).Unix() {
		t.Fatalf("mint timestamp = %d, want post-lookup clock %d", got.Timestamp, trustedMFATestNow.Add(time.Second).Unix())
	}
}

func TestTrustedMFAAbsentBindingDegradesToExactNone(t *testing.T) {
	route := trustedMFARoute(t)
	session := trustedMFAStrongSession()
	lookup := &recordingAssuranceLookup{result: oidc.SessionAssurance{
		Live:        false,
		Subject:     trustedMFATestSubject,
		AAL:         oidc.SessionAALNone,
		FactorEpoch: session.FactorEpoch + 1,
		AsOf:        trustedMFATestNow.Unix(),
	}}
	var got auth.MFAAssertion
	var signature string
	var present bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, signature, present = auth.MFAAssertionFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})

	recorder := httptest.NewRecorder()
	trustedMFAWrap(route, next, trustedMFAOptions(lookup)).ServeHTTP(
		recorder,
		trustedMFARequest(&auth.Identity{Subject: trustedMFATestSubject}, &session),
	)

	if recorder.Code != http.StatusNoContent || lookup.calls != 1 {
		t.Fatalf("absent binding status/lookups = %d/%d, want 204/1", recorder.Code, lookup.calls)
	}
	assertTrustedMFAAssertion(t, got, signature, present, trustedMFANoneAssertion(t, route))
}

func TestTrustedMFAStaleStrongSessionDegradesToExactNone(t *testing.T) {
	route := trustedMFARoute(t)
	session := trustedMFAStrongSession()
	session.AuthTime = trustedMFATestNow.Unix() - auth.MFAAssertionFreshnessSeconds - 1
	lookup := &recordingAssuranceLookup{result: trustedMFALiveAssurance()}
	lookup.result.AuthTime = session.AuthTime
	var got auth.MFAAssertion
	var signature string
	var present bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, signature, present = auth.MFAAssertionFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})

	recorder := httptest.NewRecorder()
	trustedMFAWrap(route, next, trustedMFAOptions(lookup)).ServeHTTP(
		recorder,
		trustedMFARequest(&auth.Identity{Subject: trustedMFATestSubject}, &session),
	)

	if recorder.Code != http.StatusNoContent || lookup.calls != 1 {
		t.Fatalf("stale strong status/lookups = %d/%d, want 204/1", recorder.Code, lookup.calls)
	}
	assertTrustedMFAAssertion(t, got, signature, present, trustedMFANoneAssertion(t, route))
}

func TestTrustedMFAFailuresAreNoStoreAndDoNotReachNext(t *testing.T) {
	tests := []struct {
		name            string
		missingIdentity bool
		missingSession  bool
		missingKey      bool
		lookupErr       error
		mutateSession   func(*oidc.Session)
		mutateResult    func(*oidc.SessionAssurance)
		wantLookups     int
	}{
		{
			name:        "lookup error",
			lookupErr:   errors.New("keystone unavailable"),
			wantLookups: 1,
		},
		{
			name: "malformed lookup result",
			mutateResult: func(result *oidc.SessionAssurance) {
				result.AAL = "AAL2"
			},
			wantLookups: 1,
		},
		{
			name: "authoritative subject mismatch",
			mutateResult: func(result *oidc.SessionAssurance) {
				result.Subject = "u_other"
			},
			wantLookups: 1,
		},
		{
			name: "authoritative binding mismatch",
			mutateResult: func(result *oidc.SessionAssurance) {
				result.SessionBinding = "2e0007c3bba79f5c4f0c6f61e4081ed08ed2e1698268a86eaf96ebe903dd4b7f"
			},
			wantLookups: 1,
		},
		{
			name: "authoritative auth time mismatch",
			mutateResult: func(result *oidc.SessionAssurance) {
				result.AuthTime--
			},
			wantLookups: 1,
		},
		{
			name: "authoritative factor epoch mismatch",
			mutateResult: func(result *oidc.SessionAssurance) {
				result.FactorEpoch++
			},
			wantLookups: 1,
		},
		{
			name:        "assertion key missing",
			missingKey:  true,
			wantLookups: 0,
		},
		{
			name: "authority result 301 seconds stale",
			mutateResult: func(result *oidc.SessionAssurance) {
				result.AsOf = trustedMFATestNow.Unix() - 301
			},
			wantLookups: 1,
		},
		{
			name: "authority result from future",
			mutateResult: func(result *oidc.SessionAssurance) {
				result.AsOf = trustedMFATestNow.Unix() + 1
			},
			wantLookups: 1,
		},
		{
			name: "strong authentication from future",
			mutateSession: func(session *oidc.Session) {
				session.AuthTime = trustedMFATestNow.Unix() + 1
			},
			mutateResult: func(result *oidc.SessionAssurance) {
				result.AuthTime = trustedMFATestNow.Unix() + 1
			},
			wantLookups: 1,
		},
		{
			name:            "identity missing",
			missingIdentity: true,
			wantLookups:     0,
		},
		{
			name:           "gateway session missing",
			missingSession: true,
			wantLookups:    0,
		},
		{
			name: "identity and session subject mismatch",
			mutateSession: func(session *oidc.Session) {
				session.Sub = "u_other"
			},
			wantLookups: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			route := trustedMFARoute(t)
			session := trustedMFAStrongSession()
			result := trustedMFALiveAssurance()
			if test.mutateSession != nil {
				test.mutateSession(&session)
			}
			if test.mutateResult != nil {
				test.mutateResult(&result)
			}
			lookup := &recordingAssuranceLookup{result: result, err: test.lookupErr}
			opts := trustedMFAOptions(lookup)
			if test.missingKey {
				opts.MFAAssertionHMACKey = ""
			}
			var identity *auth.Identity
			if !test.missingIdentity {
				identity = &auth.Identity{Subject: trustedMFATestSubject}
			}
			var requestSession *oidc.Session
			if !test.missingSession {
				requestSession = &session
			}
			nextCalls := 0
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				nextCalls++
				w.WriteHeader(http.StatusNoContent)
			})

			recorder := httptest.NewRecorder()
			trustedMFAWrap(route, next, opts).ServeHTTP(
				recorder,
				trustedMFARequest(identity, requestSession),
			)

			if recorder.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503", recorder.Code)
			}
			if got := recorder.Header().Get("Cache-Control"); got != "private, no-store" {
				t.Fatalf("Cache-Control = %q, want private, no-store", got)
			}
			if got := recorder.Header().Get("Retry-After"); got != "5" {
				t.Fatalf("Retry-After = %q, want 5", got)
			}
			if nextCalls != 0 {
				t.Fatalf("next calls = %d, want 0", nextCalls)
			}
			if lookup.calls != test.wantLookups {
				t.Fatalf("lookup calls = %d, want %d", lookup.calls, test.wantLookups)
			}
		})
	}
}

func trustedMFARoute(t *testing.T) config.Route {
	t.Helper()
	store := mustRoutes(t, []config.Route{{
		Name:     "cpa-console",
		Match:    config.Match{Host: "ai.w33d.xyz", PathPrefix: "/console"},
		Upstream: "https://cpa.service.internal:8443/management",
		Auth:     config.AuthSSO,
	}})
	return store.Routes()[0]
}

func trustedMFAOptions(lookup oidc.AssuranceLookup) Options {
	return Options{
		TrustedMFAEnabled:   true,
		AssuranceLookup:     lookup,
		MFAAssertionHMACKey: trustedMFATestKey,
		Now:                 func() time.Time { return trustedMFATestNow },
	}
}

func trustedMFARequest(identity *auth.Identity, session *oidc.Session) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "https://ai.w33d.xyz/console", nil)
	ctx := request.Context()
	if identity != nil {
		ctx = auth.ContextWithIdentity(ctx, identity)
	}
	if session != nil {
		ctx = oidc.ContextWithGatewaySession(ctx, *session)
	}
	return request.WithContext(ctx)
}

func trustedMFAStrongSession() oidc.Session {
	return oidc.Session{
		Sub:            trustedMFATestSubject,
		AAL:            oidc.SessionMFAStrong,
		UV:             true,
		AuthTime:       trustedMFATestNow.Unix() - 100,
		SessionBinding: trustedMFATestBinding,
		FactorEpoch:    7,
	}
}

func trustedMFALiveAssurance() oidc.SessionAssurance {
	session := trustedMFAStrongSession()
	return oidc.SessionAssurance{
		Live:           true,
		Subject:        session.Sub,
		SessionBinding: session.SessionBinding,
		AAL:            session.AAL,
		UV:             session.UV,
		AuthTime:       session.AuthTime,
		FactorEpoch:    session.FactorEpoch,
		AsOf:           trustedMFATestNow.Unix(),
	}
}

func trustedMFANoneAssertion(t *testing.T, route config.Route) auth.MFAAssertion {
	t.Helper()
	assertion := auth.MFAAssertion{
		Subject:   trustedMFATestSubject,
		AAL:       auth.MFAAALNone,
		Route:     route.Name,
		Audience:  route.UpstreamURL().Hostname(),
		Timestamp: trustedMFATestNow.Unix(),
	}
	assertion.Evidence = trustedMFAEvidence(t, assertion)
	return assertion
}

func trustedMFAStrongAssertion(t *testing.T, route config.Route) auth.MFAAssertion {
	t.Helper()
	session := trustedMFAStrongSession()
	assertion := auth.MFAAssertion{
		Subject:        session.Sub,
		AAL:            auth.MFAAALStrong,
		UV:             true,
		AuthTime:       session.AuthTime,
		SessionBinding: session.SessionBinding,
		FactorEpoch:    session.FactorEpoch,
		Route:          route.Name,
		Audience:       route.UpstreamURL().Hostname(),
		Timestamp:      trustedMFATestNow.Unix(),
	}
	assertion.Evidence = trustedMFAEvidence(t, assertion)
	return assertion
}

func trustedMFAEvidence(t *testing.T, assertion auth.MFAAssertion) string {
	t.Helper()
	evidence, err := auth.MFAEvidenceDigest(assertion)
	if err != nil {
		t.Fatalf("MFAEvidenceDigest() error = %v", err)
	}
	return evidence
}

func assertTrustedMFAAssertion(
	t *testing.T,
	got auth.MFAAssertion,
	signature string,
	present bool,
	want auth.MFAAssertion,
) {
	t.Helper()
	if !present {
		t.Fatal("trusted MFA assertion is missing from request context")
	}
	if got != want {
		t.Fatalf("assertion = %+v, want %+v", got, want)
	}
	if err := auth.VerifyMFAAssertion(
		trustedMFATestKey,
		"",
		got,
		signature,
		want.Subject,
		want.Route,
		want.Audience,
		trustedMFATestNow.Unix(),
	); err != nil {
		t.Fatalf("VerifyMFAAssertion() error = %v", err)
	}
}
