package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/holdfast/sluice/internal/auth"
	"github.com/holdfast/sluice/internal/config"
	"github.com/holdfast/sluice/internal/oidc"
)

func TestReverseProxyStripsForgedMFAHeadersAndInjectsTrustedContext(t *testing.T) {
	observed := make(chan http.Header, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	route := validatedMFAProxyRoute(t, upstream.URL)
	proxy := newReverseProxy(route, nil, "", "", "", auth.AuthorizationContextV2Keyring{}, config.GatewayZoneInternal, "")

	request := httptest.NewRequest(http.MethodGet, "https://admin.w33d.xyz/console", nil)
	for _, name := range []string{
		auth.HeaderAuthMFASubject,
		auth.HeaderAuthMFAAAL,
		auth.HeaderAuthMFAUV,
		auth.HeaderAuthMFAAuthTime,
		auth.HeaderAuthMFASessionBinding,
		auth.HeaderAuthMFAFactorEpoch,
		auth.HeaderAuthMFARoute,
		auth.HeaderAuthMFAAudience,
		auth.HeaderAuthMFAEvidence,
		auth.HeaderAuthMFATimestamp,
		auth.HeaderAuthMFASig,
	} {
		request.Header.Set(name, "forged")
	}
	response := httptest.NewRecorder()
	proxy.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		body, _ := io.ReadAll(response.Result().Body)
		t.Fatalf("proxy status = %d body=%q", response.Code, body)
	}
	withoutContext := <-observed
	for name := range withoutContext {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), "X-Auth-Mfa-") {
			t.Fatalf("forged header survived without context: %s=%q", name, withoutContext.Values(name))
		}
	}

	const key = "proxy-mfa-assertion-key-0123456789abcdef"
	now := time.Now().Unix()
	assertion := auth.MFAAssertion{
		Subject:        "alice",
		AAL:            auth.MFAAALStrong,
		UV:             true,
		AuthTime:       now - 10,
		SessionBinding: strings.Repeat("a", 64),
		FactorEpoch:    9,
		Route:          route.Name,
		Audience:       route.UpstreamURL().Hostname(),
		Timestamp:      now,
	}
	var err error
	assertion.Evidence, err = auth.MFAEvidenceDigest(assertion)
	if err != nil {
		t.Fatalf("MFAEvidenceDigest: %v", err)
	}
	signature, err := auth.SignMFAAssertion(key, assertion)
	if err != nil {
		t.Fatalf("SignMFAAssertion: %v", err)
	}
	request = httptest.NewRequest(http.MethodGet, "https://admin.w33d.xyz/console", nil)
	request.Header.Set(auth.HeaderAuthMFAAAL, auth.MFAAALNone)
	request.Header.Set(auth.HeaderAuthMFASubject, "mallory")
	request.Header.Set(auth.HeaderAuthMFASig, "forged")
	request = request.WithContext(auth.ContextWithMFAAssertion(request.Context(), assertion, signature))
	response = httptest.NewRecorder()
	proxy.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("proxy status with context = %d", response.Code)
	}
	got := <-observed
	want := map[string]string{
		auth.HeaderAuthMFASubject:        assertion.Subject,
		auth.HeaderAuthMFAAAL:            assertion.AAL,
		auth.HeaderAuthMFAUV:             "1",
		auth.HeaderAuthMFAAuthTime:       strconv.FormatInt(assertion.AuthTime, 10),
		auth.HeaderAuthMFASessionBinding: assertion.SessionBinding,
		auth.HeaderAuthMFAFactorEpoch:    strconv.FormatInt(assertion.FactorEpoch, 10),
		auth.HeaderAuthMFARoute:          assertion.Route,
		auth.HeaderAuthMFAAudience:       assertion.Audience,
		auth.HeaderAuthMFAEvidence:       assertion.Evidence,
		auth.HeaderAuthMFATimestamp:      strconv.FormatInt(assertion.Timestamp, 10),
		auth.HeaderAuthMFASig:            signature,
	}
	for name, value := range want {
		if gotValue := got.Get(name); gotValue != value {
			t.Errorf("%s = %q, want %q", name, gotValue, value)
		}
	}
}

func TestTrustedMFAResponseCannotBeMadeCacheableByUpstream(t *testing.T) {
	route := validatedMFAProxyRoute(t, "http://upstream.test")
	session := oidc.Session{Sub: "alice", AAL: oidc.SessionAALNone}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
	})
	request := httptest.NewRequest(http.MethodGet, "https://admin.w33d.xyz/console", nil)
	ctx := auth.ContextWithIdentity(request.Context(), &auth.Identity{Subject: "alice"})
	ctx = oidc.ContextWithGatewaySession(ctx, session)
	request = request.WithContext(ctx)
	recorder := httptest.NewRecorder()
	trustedMFAWrap(route, next, Options{
		TrustedMFAEnabled:   true,
		MFAAssertionHMACKey: "proxy-mfa-assertion-key-0123456789abcdef",
	}).ServeHTTP(recorder, request)
	if got := recorder.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Fatalf("Cache-Control = %q, want private, no-store", got)
	}
}

func validatedMFAProxyRoute(t *testing.T, upstream string) config.Route {
	t.Helper()
	cfg := config.Config{
		Routes: []config.Route{{
			Name:     "newapi-console",
			Match:    config.Match{Host: "admin.w33d.xyz", PathPrefix: "/"},
			Upstream: upstream,
			Auth:     config.AuthSSO,
		}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate route: %v", err)
	}
	return cfg.Routes[0]
}
