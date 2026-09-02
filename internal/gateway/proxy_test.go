package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/holdfast/sluice/internal/application"
	"github.com/holdfast/sluice/internal/auth"
	"github.com/holdfast/sluice/internal/config"
	"github.com/holdfast/sluice/internal/oidc"
	"github.com/holdfast/sluice/internal/pat"
	"github.com/holdfast/sluice/internal/rbac"
)

type unusedKeyResolver struct{}

type gatewayPATIntrospector struct {
	result pat.Result
	err    error
}

type gatewayApplicationIntrospector struct {
	result application.Result
	err    error
	calls  int
}

func (i *gatewayApplicationIntrospector) Introspect(context.Context, string, string) (application.Result, error) {
	i.calls++
	return i.result, i.err
}

func (i gatewayPATIntrospector) Introspect(context.Context, string) (pat.Result, error) {
	return i.result, i.err
}

func (unusedKeyResolver) KeyByKID(context.Context, string) (*rsa.PublicKey, error) {
	return nil, errors.New("unused key resolver")
}

func newGatewayTestProvider(t *testing.T) *oidc.Provider {
	t.Helper()
	p, err := oidc.NewProvider(oidc.Config{
		Issuer:        "https://id.example",
		TokenURL:      "https://id.example/token",
		ClientID:      "gw-sluice",
		RedirectURI:   "https://id.example/_gw/auth/callback",
		SessionSecret: "unit-test-secret",
	}, unusedKeyResolver{}, nil, oidc.NewMemoryStore(), oidc.NewMemoryStore(), nil)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return p
}

func TestGatewayZoneHeaderOverwritesInbound(t *testing.T) {
	type contextHeaders struct {
		zones []string
		sigs  []string
		unix  int64
	}
	seen := make(chan contextHeaders, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- contextHeaders{
			zones: r.Header.Values(gatewayZoneHeader),
			sigs:  r.Header.Values(auth.HeaderGatewayZoneSig),
			unix:  time.Now().Unix(),
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	store := mustRoutes(t, []config.Route{
		{Name: "public", Match: config.Match{Host: "public.example", PathPrefix: "/"}, Upstream: upstream.URL, Auth: config.AuthPublic},
	})
	handler := NewServer(store, Options{
		GatewayZone:        config.GatewayZoneInternal,
		GatewayZoneHMACKey: "test-key",
	}).Handler()

	req := httptest.NewRequest(http.MethodGet, "http://public.example/", nil)
	req.Host = "public.example"
	req.Header.Add(gatewayZoneHeader, config.GatewayZoneExternal)
	req.Header.Add(gatewayZoneHeader, "spoofed")
	req.Header.Set(auth.HeaderGatewayZoneSig, "spoofed")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	got := <-seen
	if len(got.zones) != 1 {
		t.Fatalf("%s values = %v, want exactly one", gatewayZoneHeader, got.zones)
	}
	if got.zones[0] != config.GatewayZoneInternal {
		t.Errorf("%s = %q, want %q", gatewayZoneHeader, got.zones[0], config.GatewayZoneInternal)
	}
	if len(got.sigs) != 1 || got.sigs[0] == "" || got.sigs[0] == "spoofed" {
		t.Errorf("%s values = %v, want one Sluice-minted signature", auth.HeaderGatewayZoneSig, got.sigs)
	}
	current := auth.SignGatewayZone("test-key", "public", "public.example", config.GatewayZoneInternal, got.unix)
	previous := auth.SignGatewayZone("test-key", "public", "public.example", config.GatewayZoneInternal, got.unix-60)
	if got.sigs[0] != current && got.sigs[0] != previous {
		t.Errorf("%s is not bound to the matched route, host, zone, and current window", auth.HeaderGatewayZoneSig)
	}
}

func TestSSOOptionalWithoutProviderFallsThrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	store := mustRoutes(t, []config.Route{
		{Name: "git", Match: config.Match{Host: "git.example", PathPrefix: "/"}, Upstream: upstream.URL, Auth: config.AuthSSOOptional},
	})
	handler := NewServer(store, Options{}).Handler()

	req := httptest.NewRequest(http.MethodGet, "http://git.example/repos", nil)
	req.Host = "git.example"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
}

func TestSSOOptionalAnonymousRoutePassesThroughWithoutGateOrSpoofedIdentity(t *testing.T) {
	seenSubject := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenSubject <- r.Header.Get(auth.HeaderAuthSubject)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	verdict := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("anonymous optional route should not call Verdict")
	}))
	defer verdict.Close()

	store := mustRoutes(t, []config.Route{
		{
			Name:         "git",
			Match:        config.Match{Host: "git.example", PathPrefix: "/"},
			Upstream:     upstream.URL,
			Auth:         config.AuthSSOOptional,
			RequireGroup: "estate-users",
		},
	})
	handler := NewServer(store, Options{
		Provider: newGatewayTestProvider(t),
		Authz: rbac.New(rbac.Config{
			Enabled:    true,
			VerdictURL: verdict.URL,
			Token:      "verdict-token",
		}),
	}).Handler()

	req := httptest.NewRequest(http.MethodGet, "http://git.example/repos", nil)
	req.Host = "git.example"
	req.Header.Set(auth.HeaderAuthSubject, "forged-user")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if got := <-seenSubject; got != "" {
		t.Fatalf("%s reached upstream as %q, want stripped/empty", auth.HeaderAuthSubject, got)
	}
}

func TestPATRouteTerminatesTokenAndInjectsOnlyVerifiedIdentity(t *testing.T) {
	type observed struct {
		authorization   string
		subject         string
		scope           string
		signature       string
		scopeSignatures []string
		unix            int64
	}
	seen := make(chan observed, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- observed{
			authorization:   r.Header.Get("Authorization"),
			subject:         r.Header.Get(auth.HeaderAuthSubject),
			scope:           r.Header.Get(auth.HeaderAuthScope),
			signature:       r.Header.Get(auth.HeaderAuthSig),
			scopeSignatures: r.Header.Values(auth.HeaderAuthScopeSig),
			unix:            time.Now().Unix(),
		}
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("Vary", "Accept-Encoding")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	const requiredScope = "corvid:temp-mail:manage"
	store := mustRoutes(t, []config.Route{{
		Name:         "corvid-delete",
		Match:        config.Match{Host: "mail.example", PathPrefix: "/api/v1/temp-mailboxes/"},
		Upstream:     upstream.URL,
		Auth:         config.AuthPAT,
		RequireScope: requiredScope,
	}})
	handler := NewServer(store, Options{
		PATIntrospector: gatewayPATIntrospector{result: pat.Result{
			Active:  true,
			Subject: "u_test",
			Scope:   "profile " + requiredScope,
		}},
		GatewayHMACKey: "identity-hmac-key",
	}).Handler()

	const rawPAT = "pat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	req := httptest.NewRequest(http.MethodDelete, "http://mail.example/api/v1/temp-mailboxes/opaque-id", nil)
	req.Host = "mail.example"
	req.Header.Set("Authorization", "Bearer "+rawPAT)
	req.Header.Add(auth.HeaderAuthScopeSig, "forged-one")
	req.Header.Add(auth.HeaderAuthScopeSig, "forged-two")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	got := <-seen
	if got.authorization != "" {
		t.Fatalf("raw PAT reached upstream in Authorization: %q", got.authorization)
	}
	if got.subject != "u_test" || got.scope != "profile "+requiredScope || got.signature == "" {
		t.Fatalf("upstream identity = %+v", got)
	}
	if len(got.scopeSignatures) != 1 || got.scopeSignatures[0] == "forged-one" || got.scopeSignatures[0] == "forged-two" {
		t.Fatalf("upstream PAT scope signatures = %q, want one Sluice-minted value", got.scopeSignatures)
	}
	wantCurrent := auth.SignPATScope("identity-hmac-key", "u_test", "profile "+requiredScope, requiredScope, got.unix)
	wantPrevious := auth.SignPATScope("identity-hmac-key", "u_test", "profile "+requiredScope, requiredScope, got.unix-60)
	if got.scopeSignatures[0] != wantCurrent && got.scopeSignatures[0] != wantPrevious {
		t.Fatalf("PAT scope signature = %q, want current or previous window", got.scopeSignatures[0])
	}
	if got := rec.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if !headerHasValue(rec.Header().Values("Vary"), "Accept-Encoding") || !headerHasValue(rec.Header().Values("Vary"), "Authorization") {
		t.Fatalf("Vary = %q", rec.Header().Values("Vary"))
	}
}

func TestPATRouteMissingIntrospectionConfigFailsClosed(t *testing.T) {
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamHit = true
	}))
	defer upstream.Close()
	store := mustRoutes(t, []config.Route{{
		Name:         "corvid-delete",
		Match:        config.Match{Host: "mail.example", PathPrefix: "/api/"},
		Upstream:     upstream.URL,
		Auth:         config.AuthPAT,
		RequireScope: "corvid:temp-mail:delete",
	}})
	handler := NewServer(store, Options{}).Handler()
	req := httptest.NewRequest(http.MethodDelete, "http://mail.example/api/resource", nil)
	req.Host = "mail.example"
	req.Header.Set("Authorization", "Bearer pat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if upstreamHit {
		t.Fatal("PAT route reached upstream without introspection configuration")
	}
	if rec.Header().Get("Cache-Control") != "private, no-store" || !headerHasValue(rec.Header().Values("Vary"), "Authorization") {
		t.Fatalf("privacy headers: Cache-Control=%q Vary=%q", rec.Header().Get("Cache-Control"), rec.Header().Values("Vary"))
	}
}

func TestNonPATRoutePreservesAuthorizationHeader(t *testing.T) {
	type observed struct {
		authorization  string
		scopeSignature string
	}
	seen := make(chan observed, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- observed{
			authorization:  r.Header.Get("Authorization"),
			scopeSignature: r.Header.Get(auth.HeaderAuthScopeSig),
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	store := mustRoutes(t, []config.Route{{
		Name: "existing-public", Match: config.Match{Host: "api.example", PathPrefix: "/"},
		Upstream: upstream.URL, Auth: config.AuthPublic,
	}})
	handler := NewServer(store, Options{}).Handler()
	req := httptest.NewRequest(http.MethodGet, "http://api.example/resource", nil)
	req.Host = "api.example"
	req.Header.Set("Authorization", "Bearer existing-non-pat-credential")
	req.Header.Set(auth.HeaderAuthScopeSig, "forged")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	got := <-seen
	if got.authorization != "Bearer existing-non-pat-credential" {
		t.Fatalf("Authorization = %q, existing non-PAT behavior changed", got.authorization)
	}
	if got.scopeSignature != "" {
		t.Fatalf("non-PAT route forwarded %s = %q, want stripped/absent", auth.HeaderAuthScopeSig, got.scopeSignature)
	}
}

func TestNonPATRouteWithIdentityDoesNotInjectScopeSignature(t *testing.T) {
	type observed struct {
		identitySignature string
		scopeSignature    string
	}
	seen := make(chan observed, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- observed{
			identitySignature: r.Header.Get(auth.HeaderAuthSig),
			scopeSignature:    r.Header.Get(auth.HeaderAuthScopeSig),
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	store := mustRoutes(t, []config.Route{{
		Name:     "existing-bearer",
		Match:    config.Match{Host: "api.example", PathPrefix: "/"},
		Upstream: upstream.URL,
		Auth:     config.AuthBearer,
	}})
	proxy := newReverseProxy(store.Routes()[0], nil, "identity-hmac-key", "", "", auth.AuthorizationContextV2Keyring{}, "external", "")
	req := httptest.NewRequest(http.MethodGet, "http://api.example/resource", nil)
	req.Host = "api.example"
	req.Header.Set(auth.HeaderAuthScopeSig, "forged")
	ctx := auth.ContextWithIdentity(req.Context(), &auth.Identity{
		Subject: "u_test",
		Scope:   "profile",
	})
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req.WithContext(ctx))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	got := <-seen
	if got.identitySignature == "" {
		t.Fatal("verified non-PAT identity did not receive the existing identity signature")
	}
	if got.scopeSignature != "" {
		t.Fatalf("non-PAT identity received %s = %q, want absent", auth.HeaderAuthScopeSig, got.scopeSignature)
	}
}

func TestAllowedPermissionContextIsSignedAndSpoofedHeadersAreReplaced(t *testing.T) {
	seen := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	route := mustRoutes(t, []config.Route{{
		Name:     "cpa-root",
		Match:    config.Match{Host: "cpa.example", PathPrefix: "/"},
		Upstream: upstream.URL,
		Auth:     config.AuthSSO,
	}}).Routes()[0]
	proxy := newReverseProxy(route, nil, "", "", "authz-key", auth.AuthorizationContextV2Keyring{}, "internal", "")
	req := httptest.NewRequest(http.MethodGet, "http://cpa.example/", nil)
	req.Host = "cpa.example"
	for _, header := range []string{
		auth.HeaderAuthPermission,
		auth.HeaderAuthObject,
		auth.HeaderAuthDecision,
		auth.HeaderAuthDecisionID,
		auth.HeaderAuthRevocationEpoch,
		auth.HeaderAuthContextTime,
		auth.HeaderAuthContextSig,
	} {
		req.Header.Set(header, "forged")
	}
	decision := auth.AuthorizationContext{
		Permission:      "cpa.console.enter",
		Object:          "route:cpa-root",
		Decision:        "Allow",
		DecisionID:      "dec_123",
		RevocationEpoch: 42,
		Timestamp:       1_765_000_000,
	}
	req = req.WithContext(auth.ContextWithAuthorization(req.Context(), decision))
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", recorder.Code)
	}
	headers := <-seen
	if headers.Get(auth.HeaderAuthPermission) != decision.Permission ||
		headers.Get(auth.HeaderAuthObject) != decision.Object ||
		headers.Get(auth.HeaderAuthDecision) != "Allow" ||
		headers.Get(auth.HeaderAuthDecisionID) != decision.DecisionID ||
		headers.Get(auth.HeaderAuthRevocationEpoch) != "42" ||
		headers.Get(auth.HeaderAuthContextTime) != "1765000000" {
		t.Fatalf("authorization headers = %#v", headers)
	}
	if got := headers.Get(auth.HeaderAuthContextSig); got == "" || got == "forged" {
		t.Fatalf("authorization signature = %q", got)
	}
}

func TestAllowedPermissionContextDualWritesCompleteV2Headers(t *testing.T) {
	seen := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	route := mustRoutes(t, []config.Route{{
		Name:     "cpa-root",
		Match:    config.Match{Host: "cpa.w33d.xyz", PathPrefix: "/"},
		Upstream: upstream.URL,
		Auth:     config.AuthSSO,
	}}).Routes()[0]
	keyring := auth.AuthorizationContextV2Keyring{
		Current: auth.AuthorizationContextV2Key{
			KID: "authz2-2026a",
			Key: "authz2-ctx-golden-key-0123456789abcdef",
		},
		Previous: auth.AuthorizationContextV2Key{
			KID: "authz2-2025h",
			Key: "authz2-ctx-golden-prev-0123456789abcdef",
		},
	}
	proxy := newReverseProxy(route, nil, "", "", "legacy-authz-key", keyring, "internal", "")
	req := httptest.NewRequest(http.MethodGet, "http://cpa.w33d.xyz/", nil)
	req.Host = "cpa.w33d.xyz"
	v2Headers := []string{
		auth.HeaderAuthContextV2KID,
		auth.HeaderAuthContextV2Issuer,
		auth.HeaderAuthContextV2Subject,
		auth.HeaderAuthContextV2Route,
		auth.HeaderAuthContextV2Audience,
		auth.HeaderAuthContextV2Zone,
		auth.HeaderAuthContextV2Permission,
		auth.HeaderAuthContextV2ResourceVersion,
		auth.HeaderAuthContextV2ResourceType,
		auth.HeaderAuthContextV2ResourceID,
		auth.HeaderAuthContextV2Risk,
		auth.HeaderAuthContextV2Decision,
		auth.HeaderAuthContextV2DecisionID,
		auth.HeaderAuthContextV2PolicyEpoch,
		auth.HeaderAuthContextV2IssuedAt,
		auth.HeaderAuthContextV2Expiry,
		auth.HeaderAuthContextV2Signature,
	}
	for _, header := range v2Headers {
		req.Header.Add(header, "forged-one")
		req.Header.Add(header, "forged-two")
	}
	decision := auth.AuthorizationContext{
		Permission:      "cpa.console.enter",
		Object:          "route:cpa-root",
		Decision:        "Allow",
		DecisionID:      "dec_0123456789abcdef0123456789abcdef",
		RevocationEpoch: 42,
		Timestamp:       1_765_000_000,
		Subject:         "user:alice",
		Risk:            "critical",
	}
	req = req.WithContext(auth.ContextWithAuthorization(req.Context(), decision))
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", recorder.Code)
	}
	headers := <-seen
	for _, header := range v2Headers {
		if values := headers.Values(header); len(values) != 1 || values[0] == "forged-one" || values[0] == "forged-two" {
			t.Fatalf("%s values = %q, want one Sluice-minted value", header, values)
		}
	}
	const wantSignature = "bc5d6152f44d7c4ca8110e7eac191bce169d9b46a0de7dcfdc67839ddbb03929"
	if got := headers.Get(auth.HeaderAuthContextV2Signature); got != wantSignature {
		t.Fatalf("v2 signature = %q, want %q", got, wantSignature)
	}
	if headers.Get(auth.HeaderAuthContextV2Subject) != "user:alice" ||
		headers.Get(auth.HeaderAuthContextV2Audience) != "cpa.w33d.xyz" ||
		headers.Get(auth.HeaderAuthContextV2Expiry) != "1765000090" {
		t.Fatalf("unexpected v2 context: %#v", headers)
	}
	if headers.Get(auth.HeaderAuthContextSig) == "" {
		t.Fatal("legacy v1 authorization context was not preserved during v2 dual-write")
	}
}

func TestApplicationProxyStripsCredentialAndBindsCompleteContext(t *testing.T) {
	fixedNow := time.Unix(1_900_000_000, 0)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, ed25519.SeedSize))
	signer, err := application.NewContextSigner(application.SigningKeyring{
		ActiveKID: "appctx-2026a", PrivateKeys: map[string]ed25519.PrivateKey{"appctx-2026a": private},
	}, func() time.Time { return fixedNow }, bytes.NewReader(bytes.Repeat([]byte{3}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	digest := hex.EncodeToString(bytes.Repeat([]byte{4}, 32))
	introspector := &gatewayApplicationIntrospector{result: application.Result{
		Active: true, Subject: "application:abcdefghijklmnop", ApplicationSub: "application:abcdefghijklmnop",
		Scopes: []string{"analysis.create", "analysis.read"}, ExpiresAt: fixedNow.Unix() + 600,
		ClientID: "client_abcdefghijklmnop", CredentialID: "cred_abcdefghijklmnop", Fingerprint: digest,
		GrantID: "grant_abcdefghijklmnop", PackageID: "pkg_analyze_mcp_client", PackageRevisionDigest: digest,
		Audience: "analyze-facade", CredentialVersion: 2, SubjectVersion: 4,
		CredentialState: application.CredentialActive, PolicyEpoch: 7, RevocationEpoch: 9,
	}}
	store := mustRoutes(t, []config.Route{{Name: "analyze-mcp", Match: config.Match{Host: "analyze.w33d.xyz", PathPrefix: "/mcp"}, Upstream: upstream.URL, Auth: config.AuthApplication}})
	handler := NewServer(store, Options{ApplicationIntrospector: introspector, ApplicationContextSigner: signer}).Handler()
	body := `{"jsonrpc":"2.0","method":"tools/list"}`
	req := httptest.NewRequest(http.MethodPost, "https://analyze.w33d.xyz/mcp", strings.NewReader(body))
	req.Host = "analyze.w33d.xyz"
	req.Header.Set("Authorization", "Bearer "+applicationTokenForGatewayTest)
	req.Header.Set("Cookie", "__Secure-gw=must-not-pass; app=value")
	req.Header.Set("Mcp-Session-Id", "session_abcdefghijklmnop")
	req.Header.Set("X-Request-Id", "req_abcdefghijklmnop")
	req.Header.Set("X-Correlation-Id", "corr_abcdefghijklmnop")
	req.Header.Add(application.HeaderContext, "forged-one")
	req.Header.Add(application.HeaderContext, "forged-two")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	got := <-seen
	if got.Get("Authorization") != "" || got.Get("Cookie") != "" {
		t.Fatalf("raw credentials reached upstream")
	}
	for _, name := range []string{application.HeaderKID, application.HeaderContext, application.HeaderSig} {
		if values := got.Values(name); len(values) != 1 || strings.HasPrefix(values[0], "forged") {
			t.Fatalf("%s=%q", name, values)
		}
	}
	bodyHash := sha256.Sum256([]byte(body))
	sessionHash := sha256.Sum256([]byte("session_abcdefghijklmnop"))
	verified, err := application.VerifyContextHeaders(got, application.VerificationKeyring{Keys: map[string]application.VerificationKey{"appctx-2026a": {PublicKey: private.Public().(ed25519.PublicKey)}}}, fixedNow, application.ExpectedRequest{
		Audience: "analyze-facade", Route: "analyze-mcp", Method: http.MethodPost, NormalizedPath: "/mcp",
		BodySHA256: hex.EncodeToString(bodyHash[:]), RequestID: "req_abcdefghijklmnop", MCPSessionDigest: hex.EncodeToString(sessionHash[:]),
	}, application.NewMemoryReplayGuard())
	if err != nil {
		t.Fatal(err)
	}
	if verified.CredentialState != application.CredentialActive || verified.OverlapUntil != nil || verified.CorrelationID != "corr_abcdefghijklmnop" || verified.PolicyEpoch != 7 || verified.RevocationEpoch != 9 {
		t.Fatalf("verified=%+v", verified)
	}
	if introspector.calls != 1 {
		t.Fatalf("introspection calls=%d", introspector.calls)
	}
}

func TestTrustedMFASponsorAssertionIssuedInPlaceAndStripsClientHeaders(t *testing.T) {
	fixedNow := time.Unix(1_900_000_000, 0)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, ed25519.SeedSize))
	signer, err := application.NewSponsorSigner(application.SigningKeyring{ActiveKID: "appctx-2026a", PrivateKeys: map[string]ed25519.PrivateKey{"appctx-2026a": private}}, func() time.Time { return fixedNow }, bytes.NewReader(bytes.Repeat([]byte{2}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	route := mustRoutes(t, []config.Route{{Name: "access-applications", Match: config.Match{Host: "analyze.w33d.xyz", PathPrefix: "/api/v1/application-requests/"}, Upstream: upstream.URL, Auth: config.AuthSSO}}).Routes()[0]
	proxy := newReverseProxy(route, nil, "", "", "", auth.AuthorizationContextV2Keyring{}, config.GatewayZoneExternal, "")
	handler := sponsorAssertionWrap(route, proxy, Options{SponsorAssertionSigner: signer, Now: func() time.Time { return fixedNow }})
	req := httptest.NewRequest(http.MethodPost, "https://analyze.w33d.xyz/api/v1/application-requests/abcdefghijklmnop/submit", strings.NewReader(`{"expected_version":3}`))
	for _, name := range []string{application.HeaderSponsorKID, application.HeaderSponsorAssertion, application.HeaderSponsorSig} {
		req.Header.Add(name, "forged-one")
		req.Header.Add(name, "forged-two")
	}
	ctx := auth.ContextWithIdentity(req.Context(), &auth.Identity{Subject: "usr_abcdefghijklmnop"})
	mfa := auth.MFAAssertion{Subject: "usr_abcdefghijklmnop", AAL: auth.MFAAALStrong, UV: true, AuthTime: fixedNow.Unix() - 10, SessionBinding: strings.Repeat("a", 64), FactorEpoch: 2, Route: route.Name, Audience: "access-governance", Evidence: strings.Repeat("b", 64), Timestamp: fixedNow.Unix()}
	ctx = auth.ContextWithMFAAssertion(ctx, mfa, "test-signature")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req.WithContext(ctx))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	headers := <-seen
	assertion, err := application.VerifySponsorHeaders(headers, map[string]ed25519.PublicKey{"appctx-2026a": private.Public().(ed25519.PublicKey)}, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	if assertion.RequestID != "abcdefghijklmnop" || assertion.RequestVersion != 3 || assertion.SessionBinding != strings.Repeat("a", 64) || assertion.AuthTime != fixedNow.Unix()-10 || len(assertion.AMR) != 2 {
		t.Fatalf("assertion=%+v", assertion)
	}
	for _, name := range []string{application.HeaderSponsorKID, application.HeaderSponsorAssertion, application.HeaderSponsorSig} {
		if len(headers.Values(name)) != 1 {
			t.Fatalf("%s=%q", name, headers.Values(name))
		}
	}

	nonSubmit := httptest.NewRequest(http.MethodPost, "https://analyze.w33d.xyz/api/v1/application-requests/abcdefghijklmnop/cancel", strings.NewReader(`{"expected_version":3}`))
	nonSubmit.Header.Set(application.HeaderSponsorAssertion, "forged")
	nonSubmitRecorder := httptest.NewRecorder()
	handler.ServeHTTP(nonSubmitRecorder, nonSubmit.WithContext(ctx))
	if nonSubmitRecorder.Code != http.StatusNoContent {
		t.Fatalf("non-submit status=%d body=%q", nonSubmitRecorder.Code, nonSubmitRecorder.Body.String())
	}
	for name, values := range <-seen {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), "X-Sponsor-Assertion") && len(values) != 0 {
			t.Fatalf("non-submit forwarded %s=%q", name, values)
		}
	}

	stale := httptest.NewRequest(http.MethodPost, "https://analyze.w33d.xyz/api/v1/application-requests/abcdefghijklmnop/submit", strings.NewReader(`{"expected_version":3}`))
	staleMFA := mfa
	staleMFA.AuthTime = fixedNow.Unix() - application.SponsorTTLSeconds - 1
	staleContext := auth.ContextWithMFAAssertion(ctx, staleMFA, "test-signature")
	staleRecorder := httptest.NewRecorder()
	handler.ServeHTTP(staleRecorder, stale.WithContext(staleContext))
	if staleRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("stale MFA status=%d body=%q", staleRecorder.Code, staleRecorder.Body.String())
	}
}

const applicationTokenForGatewayTest = "app_v1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func headerHasValue(values []string, want string) bool {
	for _, value := range values {
		for _, field := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(field), want) {
				return true
			}
		}
	}
	return false
}
