package config

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// minimalValid returns a config with one route so Validate's route checks pass,
// letting each test focus on the TLS / fetch-url surface.
func minimalValid() *Config {
	return &Config{
		KeystoneIssuer: "http://127.0.0.1:8080",
		Routes: []Route{
			{Name: "ok", Match: Match{PathPrefix: "/api"}, Upstream: "http://127.0.0.1:8081"},
		},
	}
}

func validTrustedMFAConfig() *Config {
	c := minimalValid()
	c.TrustedMFAEnabled = true
	c.KeystoneAssuranceURL = "https://keystone:8443/internal/v1/session-assurance"
	c.KeystoneAssuranceServiceToken = strings.Repeat("l", 32)
	c.MFAAssertionHMACKey = strings.Repeat("c", 32)
	c.GWClientSecret = strings.Repeat("o", 32)
	c.GWSessionSecret = strings.Repeat("s", 32)
	c.GWSessionRevocationToken = strings.Repeat("r", 32)
	c.AuditIngestToken = strings.Repeat("a", 32)
	c.VerdictDecisionToken = strings.Repeat("v", 32)
	c.GatewayHMACKey = strings.Repeat("i", 32)
	c.GatewayZoneHMACKey = strings.Repeat("z", 32)
	c.GatewayAuthzHMACKey = strings.Repeat("g", 32)
	return c
}

func TestPermissionRouteDefaultsAndValidation(t *testing.T) {
	c := minimalValid()
	c.Routes[0].Auth = AuthSSO
	c.Routes[0].RequirePermission = "cpa.console.enter"
	c.Routes[0].InternalOnly = true
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate(permission route): %v", err)
	}
	route := c.Routes[0]
	if route.PermissionResource != "route:ok" || route.Risk != RiskLow || !route.InternalOnly {
		t.Fatalf("normalized permission route = %+v", route)
	}

	for _, mutate := range []func(*Route){
		func(route *Route) { route.Auth = AuthSSOOptional },
		func(route *Route) { route.RequirePermission = "cpa.enter" },
		func(route *Route) { route.PermissionResource = "Route:ok" },
		func(route *Route) { route.Risk = "severe" },
	} {
		invalid := minimalValid()
		invalid.Routes[0].Auth = AuthSSO
		invalid.Routes[0].RequirePermission = "cpa.console.enter"
		mutate(&invalid.Routes[0])
		if err := invalid.Validate(); err == nil {
			t.Fatalf("invalid permission route accepted: %+v", invalid.Routes[0])
		}
	}
}

func TestValidateTLSModeOffDefaults(t *testing.T) {
	c := minimalValid()
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate error: %v", err)
	}
	if c.TLSMode != TLSModeOff {
		t.Errorf("TLSMode = %q, want %q (default)", c.TLSMode, TLSModeOff)
	}
	if c.HTTPAddr != DefaultHTTPAddr {
		t.Errorf("HTTPAddr = %q, want %q", c.HTTPAddr, DefaultHTTPAddr)
	}
	if c.HTTPSAddr != DefaultHTTPSAddr {
		t.Errorf("HTTPSAddr = %q, want %q", c.HTTPSAddr, DefaultHTTPSAddr)
	}
	if c.ACMECacheDir != DefaultACMECacheDir {
		t.Errorf("ACMECacheDir = %q, want %q", c.ACMECacheDir, DefaultACMECacheDir)
	}
}

func TestValidateTLSModeFileRequiresCertAndKey(t *testing.T) {
	c := minimalValid()
	c.TLSMode = TLSModeFile
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for file mode without cert/key, got nil")
	}

	c = minimalValid()
	c.TLSMode = TLSModeFile
	c.TLSCertFile = "/tmp/cert.pem"
	c.TLSKeyFile = "/tmp/key.pem"
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate(file with cert+key) error: %v", err)
	}
}

func TestValidateTLSModeACMERequiresDomain(t *testing.T) {
	c := minimalValid()
	c.TLSMode = TLSModeACME
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for acme mode without acme_domain, got nil")
	}

	c = minimalValid()
	c.TLSMode = TLSModeACME
	c.ACMEDomain = "id.w33d.xyz"
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate(acme with domain) error: %v", err)
	}
	// Cache dir default applies in acme mode too.
	if c.ACMECacheDir != DefaultACMECacheDir {
		t.Errorf("ACMECacheDir = %q, want %q", c.ACMECacheDir, DefaultACMECacheDir)
	}
}

func TestValidateTLSModeInvalid(t *testing.T) {
	c := minimalValid()
	c.TLSMode = "bogus"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for invalid tls_mode, got nil")
	}
}

func TestApplyEnvTLSOverrides(t *testing.T) {
	t.Setenv(EnvTLSMode, "file")
	t.Setenv(EnvTLSCertFile, "/certs/fullchain.pem")
	t.Setenv(EnvTLSKeyFile, "/certs/privkey.pem")
	t.Setenv(EnvHTTPAddr, ":8080")
	t.Setenv(EnvHTTPSAddr, ":8443")

	c := minimalValid()
	c.ApplyEnv()
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate error: %v", err)
	}
	if c.TLSMode != TLSModeFile {
		t.Errorf("TLSMode = %q, want file", c.TLSMode)
	}
	if c.TLSCertFile != "/certs/fullchain.pem" || c.TLSKeyFile != "/certs/privkey.pem" {
		t.Errorf("cert/key not applied: %q %q", c.TLSCertFile, c.TLSKeyFile)
	}
	if c.HTTPAddr != ":8080" || c.HTTPSAddr != ":8443" {
		t.Errorf("addrs not applied: %q %q", c.HTTPAddr, c.HTTPSAddr)
	}
}

func TestApplyEnvACMEOverrides(t *testing.T) {
	t.Setenv(EnvTLSMode, "acme")
	t.Setenv(EnvACMEDomain, "id.w33d.xyz")
	t.Setenv(EnvACMEEmail, "ops@w33d.xyz")
	t.Setenv(EnvACMECacheDir, "/var/acme")
	t.Setenv(EnvACMEDirectoryURL, "https://acme-staging-v02.api.letsencrypt.org/directory")

	c := minimalValid()
	c.ApplyEnv()
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate error: %v", err)
	}
	if c.TLSMode != TLSModeACME {
		t.Errorf("TLSMode = %q, want acme", c.TLSMode)
	}
	if c.ACMEDomain != "id.w33d.xyz" || c.ACMEEmail != "ops@w33d.xyz" {
		t.Errorf("acme domain/email not applied: %q %q", c.ACMEDomain, c.ACMEEmail)
	}
	if c.ACMECacheDir != "/var/acme" {
		t.Errorf("acme cache dir not applied: %q", c.ACMECacheDir)
	}
	if c.ACMEDirectoryURL == "" {
		t.Errorf("acme directory url not applied")
	}
}

// The internal-fetch overrides must NOT change the public issuer used for iss
// validation, and an explicit OIDC_DISCOVERY_URL must win even when
// KEYSTONE_ISSUER is also set (issuer-derive happens first, override second).
func TestApplyEnvFetchURLOverridesKeepPublicIssuer(t *testing.T) {
	t.Setenv(EnvKeystoneIssuer, "https://id.w33d.xyz")
	t.Setenv(EnvDiscoveryURL, "http://keystone:8080/.well-known/openid-configuration")
	t.Setenv(EnvJWKSFetchURL, "http://keystone:8080/jwks.json")

	c := minimalValid()
	c.ApplyEnv()
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate error: %v", err)
	}
	if c.KeystoneIssuer != "https://id.w33d.xyz" {
		t.Errorf("KeystoneIssuer = %q, want public https://id.w33d.xyz", c.KeystoneIssuer)
	}
	if c.DiscoveryURL != "http://keystone:8080/.well-known/openid-configuration" {
		t.Errorf("DiscoveryURL override not respected (issuer-derive must not clobber it): %q", c.DiscoveryURL)
	}
	if c.JWKSFetchURL != "http://keystone:8080/jwks.json" {
		t.Errorf("JWKSFetchURL = %q, want internal jwks", c.JWKSFetchURL)
	}
}

func TestLoadExampleConfig(t *testing.T) {
	path := filepath.Join("..", "..", "config.example.json")
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile(%s) error: %v", path, err)
	}
	if cfg.ListenAddr != "127.0.0.1:9090" {
		t.Errorf("ListenAddr = %q, want 127.0.0.1:9090", cfg.ListenAddr)
	}
	if cfg.KeystoneIssuer != "http://127.0.0.1:8080" {
		t.Errorf("KeystoneIssuer = %q", cfg.KeystoneIssuer)
	}
	if len(cfg.Routes) != 2 {
		t.Fatalf("got %d routes, want 2", len(cfg.Routes))
	}
	// Upstream URLs must be parsed during Validate.
	for _, r := range cfg.Routes {
		if r.UpstreamURL() == nil {
			t.Errorf("route %q: UpstreamURL not parsed", r.Name)
		}
	}
	// One public and one protected route per the seed table.
	var pub, prot int
	for _, r := range cfg.Routes {
		if r.Protected {
			prot++
		} else {
			pub++
		}
	}
	if pub != 1 || prot != 1 {
		t.Errorf("want 1 public + 1 protected, got %d public / %d protected", pub, prot)
	}
}

// Route.Auth normalisation: empty derives from Protected; explicit values are
// validated and re-sync Protected; an unknown mode is rejected.
func TestRouteAuthModeNormalization(t *testing.T) {
	cases := []struct {
		name          string
		in            Route
		wantAuth      string
		wantProtected bool
	}{
		{"empty+unprotected->public", Route{Name: "a", Match: Match{PathPrefix: "/"}, Upstream: "http://u:1"}, AuthPublic, false},
		{"empty+protected->bearer", Route{Name: "b", Match: Match{PathPrefix: "/"}, Upstream: "http://u:1", Protected: true}, AuthBearer, true},
		{"explicit public", Route{Name: "c", Match: Match{PathPrefix: "/"}, Upstream: "http://u:1", Auth: "public", Protected: true}, AuthPublic, false},
		{"explicit bearer", Route{Name: "d", Match: Match{PathPrefix: "/"}, Upstream: "http://u:1", Auth: "BEARER"}, AuthBearer, true},
		{"explicit pat syncs protected", Route{Name: "e", Match: Match{PathPrefix: "/"}, Upstream: "http://u:1", Auth: "PAT", RequireScope: "corvid:temp-mail:delete"}, AuthPAT, true},
		{"explicit sso syncs protected", Route{Name: "f", Match: Match{PathPrefix: "/"}, Upstream: "http://u:1", Auth: "sso"}, AuthSSO, true},
		{"explicit sso-optional validates", Route{Name: "g", Match: Match{PathPrefix: "/"}, Upstream: "http://u:1", Auth: "sso-optional"}, AuthSSOOptional, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{KeystoneIssuer: "http://127.0.0.1:8080", Routes: []Route{tc.in}}
			if err := c.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			got := c.Routes[0]
			if got.Auth != tc.wantAuth {
				t.Errorf("Auth = %q, want %q", got.Auth, tc.wantAuth)
			}
			if got.Protected != tc.wantProtected {
				t.Errorf("Protected = %v, want %v", got.Protected, tc.wantProtected)
			}
		})
	}
}

func TestRouteAuthModeRejectsUnknown(t *testing.T) {
	c := &Config{
		KeystoneIssuer: "http://127.0.0.1:8080",
		Routes:         []Route{{Name: "bad", Match: Match{PathPrefix: "/"}, Upstream: "http://u:1", Auth: "magic"}},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for unknown auth mode")
	}
}

func TestPATRouteRequiresExactlyOneScope(t *testing.T) {
	cases := []struct {
		name  string
		auth  string
		scope string
		ok    bool
	}{
		{name: "pat-exact", auth: AuthPAT, scope: "corvid:temp-mail:delete", ok: true},
		{name: "pat-trims-outer-space", auth: AuthPAT, scope: "  corvid:temp-mail:delete  ", ok: true},
		{name: "pat-empty", auth: AuthPAT, scope: ""},
		{name: "pat-multiple", auth: AuthPAT, scope: "scope:one scope:two"},
		{name: "public-must-not-accept", auth: AuthPublic, scope: "scope:one"},
		{name: "public-must-not-silently-accept-whitespace", auth: AuthPublic, scope: "   "},
		{name: "bearer-must-not-accept", auth: AuthBearer, scope: "scope:one"},
		{name: "sso-must-not-accept", auth: AuthSSO, scope: "scope:one"},
		{name: "sso-optional-must-not-accept", auth: AuthSSOOptional, scope: "scope:one"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{Routes: []Route{{
				Name:         "route",
				Match:        Match{PathPrefix: "/"},
				Upstream:     "http://upstream:8080",
				Auth:         tc.auth,
				RequireScope: tc.scope,
			}}}
			err := c.Validate()
			if tc.ok && err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("Validate unexpectedly accepted invalid auth/require_scope combination")
			}
			if tc.ok && c.Routes[0].RequireScope != "corvid:temp-mail:delete" {
				t.Fatalf("RequireScope = %q", c.Routes[0].RequireScope)
			}
		})
	}
}

func TestStepUpResumePathRequiresExactHostSSORoute(t *testing.T) {
	validRoute := Route{
		Name:             "access-root",
		Match:            Match{Host: "access.w33d.xyz", PathPrefix: "/"},
		Upstream:         "http://access-governance:9390",
		Auth:             AuthSSO,
		StepUpResumePath: "/request/scope/step-up/",
	}
	for _, test := range []struct {
		name  string
		alter func(*Route)
		want  string
	}{
		{name: "valid", alter: func(*Route) {}},
		{name: "host agnostic", alter: func(route *Route) { route.Match.Host = "" }, want: "exact-host"},
		{name: "host authority", alter: func(route *Route) { route.Match.Host = "access.w33d.xyz@evil.example" }, want: "exact-host"},
		{name: "host port", alter: func(route *Route) { route.Match.Host = "access.w33d.xyz:443" }, want: "exact-host"},
		{name: "public auth", alter: func(route *Route) { route.Auth = AuthPublic }, want: "auth=sso"},
		{name: "missing trailing slash", alter: func(route *Route) { route.StepUpResumePath = "/request/scope/step-up" }, want: "ending in /"},
		{name: "protocol relative", alter: func(route *Route) { route.StepUpResumePath = "//evil.example/" }, want: "safe absolute"},
		{name: "backslash", alter: func(route *Route) { route.StepUpResumePath = `/request/\\evil/` }, want: "safe absolute"},
		{name: "encoded backslash", alter: func(route *Route) { route.StepUpResumePath = `/request/%5cevil/` }, want: "scheme, authority"},
		{name: "query", alter: func(route *Route) { route.StepUpResumePath = "/request/?next=/" }, want: "safe absolute"},
		{name: "fragment", alter: func(route *Route) { route.StepUpResumePath = "/request/#next/" }, want: "safe absolute"},
		{name: "control", alter: func(route *Route) { route.StepUpResumePath = "/request/\n/" }, want: "safe absolute"},
	} {
		t.Run(test.name, func(t *testing.T) {
			route := validRoute
			test.alter(&route)
			config := &Config{KeystoneIssuer: "http://127.0.0.1:8080", Routes: []Route{route}}
			err := config.Validate()
			if test.want == "" {
				if err != nil {
					t.Fatalf("valid route rejected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestApplyEnvPATIntrospectionURL(t *testing.T) {
	t.Setenv(EnvPATIntrospectionURL, "  https://keystone:8443/internal/v1/pats/introspect  ")
	c := minimalValid()
	c.ApplyEnv()
	if got := c.PATIntrospectionURL; got != "https://keystone:8443/internal/v1/pats/introspect" {
		t.Fatalf("PATIntrospectionURL = %q", got)
	}
}

// OIDC SSO + internal-mTLS env overrides apply, default the public issuer to the
// keystone issuer, and never hard-fail Validate (safe-degrade is done in main).
func TestApplyEnvGatewayOIDCAndMTLS(t *testing.T) {
	t.Setenv(EnvKeystoneIssuer, "https://id.w33d.xyz")
	t.Setenv(EnvGWOIDC, "on")
	t.Setenv(EnvGWClientID, "gw-sluice")
	t.Setenv(EnvGWClientSecret, "s3cret")
	t.Setenv(EnvGWRedirectURI, "https://id.w33d.xyz/_gw/auth/callback")
	t.Setenv(EnvGWTokenURL, "https://keystone:8443/token")
	t.Setenv(EnvGWSessionTTL, "2h")
	t.Setenv(EnvGWSessionSecret, "cookie-key")
	t.Setenv(EnvGWSessionRevocationToken, "dedicated-session-revocation-token")
	t.Setenv(EnvInternalMTLS, "on")
	t.Setenv(EnvKeystoneMTLSCert, "/certs/sluice.crt")
	t.Setenv(EnvKeystoneMTLSKey, "/certs/sluice.key")
	t.Setenv(EnvKeystoneMTLSCA, "/certs/root.crt")
	t.Setenv(EnvKeystoneTLSServerName, "keystone")

	c := minimalValid()
	c.ApplyEnv()
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !c.GWOIDCEnabled {
		t.Error("GWOIDCEnabled = false, want true")
	}
	if c.OIDCIssuer != "https://id.w33d.xyz" {
		t.Errorf("OIDCIssuer = %q, want public issuer (defaulted from KEYSTONE_ISSUER)", c.OIDCIssuer)
	}
	if c.GWClientID != "gw-sluice" || c.GWClientSecret != "s3cret" {
		t.Errorf("client creds not applied: %q %q", c.GWClientID, c.GWClientSecret)
	}
	if c.GWRedirectURI != "https://id.w33d.xyz/_gw/auth/callback" || c.GWTokenURL != "https://keystone:8443/token" {
		t.Errorf("gw urls not applied: %q %q", c.GWRedirectURI, c.GWTokenURL)
	}
	if c.GWSessionTTL != 2*time.Hour {
		t.Errorf("GWSessionTTL = %v, want 2h", c.GWSessionTTL)
	}
	if c.GWSessionRevocationToken != "dedicated-session-revocation-token" {
		t.Errorf("GWSessionRevocationToken = %q, want env value", c.GWSessionRevocationToken)
	}
	if !c.InternalMTLS || c.KeystoneMTLSCert != "/certs/sluice.crt" || c.KeystoneTLSServerName != "keystone" {
		t.Errorf("mtls knobs not applied: %+v", c)
	}
}

func TestApplyEnvTrustedMFA(t *testing.T) {
	t.Setenv(EnvTrustedMFAEnabled, "on")
	t.Setenv(EnvKeystoneAssuranceURL, "https://keystone:8443/internal/v1/session-assurance")
	t.Setenv(EnvKeystoneAssuranceServiceToken, strings.Repeat("l", 32))
	t.Setenv(EnvMFAAssertionHMACKey, strings.Repeat("c", 32))

	c := minimalValid()
	c.ApplyEnv()
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !c.TrustedMFAEnabled {
		t.Fatal("TrustedMFAEnabled = false, want true")
	}
	if c.KeystoneAssuranceURL != "https://keystone:8443/internal/v1/session-assurance" {
		t.Fatalf("KeystoneAssuranceURL = %q", c.KeystoneAssuranceURL)
	}
	if c.KeystoneAssuranceServiceToken != strings.Repeat("l", 32) {
		t.Fatal("KeystoneAssuranceServiceToken did not use the environment overlay")
	}
	if c.MFAAssertionHMACKey != strings.Repeat("c", 32) {
		t.Fatal("MFAAssertionHMACKey did not use the environment overlay")
	}
}

func TestTrustedMFADisabledPreservesLegacyConfiguration(t *testing.T) {
	t.Setenv(EnvTrustedMFAEnabled, "off")
	t.Setenv(EnvKeystoneAssuranceURL, "not-an-absolute-url")
	t.Setenv(EnvKeystoneAssuranceServiceToken, "short")
	t.Setenv(EnvMFAAssertionHMACKey, "short")

	c := minimalValid()
	c.ApplyEnv()
	if c.TrustedMFAEnabled {
		t.Fatal("TrustedMFAEnabled = true, want disabled backward-compatible behavior")
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled Trusted MFA rejected legacy configuration: %v", err)
	}
}

func TestApplyEnvTrustedMFARejectsInvalidToggle(t *testing.T) {
	t.Setenv(EnvTrustedMFAEnabled, "onn")

	c := minimalValid()
	c.ApplyEnv()
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "TRUSTED_MFA must be exactly on or off") {
		t.Fatalf("Validate error = %v, want strict TRUSTED_MFA toggle rejection", err)
	}
}

func TestValidateTrustedMFARequiresStrictAssuranceURL(t *testing.T) {
	for _, test := range []struct {
		name string
		url  string
	}{
		{name: "missing", url: ""},
		{name: "relative", url: "/internal/v1/session-assurance"},
		{name: "missing host", url: "https:///internal/v1/session-assurance"},
		{name: "unsupported scheme", url: "ftp://keystone/internal/v1/session-assurance"},
		{name: "userinfo", url: "https://service:secret@keystone/internal/v1/session-assurance"},
		{name: "query", url: "https://keystone/internal/v1/session-assurance?subject=user"},
		{name: "fragment", url: "https://keystone/internal/v1/session-assurance#fragment"},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := validTrustedMFAConfig()
			c.KeystoneAssuranceURL = test.url
			if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "keystone_assurance_url") {
				t.Fatalf("Validate error = %v, want strict assurance URL rejection", err)
			}
		})
	}

	for _, endpoint := range []string{
		"http://keystone:8080/internal/v1/session-assurance",
		"https://keystone:8443/internal/v1/session-assurance",
	} {
		t.Run("accept "+endpoint[:strings.Index(endpoint, ":")], func(t *testing.T) {
			c := validTrustedMFAConfig()
			c.KeystoneAssuranceURL = endpoint
			if err := c.Validate(); err != nil {
				t.Fatalf("valid assurance URL %q rejected: %v", endpoint, err)
			}
		})
	}

	c := validTrustedMFAConfig()
	c.InternalMTLS = true
	c.KeystoneAssuranceURL = "http://keystone:8080/internal/v1/session-assurance"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "internal_mtls requires an https") {
		t.Fatalf("Validate error = %v, want mTLS downgrade rejection", err)
	}
}

func TestValidateTrustedMFASecretBoundsAndVisibleASCII(t *testing.T) {
	type secretSetter struct {
		name string
		set  func(*Config, string)
	}
	secrets := []secretSetter{
		{
			name: "keystone_assurance_service_token",
			set: func(c *Config, value string) {
				c.KeystoneAssuranceServiceToken = value
			},
		},
		{
			name: "mfa_assertion_hmac_key",
			set: func(c *Config, value string) {
				c.MFAAssertionHMACKey = value
			},
		},
	}
	for _, required := range secrets {
		t.Run(required.name+"/required", func(t *testing.T) {
			c := validTrustedMFAConfig()
			required.set(c, "")
			if err := c.Validate(); err == nil || !strings.Contains(err.Error(), required.name) {
				t.Fatalf("Validate error = %v, want missing required secret rejection", err)
			}
		})
	}

	invalidValues := []struct {
		name string
		make func(byte) string
		want string
	}{
		{name: "31 bytes", make: func(fill byte) string { return strings.Repeat(string(fill), 31) }, want: "between 32 and 512"},
		{name: "513 bytes", make: func(fill byte) string { return strings.Repeat(string(fill), 513) }, want: "between 32 and 512"},
		{name: "space", make: func(fill byte) string { return strings.Repeat(string(fill), 31) + " " }, want: "visible ASCII"},
		{name: "delete", make: func(fill byte) string { return strings.Repeat(string(fill), 31) + "\x7f" }, want: "visible ASCII"},
		{name: "non ASCII", make: func(fill byte) string { return strings.Repeat(string(fill), 30) + "é" }, want: "visible ASCII"},
	}
	for i, secret := range secrets {
		fill := byte('X' + i)
		for _, invalid := range invalidValues {
			t.Run(secret.name+"/reject "+invalid.name, func(t *testing.T) {
				c := validTrustedMFAConfig()
				secret.set(c, invalid.make(fill))
				if err := c.Validate(); err == nil || !strings.Contains(err.Error(), invalid.want) {
					t.Fatalf("Validate error = %v, want %q", err, invalid.want)
				}
			})
		}
		for _, valid := range []struct {
			name  string
			value string
		}{
			{name: "32 visible ASCII bytes", value: strings.Repeat(string(fill), 32)},
			{name: "512 visible ASCII bytes", value: strings.Repeat(string(fill), 512)},
			{name: "visible ASCII endpoints", value: strings.Repeat("!~", 16)},
		} {
			t.Run(secret.name+"/accept "+valid.name, func(t *testing.T) {
				c := validTrustedMFAConfig()
				secret.set(c, valid.value)
				if err := c.Validate(); err != nil {
					t.Fatalf("valid %s rejected: %v", secret.name, err)
				}
			})
		}
	}

}

func TestValidateTrustedMFACredentialsArePairwiseDistinct(t *testing.T) {
	type credentialSetter struct {
		name string
		set  func(*Config, string)
	}
	credentials := []credentialSetter{
		{name: "OIDC client secret", set: func(c *Config, value string) { c.GWClientSecret = value }},
		{name: "gateway session secret", set: func(c *Config, value string) { c.GWSessionSecret = value }},
		{name: "session revocation token", set: func(c *Config, value string) { c.GWSessionRevocationToken = value }},
		{name: "Keystone assurance lookup token", set: func(c *Config, value string) { c.KeystoneAssuranceServiceToken = value }},
		{name: "MFA assertion current key", set: func(c *Config, value string) { c.MFAAssertionHMACKey = value }},
		{name: "audit ingest token", set: func(c *Config, value string) { c.AuditIngestToken = value }},
		{name: "Verdict decision token", set: func(c *Config, value string) { c.VerdictDecisionToken = value }},
		{name: "gateway identity key", set: func(c *Config, value string) { c.GatewayHMACKey = value }},
		{name: "gateway zone key", set: func(c *Config, value string) { c.GatewayZoneHMACKey = value }},
		{name: "gateway authorization key", set: func(c *Config, value string) { c.GatewayAuthzHMACKey = value }},
	}
	shared := strings.Repeat("x", 32)
	for i := 0; i < len(credentials); i++ {
		for j := i + 1; j < len(credentials); j++ {
			left := credentials[i]
			right := credentials[j]
			t.Run(left.name+"/"+right.name, func(t *testing.T) {
				c := validTrustedMFAConfig()
				left.set(c, shared)
				right.set(c, shared)
				if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "must be distinct") {
					t.Fatalf("Validate error = %v, want duplicate credential rejection", err)
				}
			})
		}
	}

	if err := validTrustedMFAConfig().Validate(); err != nil {
		t.Fatalf("pairwise-distinct Trusted MFA credentials rejected: %v", err)
	}
}

func TestSessionRevocationTokenMustBeStrongAndDistinct(t *testing.T) {
	for _, test := range []struct {
		name  string
		apply func(*Config)
	}{
		{
			name: "too short",
			apply: func(config *Config) {
				config.GWSessionRevocationToken = "short"
			},
		},
		{
			name: "reuses session secret",
			apply: func(config *Config) {
				config.GWSessionSecret = "shared-credential-that-is-at-least-32-bytes"
				config.GWSessionRevocationToken = config.GWSessionSecret
			},
		},
		{
			name: "reuses authorization key",
			apply: func(config *Config) {
				config.GatewayAuthzHMACKey = "shared-credential-that-is-at-least-32-bytes"
				config.GWSessionRevocationToken = config.GatewayAuthzHMACKey
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := minimalValid()
			test.apply(config)
			if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "gw_session_revocation_token") {
				t.Fatalf("Validate error = %v, want revocation-token rejection", err)
			}
		})
	}

	valid := minimalValid()
	valid.GWSessionSecret = "session-secret-that-is-at-least-32-bytes"
	valid.GWSessionRevocationToken = "independent-revocation-token-at-least-32-bytes"
	if err := valid.Validate(); err != nil {
		t.Fatalf("independent token rejected: %v", err)
	}
}

// CookieDomain defaults to the parent registrable domain (one login spans every
// subdomain) and is overridable via COOKIE_DOMAIN.
func TestCookieDomainDefaultAndOverride(t *testing.T) {
	def := minimalValid()
	def.ApplyEnv()
	if err := def.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if def.CookieDomain != DefaultCookieDomain {
		t.Errorf("CookieDomain = %q, want default %q", def.CookieDomain, DefaultCookieDomain)
	}

	t.Setenv(EnvCookieDomain, ".example.test")
	c := minimalValid()
	c.ApplyEnv()
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if c.CookieDomain != ".example.test" {
		t.Errorf("CookieDomain = %q, want .example.test (env override)", c.CookieDomain)
	}
}

// Audit env overrides apply, and AuditEnabled stays OFF by default (so the
// gateway emits nothing unless explicitly toggled on).
func TestApplyEnvAuditOverrides(t *testing.T) {
	def := minimalValid()
	def.ApplyEnv()
	if err := def.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if def.AuditEnabled {
		t.Error("AuditEnabled must default OFF")
	}

	t.Setenv(EnvAuditEnabled, "on")
	t.Setenv(EnvWatchtowerURL, "http://watchtower:8500")
	t.Setenv(EnvAuditIngestToken, "ingest-token")

	c := minimalValid()
	c.ApplyEnv()
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !c.AuditEnabled {
		t.Error("AuditEnabled = false, want true")
	}
	if c.WatchtowerURL != "http://watchtower:8500" {
		t.Errorf("WatchtowerURL = %q, want http://watchtower:8500", c.WatchtowerURL)
	}
	if c.AuditIngestToken != "ingest-token" {
		t.Errorf("AuditIngestToken = %q, want ingest-token", c.AuditIngestToken)
	}
}

func TestApplyEnvVerdictDecisionToken(t *testing.T) {
	t.Setenv(EnvRBACEnabled, "on")
	t.Setenv(EnvVerdictURL, "http://verdict:9140")
	t.Setenv(EnvVerdictDecisionToken, strings.Repeat("d", 32))
	// The retired broad token must not be accepted as a compatibility fallback.
	t.Setenv("VERDICT_SERVICE_TOKEN", strings.Repeat("l", 32))

	c := minimalValid()
	c.ApplyEnv()
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if c.VerdictDecisionToken != strings.Repeat("d", 32) {
		t.Fatalf("VerdictDecisionToken = %q, want scoped env value", c.VerdictDecisionToken)
	}
}

func TestValidateRBACRequiresScopedDecisionCredential(t *testing.T) {
	validToken := strings.Repeat("d", 32)
	for _, test := range []struct {
		name  string
		apply func(*Config)
		want  string
	}{
		{
			name: "missing url",
			apply: func(config *Config) {
				config.VerdictDecisionToken = validToken
			},
			want: "verdict_url",
		},
		{
			name: "relative url",
			apply: func(config *Config) {
				config.VerdictURL = "verdict:9140"
				config.VerdictDecisionToken = validToken
			},
			want: "absolute verdict_url",
		},
		{
			name: "missing token",
			apply: func(config *Config) {
				config.VerdictURL = "http://verdict:9140"
			},
			want: "verdict_decision_token",
		},
		{
			name: "short token",
			apply: func(config *Config) {
				config.VerdictURL = "http://verdict:9140"
				config.VerdictDecisionToken = "short"
			},
			want: "between 32 and 512",
		},
		{
			name: "oversized token",
			apply: func(config *Config) {
				config.VerdictURL = "http://verdict:9140"
				config.VerdictDecisionToken = strings.Repeat("d", 513)
			},
			want: "between 32 and 512",
		},
		{
			name: "non-visible token",
			apply: func(config *Config) {
				config.VerdictURL = "http://verdict:9140"
				config.VerdictDecisionToken = strings.Repeat("d", 31) + "\n"
			},
			want: "visible ASCII",
		},
		{
			name: "reused gateway credential",
			apply: func(config *Config) {
				config.VerdictURL = "http://verdict:9140"
				config.VerdictDecisionToken = validToken
				config.GatewayHMACKey = validToken
			},
			want: "must be distinct",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := minimalValid()
			config.RBACEnabled = true
			test.apply(config)
			if err := config.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate error = %v, want %q", err, test.want)
			}
		})
	}

	valid := minimalValid()
	valid.RBACEnabled = true
	valid.VerdictURL = "http://verdict:9140"
	valid.VerdictDecisionToken = validToken
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid scoped decision credential rejected: %v", err)
	}
}

func TestGatewayDefaults(t *testing.T) {
	t.Setenv(EnvGatewayZone, "")

	c := minimalValid()
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if c.OIDCIssuer != c.KeystoneIssuer {
		t.Errorf("OIDCIssuer = %q, want default = KeystoneIssuer %q", c.OIDCIssuer, c.KeystoneIssuer)
	}
	if c.GWSessionTTL != DefaultGWSessionTTL {
		t.Errorf("GWSessionTTL = %v, want %v", c.GWSessionTTL, DefaultGWSessionTTL)
	}
	if c.KeystoneTLSServerName != "keystone" {
		t.Errorf("KeystoneTLSServerName = %q, want keystone", c.KeystoneTLSServerName)
	}
	if c.GWOIDCEnabled || c.InternalMTLS {
		t.Error("OIDC/mTLS must default OFF")
	}
	if c.GatewayZone != DefaultGatewayZone {
		t.Errorf("GatewayZone = %q, want default %q", c.GatewayZone, DefaultGatewayZone)
	}
}

func TestApplyEnvGatewayZoneOverride(t *testing.T) {
	t.Setenv(EnvGatewayZone, GatewayZoneInternal)
	t.Setenv(EnvGatewayZoneHMACKey, "zone-context-key")

	c := minimalValid()
	c.ApplyEnv()
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if c.GatewayZone != GatewayZoneInternal {
		t.Errorf("GatewayZone = %q, want %q", c.GatewayZone, GatewayZoneInternal)
	}
	if c.GatewayZoneHMACKey != "zone-context-key" {
		t.Errorf("GatewayZoneHMACKey = %q, want env override", c.GatewayZoneHMACKey)
	}
}

func TestValidateRejectsReusedGatewayContextKey(t *testing.T) {
	c := minimalValid()
	c.GatewayHMACKey = "shared-key"
	c.GatewayZoneHMACKey = "shared-key"

	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "must be distinct") {
		t.Fatalf("Validate error = %v, want distinct gateway HMAC keys error", err)
	}
}

func TestValidateRejectsReusedAuthorizationContextKey(t *testing.T) {
	for _, configure := range []func(*Config){
		func(config *Config) {
			config.GatewayHMACKey = "shared-key"
			config.GatewayAuthzHMACKey = "shared-key"
		},
		func(config *Config) {
			config.GatewayZoneHMACKey = "shared-key"
			config.GatewayAuthzHMACKey = "shared-key"
		},
	} {
		config := minimalValid()
		configure(config)
		if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "must be distinct") {
			t.Fatalf("Validate error = %v, want distinct authorization HMAC key", err)
		}
	}
}

func TestApplyEnvAuthorizationContextV2Rotation(t *testing.T) {
	t.Setenv(EnvGatewayAuthzContextV2HMACKIDCurrent, "authz2-2026a")
	t.Setenv(EnvGatewayAuthzContextV2HMACKeyCurrent, strings.Repeat("c", 32))
	t.Setenv(EnvGatewayAuthzContextV2HMACKIDPrevious, "authz2-2025h")
	t.Setenv(EnvGatewayAuthzContextV2HMACKeyPrevious, strings.Repeat("p", 32))

	c := minimalValid()
	c.ApplyEnv()
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !c.AuthorizationContextV2Enabled() ||
		c.GatewayAuthzContextV2HMACKIDCurrent != "authz2-2026a" ||
		c.GatewayAuthzContextV2HMACKIDPrevious != "authz2-2025h" {
		t.Fatalf("v2 rotation env was not loaded atomically: %+v", c)
	}
}

func TestValidateAuthorizationContextV2RejectsTornDuplicateAndReusedBindings(t *testing.T) {
	valid := func() *Config {
		c := minimalValid()
		c.GatewayAuthzContextV2HMACKIDCurrent = "authz2-2026a"
		c.GatewayAuthzContextV2HMACKeyCurrent = strings.Repeat("c", 32)
		c.GatewayAuthzContextV2HMACKIDPrevious = "authz2-2025h"
		c.GatewayAuthzContextV2HMACKeyPrevious = strings.Repeat("p", 32)
		return c
	}
	for _, test := range []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "missing current kid", mutate: func(c *Config) { c.GatewayAuthzContextV2HMACKIDCurrent = "" }},
		{name: "missing current key", mutate: func(c *Config) { c.GatewayAuthzContextV2HMACKeyCurrent = "" }},
		{name: "missing previous kid", mutate: func(c *Config) { c.GatewayAuthzContextV2HMACKIDPrevious = "" }},
		{name: "missing previous key", mutate: func(c *Config) { c.GatewayAuthzContextV2HMACKeyPrevious = "" }},
		{name: "duplicate kid", mutate: func(c *Config) { c.GatewayAuthzContextV2HMACKIDPrevious = c.GatewayAuthzContextV2HMACKIDCurrent }},
		{name: "duplicate key", mutate: func(c *Config) { c.GatewayAuthzContextV2HMACKeyPrevious = c.GatewayAuthzContextV2HMACKeyCurrent }},
		{name: "invalid kid", mutate: func(c *Config) { c.GatewayAuthzContextV2HMACKIDCurrent = "Authz2 Current" }},
		{name: "short key", mutate: func(c *Config) { c.GatewayAuthzContextV2HMACKeyCurrent = "short" }},
		{name: "legacy key reuse", mutate: func(c *Config) { c.GatewayAuthzHMACKey = c.GatewayAuthzContextV2HMACKeyCurrent }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := valid()
			test.mutate(c)
			if err := c.Validate(); err == nil {
				t.Fatalf("invalid v2 rotation accepted: %+v", c)
			}
		})
	}

	currentOnly := valid()
	currentOnly.GatewayAuthzContextV2HMACKIDPrevious = ""
	currentOnly.GatewayAuthzContextV2HMACKeyPrevious = ""
	if err := currentOnly.Validate(); err != nil {
		t.Fatalf("current-only rotation rejected: %v", err)
	}
}

func TestAuthorizationContextV2PermissionRouteRequiresExactHost(t *testing.T) {
	build := func(host string) *Config {
		c := minimalValid()
		c.Routes[0].Auth = AuthSSO
		c.Routes[0].Match.Host = host
		c.Routes[0].RequirePermission = "cpa.console.enter"
		c.GatewayAuthzContextV2HMACKIDCurrent = "authz2-2026a"
		c.GatewayAuthzContextV2HMACKeyCurrent = strings.Repeat("c", 32)
		return c
	}
	if err := build("").Validate(); err == nil || !strings.Contains(err.Error(), "exact lowercase host") {
		t.Fatalf("hostless v2 permission route error = %v", err)
	}
	if err := build("cpa.w33d.xyz").Validate(); err != nil {
		t.Fatalf("exact-host v2 permission route rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "noncanonical route", mutate: func(c *Config) { c.Routes[0].Name = "CPA Root" }},
		{name: "noncanonical resource", mutate: func(c *Config) { c.Routes[0].PermissionResource = "route:folders/1" }},
		{name: "any resource", mutate: func(c *Config) { c.Routes[0].PermissionResource = "any:everything" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := build("cpa.w33d.xyz")
			test.mutate(c)
			if err := c.Validate(); err == nil {
				t.Fatalf("noncanonical v2 route accepted: %+v", c.Routes[0])
			}
		})
	}
}

func TestValidateRejectsMissingUpstream(t *testing.T) {
	c := &Config{
		KeystoneIssuer: "http://127.0.0.1:8080",
		Routes: []Route{
			{Name: "bad", Match: Match{PathPrefix: "/api"}, Upstream: ""},
		},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for missing upstream, got nil")
	}
}

func TestValidateRejectsMissingPathPrefix(t *testing.T) {
	c := &Config{
		KeystoneIssuer: "http://127.0.0.1:8080",
		Routes: []Route{
			{Name: "bad", Match: Match{PathPrefix: ""}, Upstream: "http://127.0.0.1:8081"},
		},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for missing path_prefix, got nil")
	}
}

func TestValidateRejectsRelativeUpstream(t *testing.T) {
	c := &Config{
		KeystoneIssuer: "http://127.0.0.1:8080",
		Routes: []Route{
			{Name: "bad", Match: Match{PathPrefix: "/api"}, Upstream: "not-a-url"},
		},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for non-absolute upstream, got nil")
	}
}

func TestDiscoveryURLDerivedFromIssuer(t *testing.T) {
	c := &Config{
		KeystoneIssuer: "http://127.0.0.1:8080",
		Routes: []Route{
			{Name: "ok", Match: Match{PathPrefix: "/api"}, Upstream: "http://127.0.0.1:8081"},
		},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate error: %v", err)
	}
	want := "http://127.0.0.1:8080/.well-known/openid-configuration"
	if c.DiscoveryURL != want {
		t.Errorf("DiscoveryURL = %q, want %q", c.DiscoveryURL, want)
	}
}

func TestDiscoveryURLOverrideRespected(t *testing.T) {
	c := &Config{
		KeystoneIssuer: "http://127.0.0.1:8080",
		DiscoveryURL:   "http://example.test/custom-discovery",
		Routes: []Route{
			{Name: "ok", Match: Match{PathPrefix: "/api"}, Upstream: "http://127.0.0.1:8081"},
		},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate error: %v", err)
	}
	if c.DiscoveryURL != "http://example.test/custom-discovery" {
		t.Errorf("DiscoveryURL override not respected: %q", c.DiscoveryURL)
	}
}
