package config

import (
	"path/filepath"
	"testing"
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
