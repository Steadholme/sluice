// Package config loads and validates the Sluice gateway configuration.
//
// The configuration is a JSON file describing the listen address, the expected
// Keystone (OIDC) issuer, and a static route table. In v0 the route table is
// read once into memory; the store package owns the seam where a future
// CDC/FusionDB-backed route source can plug in without touching this loader.
package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// Default values mirror the shared integration contract: Sluice binds
// 127.0.0.1:9090 and trusts a Keystone issuer at 127.0.0.1:8080.
const (
	DefaultListenAddr          = "127.0.0.1:9090"
	DefaultKeystoneIssuer      = "http://127.0.0.1:8080"
	DefaultJWKSRefreshInterval = 5 * time.Minute
	// DefaultHTTPAddr / DefaultHTTPSAddr are the bind addresses used only when
	// TLS is enabled (TLS_MODE=file|acme). :80 serves the ACME HTTP-01 challenge
	// and HTTP->HTTPS redirect; :443 serves the TLS-terminated gateway. In off
	// mode neither is used and the gateway binds the single plain ListenAddr.
	DefaultHTTPAddr  = ":80"
	DefaultHTTPSAddr = ":443"
	// DefaultACMECacheDir is the autocert cache directory (issued certs + account
	// key). It is a Docker VOLUME owned by the non-root runtime user.
	DefaultACMECacheDir = "/acme"
	// DefaultJWKSRotationCooldown is the SHORT reactive cooldown after a
	// successful JWKS refresh during which a healthy cache treats an unknown kid
	// as a garbage-kid storm; past it an unknown kid is assumed to be a real
	// signing-key rotation and refetched. Decoupled from (and much shorter than)
	// JWKSRefreshInterval so a rotated Keystone kid is picked up within seconds.
	DefaultJWKSRotationCooldown = 5 * time.Second
	// discoverySuffix is appended to the issuer to derive the OIDC discovery
	// document URL when DiscoveryURL is not explicitly configured.
	discoverySuffix = "/.well-known/openid-configuration"
)

// Environment variable names that override the dev-contract defaults. They are
// applied by ApplyEnv before Validate, so an unset variable keeps the file/built
// in default unchanged.
const (
	EnvListenAddr     = "LISTEN_ADDR"     // overrides listen_addr
	EnvKeystoneIssuer = "KEYSTONE_ISSUER" // overrides keystone_issuer (and re-derives discovery)
	EnvStore          = "SLUICE_STORE"    // route store kind: static|postgres (default static)
	EnvDatabaseURL    = "DATABASE_URL"    // postgres DSN (postgres store)
	EnvRoutesSeed     = "ROUTES_SEED"     // path to a routes seed config (postgres store)
	// EnvJWKSRotationCooldown overrides jwks_rotation_cooldown, the SHORT reactive
	// kid-miss refresh cooldown. Accepts a Go duration string (e.g. "5s"); a
	// malformed value is treated as unset so the default still applies.
	EnvJWKSRotationCooldown = "JWKS_ROTATION_COOLDOWN"

	// TLS / public-exposure knobs. TLS_MODE selects how Sluice terminates TLS;
	// the rest configure the file and acme modes and the :80/:443 bind addrs.
	EnvTLSMode          = "TLS_MODE"           // off | file | acme (default off)
	EnvTLSCertFile      = "TLS_CERT_FILE"      // file mode: PEM certificate (chain)
	EnvTLSKeyFile       = "TLS_KEY_FILE"       // file mode: PEM private key
	EnvACMEDomain       = "ACME_DOMAIN"        // acme mode: the single allowed host (HostPolicy)
	EnvACMEEmail        = "ACME_EMAIL"         // acme mode: ACME account contact email
	EnvACMECacheDir     = "ACME_CACHE_DIR"     // acme mode: autocert.DirCache directory
	EnvACMEDirectoryURL = "ACME_DIRECTORY_URL" // acme mode: optional ACME directory (e.g. LE staging)
	EnvHTTPAddr         = "HTTP_ADDR"          // tls modes: :80 ACME-challenge + redirect bind
	EnvHTTPSAddr        = "HTTPS_ADDR"         // tls modes: :443 HTTPS bind

	// Issuer-vs-internal-fetch overrides. KEYSTONE_ISSUER stays the PUBLIC issuer
	// used for JWT iss validation; these two let Sluice FETCH discovery/JWKS from
	// the INTERNAL Keystone (e.g. http://keystone:8080) to avoid a TLS loopback.
	EnvDiscoveryURL = "OIDC_DISCOVERY_URL" // overrides discovery_url (discovery doc fetch URL)
	EnvJWKSFetchURL = "JWKS_FETCH_URL"     // direct jwks_uri; bypasses discovery entirely
)

// TLS termination modes selectable via EnvTLSMode.
const (
	TLSModeOff  = "off"  // plain HTTP on ListenAddr (dev default; unchanged behavior)
	TLSModeFile = "file" // HTTPS from TLS_CERT_FILE/TLS_KEY_FILE on HTTPSAddr
	TLSModeACME = "acme" // HTTPS via Let's Encrypt autocert on HTTPSAddr
)

// Store kinds selectable via EnvStore.
const (
	StoreStatic   = "static"
	StorePostgres = "postgres"
)

// Match describes how an incoming request is matched to a Route.
//
// Host is optional: when set it must equal the request Host exactly. PathPrefix
// is required and participates in longest-prefix-wins routing.
type Match struct {
	Host       string `json:"host,omitempty"`
	PathPrefix string `json:"path_prefix"`
}

// Route is a single proxy rule: requests matching Match are streamed to
// Upstream. When Protected is true the forward-auth middleware enforces a valid
// Keystone-issued RS256 bearer token before proxying.
type Route struct {
	Name      string `json:"name"`
	Match     Match  `json:"match"`
	Upstream  string `json:"upstream"`
	Protected bool   `json:"protected"`

	// upstreamURL is the parsed form of Upstream, populated by Validate so the
	// data path never re-parses on the hot path. Unexported so it is not part
	// of the JSON surface.
	upstreamURL *url.URL
}

// UpstreamURL returns the parsed upstream target. It is only valid after the
// owning Config has passed Validate.
func (r *Route) UpstreamURL() *url.URL { return r.upstreamURL }

// Config is the top-level Sluice configuration.
type Config struct {
	ListenAddr           string        `json:"listen_addr"`
	KeystoneIssuer       string        `json:"keystone_issuer"`
	DiscoveryURL         string        `json:"discovery_url"`
	JWKSFetchURL         string        `json:"jwks_fetch_url"`
	JWKSRefreshInterval  time.Duration `json:"jwks_refresh_interval"`
	JWKSRotationCooldown time.Duration `json:"jwks_rotation_cooldown"`

	// TLS termination + public exposure. Defaults keep TLSMode=off so existing
	// deployments and tests bind a single plain HTTP listener on ListenAddr.
	TLSMode          string `json:"tls_mode"`
	TLSCertFile      string `json:"tls_cert_file"`
	TLSKeyFile       string `json:"tls_key_file"`
	ACMEDomain       string `json:"acme_domain"`
	ACMEEmail        string `json:"acme_email"`
	ACMECacheDir     string `json:"acme_cache_dir"`
	ACMEDirectoryURL string `json:"acme_directory_url"`
	HTTPAddr         string `json:"http_addr"`
	HTTPSAddr        string `json:"https_addr"`

	Routes []Route `json:"routes"`
}

// parseFile reads and JSON-decodes a configuration file without validating it.
func parseFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	return &c, nil
}

// LoadFile reads and validates a configuration file from disk.
func LoadFile(path string) (*Config, error) {
	c, err := parseFile(path)
	if err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("config: validate %s: %w", path, err)
	}
	return c, nil
}

// LoadFileWithEnv reads a configuration file, applies environment overrides
// (ApplyEnv), then validates. This is the entrypoint used by the binary so that
// every dev-contract default is overridable by env while staying unchanged when
// the env is unset.
func LoadFileWithEnv(path string) (*Config, error) {
	c, err := parseFile(path)
	if err != nil {
		return nil, err
	}
	c.ApplyEnv()
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("config: validate %s: %w", path, err)
	}
	return c, nil
}

// ApplyEnv overlays environment overrides onto the configuration. It must be
// called before Validate. Unset variables leave the existing value untouched.
// Overriding the issuer clears any derived discovery URL so Validate re-derives
// it from the new issuer.
func (c *Config) ApplyEnv() {
	if v := os.Getenv(EnvListenAddr); v != "" {
		c.ListenAddr = v
	}
	if v := os.Getenv(EnvKeystoneIssuer); v != "" {
		c.KeystoneIssuer = v
		// Re-derive discovery from the new issuer (Validate does this when empty).
		// An explicit OIDC_DISCOVERY_URL below still wins because it is applied
		// after this reset.
		c.DiscoveryURL = ""
	}
	// Issuer-vs-internal-fetch overrides. These point Sluice at the INTERNAL
	// Keystone for fetching discovery/JWKS without changing the PUBLIC iss above.
	if v := os.Getenv(EnvDiscoveryURL); v != "" {
		c.DiscoveryURL = v
	}
	if v := os.Getenv(EnvJWKSFetchURL); v != "" {
		c.JWKSFetchURL = v
	}
	if v := os.Getenv(EnvJWKSRotationCooldown); v != "" {
		// Go duration string (e.g. "5s"); a malformed value is treated as unset so
		// Validate applies DefaultJWKSRotationCooldown.
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			c.JWKSRotationCooldown = d
		}
	}
	// TLS / public-exposure overrides.
	if v := os.Getenv(EnvTLSMode); v != "" {
		c.TLSMode = v
	}
	if v := os.Getenv(EnvTLSCertFile); v != "" {
		c.TLSCertFile = v
	}
	if v := os.Getenv(EnvTLSKeyFile); v != "" {
		c.TLSKeyFile = v
	}
	if v := os.Getenv(EnvACMEDomain); v != "" {
		c.ACMEDomain = v
	}
	if v := os.Getenv(EnvACMEEmail); v != "" {
		c.ACMEEmail = v
	}
	if v := os.Getenv(EnvACMECacheDir); v != "" {
		c.ACMECacheDir = v
	}
	if v := os.Getenv(EnvACMEDirectoryURL); v != "" {
		c.ACMEDirectoryURL = v
	}
	if v := os.Getenv(EnvHTTPAddr); v != "" {
		c.HTTPAddr = v
	}
	if v := os.Getenv(EnvHTTPSAddr); v != "" {
		c.HTTPSAddr = v
	}
}

// Validate applies defaults, parses upstream URLs, derives the discovery URL,
// and rejects structurally invalid routes. It mutates the receiver in place so
// that callers receive a ready-to-use configuration.
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		c.ListenAddr = DefaultListenAddr
	}
	if c.KeystoneIssuer == "" {
		c.KeystoneIssuer = DefaultKeystoneIssuer
	}
	if c.JWKSRefreshInterval <= 0 {
		c.JWKSRefreshInterval = DefaultJWKSRefreshInterval
	}
	if c.JWKSRotationCooldown <= 0 {
		c.JWKSRotationCooldown = DefaultJWKSRotationCooldown
	}
	if _, err := url.Parse(c.KeystoneIssuer); err != nil {
		return fmt.Errorf("invalid keystone_issuer %q: %w", c.KeystoneIssuer, err)
	}
	// Derive the OIDC discovery URL from the issuer when not overridden.
	if c.DiscoveryURL == "" {
		c.DiscoveryURL = strings.TrimRight(c.KeystoneIssuer, "/") + discoverySuffix
	}

	if err := c.validateTLS(); err != nil {
		return err
	}

	if len(c.Routes) == 0 {
		return fmt.Errorf("no routes configured")
	}
	for i := range c.Routes {
		r := &c.Routes[i]
		if r.Upstream == "" {
			return fmt.Errorf("route %q: empty upstream", routeName(r, i))
		}
		if r.Match.PathPrefix == "" {
			return fmt.Errorf("route %q: empty match.path_prefix", routeName(r, i))
		}
		u, err := url.Parse(r.Upstream)
		if err != nil {
			return fmt.Errorf("route %q: invalid upstream %q: %w", routeName(r, i), r.Upstream, err)
		}
		if u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("route %q: upstream %q must be an absolute URL", routeName(r, i), r.Upstream)
		}
		r.upstreamURL = u
	}
	return nil
}

// validateTLS applies TLS defaults and enforces the per-mode required fields. It
// is called from Validate after the issuer/discovery wiring. Defaults keep
// TLSMode=off so an unset configuration binds a single plain HTTP listener and
// every existing test/deployment is unchanged.
func (c *Config) validateTLS() error {
	if c.TLSMode == "" {
		c.TLSMode = TLSModeOff
	}
	c.TLSMode = strings.ToLower(c.TLSMode)
	if c.HTTPAddr == "" {
		c.HTTPAddr = DefaultHTTPAddr
	}
	if c.HTTPSAddr == "" {
		c.HTTPSAddr = DefaultHTTPSAddr
	}
	if c.ACMECacheDir == "" {
		c.ACMECacheDir = DefaultACMECacheDir
	}

	switch c.TLSMode {
	case TLSModeOff:
		// Plain HTTP on ListenAddr; nothing else required.
	case TLSModeFile:
		if c.TLSCertFile == "" || c.TLSKeyFile == "" {
			return fmt.Errorf("tls_mode=file requires tls_cert_file and tls_key_file")
		}
	case TLSModeACME:
		if c.ACMEDomain == "" {
			return fmt.Errorf("tls_mode=acme requires acme_domain")
		}
	default:
		return fmt.Errorf("invalid tls_mode %q (want %s|%s|%s)", c.TLSMode, TLSModeOff, TLSModeFile, TLSModeACME)
	}
	return nil
}

func routeName(r *Route, i int) string {
	if r.Name != "" {
		return r.Name
	}
	return fmt.Sprintf("#%d", i)
}
