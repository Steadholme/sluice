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
	JWKSRefreshInterval  time.Duration `json:"jwks_refresh_interval"`
	JWKSRotationCooldown time.Duration `json:"jwks_rotation_cooldown"`
	Routes               []Route       `json:"routes"`
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
		c.DiscoveryURL = ""
	}
	if v := os.Getenv(EnvJWKSRotationCooldown); v != "" {
		// Go duration string (e.g. "5s"); a malformed value is treated as unset so
		// Validate applies DefaultJWKSRotationCooldown.
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			c.JWKSRotationCooldown = d
		}
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

func routeName(r *Route, i int) string {
	if r.Name != "" {
		return r.Name
	}
	return fmt.Sprintf("#%d", i)
}
