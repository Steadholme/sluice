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
	"strconv"
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

// Per-route authentication modes (Route.Auth). They generalise the legacy
// boolean Protected: "public" == not protected, "bearer" == the existing
// forward-auth (Authorization: Bearer RS256 JWT) API path, and "sso" == the new
// OIDC BROWSER SSO path (gateway session cookie, redirect to Keystone login).
const (
	AuthPublic = "public"
	AuthBearer = "bearer"
	AuthSSO    = "sso"
)

// OIDC browser-SSO + internal-mTLS environment variables. All are off by default
// so an unset deployment keeps the pure bearer/public, plain-http behavior.
const (
	EnvGWOIDC          = "GW_OIDC"           // on|off — enable the OIDC browser-SSO relying party
	EnvOIDCIssuer      = "OIDC_ISSUER"       // PUBLIC issuer for the authorize redirect + id_token iss/aud (default = KEYSTONE_ISSUER)
	EnvGWClientID      = "GW_CLIENT_ID"      // gateway OIDC client_id registered in Keystone
	EnvGWClientSecret  = "GW_CLIENT_SECRET"  // gateway client secret (client_secret_post at the token endpoint)
	EnvGWRedirectURI   = "GW_REDIRECT_URI"   // PUBLIC redirect_uri, e.g. https://id.w33d.xyz/_gw/auth/callback
	EnvGWTokenURL      = "GW_TOKEN_URL"      // INTERNAL token endpoint (mTLS), e.g. https://keystone:8443/token
	EnvGWSessionTTL    = "GW_SESSION_TTL"    // gateway session lifetime (Go duration; default 8h)
	EnvGWSessionSecret = "GW_SESSION_SECRET" // HMAC key signing the opaque __Secure-gw cookie id
	EnvCookieDomain    = "COOKIE_DOMAIN"     // Domain attribute for the gateway session cookie (default .w33d.xyz)

	EnvInternalMTLS          = "INTERNAL_MTLS"           // on|off — mTLS for the internal Keystone hop
	EnvKeystoneMTLSCert      = "KEYSTONE_MTLS_CERT"      // client cert PEM (Keyward CN=sluice)
	EnvKeystoneMTLSKey       = "KEYSTONE_MTLS_KEY"       // client key PEM
	EnvKeystoneMTLSCA        = "KEYSTONE_MTLS_CA"        // trust anchor PEM (Keyward root)
	EnvKeystoneTLSServerName = "KEYSTONE_TLS_SERVERNAME" // pinned server name (default "keystone")
)

// Audit (Watchtower) environment variables. All optional; AUDIT_ENABLED defaults
// off so existing dev/tests are unchanged. When off, no audit events are emitted.
const (
	EnvAuditEnabled     = "AUDIT_ENABLED"      // on|off — emit security audit events to Watchtower (default off)
	EnvWatchtowerURL    = "WATCHTOWER_URL"     // Watchtower base URL, e.g. http://watchtower:8500
	EnvAuditIngestToken = "AUDIT_INGEST_TOKEN" // bearer credential for POST /events
)

// WAF (Aegis inline WAF + rate limiter) environment variables. All optional;
// WAF_ENABLED defaults OFF so the public ingress keeps its exact current
// behavior. Even when enabled the WAF only engages on routes opted in with
// waf=true, so an unset deployment is a pure pass-through.
const (
	EnvWAFEnabled      = "WAF_ENABLED"        // on|off — enable the inline WAF + rate limiter (default off)
	EnvWAFThreshold    = "WAF_THRESHOLD"      // int — block when the accumulated rule score >= threshold
	EnvWAFRateBurst    = "WAF_RATE_BURST"     // int — max requests per client within the rate window (0 disables rate limiting)
	EnvWAFRateWindow   = "WAF_RATE_WINDOW"    // Go duration — sliding rate-limit window (e.g. "1m")
	EnvWAFMaxBodyBytes = "WAF_MAX_BODY_BYTES" // int64 — request body inspection/size cap in bytes (0 disables the cap)
	EnvWAFUploadTypes  = "WAF_UPLOAD_TYPES"   // comma list — allowed upload content-types; empty allows all
)

// WAF defaults. The threshold matches the embedded ruleset, where a single
// critical detection (score 5) blocks; the rate window/burst default to a
// generous 120 requests/minute per client; the body cap defaults to 10 MiB.
const (
	DefaultWAFThreshold    = 5
	DefaultWAFRateBurst    = 120
	DefaultWAFRateWindow   = time.Minute
	DefaultWAFMaxBodyBytes = 10 << 20 // 10 MiB
)

// DefaultGWSessionTTL is the gateway browser-session lifetime when unset.
const DefaultGWSessionTTL = 8 * time.Hour

// DefaultCookieDomain scopes the gateway session cookie to the parent registrable
// domain so one login covers every *.w33d.xyz subdomain (cross-subdomain SSO).
const DefaultCookieDomain = ".w33d.xyz"

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

	// Auth is the per-route authentication mode: "public" | "bearer" | "sso".
	// It is optional and normalised by Validate: an empty value is derived from
	// the legacy Protected boolean (true -> "bearer", false -> "public"), so
	// existing configs and route rows keep their exact behavior. Protected is in
	// turn re-synced to (Auth != "public") for any legacy reader.
	Auth string `json:"auth,omitempty"`

	// Waf opts this route into the inline WAF + rate limiter (Aegis). It is
	// OPTIONAL and defaults off: an absent field in routes.seed.json (or a
	// pre-existing route row) parses to false, so the WAF never engages unless a
	// route is explicitly flagged AND WAF_ENABLED is on. This keeps the public
	// ingress behavior identical until both switches are set.
	Waf bool `json:"waf,omitempty"`

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

	// OIDC browser-SSO relying party. Off by default (GWOIDCEnabled=false) so the
	// gateway stays a pure bearer/public forward-auth. When enabled, sso routes
	// gate the BROWSER through Keystone's login; the token/JWKS calls go INTERNAL
	// (optionally over mTLS) while the user-facing authorize redirect uses the
	// PUBLIC OIDCIssuer.
	GWOIDCEnabled   bool          `json:"gw_oidc_enabled"`
	OIDCIssuer      string        `json:"oidc_issuer"`
	GWClientID      string        `json:"gw_client_id"`
	GWClientSecret  string        `json:"gw_client_secret"`
	GWRedirectURI   string        `json:"gw_redirect_uri"`
	GWTokenURL      string        `json:"gw_token_url"`
	GWSessionTTL    time.Duration `json:"gw_session_ttl"`
	GWSessionSecret string        `json:"gw_session_secret"`
	// CookieDomain is the Domain attribute of the gateway session cookie. Default
	// .w33d.xyz makes one login span every subdomain; an explicit empty value (via
	// COOKIE_DOMAIN="") keeps the cookie host-only.
	CookieDomain string `json:"cookie_domain"`

	// Internal mTLS to Keystone. Off by default; when on, the gateway presents a
	// Keyward client cert on the internal hop (proxy upstream + token/JWKS).
	InternalMTLS          bool   `json:"internal_mtls"`
	KeystoneMTLSCert      string `json:"keystone_mtls_cert"`
	KeystoneMTLSKey       string `json:"keystone_mtls_key"`
	KeystoneMTLSCA        string `json:"keystone_mtls_ca"`
	KeystoneTLSServerName string `json:"keystone_tls_servername"`

	// Audit to Watchtower. Off by default (AuditEnabled=false) so the gateway
	// emits nothing and behavior is unchanged. When on, security-relevant gateway
	// actions are fire-and-forget POSTed to WatchtowerURL with AuditIngestToken.
	AuditEnabled     bool   `json:"audit_enabled"`
	WatchtowerURL    string `json:"watchtower_url"`
	AuditIngestToken string `json:"audit_ingest_token"`

	// WAF (Aegis). Off by default (WAFEnabled=false) so the gateway is a pure
	// pass-through and the public ingress is unchanged. When on, only routes with
	// Waf=true are inspected. Threshold/rate/body-cap defaults are applied by
	// Validate.
	WAFEnabled      bool          `json:"waf_enabled"`
	WAFThreshold    int           `json:"waf_threshold"`
	WAFRateBurst    int           `json:"waf_rate_burst"`
	WAFRateWindow   time.Duration `json:"waf_rate_window"`
	WAFMaxBodyBytes int64         `json:"waf_max_body_bytes"`
	WAFUploadTypes  []string      `json:"waf_upload_types"`

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

	// OIDC browser-SSO overrides.
	if v := os.Getenv(EnvGWOIDC); v != "" {
		c.GWOIDCEnabled = envOn(v)
	}
	if v := os.Getenv(EnvOIDCIssuer); v != "" {
		c.OIDCIssuer = v
	}
	if v := os.Getenv(EnvGWClientID); v != "" {
		c.GWClientID = v
	}
	if v := os.Getenv(EnvGWClientSecret); v != "" {
		c.GWClientSecret = v
	}
	if v := os.Getenv(EnvGWRedirectURI); v != "" {
		c.GWRedirectURI = v
	}
	if v := os.Getenv(EnvGWTokenURL); v != "" {
		c.GWTokenURL = v
	}
	if v := os.Getenv(EnvGWSessionTTL); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			c.GWSessionTTL = d
		}
	}
	if v := os.Getenv(EnvGWSessionSecret); v != "" {
		c.GWSessionSecret = v
	}
	if v := os.Getenv(EnvCookieDomain); v != "" {
		c.CookieDomain = v
	}

	// Internal mTLS overrides.
	if v := os.Getenv(EnvInternalMTLS); v != "" {
		c.InternalMTLS = envOn(v)
	}
	if v := os.Getenv(EnvKeystoneMTLSCert); v != "" {
		c.KeystoneMTLSCert = v
	}
	if v := os.Getenv(EnvKeystoneMTLSKey); v != "" {
		c.KeystoneMTLSKey = v
	}
	if v := os.Getenv(EnvKeystoneMTLSCA); v != "" {
		c.KeystoneMTLSCA = v
	}
	if v := os.Getenv(EnvKeystoneTLSServerName); v != "" {
		c.KeystoneTLSServerName = v
	}

	// Audit overrides.
	if v := os.Getenv(EnvAuditEnabled); v != "" {
		c.AuditEnabled = envOn(v)
	}
	if v := os.Getenv(EnvWatchtowerURL); v != "" {
		c.WatchtowerURL = v
	}
	if v := os.Getenv(EnvAuditIngestToken); v != "" {
		c.AuditIngestToken = v
	}

	// WAF overrides. A malformed numeric/duration value is treated as unset so
	// Validate applies the default, never taking the gateway down on a typo.
	if v := os.Getenv(EnvWAFEnabled); v != "" {
		c.WAFEnabled = envOn(v)
	}
	if v := os.Getenv(EnvWAFThreshold); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			c.WAFThreshold = n
		}
	}
	if v := os.Getenv(EnvWAFRateBurst); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 0 {
			c.WAFRateBurst = n
		}
	}
	if v := os.Getenv(EnvWAFRateWindow); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			c.WAFRateWindow = d
		}
	}
	if v := os.Getenv(EnvWAFMaxBodyBytes); v != "" {
		if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil && n >= 0 {
			c.WAFMaxBodyBytes = n
		}
	}
	if v := os.Getenv(EnvWAFUploadTypes); v != "" {
		c.WAFUploadTypes = splitList(v)
	}
}

// splitList parses a comma-separated env value into a trimmed, non-empty slice.
func splitList(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// envOn parses a boolean-ish toggle. "on", "true", "1", "yes" (any case) enable;
// everything else (incl. "off") disables, so a typo fails safe to off.
func envOn(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "on", "true", "1", "yes":
		return true
	default:
		return false
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
	c.applyGatewayDefaults()
	c.applyWAFDefaults()

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

		if err := normalizeAuth(r); err != nil {
			return fmt.Errorf("route %q: %w", routeName(r, i), err)
		}
	}
	return nil
}

// normalizeAuth resolves a route's effective auth mode. An empty Auth is derived
// from the legacy Protected boolean so existing configs/rows are unchanged; an
// explicit Auth is validated against the known modes. Protected is then re-synced
// to (Auth != public) so any legacy consumer of the boolean stays correct.
func normalizeAuth(r *Route) error {
	r.Auth = strings.ToLower(strings.TrimSpace(r.Auth))
	if r.Auth == "" {
		if r.Protected {
			r.Auth = AuthBearer
		} else {
			r.Auth = AuthPublic
		}
	}
	switch r.Auth {
	case AuthPublic, AuthBearer, AuthSSO:
	default:
		return fmt.Errorf("invalid auth %q (want %s|%s|%s)", r.Auth, AuthPublic, AuthBearer, AuthSSO)
	}
	r.Protected = r.Auth != AuthPublic
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

// applyGatewayDefaults fills in OIDC/mTLS defaults. It deliberately does NOT
// hard-fail on an incomplete OIDC/mTLS configuration: the relying-party and the
// mTLS transport are built best-effort in main so a misconfiguration degrades to
// the unchanged bearer/public + plain-http behavior instead of taking the whole
// gateway down. The PUBLIC OIDC issuer defaults to KeystoneIssuer so the
// authorize redirect and the id_token iss/aud validation share one source.
func (c *Config) applyGatewayDefaults() {
	if c.OIDCIssuer == "" {
		c.OIDCIssuer = c.KeystoneIssuer
	}
	if c.GWSessionTTL <= 0 {
		c.GWSessionTTL = DefaultGWSessionTTL
	}
	if c.CookieDomain == "" {
		c.CookieDomain = DefaultCookieDomain
	}
	if c.KeystoneTLSServerName == "" {
		c.KeystoneTLSServerName = "keystone"
	}
}

// applyWAFDefaults fills in the WAF tuning knobs. Like the OIDC defaults it never
// hard-fails: the WAF is built best-effort in main and stays a pass-through when
// disabled, so an incomplete configuration degrades to the unchanged behavior.
func (c *Config) applyWAFDefaults() {
	if c.WAFThreshold <= 0 {
		c.WAFThreshold = DefaultWAFThreshold
	}
	if c.WAFRateBurst < 0 {
		c.WAFRateBurst = 0
	}
	if c.WAFRateBurst == 0 {
		c.WAFRateBurst = DefaultWAFRateBurst
	}
	if c.WAFRateWindow <= 0 {
		c.WAFRateWindow = DefaultWAFRateWindow
	}
	if c.WAFMaxBodyBytes < 0 {
		c.WAFMaxBodyBytes = 0
	}
	if c.WAFMaxBodyBytes == 0 {
		c.WAFMaxBodyBytes = DefaultWAFMaxBodyBytes
	}
}

func routeName(r *Route, i int) string {
	if r.Name != "" {
		return r.Name
	}
	return fmt.Sprintf("#%d", i)
}
