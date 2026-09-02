// Package config loads and validates the Sluice gateway configuration.
//
// The configuration is a JSON file describing the listen address, the expected
// Keystone (OIDC) issuer, and a static route table. In v0 the route table is
// read once into memory; the store package owns the seam where a future
// CDC/FusionDB-backed route source can plug in without touching this loader.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/holdfast/sluice/internal/application"
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

// Gateway zone values injected into X-Gateway-Zone for downstream services.
const (
	GatewayZoneExternal = "external"
	GatewayZoneInternal = "internal"
	DefaultGatewayZone  = GatewayZoneExternal
)

// Environment variable names that override the dev-contract defaults. They are
// applied by ApplyEnv before Validate, so an unset variable keeps the file/built
// in default unchanged.
const (
	EnvListenAddr     = "LISTEN_ADDR"     // overrides listen_addr
	EnvKeystoneIssuer = "KEYSTONE_ISSUER" // overrides keystone_issuer (and re-derives discovery)
	EnvBearerAudience = "SLUICE_AUDIENCE" // expected bearer-token aud; empty = aud not enforced (v0)
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
	// EnvPATIntrospectionURL is the explicit INTERNAL Keystone endpoint used only
	// by auth="pat" routes. It is never derived from the public issuer: leaving it
	// unset keeps PAT routes fail-closed without changing any other auth mode.
	EnvPATIntrospectionURL              = "PAT_INTROSPECTION_URL"
	EnvApplicationIntrospectionURL      = "ACCESS_APPLICATION_INTROSPECTION_URL"
	EnvApplicationIntrospectionToken    = "ACCESS_INTROSPECTION_TOKEN"
	EnvApplicationContextActiveKID      = "SLUICE_APPLICATION_CONTEXT_ACTIVE_KID"
	EnvApplicationContextSigningKeyring = "SLUICE_APPLICATION_CONTEXT_SIGNING_KEYRING"
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
// forward-auth (Authorization: Bearer RS256 JWT) API path, "pat" == isolated
// opaque-token introspection with an exact required scope, "sso" == the OIDC
// BROWSER SSO path (gateway session cookie, redirect to Keystone login), and
// "sso-optional" == anonymous pass-through with identity injection only when a
// valid gateway session already exists.
const (
	AuthPublic      = "public"
	AuthBearer      = "bearer"
	AuthPAT         = "pat"
	AuthApplication = "application"
	AuthSSO         = "sso"
	AuthSSOOptional = "sso-optional"
)

// OIDC browser-SSO + internal-mTLS environment variables. All are off by default
// so an unset deployment keeps the pure bearer/public, plain-http behavior.
const (
	EnvGWOIDC                   = "GW_OIDC"                     // on|off — enable the OIDC browser-SSO relying party
	EnvOIDCIssuer               = "OIDC_ISSUER"                 // PUBLIC issuer for the authorize redirect + id_token iss/aud (default = KEYSTONE_ISSUER)
	EnvGWClientID               = "GW_CLIENT_ID"                // gateway OIDC client_id registered in Keystone
	EnvGWClientSecret           = "GW_CLIENT_SECRET"            // gateway client secret (client_secret_post at the token endpoint)
	EnvGWRedirectURI            = "GW_REDIRECT_URI"             // PUBLIC redirect_uri, e.g. https://id.w33d.xyz/_gw/auth/callback
	EnvGWTokenURL               = "GW_TOKEN_URL"                // INTERNAL token endpoint (mTLS), e.g. https://keystone:8443/token
	EnvGWSessionTTL             = "GW_SESSION_TTL"              // gateway session lifetime (Go duration; default 8h)
	EnvGWSessionSecret          = "GW_SESSION_SECRET"           // HMAC key signing the opaque __Secure-gw cookie id
	EnvGWSessionRevocationToken = "GW_SESSION_REVOCATION_TOKEN" // bearer credential for the internal subject-wide session revocation endpoint
	EnvCookieDomain             = "COOKIE_DOMAIN"               // Domain attribute for the gateway session cookie (default .w33d.xyz)

	EnvInternalMTLS          = "INTERNAL_MTLS"           // on|off — mTLS for the internal Keystone hop
	EnvKeystoneMTLSCert      = "KEYSTONE_MTLS_CERT"      // client cert PEM (Keyward CN=sluice)
	EnvKeystoneMTLSKey       = "KEYSTONE_MTLS_KEY"       // client key PEM
	EnvKeystoneMTLSCA        = "KEYSTONE_MTLS_CA"        // trust anchor PEM (Keyward root)
	EnvKeystoneTLSServerName = "KEYSTONE_TLS_SERVERNAME" // pinned server name (default "keystone")

	EnvTrustedMFAEnabled             = "TRUSTED_MFA"                      // on|off — enable per-request authoritative MFA assertions
	EnvKeystoneAssuranceURL          = "KEYSTONE_ASSURANCE_URL"           // internal POST /internal/v1/session-assurance
	EnvKeystoneAssuranceServiceToken = "KEYSTONE_ASSURANCE_SERVICE_TOKEN" // independent Keystone lookup bearer credential
	EnvMFAAssertionHMACKey           = "MFA_ASSERTION_HMAC_KEY"           // current downstream assertion key
)

// Audit (Watchtower) environment variables. All optional; AUDIT_ENABLED defaults
// off so existing dev/tests are unchanged. When off, no audit events are emitted.
const (
	EnvAuditEnabled     = "AUDIT_ENABLED"      // on|off — emit security audit events to Watchtower (default off)
	EnvWatchtowerURL    = "WATCHTOWER_URL"     // Watchtower base URL, e.g. http://watchtower:8500
	EnvAuditIngestToken = "AUDIT_INGEST_TOKEN" // bearer credential for POST /events
)

// RBAC (Verdict-backed per-route group gating) environment variables. All
// optional; RBAC_ENABLED defaults OFF so an `auth=sso` route's require_group is a
// no-op until both the flag and Verdict wiring are set.
const (
	EnvRBACEnabled          = "RBAC_ENABLED"           // on|off — enable per-route group gating (default off)
	EnvVerdictURL           = "VERDICT_URL"            // Verdict base URL, e.g. http://verdict:9140
	EnvVerdictDecisionToken = "VERDICT_DECISION_TOKEN" // least-privilege bearer credential for Verdict decision APIs
	EnvGatewayHMACKey       = "GATEWAY_HMAC_KEY"       // HMAC key binding injected identity into X-Auth-Sig
	EnvGatewayZoneHMACKey   = "GATEWAY_ZONE_HMAC_KEY"  // dedicated HMAC key binding route+host+zone
	EnvGatewayZone          = "GATEWAY_ZONE"           // internal|external zone injected into X-Gateway-Zone
	EnvGatewayAuthzHMACKey  = "GATEWAY_AUTHZ_HMAC_KEY" // dedicated HMAC key for allowed permission context

	EnvGatewayAuthzContextV2HMACKeyCurrent  = "GATEWAY_AUTHZ_CTX_V2_HMAC_KEY_CURRENT"
	EnvGatewayAuthzContextV2HMACKIDCurrent  = "GATEWAY_AUTHZ_CTX_V2_HMAC_KID_CURRENT"
	EnvGatewayAuthzContextV2HMACKeyPrevious = "GATEWAY_AUTHZ_CTX_V2_HMAC_KEY_PREVIOUS"
	EnvGatewayAuthzContextV2HMACKIDPrevious = "GATEWAY_AUTHZ_CTX_V2_HMAC_KID_PREVIOUS"
)

const (
	RiskLow      = "low"
	RiskMedium   = "medium"
	RiskHigh     = "high"
	RiskCritical = "critical"
)

var permissionPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*){2}(\.[a-z0-9_-]+)?$`)
var authzContextV2KIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
var authzContextV2RoutePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// EnvPublicOnly, when on, makes this Sluice instance a PUBLIC-facing gateway that
// serves ONLY non-internal routes: any route carrying a require_group (the mgmt
// consoles) is treated as nonexistent (404). A companion INTERNAL instance runs
// with PUBLIC_ONLY off (serves all routes) bound to the VPN interface, so the mgmt
// consoles are reachable only over the VPN. Default off = serve every route
// (single-gateway behavior, unchanged).
const EnvPublicOnly = "PUBLIC_ONLY"

// EnvPublicOnlyAllow is a comma-separated allow-list of hosts that stay served on a
// PUBLIC_ONLY gateway EVEN when they carry a require_group. Their gate is NOT lifted —
// SSO + Verdict group gating still runs; this only removes the blanket public-plane 404
// so a bootstrap surface (the VPN enrollment portal vpn.w33d.xyz) is reachable over
// public TLS to authenticate and pull WireGuard credentials BEFORE the operator can get
// onto the VPN. Empty = strict PublicOnly (every require_group route 404s publicly).
const EnvPublicOnlyAllow = "PUBLIC_ONLY_ALLOW"

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

	// Auth is the per-route authentication mode: "public" | "bearer" | "pat" |
	// "sso" | "sso-optional". PAT is deliberately separate from bearer: it
	// introspects an opaque Keystone PAT and never changes the JWT verifier.
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

	// RequireGroup, when non-empty on an `auth=sso` route, gates the route behind
	// membership of that group (decided by Verdict). OPTIONAL and default empty: an
	// absent field (or a pre-existing route row) parses to "", so the route stays
	// plain SSO (any authenticated user) until it is explicitly set AND RBAC_ENABLED
	// is on — keeping the ingress behavior identical.
	RequireGroup string `json:"require_group,omitempty"`

	// InternalOnly is an exposure-plane decision independent from authentication
	// and authorization. PublicOnly gateways never route an InternalOnly row.
	InternalOnly bool `json:"internal_only,omitempty"`

	// RequirePermission is the opaque enterprise entitlement checked by Verdict
	// v2 after SSO. It is valid only on auth=sso routes. PermissionResource is a
	// typed resource urn; an empty value becomes route:<route-name>.
	RequirePermission  string `json:"require_permission,omitempty"`
	PermissionResource string `json:"permission_resource,omitempty"`
	Risk               string `json:"risk,omitempty"`

	// StepUpResumePath opts one exact-host SSO route into the gateway-owned step-up
	// interstitial. It is a fixed absolute-path prefix such as
	// /request/scope/step-up/; the browser can append only an opaque handle id.
	StepUpResumePath string `json:"step_up_resume_path,omitempty"`

	// RequireScope is the single exact scope required by an auth="pat" route.
	// It is mandatory for PAT routes and rejected on every other auth mode, so a
	// typo cannot silently widen a route or create ambiguous mixed auth semantics.
	RequireScope string `json:"require_scope,omitempty"`

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
	ListenAddr     string `json:"listen_addr"`
	KeystoneIssuer string `json:"keystone_issuer"`
	// BearerAudience, when non-empty, is the aud that bearer access tokens must
	// carry (SLUICE_AUDIENCE). Empty keeps the v0 behavior: aud is not enforced.
	BearerAudience string `json:"bearer_audience"`
	DiscoveryURL   string `json:"discovery_url"`
	JWKSFetchURL   string `json:"jwks_fetch_url"`
	// PATIntrospectionURL is the explicit internal Keystone opaque-PAT
	// introspection endpoint. Empty is permitted at startup; PAT routes then
	// return 503 while all existing auth modes retain their behavior.
	PATIntrospectionURL              string        `json:"pat_introspection_url"`
	ApplicationIntrospectionURL      string        `json:"application_introspection_url"`
	ApplicationIntrospectionToken    string        `json:"application_introspection_token"`
	ApplicationContextActiveKID      string        `json:"application_context_active_kid"`
	ApplicationContextSigningKeyring string        `json:"application_context_signing_keyring"`
	JWKSRefreshInterval              time.Duration `json:"jwks_refresh_interval"`
	JWKSRotationCooldown             time.Duration `json:"jwks_rotation_cooldown"`

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
	// GWSessionRevocationToken enables the gateway-owned internal JML endpoint
	// that deletes every browser session for one exact Keystone subject. Empty
	// keeps the endpoint nonexistent (404), which is the public-gateway default.
	GWSessionRevocationToken string `json:"gw_session_revocation_token"`
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

	// Trusted MFA is an opt-in rollout gate. When enabled, Sluice revalidates each strong
	// gateway session against Keystone and signs a route/audience-bound assertion with a key
	// independent from cookie, identity, zone, and authorization-context credentials.
	TrustedMFAEnabled             bool   `json:"trusted_mfa_enabled"`
	KeystoneAssuranceURL          string `json:"keystone_assurance_url"`
	KeystoneAssuranceServiceToken string `json:"keystone_assurance_service_token"`
	MFAAssertionHMACKey           string `json:"mfa_assertion_hmac_key"`
	trustedMFAEnvError            string

	// Audit to Watchtower. Off by default (AuditEnabled=false) so the gateway
	// emits nothing and behavior is unchanged. When on, security-relevant gateway
	// actions are fire-and-forget POSTed to WatchtowerURL with AuditIngestToken.
	AuditEnabled     bool   `json:"audit_enabled"`
	WatchtowerURL    string `json:"watchtower_url"`
	AuditIngestToken string `json:"audit_ingest_token"`

	// RBAC (Verdict-backed group gating). Off by default (RBACEnabled=false) so a
	// route's require_group is ignored and every sso route is plain SSO. When on,
	// group-gated routes consult VerdictURL with a decision-only credential.
	RBACEnabled          bool   `json:"rbac_enabled"`
	VerdictURL           string `json:"verdict_url"`
	VerdictDecisionToken string `json:"verdict_decision_token"`

	// GatewayHMACKey, when set, makes the proxy sign the injected identity into
	// X-Auth-Sig so backends can prove it came from Sluice.
	GatewayHMACKey string `json:"gateway_hmac_key"`
	// GatewayZoneHMACKey is a separate, narrowly distributed key for the route+host-bound
	// X-Gateway-Zone-Sig. It must not inherit the estate-wide identity verification key.
	GatewayZoneHMACKey string `json:"gateway_zone_hmac_key"`
	// GatewayAuthzHMACKey signs a domain-separated permission decision context.
	// It must be distinct from both legacy identity and gateway-zone keys.
	GatewayAuthzHMACKey string `json:"gateway_authz_hmac_key"`
	// Authorization-context v2 uses an atomic current/previous KID snapshot.
	// Current is mandatory when v2 is enabled; previous is an optional overlap
	// binding. The legacy key above remains independent for v1 dual-write.
	GatewayAuthzContextV2HMACKeyCurrent  string `json:"gateway_authz_ctx_v2_hmac_key_current"`
	GatewayAuthzContextV2HMACKIDCurrent  string `json:"gateway_authz_ctx_v2_hmac_kid_current"`
	GatewayAuthzContextV2HMACKeyPrevious string `json:"gateway_authz_ctx_v2_hmac_key_previous"`
	GatewayAuthzContextV2HMACKIDPrevious string `json:"gateway_authz_ctx_v2_hmac_kid_previous"`
	// GatewayZone is injected into X-Gateway-Zone on every forwarded request.
	// Empty defaults to "external" so an unset public gateway never claims internal.
	GatewayZone string `json:"gateway_zone"`

	// PublicOnly makes this instance drop internal (require_group) routes -> 404,
	// so the public gateway does not expose the mgmt consoles. Default false.
	PublicOnly bool `json:"public_only"`
	// PublicOnlyAllow lists hosts served on a PublicOnly gateway despite a require_group
	// (their SSO + group gate still applies). Empty = strict PublicOnly. See EnvPublicOnlyAllow.
	PublicOnlyAllow []string `json:"public_only_allow"`

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
	if v := os.Getenv(EnvBearerAudience); v != "" {
		c.BearerAudience = v
	}
	// Issuer-vs-internal-fetch overrides. These point Sluice at the INTERNAL
	// Keystone for fetching discovery/JWKS without changing the PUBLIC iss above.
	if v := os.Getenv(EnvDiscoveryURL); v != "" {
		c.DiscoveryURL = v
	}
	if v := os.Getenv(EnvJWKSFetchURL); v != "" {
		c.JWKSFetchURL = v
	}
	if v := os.Getenv(EnvPATIntrospectionURL); v != "" {
		c.PATIntrospectionURL = strings.TrimSpace(v)
	}
	if v := os.Getenv(EnvApplicationIntrospectionURL); v != "" {
		c.ApplicationIntrospectionURL = strings.TrimSpace(v)
	}
	if v := os.Getenv(EnvApplicationIntrospectionToken); v != "" {
		c.ApplicationIntrospectionToken = v
	}
	if v := os.Getenv(EnvApplicationContextActiveKID); v != "" {
		c.ApplicationContextActiveKID = strings.TrimSpace(v)
	}
	if v := os.Getenv(EnvApplicationContextSigningKeyring); v != "" {
		c.ApplicationContextSigningKeyring = v
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
	if v := os.Getenv(EnvGWSessionRevocationToken); v != "" {
		c.GWSessionRevocationToken = v
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
	if v, ok := os.LookupEnv(EnvTrustedMFAEnabled); ok {
		c.trustedMFAEnvError = ""
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "on":
			c.TrustedMFAEnabled = true
		case "off":
			c.TrustedMFAEnabled = false
		default:
			c.trustedMFAEnvError = fmt.Sprintf("%s must be exactly on or off", EnvTrustedMFAEnabled)
		}
	}
	if v := os.Getenv(EnvKeystoneAssuranceURL); v != "" {
		c.KeystoneAssuranceURL = v
	}
	if v := os.Getenv(EnvKeystoneAssuranceServiceToken); v != "" {
		c.KeystoneAssuranceServiceToken = v
	}
	if v := os.Getenv(EnvMFAAssertionHMACKey); v != "" {
		c.MFAAssertionHMACKey = v
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

	// RBAC overrides.
	if v := os.Getenv(EnvRBACEnabled); v != "" {
		c.RBACEnabled = envOn(v)
	}
	if v := os.Getenv(EnvVerdictURL); v != "" {
		c.VerdictURL = v
	}
	if v := os.Getenv(EnvVerdictDecisionToken); v != "" {
		c.VerdictDecisionToken = v
	}
	if v := os.Getenv(EnvGatewayHMACKey); v != "" {
		c.GatewayHMACKey = v
	}
	if v := os.Getenv(EnvGatewayZoneHMACKey); v != "" {
		c.GatewayZoneHMACKey = v
	}
	if v := os.Getenv(EnvGatewayAuthzHMACKey); v != "" {
		c.GatewayAuthzHMACKey = v
	}
	if v, ok := os.LookupEnv(EnvGatewayAuthzContextV2HMACKeyCurrent); ok {
		c.GatewayAuthzContextV2HMACKeyCurrent = v
	}
	if v, ok := os.LookupEnv(EnvGatewayAuthzContextV2HMACKIDCurrent); ok {
		c.GatewayAuthzContextV2HMACKIDCurrent = v
	}
	if v, ok := os.LookupEnv(EnvGatewayAuthzContextV2HMACKeyPrevious); ok {
		c.GatewayAuthzContextV2HMACKeyPrevious = v
	}
	if v, ok := os.LookupEnv(EnvGatewayAuthzContextV2HMACKIDPrevious); ok {
		c.GatewayAuthzContextV2HMACKIDPrevious = v
	}
	if v := os.Getenv(EnvGatewayZone); v != "" {
		c.GatewayZone = v
	}
	if v := os.Getenv(EnvPublicOnly); v != "" {
		c.PublicOnly = envOn(v)
	}
	if v := os.Getenv(EnvPublicOnlyAllow); v != "" {
		c.PublicOnlyAllow = splitList(v)
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
	if err := c.normalizeGatewayZone(); err != nil {
		return err
	}
	if c.GatewayHMACKey != "" && c.GatewayZoneHMACKey == c.GatewayHMACKey {
		return fmt.Errorf("gateway_zone_hmac_key must be distinct from gateway_hmac_key")
	}
	if c.GatewayAuthzHMACKey != "" &&
		(c.GatewayAuthzHMACKey == c.GatewayHMACKey || c.GatewayAuthzHMACKey == c.GatewayZoneHMACKey) {
		return fmt.Errorf("gateway_authz_hmac_key must be distinct from gateway identity and zone keys")
	}
	if err := c.validateAuthorizationContextV2(); err != nil {
		return err
	}
	if err := c.validateTrustedMFA(); err != nil {
		return err
	}
	if err := c.validateApplicationAuth(); err != nil {
		return err
	}
	if c.RBACEnabled {
		if c.VerdictURL == "" {
			return fmt.Errorf("rbac_enabled requires verdict_url")
		}
		verdictURL, err := url.Parse(c.VerdictURL)
		if err != nil || verdictURL.Scheme == "" || verdictURL.Host == "" {
			return fmt.Errorf("rbac_enabled requires an absolute verdict_url")
		}
		if err := validateVisibleASCIISecret("verdict_decision_token", c.VerdictDecisionToken); err != nil {
			return err
		}
		for _, secret := range []string{
			c.GWSessionSecret,
			c.GatewayHMACKey,
			c.GatewayZoneHMACKey,
			c.GatewayAuthzHMACKey,
			c.GWSessionRevocationToken,
			c.AuditIngestToken,
		} {
			if secret != "" && c.VerdictDecisionToken == secret {
				return fmt.Errorf("verdict_decision_token must be distinct from other gateway credentials")
			}
		}
	}
	if c.GWSessionRevocationToken != "" {
		if len(c.GWSessionRevocationToken) < 32 {
			return fmt.Errorf("gw_session_revocation_token must contain at least 32 bytes")
		}
		for _, secret := range []string{
			c.GWSessionSecret,
			c.GatewayHMACKey,
			c.GatewayZoneHMACKey,
			c.GatewayAuthzHMACKey,
			c.VerdictDecisionToken,
			c.AuditIngestToken,
		} {
			if secret != "" && c.GWSessionRevocationToken == secret {
				return fmt.Errorf("gw_session_revocation_token must be distinct from other gateway credentials")
			}
		}
	}
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
		if r.Auth == AuthApplication && u.Path != "" && u.Path != "/" {
			return fmt.Errorf("route %q: auth=application requires an upstream without a path prefix", routeName(r, i))
		}
		if err := validateRouteScope(r); err != nil {
			return fmt.Errorf("route %q: %w", routeName(r, i), err)
		}
		if err := validateRoutePermission(r); err != nil {
			return fmt.Errorf("route %q: %w", routeName(r, i), err)
		}
		if r.RequirePermission != "" && c.AuthorizationContextV2Enabled() {
			if !authzContextV2RoutePattern.MatchString(r.Name) {
				return fmt.Errorf("route %q: authorization-context v2 requires a canonical route name", routeName(r, i))
			}
			if !validStepUpHost(r.Match.Host) {
				return fmt.Errorf("route %q: authorization-context v2 requires an exact lowercase host", routeName(r, i))
			}
			kind, id, _ := strings.Cut(r.PermissionResource, ":")
			if kind == "any" || !validAuthzContextV2ResourceID(id) {
				return fmt.Errorf("route %q: permission_resource is not canonical for authorization-context v2", routeName(r, i))
			}
		}
		if err := validateRouteStepUp(r); err != nil {
			return fmt.Errorf("route %q: %w", routeName(r, i), err)
		}
	}
	return nil
}

func validateRouteStepUp(r *Route) error {
	r.StepUpResumePath = strings.TrimSpace(r.StepUpResumePath)
	if r.StepUpResumePath == "" {
		return nil
	}
	if r.Auth != AuthSSO || !validStepUpHost(r.Match.Host) {
		return fmt.Errorf("step_up_resume_path requires an exact-host auth=sso route")
	}
	path := r.StepUpResumePath
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") ||
		!strings.HasSuffix(path, "/") || strings.ContainsAny(path, "\\?#") ||
		strings.IndexFunc(path, unicode.IsControl) >= 0 {
		return fmt.Errorf("step_up_resume_path must be a safe absolute path prefix ending in /")
	}
	parsed, err := url.ParseRequestURI(path)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		strings.Contains(parsed.Path, "\\") || strings.IndexFunc(parsed.Path, unicode.IsControl) >= 0 {
		return fmt.Errorf("step_up_resume_path must not contain a scheme, authority, query, or fragment")
	}
	return nil
}

func validStepUpHost(host string) bool {
	if host == "" || len(host) > 253 || host != strings.ToLower(host) ||
		strings.ContainsAny(host, ":/@\\?#") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			b := label[i]
			if (b < 'a' || b > 'z') && (b < '0' || b > '9') && b != '-' {
				return false
			}
		}
	}
	return true
}

// AuthorizationContextV2Enabled reports whether the complete current binding
// is present. Validate rejects every torn current/previous combination before a
// Config reaches the request path.
func (c *Config) AuthorizationContextV2Enabled() bool {
	return c != nil && c.GatewayAuthzContextV2HMACKeyCurrent != "" && c.GatewayAuthzContextV2HMACKIDCurrent != ""
}

func (c *Config) validateAuthorizationContextV2() error {
	currentKeySet := c.GatewayAuthzContextV2HMACKeyCurrent != ""
	currentKIDSet := c.GatewayAuthzContextV2HMACKIDCurrent != ""
	previousKeySet := c.GatewayAuthzContextV2HMACKeyPrevious != ""
	previousKIDSet := c.GatewayAuthzContextV2HMACKIDPrevious != ""

	if currentKeySet != currentKIDSet {
		return fmt.Errorf("gateway authorization-context v2 current KID and key must be configured together")
	}
	if previousKeySet != previousKIDSet {
		return fmt.Errorf("gateway authorization-context v2 previous KID and key must be configured together")
	}
	if !currentKeySet {
		if previousKeySet {
			return fmt.Errorf("gateway authorization-context v2 previous binding requires current binding")
		}
		return nil
	}
	if !authzContextV2KIDPattern.MatchString(c.GatewayAuthzContextV2HMACKIDCurrent) {
		return fmt.Errorf("gateway authorization-context v2 current KID is invalid")
	}
	if err := validateVisibleASCIISecret("gateway authorization-context v2 current key", c.GatewayAuthzContextV2HMACKeyCurrent); err != nil {
		return err
	}
	if previousKeySet {
		if !authzContextV2KIDPattern.MatchString(c.GatewayAuthzContextV2HMACKIDPrevious) {
			return fmt.Errorf("gateway authorization-context v2 previous KID is invalid")
		}
		if err := validateVisibleASCIISecret("gateway authorization-context v2 previous key", c.GatewayAuthzContextV2HMACKeyPrevious); err != nil {
			return err
		}
		if c.GatewayAuthzContextV2HMACKIDCurrent == c.GatewayAuthzContextV2HMACKIDPrevious {
			return fmt.Errorf("gateway authorization-context v2 current and previous KID must be distinct")
		}
		if c.GatewayAuthzContextV2HMACKeyCurrent == c.GatewayAuthzContextV2HMACKeyPrevious {
			return fmt.Errorf("gateway authorization-context v2 current and previous key material must be distinct")
		}
	}

	otherCredentials := map[string]string{
		"OIDC client secret":               c.GWClientSecret,
		"gateway session secret":           c.GWSessionSecret,
		"gateway identity key":             c.GatewayHMACKey,
		"gateway zone key":                 c.GatewayZoneHMACKey,
		"legacy gateway authorization key": c.GatewayAuthzHMACKey,
		"MFA assertion key":                c.MFAAssertionHMACKey,
		"Keystone assurance service token": c.KeystoneAssuranceServiceToken,
		"Verdict decision token":           c.VerdictDecisionToken,
		"gateway session revocation token": c.GWSessionRevocationToken,
		"Watchtower audit ingestion token": c.AuditIngestToken,
	}
	for label, key := range map[string]string{
		"current":  c.GatewayAuthzContextV2HMACKeyCurrent,
		"previous": c.GatewayAuthzContextV2HMACKeyPrevious,
	} {
		if key == "" {
			continue
		}
		for otherLabel, other := range otherCredentials {
			if other != "" && key == other {
				return fmt.Errorf("gateway authorization-context v2 %s key must be distinct from %s", label, otherLabel)
			}
		}
	}
	return nil
}

func (c *Config) validateTrustedMFA() error {
	if c.trustedMFAEnvError != "" {
		return errors.New(c.trustedMFAEnvError)
	}
	if !c.TrustedMFAEnabled {
		return nil
	}
	endpoint, err := url.Parse(strings.TrimSpace(c.KeystoneAssuranceURL))
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" ||
		(endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.User != nil ||
		endpoint.Fragment != "" || endpoint.RawQuery != "" {
		return fmt.Errorf("trusted_mfa_enabled requires an absolute keystone_assurance_url without userinfo, query, or fragment")
	}
	if c.InternalMTLS && endpoint.Scheme != "https" {
		return fmt.Errorf("internal_mtls requires an https keystone_assurance_url")
	}
	for name, secret := range map[string]string{
		"keystone_assurance_service_token": c.KeystoneAssuranceServiceToken,
		"mfa_assertion_hmac_key":           c.MFAAssertionHMACKey,
	} {
		if err := validateVisibleASCIISecret(name, secret); err != nil {
			return err
		}
	}
	credentials := map[string]string{
		"keystone assurance service token": c.KeystoneAssuranceServiceToken,
		"MFA assertion current key":        c.MFAAssertionHMACKey,
		"OIDC client secret":               c.GWClientSecret,
		"gateway session secret":           c.GWSessionSecret,
		"gateway identity key":             c.GatewayHMACKey,
		"gateway zone key":                 c.GatewayZoneHMACKey,
		"gateway authorization key":        c.GatewayAuthzHMACKey,
		"Verdict decision token":           c.VerdictDecisionToken,
		"session revocation token":         c.GWSessionRevocationToken,
		"audit ingest token":               c.AuditIngestToken,
	}
	for leftName, left := range credentials {
		if left == "" {
			continue
		}
		for rightName, right := range credentials {
			if leftName < rightName && right != "" && left == right {
				return fmt.Errorf("%s must be distinct from %s", leftName, rightName)
			}
		}
	}
	return nil
}

func validateVisibleASCIISecret(name, value string) error {
	if len(value) < 32 || len(value) > 512 {
		return fmt.Errorf("%s must contain between 32 and 512 bytes", name)
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return fmt.Errorf("%s must contain only visible ASCII bytes", name)
		}
	}
	return nil
}

func validateRoutePermission(r *Route) error {
	r.RequirePermission = strings.TrimSpace(r.RequirePermission)
	r.PermissionResource = strings.TrimSpace(r.PermissionResource)
	r.Risk = strings.ToLower(strings.TrimSpace(r.Risk))
	if r.Risk == "" {
		r.Risk = RiskLow
	}
	switch r.Risk {
	case RiskLow, RiskMedium, RiskHigh, RiskCritical:
	default:
		return fmt.Errorf("invalid risk %q (want low|medium|high|critical)", r.Risk)
	}
	if r.RequirePermission == "" {
		if r.PermissionResource != "" {
			return fmt.Errorf("permission_resource requires require_permission")
		}
		return nil
	}
	if r.Auth != AuthSSO {
		return fmt.Errorf("require_permission is only valid with auth=%s", AuthSSO)
	}
	if !permissionPattern.MatchString(r.RequirePermission) {
		return fmt.Errorf("invalid require_permission %q", r.RequirePermission)
	}
	if r.PermissionResource == "" {
		r.PermissionResource = "route:" + r.Name
	}
	kind, id, ok := strings.Cut(r.PermissionResource, ":")
	if !ok || !validResourceType(kind) || id == "" || strings.ContainsAny(id, "\r\n\x00") {
		return fmt.Errorf("permission_resource must be a valid type:id value")
	}
	return nil
}

func validResourceType(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for i := 1; i < len(value); i++ {
		b := value[i]
		if (b < 'a' || b > 'z') && (b < '0' || b > '9') && b != '-' {
			return false
		}
	}
	return true
}

func validAuthzContextV2ResourceID(value string) bool {
	if value == "" || len(value) > 256 || strings.Contains(value, "://") {
		return false
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		if (b < 'a' || b > 'z') && (b < 'A' || b > 'Z') && (b < '0' || b > '9') &&
			b != '-' && b != '_' && b != '.' && b != ':' && b != '@' {
			return false
		}
	}
	return true
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
	case AuthPublic, AuthBearer, AuthPAT, AuthApplication, AuthSSO, AuthSSOOptional:
	default:
		return fmt.Errorf("invalid auth %q (want %s|%s|%s|%s|%s|%s)", r.Auth, AuthPublic, AuthBearer, AuthPAT, AuthApplication, AuthSSO, AuthSSOOptional)
	}
	r.Protected = r.Auth != AuthPublic
	return nil
}

// validateRouteScope locks require_scope to the PAT auth mode. A route accepts
// exactly one scope token (no whitespace-separated alternatives); the
// introspector later checks exact membership in Keystone's space-delimited
// scope response.
func validateRouteScope(r *Route) error {
	raw := r.RequireScope
	if r.Auth != AuthPAT && r.Auth != AuthApplication {
		if raw != "" {
			return fmt.Errorf("require_scope is only valid with auth=%s", AuthPAT)
		}
		return nil
	}
	r.RequireScope = strings.TrimSpace(raw)
	if r.RequireScope == "" && r.Auth == AuthApplication {
		return nil
	}
	if r.RequireScope == "" {
		return fmt.Errorf("auth=%s requires require_scope", AuthPAT)
	}
	fields := strings.Fields(r.RequireScope)
	if len(fields) != 1 || fields[0] != r.RequireScope {
		return fmt.Errorf("require_scope must be exactly one scope token")
	}
	return nil
}

func (c *Config) validateApplicationAuth() error {
	configured := c.ApplicationIntrospectionURL != "" || c.ApplicationIntrospectionToken != "" || c.ApplicationContextActiveKID != "" || c.ApplicationContextSigningKeyring != ""
	if !configured {
		return nil
	}
	endpoint, err := url.Parse(strings.TrimSpace(c.ApplicationIntrospectionURL))
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return fmt.Errorf("application auth requires an absolute application_introspection_url without userinfo, query, or fragment")
	}
	if err := validateVisibleASCIISecret("application_introspection_token", c.ApplicationIntrospectionToken); err != nil {
		return err
	}
	if _, err := application.ParseSigningKeyring(c.ApplicationContextActiveKID, c.ApplicationContextSigningKeyring); err != nil {
		return fmt.Errorf("application auth requires a complete Ed25519 active KID and signing keyring")
	}
	for _, other := range []string{c.GWClientSecret, c.GWSessionSecret, c.GWSessionRevocationToken, c.KeystoneAssuranceServiceToken, c.MFAAssertionHMACKey, c.AuditIngestToken, c.VerdictDecisionToken, c.GatewayHMACKey, c.GatewayZoneHMACKey, c.GatewayAuthzHMACKey} {
		if other != "" && c.ApplicationIntrospectionToken == other {
			return fmt.Errorf("application_introspection_token must be distinct from other gateway credentials")
		}
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

// normalizeGatewayZone keeps the injected trust header on the fixed contract:
// external by default, and only external/internal when configured.
func (c *Config) normalizeGatewayZone() error {
	c.GatewayZone = strings.ToLower(strings.TrimSpace(c.GatewayZone))
	if c.GatewayZone == "" {
		c.GatewayZone = DefaultGatewayZone
	}
	switch c.GatewayZone {
	case GatewayZoneExternal, GatewayZoneInternal:
		return nil
	default:
		return fmt.Errorf("invalid gateway_zone %q (want %s|%s)", c.GatewayZone, GatewayZoneExternal, GatewayZoneInternal)
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
