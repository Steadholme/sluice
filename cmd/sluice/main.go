// Command sluice runs the Sluice v0 L7 reverse-proxy / SSO forward-auth gateway.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/holdfast/sluice/internal/audit"
	"github.com/holdfast/sluice/internal/auth"
	"github.com/holdfast/sluice/internal/config"
	"github.com/holdfast/sluice/internal/gateway"
	"github.com/holdfast/sluice/internal/mtls"
	"github.com/holdfast/sluice/internal/oidc"
	"github.com/holdfast/sluice/internal/rbac"
	"github.com/holdfast/sluice/internal/store"
	"github.com/holdfast/sluice/internal/waf"
)

func main() {
	configPath := flag.String("config", "config.json", "path to the JSON config file")
	healthcheck := flag.Bool("healthcheck", false, "probe /healthz on the configured listen addr and exit 0 (healthy) or 1")
	flag.Parse()

	if *healthcheck {
		os.Exit(runHealthcheck())
	}

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	cfg, err := config.LoadFileWithEnv(*configPath)
	if err != nil {
		log.Error("load config", "error", err)
		os.Exit(1)
	}

	routeStore, closeStore, err := buildStore(cfg, log)
	if err != nil {
		log.Error("build store", "error", err)
		os.Exit(1)
	}
	defer closeStore()

	// Internal mTLS transport/client for the Keystone hop (proxy upstream + the
	// OIDC token/JWKS calls). Built best-effort: if INTERNAL_MTLS=on but the certs
	// are missing/malformed, log and fall back to the plain-http path rather than
	// taking the gateway down. internalClient (when set) carries the client cert so
	// JWKS/token fetches to https://keystone:8443 present it.
	mtlsTransport, internalClient := buildInternalMTLS(cfg, log)

	// Build the JWKS cache + verifier. The issuer is the PUBLIC iss validated on
	// every token; discovery/JWKS are FETCHED from cfg.DiscoveryURL (optionally an
	// internal Keystone via OIDC_DISCOVERY_URL), and a direct JWKS_FETCH_URL — when
	// set — bypasses discovery so JWKS is pulled from the internal Keystone without
	// a TLS loopback. Warm the cache best-effort; a failure here is non-fatal
	// because the verifier refreshes lazily on first protected request and recovers
	// as soon as Keystone is up.
	jwksClient := &http.Client{Timeout: 10 * time.Second}
	if internalClient != nil {
		jwksClient = internalClient
	}
	jwks := auth.NewJWKSCache(cfg.DiscoveryURL, jwksClient, cfg.JWKSRefreshInterval,
		auth.WithRotationCooldown(cfg.JWKSRotationCooldown),
		auth.WithJWKSURI(cfg.JWKSFetchURL))
	warmCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := jwks.Warm(warmCtx); err != nil {
		log.Warn("jwks warm-up failed; will retry lazily", "error", err)
	}
	cancel()
	verifier := auth.NewVerifierWithAudience(jwks, cfg.KeystoneIssuer, cfg.BearerAudience)

	// Non-blocking audit emitter (env-toggled by AUDIT_ENABLED). When off it is a
	// no-op; when on it fire-and-forget POSTs security events to Watchtower without
	// ever touching the request path. Watchtower being down can never break login
	// or proxying.
	auditor := audit.New(audit.Config{
		Enabled: cfg.AuditEnabled,
		URL:     cfg.WatchtowerURL,
		Token:   cfg.AuditIngestToken,
		Source:  audit.SourceSluice,
		Log:     log,
	})
	defer auditor.Close()

	// OIDC browser-SSO relying party (env-toggled by GW_OIDC). Built best-effort:
	// a misconfiguration disables SSO (sso routes fail closed) but never blocks the
	// bearer/public paths from starting.
	provider, closeProvider := buildProvider(cfg, jwks, internalClient, auditor, log)
	defer closeProvider()

	// Inline WAF + rate limiter (Aegis), env-toggled by WAF_ENABLED. Off by default:
	// a disabled engine is a pass-through and only routes flagged waf=true are
	// inspected even when on, so the public ingress keeps its exact behavior until
	// both switches are set. Blocked/flagged events reuse the same non-blocking
	// audit emitter, so Watchtower being down can never affect the request path.
	wafEngine := waf.New(waf.Config{
		Enabled:            cfg.WAFEnabled,
		Threshold:          cfg.WAFThreshold,
		RateBurst:          cfg.WAFRateBurst,
		RateWindow:         cfg.WAFRateWindow,
		MaxBodyBytes:       cfg.WAFMaxBodyBytes,
		AllowedUploadTypes: cfg.WAFUploadTypes,
		// The trusted edge (Sluice's own ingress / load balancer) populates
		// X-Forwarded-For, so honor it for the per-client rate-limit key.
		TrustForwardedFor: true,
		Auditor:           auditor,
		Log:               log,
	})
	defer wafEngine.Close()

	// Verdict-backed RBAC authorizer (env-toggled by RBAC_ENABLED). Off/unconfigured
	// is a no-op: a route's require_group is ignored and every sso route stays plain
	// SSO. When on, group-gated sso routes consult Verdict over the internal network
	// (VERDICT_URL) with the service token; a cold-cache Verdict outage fails closed.
	authz := rbac.New(rbac.Config{
		Enabled:    cfg.RBACEnabled,
		VerdictURL: cfg.VerdictURL,
		Token:      cfg.VerdictServiceToken,
		Log:        log,
	})

	// In acme mode the autocert HostPolicy is the live route hosts ∪ the apex ∪ the
	// legacy ACME_DOMAIN, so we hand serve() the same route store to read from.
	acmeHosts := gateway.RouteHostSet(routeStore, cfg.ACMEDomain, apexHost(cfg))

	opts := gateway.Options{
		Verifier:             verifier,
		Provider:             provider,
		Transport:            mtlsTransport,
		Auditor:              auditor,
		WAF:                  wafEngine,
		Authz:                authz,
		PublicOnly:           cfg.PublicOnly,
		PublicOnlyAllowHosts: hostSet(cfg.PublicOnlyAllow),
		GatewayHMACKey:       cfg.GatewayHMACKey,
		GatewayZoneHMACKey:   cfg.GatewayZoneHMACKey,
		GatewayZone:          cfg.GatewayZone,
		SessionCookieName:    oidc.DefaultCookieName,
	}
	// Rebuild the request handler from the (hot-reloading) route store whenever
	// the route set changes, so DB route edits — e.g. a new SiteFlow deployment
	// host inserted by the gateway-sync reconciler — take effect without a
	// restart. This applies on the PublicOnly public instance too: each rebuild
	// re-runs NewServer's PublicOnly route filter against the fresh snapshot.
	buildHandler := func() http.Handler { return gateway.NewServer(routeStore, opts).Handler() }
	handler := gateway.NewReloadableHandler(context.Background(), routeStore, buildHandler, 20*time.Second, log)

	log.Info("sluice listening",
		"tls_mode", cfg.TLSMode,
		"issuer", cfg.KeystoneIssuer,
		"store", storeKind(),
		"routes", len(routeStore.Routes()),
		"internal_mtls", mtlsTransport != nil,
		"oidc_sso", provider != nil,
		"audit", cfg.AuditEnabled,
		"waf", cfg.WAFEnabled,
		"rbac", authz.Enabled(),
		"public_only", cfg.PublicOnly,
		"gateway_zone", cfg.GatewayZone,
	)
	if err := serve(log, cfg, handler, acmeHosts); err != nil {
		log.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

// apexHost is the registrable apex implied by the cookie domain (e.g. .w33d.xyz
// -> w33d.xyz), folded into the autocert allowed-host set so the apex (Portal)
// can obtain a certificate even before its route row exists.
func apexHost(cfg *config.Config) string {
	return strings.TrimPrefix(cfg.CookieDomain, ".")
}

// serve binds the gateway according to cfg.TLSMode. In off mode it serves a
// single plain HTTP listener on ListenAddr (the unchanged dev default). In file
// and acme modes it terminates TLS on HTTPSAddr and runs an HTTP server on
// HTTPAddr that serves the ACME HTTP-01 challenge (acme mode) and 301-redirects
// everything else to https. It returns the first fatal listener error.
func serve(log *slog.Logger, cfg *config.Config, handler http.Handler, acmeHosts gateway.AllowedHosts) error {
	if cfg.TLSMode == config.TLSModeOff {
		httpServer := &http.Server{
			Addr:              cfg.ListenAddr,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
		}
		log.Info("serving plain HTTP", "addr", cfg.ListenAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	}

	// TLS modes: assemble the :443 TLS config and the :80 handler.
	var tlsConf *tls.Config
	var challengeHandler http.Handler
	switch cfg.TLSMode {
	case config.TLSModeACME:
		m := gateway.NewACMEManager(cfg, acmeHosts)
		tlsConf = m.TLSConfig()
		// HTTPHandler serves /.well-known/acme-challenge/* and forwards the rest
		// to the https redirect.
		challengeHandler = m.HTTPHandler(gateway.RedirectHTTPSHandler())
		log.Info("acme enabled", "hosts", acmeHosts(), "cache", cfg.ACMECacheDir, "directory", cfg.ACMEDirectoryURL)
	case config.TLSModeFile:
		var err error
		tlsConf, err = gateway.FileTLSConfig(cfg)
		if err != nil {
			return err
		}
		challengeHandler = gateway.RedirectHTTPSHandler()
		log.Info("file tls enabled", "cert", cfg.TLSCertFile)
	default:
		return fmt.Errorf("unsupported tls_mode %q", cfg.TLSMode)
	}

	httpsServer := &http.Server{
		Addr:              cfg.HTTPSAddr,
		Handler:           handler,
		TLSConfig:         tlsConf,
		ReadHeaderTimeout: 10 * time.Second,
	}
	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           challengeHandler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Run the :80 challenge/redirect server alongside the :443 TLS server; the
	// first fatal error from either is returned.
	errc := make(chan error, 2)
	go func() {
		log.Info("serving HTTP challenge/redirect", "addr", cfg.HTTPAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errc <- fmt.Errorf("http server: %w", err)
			return
		}
		errc <- nil
	}()
	go func() {
		log.Info("serving HTTPS", "addr", cfg.HTTPSAddr)
		// Certs come from TLSConfig (file mode) or autocert (acme mode), so the
		// cert/key file arguments are empty.
		if err := httpsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			errc <- fmt.Errorf("https server: %w", err)
			return
		}
		errc <- nil
	}()
	return <-errc
}

// buildInternalMTLS builds the mTLS transport + http.Client for the internal
// Keystone hop when INTERNAL_MTLS=on. On any build failure (missing/malformed
// certs) it logs and returns (nil, nil) so the caller degrades to plain http,
// keeping the gateway up. With the toggle off it is a no-op.
func buildInternalMTLS(cfg *config.Config, log *slog.Logger) (*http.Transport, *http.Client) {
	if !cfg.InternalMTLS {
		return nil, nil
	}
	mc := mtls.Config{
		CertFile:   cfg.KeystoneMTLSCert,
		KeyFile:    cfg.KeystoneMTLSKey,
		CAFile:     cfg.KeystoneMTLSCA,
		ServerName: cfg.KeystoneTLSServerName,
	}
	t, err := mc.Transport()
	if err != nil {
		log.Error("internal mTLS disabled (transport build failed); falling back to plain http", "error", err)
		return nil, nil
	}
	log.Info("internal mTLS enabled", "servername", cfg.KeystoneTLSServerName)
	return t, &http.Client{Transport: t, Timeout: 10 * time.Second}
}

// buildProvider assembles the OIDC relying party when GW_OIDC=on. The session +
// state store is Postgres when SLUICE_STORE=postgres (DATABASE_URL set) and the
// in-memory store otherwise. Any failure logs and returns a nil provider (SSO
// routes then fail closed) plus a no-op closer, so the gateway still serves the
// bearer/public paths. The returned closer releases the Postgres pool, if any.
func buildProvider(cfg *config.Config, jwks *auth.JWKSCache, client *http.Client, auditor *audit.Emitter, log *slog.Logger) (*oidc.Provider, func()) {
	noop := func() {}
	if !cfg.GWOIDCEnabled {
		return nil, noop
	}

	var sessions oidc.SessionStore
	var states oidc.StateStore
	closer := noop
	if storeKind() == config.StorePostgres {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		ps, err := oidc.NewPostgresStore(ctx, os.Getenv(config.EnvDatabaseURL))
		if err != nil {
			log.Error("oidc browser SSO disabled (gateway store init failed); sso routes will 503", "error", err)
			return nil, noop
		}
		sessions, states, closer = ps, ps, ps.Close
	} else {
		mem := oidc.NewMemoryStore()
		sessions, states = mem, mem
	}

	provider, err := oidc.NewProvider(oidc.Config{
		Issuer:        cfg.OIDCIssuer,
		TokenURL:      cfg.GWTokenURL,
		ClientID:      cfg.GWClientID,
		ClientSecret:  cfg.GWClientSecret,
		RedirectURI:   cfg.GWRedirectURI,
		SessionTTL:    cfg.GWSessionTTL,
		SessionSecret: cfg.GWSessionSecret,
		CookieDomain:  cfg.CookieDomain,
		Auditor:       auditor,
	}, jwks, client, sessions, states, log)
	if err != nil {
		log.Error("oidc browser SSO disabled (provider build failed); sso routes will 503", "error", err)
		closer()
		return nil, noop
	}
	log.Info("oidc browser SSO enabled",
		"issuer", cfg.OIDCIssuer, "client_id", cfg.GWClientID, "token_url", cfg.GWTokenURL)
	return provider, closer
}

// storeKind returns the configured route store kind, defaulting to static.
func storeKind() string {
	if v := os.Getenv(config.EnvStore); v != "" {
		return v
	}
	return config.StoreStatic
}

// hostSet turns the PUBLIC_ONLY_ALLOW host list into a lookup set for the gateway's
// PublicOnly route filter. nil when empty, so strict PublicOnly is the default.
func hostSet(hosts []string) map[string]bool {
	if len(hosts) == 0 {
		return nil
	}
	set := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		if h != "" {
			set[h] = true
		}
	}
	return set
}

// buildStore selects the route store from SLUICE_STORE. The default static store
// keeps the current dev contract (and needs no database); postgres loads routes
// from DATABASE_URL, seeding from the config (or ROUTES_SEED) when empty. The
// returned closer releases any held resources.
func buildStore(cfg *config.Config, log *slog.Logger) (store.RouteStore, func(), error) {
	switch kind := storeKind(); kind {
	case config.StoreStatic:
		return store.NewStaticStore(cfg.Routes), func() {}, nil

	case config.StorePostgres:
		seed := cfg.Routes
		if seedPath := os.Getenv(config.EnvRoutesSeed); seedPath != "" {
			seedCfg, err := config.LoadFile(seedPath)
			if err != nil {
				return nil, nil, fmt.Errorf("load routes seed %s: %w", seedPath, err)
			}
			seed = seedCfg.Routes
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		ps, err := store.NewPostgresStore(ctx, os.Getenv(config.EnvDatabaseURL), seed)
		if err != nil {
			return nil, nil, err
		}
		log.Info("postgres route store ready", "routes", len(ps.Routes()))
		return ps, ps.Close, nil

	default:
		return nil, nil, fmt.Errorf("unknown %s=%q (want %s|%s)", config.EnvStore, kind, config.StoreStatic, config.StorePostgres)
	}
}

// runHealthcheck performs an in-container liveness probe of /healthz. It is the
// entrypoint for the Docker HEALTHCHECK on a scratch runtime with no shell or
// wget. The scheme + address follow TLS_MODE: off probes plain HTTP on
// LISTEN_ADDR; file/acme probe HTTPS on HTTPS_ADDR (with certificate
// verification skipped, since the loopback dial won't match the public SNI host
// and self-signed certs are expected in file mode). Returns a process exit code.
func runHealthcheck() int {
	scheme, addr, client := healthcheckTarget()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: bad addr %q: %v\n", addr, err)
		return 1
	}
	// A bind host of 0.0.0.0 / :: / empty is not dialable; probe loopback.
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	url := fmt.Sprintf("%s://%s/healthz", scheme, net.JoinHostPort(host, port))
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: GET %s: %v\n", url, err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck: %s -> %d\n", url, resp.StatusCode)
		return 1
	}
	return 0
}

// healthcheckTarget selects the scheme, address, and HTTP client for the probe
// based on TLS_MODE. In TLS modes it targets HTTPS_ADDR over a TLS client that
// skips verification (loopback dial, public-host cert).
func healthcheckTarget() (scheme, addr string, client *http.Client) {
	timeout := 3 * time.Second
	mode := os.Getenv(config.EnvTLSMode)
	if mode == config.TLSModeFile || mode == config.TLSModeACME {
		addr = os.Getenv(config.EnvHTTPSAddr)
		if addr == "" {
			addr = config.DefaultHTTPSAddr
		}
		tlsCfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // loopback probe; hostname verified out-of-band
		// In acme mode autocert's HostPolicy only serves the whitelisted domain,
		// so the loopback probe MUST present that SNI or the handshake is rejected
		// (tls: internal error). InsecureSkipVerify still ignores the 127.0.0.1
		// vs id.w33d.xyz hostname mismatch on the dialed loopback address.
		if mode == config.TLSModeACME {
			if domain := os.Getenv(config.EnvACMEDomain); domain != "" {
				tlsCfg.ServerName = domain
			}
		}
		client = &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		}
		return "https", addr, client
	}
	addr = os.Getenv(config.EnvListenAddr)
	if addr == "" {
		addr = config.DefaultListenAddr
	}
	return "http", addr, &http.Client{Timeout: timeout}
}
