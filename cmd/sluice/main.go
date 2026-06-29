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
	"time"

	"github.com/holdfast/sluice/internal/auth"
	"github.com/holdfast/sluice/internal/config"
	"github.com/holdfast/sluice/internal/gateway"
	"github.com/holdfast/sluice/internal/store"
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

	// Build the JWKS cache + verifier. The issuer is the PUBLIC iss validated on
	// every token; discovery/JWKS are FETCHED from cfg.DiscoveryURL (optionally an
	// internal Keystone via OIDC_DISCOVERY_URL), and a direct JWKS_FETCH_URL — when
	// set — bypasses discovery so JWKS is pulled from the internal Keystone without
	// a TLS loopback. Warm the cache best-effort; a failure here is non-fatal
	// because the verifier refreshes lazily on first protected request and recovers
	// as soon as Keystone is up.
	jwks := auth.NewJWKSCache(cfg.DiscoveryURL, &http.Client{Timeout: 10 * time.Second}, cfg.JWKSRefreshInterval,
		auth.WithRotationCooldown(cfg.JWKSRotationCooldown),
		auth.WithJWKSURI(cfg.JWKSFetchURL))
	warmCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := jwks.Warm(warmCtx); err != nil {
		log.Warn("jwks warm-up failed; will retry lazily", "error", err)
	}
	cancel()
	verifier := auth.NewVerifier(jwks, cfg.KeystoneIssuer)

	srv := gateway.NewServer(routeStore, verifier)

	log.Info("sluice listening",
		"tls_mode", cfg.TLSMode,
		"issuer", cfg.KeystoneIssuer,
		"store", storeKind(),
		"routes", len(routeStore.Routes()),
	)
	if err := serve(log, cfg, srv.Handler()); err != nil {
		log.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

// serve binds the gateway according to cfg.TLSMode. In off mode it serves a
// single plain HTTP listener on ListenAddr (the unchanged dev default). In file
// and acme modes it terminates TLS on HTTPSAddr and runs an HTTP server on
// HTTPAddr that serves the ACME HTTP-01 challenge (acme mode) and 301-redirects
// everything else to https. It returns the first fatal listener error.
func serve(log *slog.Logger, cfg *config.Config, handler http.Handler) error {
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
		m := gateway.NewACMEManager(cfg)
		tlsConf = m.TLSConfig()
		// HTTPHandler serves /.well-known/acme-challenge/* and forwards the rest
		// to the https redirect.
		challengeHandler = m.HTTPHandler(gateway.RedirectHTTPSHandler())
		log.Info("acme enabled", "domain", cfg.ACMEDomain, "cache", cfg.ACMECacheDir, "directory", cfg.ACMEDirectoryURL)
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

// storeKind returns the configured route store kind, defaulting to static.
func storeKind() string {
	if v := os.Getenv(config.EnvStore); v != "" {
		return v
	}
	return config.StoreStatic
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
