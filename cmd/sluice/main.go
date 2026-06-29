// Command sluice runs the Sluice v0 L7 reverse-proxy / SSO forward-auth gateway.
package main

import (
	"context"
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

	// Build the JWKS cache + verifier from the Keystone issuer. Warm the cache
	// best-effort; a failure here is non-fatal because the verifier refreshes
	// lazily on first protected request and recovers as soon as Keystone is up.
	jwks := auth.NewJWKSCache(cfg.DiscoveryURL, &http.Client{Timeout: 10 * time.Second}, cfg.JWKSRefreshInterval,
		auth.WithRotationCooldown(cfg.JWKSRotationCooldown))
	warmCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := jwks.Warm(warmCtx); err != nil {
		log.Warn("jwks warm-up failed; will retry lazily", "error", err)
	}
	cancel()
	verifier := auth.NewVerifier(jwks, cfg.KeystoneIssuer)

	srv := gateway.NewServer(routeStore, verifier)

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Info("sluice listening",
		"addr", cfg.ListenAddr,
		"issuer", cfg.KeystoneIssuer,
		"store", storeKind(),
		"routes", len(routeStore.Routes()),
	)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error("server stopped", "error", err)
		os.Exit(1)
	}
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

// runHealthcheck performs an in-container liveness probe of /healthz against the
// configured listen address. It is the entrypoint for the Docker HEALTHCHECK on
// a scratch runtime with no shell or wget. Returns a process exit code.
func runHealthcheck() int {
	addr := os.Getenv(config.EnvListenAddr)
	if addr == "" {
		addr = config.DefaultListenAddr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: bad listen addr %q: %v\n", addr, err)
		return 1
	}
	// A bind host of 0.0.0.0 / :: / empty is not dialable; probe loopback.
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	url := fmt.Sprintf("http://%s/healthz", net.JoinHostPort(host, port))
	client := &http.Client{Timeout: 3 * time.Second}
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
