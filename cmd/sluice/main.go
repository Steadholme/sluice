// Command sluice runs the Sluice v0 L7 reverse-proxy / SSO forward-auth gateway.
package main

import (
	"context"
	"flag"
	"log/slog"
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
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		log.Error("load config", "error", err)
		os.Exit(1)
	}

	routeStore := store.NewStaticStore(cfg.Routes)

	// Build the JWKS cache + verifier from the Keystone issuer. Warm the cache
	// best-effort; a failure here is non-fatal because the verifier refreshes
	// lazily on first protected request.
	jwks := auth.NewJWKSCache(cfg.DiscoveryURL, &http.Client{Timeout: 10 * time.Second}, cfg.JWKSRefreshInterval)
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
		"routes", len(cfg.Routes),
	)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
