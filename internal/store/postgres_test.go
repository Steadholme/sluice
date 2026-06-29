package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/holdfast/sluice/internal/config"
)

// seedRoutes mirrors the dev-contract route table: one public + one protected.
func seedRoutes() []config.Route {
	return []config.Route{
		{Name: "public-api", Match: config.Match{PathPrefix: "/public"}, Upstream: "http://127.0.0.1:8081", Protected: false},
		{Name: "protected-api", Match: config.Match{Host: "api.local", PathPrefix: "/api"}, Upstream: "http://127.0.0.1:8082", Protected: true},
	}
}

// TestPostgresStoreIntegration exercises the postgres RouteStore against a real
// PostgreSQL instance. It is a clean no-op unless TEST_DATABASE_URL is set, so
// the default suite stays green with no database.
func TestPostgresStoreIntegration(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping postgres integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start from a clean slate so the test is deterministic and rerunnable.
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := pool.Exec(ctx, "DROP TABLE IF EXISTS routes"); err != nil {
		t.Fatalf("drop table: %v", err)
	}
	pool.Close()

	// (1) Fresh DB: migration runs, empty table is seeded, snapshot is parsed.
	s1, err := NewPostgresStore(ctx, dsn, seedRoutes())
	if err != nil {
		t.Fatalf("NewPostgresStore (seed): %v", err)
	}
	defer s1.Close()

	routes := s1.Routes()
	if len(routes) != 2 {
		t.Fatalf("got %d routes, want 2", len(routes))
	}
	byName := map[string]config.Route{}
	for _, r := range routes {
		byName[r.Name] = r
		if r.UpstreamURL() == nil {
			t.Errorf("route %q: UpstreamURL not parsed", r.Name)
		}
	}
	if got := byName["protected-api"]; !got.Protected || got.Match.Host != "api.local" || got.Match.PathPrefix != "/api" {
		t.Errorf("protected-api round-trip mismatch: %+v", got)
	}
	if got := byName["public-api"]; got.Protected {
		t.Errorf("public-api should not be protected: %+v", got)
	}

	// (2) Idempotent seed: a second construction over the now-populated table
	// must NOT duplicate rows and must return the same snapshot. The seed passed
	// here differs (extra route) to prove a non-empty table is left untouched.
	extraSeed := append(seedRoutes(), config.Route{
		Name: "should-not-appear", Match: config.Match{PathPrefix: "/nope"}, Upstream: "http://127.0.0.1:9999",
	})
	s2, err := NewPostgresStore(ctx, dsn, extraSeed)
	if err != nil {
		t.Fatalf("NewPostgresStore (reopen): %v", err)
	}
	defer s2.Close()
	if len(s2.Routes()) != 2 {
		t.Fatalf("reopen returned %d routes, want 2 (table must not be re-seeded)", len(s2.Routes()))
	}
	for _, r := range s2.Routes() {
		if r.Name == "should-not-appear" {
			t.Fatal("non-empty routes table was re-seeded")
		}
	}

	// (3) Empty DSN is rejected without touching the network.
	if _, err := NewPostgresStore(ctx, "", seedRoutes()); err == nil {
		t.Error("expected error for empty DSN")
	}
}
