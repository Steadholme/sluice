package store

import (
	"context"
	"os"
	"strings"
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
		{Name: "pat-api", Match: config.Match{Host: "api.local", PathPrefix: "/api/v1/delete"}, Upstream: "http://127.0.0.1:8082", Protected: true, Auth: config.AuthPAT, RequireScope: "corvid:temp-mail:delete"},
	}
}

func TestStaticStorePreservesPATRouteFields(t *testing.T) {
	route := config.Route{
		Name:         "pat-api",
		Match:        config.Match{Host: "api.local", PathPrefix: "/api/v1/delete"},
		Upstream:     "http://127.0.0.1:8082",
		Auth:         config.AuthPAT,
		RequireScope: "corvid:temp-mail:delete",
	}
	store := NewStaticStore([]config.Route{route})
	got := store.Routes()[0]
	if got.Auth != config.AuthPAT || got.RequireScope != route.RequireScope {
		t.Fatalf("PAT route fields changed in StaticStore: %+v", got)
	}
}

func TestPostgresRoutePersistenceIncludesRequireScope(t *testing.T) {
	route := seedRoutes()[2]
	values := routeValues(route)
	if len(values) != 9 || values[8] != route.RequireScope {
		t.Fatalf("routeValues = %#v, want require_scope at position 9", values)
	}
	for name, sql := range map[string]string{
		"schema":  schemaDDL,
		"migrate": addRequireScopeColumnDDL,
		"upsert":  upsertRouteSQL,
		"select":  selectRoutesSQL,
	} {
		if !strings.Contains(sql, "require_scope") {
			t.Errorf("%s SQL omits require_scope: %s", name, sql)
		}
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
	// (0) Legacy DB: migrate a routes table that predates require_scope. The old
	// public row must remain loadable with an empty scope, and the new column must
	// be physically present before the fresh-db checks below.
	if _, err := pool.Exec(ctx, `CREATE TABLE routes (
name TEXT PRIMARY KEY,
host TEXT NOT NULL DEFAULT '',
path_prefix TEXT NOT NULL,
upstream TEXT NOT NULL,
protected BOOLEAN NOT NULL DEFAULT FALSE,
auth TEXT NOT NULL DEFAULT '',
waf BOOLEAN NOT NULL DEFAULT FALSE,
require_group TEXT NOT NULL DEFAULT ''
)`); err != nil {
		t.Fatalf("create legacy routes table: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO routes (name, path_prefix, upstream, auth) VALUES ('legacy-public', '/', 'http://127.0.0.1:8081', 'public')`); err != nil {
		t.Fatalf("insert legacy route: %v", err)
	}
	legacy, err := NewPostgresStore(ctx, dsn, nil)
	if err != nil {
		t.Fatalf("NewPostgresStore (legacy migration): %v", err)
	}
	if got := legacy.Routes(); len(got) != 1 || got[0].Name != "legacy-public" || got[0].RequireScope != "" {
		t.Fatalf("legacy migration routes = %+v", got)
	}
	legacy.Close()
	var requireScopeColumns int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'routes' AND column_name = 'require_scope'`).Scan(&requireScopeColumns); err != nil {
		t.Fatalf("inspect require_scope column: %v", err)
	}
	if requireScopeColumns != 1 {
		t.Fatalf("require_scope columns = %d, want 1", requireScopeColumns)
	}
	if _, err := pool.Exec(ctx, "DROP TABLE routes"); err != nil {
		t.Fatalf("drop migrated table: %v", err)
	}
	pool.Close()

	// (1) Fresh DB: migration runs, empty table is seeded, snapshot is parsed.
	s1, err := NewPostgresStore(ctx, dsn, seedRoutes())
	if err != nil {
		t.Fatalf("NewPostgresStore (seed): %v", err)
	}
	defer s1.Close()

	routes := s1.Routes()
	if len(routes) != 3 {
		t.Fatalf("got %d routes, want 3", len(routes))
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
	if got := byName["pat-api"]; got.Auth != config.AuthPAT || got.RequireScope != "corvid:temp-mail:delete" || !got.Protected {
		t.Errorf("pat-api round-trip mismatch: %+v", got)
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
	if len(s2.Routes()) != 3 {
		t.Fatalf("reopen returned %d routes, want 3 (table must not be re-seeded)", len(s2.Routes()))
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
