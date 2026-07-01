package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/holdfast/sluice/internal/config"
)

// schemaDDL creates the routes table using only portable SQL so the same layer
// runs unchanged on FusionDB over pgwire: TEXT/BOOLEAN columns, plain PRIMARY
// KEY / NOT NULL / DEFAULT constraints, no SERIAL/JSON/arrays/extensions. A
// route's match host is stored inline (empty string == "any host"); list-y data
// is avoided entirely because a route maps to exactly one upstream.
const schemaDDL = `
CREATE TABLE IF NOT EXISTS routes (
    name        TEXT    PRIMARY KEY,
    host        TEXT    NOT NULL DEFAULT '',
    path_prefix TEXT    NOT NULL,
    upstream    TEXT    NOT NULL,
    protected   BOOLEAN NOT NULL DEFAULT FALSE,
    auth          TEXT    NOT NULL DEFAULT '',
    waf           BOOLEAN NOT NULL DEFAULT FALSE,
    require_group TEXT    NOT NULL DEFAULT ''
)`

// addAuthColumnDDL backfills the auth column on a pre-existing routes table (one
// created before per-route auth modes existed). It is idempotent; on a fresh DB
// the column already exists from schemaDDL. Existing rows get auth=” and the
// loader derives the effective mode from the legacy protected flag, so behavior
// is unchanged until a route is explicitly set to a mode (e.g. "sso").
const addAuthColumnDDL = `ALTER TABLE routes ADD COLUMN IF NOT EXISTS auth TEXT NOT NULL DEFAULT ''`

// addWafColumnDDL backfills the waf opt-in column on a pre-existing routes table
// the same way. Idempotent; existing rows default to waf=FALSE so the inline WAF
// never engages on a route until it is explicitly flagged, keeping behavior
// unchanged.
const addWafColumnDDL = `ALTER TABLE routes ADD COLUMN IF NOT EXISTS waf BOOLEAN NOT NULL DEFAULT FALSE`

// addRequireGroupColumnDDL backfills the RBAC require_group column the same way.
// Idempotent; existing rows default to '' so no route is group-gated until it is
// explicitly set, keeping behavior unchanged.
const addRequireGroupColumnDDL = `ALTER TABLE routes ADD COLUMN IF NOT EXISTS require_group TEXT NOT NULL DEFAULT ''`

const (
	countRoutesSQL = `SELECT count(*) FROM routes`
	upsertRouteSQL = `INSERT INTO routes (name, host, path_prefix, upstream, protected, auth, waf, require_group)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (name) DO NOTHING`
	selectRoutesSQL = `SELECT name, host, path_prefix, upstream, protected, auth, waf, require_group
FROM routes ORDER BY name`
)

// PostgresStore is a RouteStore backed by a portable PostgreSQL routes table.
//
// Like StaticStore it serves an immutable snapshot: routes are loaded once at
// construction (after running the idempotent migration and, if the table is
// empty, seeding it). The data path only calls Routes(), so this slots in behind
// the existing seam with zero changes to the router/proxy/auth code.
type PostgresStore struct {
	pool   *pgxpool.Pool
	routes []config.Route
}

// NewPostgresStore connects to dsn, runs the idempotent migration, seeds the
// routes table from seed when it is empty, then loads and returns an immutable
// snapshot. seed reuses the existing config.Route shape (typically the routes
// from the config/seed file), so a fresh database still has working routes.
func NewPostgresStore(ctx context.Context, dsn string, seed []config.Route) (*PostgresStore, error) {
	if dsn == "" {
		return nil, fmt.Errorf("store: postgres requires %s", config.EnvDatabaseURL)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("store: connect postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping postgres: %w", err)
	}

	s := &PostgresStore{pool: pool}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	if err := s.seedIfEmpty(ctx, seed); err != nil {
		pool.Close()
		return nil, err
	}
	if err := s.load(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

// Routes returns the immutable snapshot loaded at construction.
func (s *PostgresStore) Routes() []config.Route { return s.routes }

// Close releases the underlying connection pool.
func (s *PostgresStore) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

func (s *PostgresStore) migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, schemaDDL); err != nil {
		return fmt.Errorf("store: migrate routes table: %w", err)
	}
	if _, err := s.pool.Exec(ctx, addAuthColumnDDL); err != nil {
		return fmt.Errorf("store: add auth column: %w", err)
	}
	if _, err := s.pool.Exec(ctx, addWafColumnDDL); err != nil {
		return fmt.Errorf("store: add waf column: %w", err)
	}
	if _, err := s.pool.Exec(ctx, addRequireGroupColumnDDL); err != nil {
		return fmt.Errorf("store: add require_group column: %w", err)
	}
	return nil
}

// seedIfEmpty inserts the seed routes only when the table has no rows. The
// UPSERT (ON CONFLICT DO NOTHING) makes a concurrent double-seed harmless.
func (s *PostgresStore) seedIfEmpty(ctx context.Context, seed []config.Route) error {
	var n int
	if err := s.pool.QueryRow(ctx, countRoutesSQL).Scan(&n); err != nil {
		return fmt.Errorf("store: count routes: %w", err)
	}
	if n > 0 || len(seed) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, r := range seed {
		batch.Queue(upsertRouteSQL, r.Name, r.Match.Host, r.Match.PathPrefix, r.Upstream, r.Protected, r.Auth, r.Waf, r.RequireGroup)
	}
	br := s.pool.SendBatch(ctx, batch)
	defer br.Close()
	for range seed {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("store: seed routes: %w", err)
		}
	}
	return nil
}

// load reads all routes and parses upstream URLs via config.Validate so the
// returned snapshot is hot-path ready (UpstreamURL populated), identical to what
// StaticStore serves from the config file.
func (s *PostgresStore) load(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, selectRoutesSQL)
	if err != nil {
		return fmt.Errorf("store: query routes: %w", err)
	}
	defer rows.Close()

	var loaded []config.Route
	for rows.Next() {
		var r config.Route
		if err := rows.Scan(&r.Name, &r.Match.Host, &r.Match.PathPrefix, &r.Upstream, &r.Protected, &r.Auth, &r.Waf, &r.RequireGroup); err != nil {
			return fmt.Errorf("store: scan route: %w", err)
		}
		loaded = append(loaded, r)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("store: iterate routes: %w", err)
	}
	if len(loaded) == 0 {
		return fmt.Errorf("store: routes table is empty and no seed was provided")
	}

	// Reuse the canonical validator to parse upstream URLs and reject bad rows.
	tmp := &config.Config{Routes: loaded}
	if err := tmp.Validate(); err != nil {
		return fmt.Errorf("store: validate loaded routes: %w", err)
	}
	s.routes = tmp.Routes
	return nil
}
