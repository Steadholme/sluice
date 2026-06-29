package oidc

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// gw_sessions / gw_oauth_state use only portable standard SQL (TEXT/BIGINT, plain
// PRIMARY KEY / NOT NULL / DEFAULT) so the same layer runs unchanged on FusionDB
// over pgwire — no JSON/arrays/SERIAL/extensions.
const (
	createSessionsDDL = `
CREATE TABLE IF NOT EXISTS gw_sessions (
    id         TEXT   PRIMARY KEY,
    sub        TEXT   NOT NULL,
    email      TEXT   NOT NULL DEFAULT '',
    scope      TEXT   NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
)`
	createStateDDL = `
CREATE TABLE IF NOT EXISTS gw_oauth_state (
    state         TEXT   PRIMARY KEY,
    nonce         TEXT   NOT NULL,
    code_verifier TEXT   NOT NULL,
    original_url  TEXT   NOT NULL DEFAULT '',
    expires_at    BIGINT NOT NULL
)`

	insertSessionSQL = `INSERT INTO gw_sessions (id, sub, email, scope, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (id) DO UPDATE SET sub = EXCLUDED.sub, email = EXCLUDED.email,
    scope = EXCLUDED.scope, created_at = EXCLUDED.created_at, expires_at = EXCLUDED.expires_at`
	selectSessionSQL = `SELECT sub, email, scope, created_at, expires_at FROM gw_sessions WHERE id = $1`
	deleteSessionSQL = `DELETE FROM gw_sessions WHERE id = $1`

	insertStateSQL = `INSERT INTO gw_oauth_state (state, nonce, code_verifier, original_url, expires_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (state) DO NOTHING`
	selectStateSQL = `SELECT nonce, code_verifier, original_url, expires_at FROM gw_oauth_state WHERE state = $1`
	deleteStateSQL = `DELETE FROM gw_oauth_state WHERE state = $1`
)

// PostgresStore is a SessionStore + StateStore backed by Postgres (FusionDB-ready
// portable SQL). Expiry is enforced lazily on read, mirroring MemoryStore.
type PostgresStore struct {
	pool *pgxpool.Pool
	now  func() int64
}

// NewPostgresStore connects to dsn, runs the idempotent migrations, and returns a
// store ready for the relying party. The caller owns Close.
func NewPostgresStore(ctx context.Context, dsn string) (*PostgresStore, error) {
	if dsn == "" {
		return nil, fmt.Errorf("oidc: postgres store requires a DSN")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("oidc: connect postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("oidc: ping postgres: %w", err)
	}
	for _, ddl := range []string{createSessionsDDL, createStateDDL} {
		if _, err := pool.Exec(ctx, ddl); err != nil {
			pool.Close()
			return nil, fmt.Errorf("oidc: migrate gateway tables: %w", err)
		}
	}
	return &PostgresStore{pool: pool, now: nowUnix}, nil
}

// Close releases the connection pool.
func (s *PostgresStore) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

func (s *PostgresStore) CreateSession(ctx context.Context, sess Session) error {
	_, err := s.pool.Exec(ctx, insertSessionSQL, sess.ID, sess.Sub, sess.Email, sess.Scope, sess.CreatedAt, sess.ExpiresAt)
	if err != nil {
		return fmt.Errorf("oidc: insert session: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetSession(ctx context.Context, id string) (Session, bool, error) {
	sess := Session{ID: id}
	err := s.pool.QueryRow(ctx, selectSessionSQL, id).
		Scan(&sess.Sub, &sess.Email, &sess.Scope, &sess.CreatedAt, &sess.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, false, nil
	}
	if err != nil {
		return Session{}, false, fmt.Errorf("oidc: select session: %w", err)
	}
	if s.now() > sess.ExpiresAt {
		_ = s.DeleteSession(ctx, id)
		return Session{}, false, nil
	}
	return sess, true, nil
}

func (s *PostgresStore) DeleteSession(ctx context.Context, id string) error {
	if _, err := s.pool.Exec(ctx, deleteSessionSQL, id); err != nil {
		return fmt.Errorf("oidc: delete session: %w", err)
	}
	return nil
}

func (s *PostgresStore) PutState(ctx context.Context, st OAuthState) error {
	_, err := s.pool.Exec(ctx, insertStateSQL, st.State, st.Nonce, st.CodeVerifier, st.OriginalURL, st.ExpiresAt)
	if err != nil {
		return fmt.Errorf("oidc: insert oauth state: %w", err)
	}
	return nil
}

// TakeState reads and atomically deletes the state row in a single transaction so
// a `state` (hence an authorization code) is redeemable exactly once.
func (s *PostgresStore) TakeState(ctx context.Context, state string) (OAuthState, bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return OAuthState{}, false, fmt.Errorf("oidc: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback after commit is a no-op

	st := OAuthState{State: state}
	err = tx.QueryRow(ctx, selectStateSQL, state).
		Scan(&st.Nonce, &st.CodeVerifier, &st.OriginalURL, &st.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return OAuthState{}, false, nil
	}
	if err != nil {
		return OAuthState{}, false, fmt.Errorf("oidc: select oauth state: %w", err)
	}
	if _, err := tx.Exec(ctx, deleteStateSQL, state); err != nil {
		return OAuthState{}, false, fmt.Errorf("oidc: delete oauth state: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return OAuthState{}, false, fmt.Errorf("oidc: commit tx: %w", err)
	}
	if s.now() > st.ExpiresAt {
		return OAuthState{}, false, nil
	}
	return st, true, nil
}
