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
	postgresSchemaMigrationLockKey = "sluice:postgres-schema-migrations:v1"
	postgresSchemaMigrationLockSQL = `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`

	createSessionsDDL = `
CREATE TABLE IF NOT EXISTS gw_sessions (
    id              TEXT    PRIMARY KEY,
    sub             TEXT    NOT NULL,
    email           TEXT    NOT NULL DEFAULT '',
    scope           TEXT    NOT NULL DEFAULT '',
    created_at      BIGINT  NOT NULL,
    expires_at      BIGINT  NOT NULL,
    session_binding TEXT    NOT NULL DEFAULT '',
    aal             TEXT    NOT NULL DEFAULT 'AAL_NONE',
    uv              BOOLEAN NOT NULL DEFAULT FALSE,
    auth_time       BIGINT  NOT NULL DEFAULT 0,
    factor_epoch    BIGINT  NOT NULL DEFAULT 0
)`
	alterSessionsAssuranceDDL = `
ALTER TABLE gw_sessions
    ADD COLUMN IF NOT EXISTS session_binding TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS aal TEXT NOT NULL DEFAULT 'AAL_NONE',
    ADD COLUMN IF NOT EXISTS uv BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS auth_time BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS factor_epoch BIGINT NOT NULL DEFAULT 0`
	dropSessionsAssuranceCheckDDL = `ALTER TABLE gw_sessions DROP CONSTRAINT IF EXISTS ck_gw_sessions_assurance`
	addSessionsAssuranceCheckDDL  = `
ALTER TABLE gw_sessions ADD CONSTRAINT ck_gw_sessions_assurance CHECK (
    aal IN ('AAL_NONE','MFA_STRONG') AND auth_time >= 0 AND factor_epoch >= 0 AND
    ((aal = 'AAL_NONE' AND session_binding = '' AND uv = FALSE AND auth_time = 0 AND factor_epoch = 0) OR
     (aal = 'MFA_STRONG' AND LENGTH(session_binding) = 64 AND uv = TRUE AND auth_time > 0))
) NOT VALID`
	validateSessionsAssuranceCheckDDL = `ALTER TABLE gw_sessions VALIDATE CONSTRAINT ck_gw_sessions_assurance`
	createSessionsSubjectIndexDDL     = `CREATE INDEX IF NOT EXISTS ix_gw_sessions_sub ON gw_sessions (sub)`
	createStateDDL                    = `
CREATE TABLE IF NOT EXISTS gw_oauth_state (
    state               TEXT   PRIMARY KEY,
    nonce               TEXT   NOT NULL,
    code_verifier       TEXT   NOT NULL,
    original_url        TEXT   NOT NULL DEFAULT '',
    expires_at          BIGINT NOT NULL,
    flow                TEXT   NOT NULL DEFAULT 'login',
    expected_sub        TEXT   NOT NULL DEFAULT '',
    previous_session_id TEXT   NOT NULL DEFAULT '',
    previous_session_binding TEXT NOT NULL DEFAULT '',
    step_up_ref         TEXT   NOT NULL DEFAULT '',
    continuation_route  TEXT   NOT NULL DEFAULT '',
    continuation_host   TEXT   NOT NULL DEFAULT '',
    continuation_path   TEXT   NOT NULL DEFAULT ''
)`
	alterStateStepUpDDL = `
ALTER TABLE gw_oauth_state
    ADD COLUMN IF NOT EXISTS flow TEXT NOT NULL DEFAULT 'login',
    ADD COLUMN IF NOT EXISTS expected_sub TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS previous_session_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS previous_session_binding TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS step_up_ref TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS continuation_route TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS continuation_host TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS continuation_path TEXT NOT NULL DEFAULT ''`
	createSubjectSessionStateDDL = `
CREATE TABLE IF NOT EXISTS gw_subject_session_state (
    subject         TEXT   PRIMARY KEY,
    state           TEXT   NOT NULL CHECK (state IN ('active', 'frozen', 'terminated')),
    source_event_id TEXT   NOT NULL,
    source_version  BIGINT NOT NULL CHECK (source_version > 0),
    updated_at      BIGINT NOT NULL
)`

	insertSessionSQL = `INSERT INTO gw_sessions
    (id, sub, email, scope, created_at, expires_at, session_binding, aal, uv, auth_time, factor_epoch)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (id) DO UPDATE SET sub = EXCLUDED.sub, email = EXCLUDED.email,
    scope = EXCLUDED.scope, created_at = EXCLUDED.created_at, expires_at = EXCLUDED.expires_at,
    session_binding = EXCLUDED.session_binding, aal = EXCLUDED.aal, uv = EXCLUDED.uv,
    auth_time = EXCLUDED.auth_time, factor_epoch = EXCLUDED.factor_epoch`
	insertReplacementSessionSQL = `INSERT INTO gw_sessions
    (id, sub, email, scope, created_at, expires_at, session_binding, aal, uv, auth_time, factor_epoch)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (id) DO NOTHING`
	selectSessionSQL = `SELECT sub, email, scope, created_at, expires_at,
    session_binding, aal, uv, auth_time, factor_epoch FROM gw_sessions WHERE id = $1`
	deleteSessionSQL           = `DELETE FROM gw_sessions WHERE id = $1`
	deleteSessionsBySubjectSQL = `DELETE FROM gw_sessions WHERE sub = $1`

	insertStateSQL = `INSERT INTO gw_oauth_state
    (state, nonce, code_verifier, original_url, expires_at, flow, expected_sub, previous_session_id,
     previous_session_binding, step_up_ref, continuation_route, continuation_host, continuation_path)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
ON CONFLICT (state) DO NOTHING`
	selectStateSQL = `SELECT nonce, code_verifier, original_url, expires_at,
    flow, expected_sub, previous_session_id, previous_session_binding, step_up_ref,
    continuation_route, continuation_host,
    continuation_path FROM gw_oauth_state WHERE state = $1`
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
	if err := migratePostgresStore(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return &PostgresStore{pool: pool, now: nowUnix}, nil
}

// migratePostgresStore serializes all Sluice schema initialization through one
// transaction-scoped advisory lock. The public and WireGuard gateway instances
// share a database and can start concurrently; PostgreSQL's IF NOT EXISTS does
// not protect concurrent catalog creation from pg_class uniqueness races.
func migratePostgresStore(ctx context.Context, pool *pgxpool.Pool) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("oidc: begin gateway migration: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback after commit is a no-op
	if _, err := tx.Exec(ctx, postgresSchemaMigrationLockSQL, postgresSchemaMigrationLockKey); err != nil {
		return fmt.Errorf("oidc: lock gateway migrations: %w", err)
	}
	for _, ddl := range []string{
		createSessionsDDL,
		alterSessionsAssuranceDDL,
		dropSessionsAssuranceCheckDDL,
		addSessionsAssuranceCheckDDL,
		validateSessionsAssuranceCheckDDL,
		createSessionsSubjectIndexDDL,
		createStateDDL,
		alterStateStepUpDDL,
		createSubjectSessionStateDDL,
	} {
		if _, err := tx.Exec(ctx, ddl); err != nil {
			return fmt.Errorf("oidc: migrate gateway tables: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("oidc: commit gateway migration: %w", err)
	}
	return nil
}

// Close releases the connection pool.
func (s *PostgresStore) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

func (s *PostgresStore) CreateSession(ctx context.Context, sess Session) error {
	sess = normalizeSessionAssurance(sess)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("oidc: begin create session: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback after commit is a no-op
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", sess.Sub); err != nil {
		return fmt.Errorf("oidc: lock session subject: %w", err)
	}
	var blocked bool
	if err := tx.QueryRow(
		ctx,
		"SELECT EXISTS (SELECT 1 FROM gw_subject_session_state WHERE subject=$1 AND state<>'active')",
		sess.Sub,
	).Scan(&blocked); err != nil {
		return fmt.Errorf("oidc: read subject session state: %w", err)
	}
	if blocked {
		return ErrSubjectSessionBlocked
	}
	if _, err := tx.Exec(
		ctx,
		insertSessionSQL,
		sess.ID,
		sess.Sub,
		sess.Email,
		sess.Scope,
		sess.CreatedAt,
		sess.ExpiresAt,
		sess.SessionBinding,
		sess.AAL,
		sess.UV,
		sess.AuthTime,
		sess.FactorEpoch,
	); err != nil {
		return fmt.Errorf("oidc: insert session: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("oidc: commit create session: %w", err)
	}
	return nil
}

func (s *PostgresStore) ReplaceSession(
	ctx context.Context,
	expectedID string,
	expectedBinding string,
	sess Session,
) error {
	sess = normalizeSessionAssurance(sess)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("oidc: begin replace session: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback after commit is a no-op
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", sess.Sub); err != nil {
		return fmt.Errorf("oidc: lock replacement subject: %w", err)
	}
	decisionNow := s.now()
	var previousSub string
	var previousExpiry int64
	var previousBinding string
	err = tx.QueryRow(
		ctx,
		"SELECT sub,expires_at,session_binding FROM gw_sessions WHERE id=$1 FOR UPDATE",
		expectedID,
	).Scan(&previousSub, &previousExpiry, &previousBinding)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrSessionReplacementConflict
	}
	if err != nil {
		return fmt.Errorf("oidc: lock previous session: %w", err)
	}
	if previousSub != sess.Sub || previousBinding != expectedBinding ||
		expectedID == sess.ID || decisionNow > previousExpiry {
		return ErrSessionReplacementConflict
	}
	var successorExists bool
	if err := tx.QueryRow(
		ctx,
		"SELECT EXISTS (SELECT 1 FROM gw_sessions WHERE id=$1)",
		sess.ID,
	).Scan(&successorExists); err != nil {
		return fmt.Errorf("oidc: read replacement successor: %w", err)
	}
	if successorExists {
		return ErrSessionReplacementConflict
	}
	var blocked bool
	if err := tx.QueryRow(
		ctx,
		"SELECT EXISTS (SELECT 1 FROM gw_subject_session_state WHERE subject=$1 AND state<>'active')",
		sess.Sub,
	).Scan(&blocked); err != nil {
		return fmt.Errorf("oidc: read replacement subject state: %w", err)
	}
	if blocked {
		return ErrSubjectSessionBlocked
	}
	if !validStrongReplacementSession(sess, decisionNow) {
		return ErrSessionReplacementAssurance
	}
	if _, err := tx.Exec(ctx, deleteSessionSQL, expectedID); err != nil {
		return fmt.Errorf("oidc: delete previous session: %w", err)
	}
	result, err := tx.Exec(
		ctx,
		insertReplacementSessionSQL,
		sess.ID,
		sess.Sub,
		sess.Email,
		sess.Scope,
		sess.CreatedAt,
		sess.ExpiresAt,
		sess.SessionBinding,
		sess.AAL,
		sess.UV,
		sess.AuthTime,
		sess.FactorEpoch,
	)
	if err != nil {
		return fmt.Errorf("oidc: insert replacement session: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrSessionReplacementConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("oidc: commit replace session: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetSession(ctx context.Context, id string) (Session, bool, error) {
	sess := Session{ID: id}
	err := s.pool.QueryRow(ctx, selectSessionSQL, id).
		Scan(
			&sess.Sub,
			&sess.Email,
			&sess.Scope,
			&sess.CreatedAt,
			&sess.ExpiresAt,
			&sess.SessionBinding,
			&sess.AAL,
			&sess.UV,
			&sess.AuthTime,
			&sess.FactorEpoch,
		)
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
	return normalizeSessionAssurance(sess), true, nil
}

func (s *PostgresStore) DeleteSession(ctx context.Context, id string) error {
	if _, err := s.pool.Exec(ctx, deleteSessionSQL, id); err != nil {
		return fmt.Errorf("oidc: delete session: %w", err)
	}
	return nil
}

func (s *PostgresStore) DeleteSessionsBySubject(ctx context.Context, subject string) (int64, error) {
	result, err := s.pool.Exec(ctx, deleteSessionsBySubjectSQL, subject)
	if err != nil {
		return 0, fmt.Errorf("oidc: delete sessions by subject: %w", err)
	}
	return result.RowsAffected(), nil
}

func (s *PostgresStore) ApplySubjectSessionState(
	ctx context.Context,
	status SubjectSessionStatus,
) (SubjectSessionStateResult, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return SubjectSessionStateResult{}, fmt.Errorf("oidc: begin subject session state: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback after commit is a no-op
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", status.Subject); err != nil {
		return SubjectSessionStateResult{}, fmt.Errorf("oidc: lock session subject: %w", err)
	}
	var existingState string
	var existingEvent string
	var existingVersion int64
	err = tx.QueryRow(
		ctx,
		"SELECT state,source_event_id,source_version FROM gw_subject_session_state WHERE subject=$1 FOR UPDATE",
		status.Subject,
	).Scan(&existingState, &existingEvent, &existingVersion)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return SubjectSessionStateResult{}, fmt.Errorf("oidc: read subject session state: %w", err)
	}
	if err == nil {
		if status.SourceVersion < existingVersion {
			return SubjectSessionStateResult{}, ErrSubjectSessionStateStale
		}
		if status.SourceVersion == existingVersion {
			if string(status.State) != existingState || status.SourceEventID != existingEvent {
				return SubjectSessionStateResult{}, ErrSubjectSessionStateConflict
			}
			if err := tx.Commit(ctx); err != nil {
				return SubjectSessionStateResult{}, fmt.Errorf("oidc: commit subject session replay: %w", err)
			}
			return SubjectSessionStateResult{Replayed: true}, nil
		}
	}
	if _, err := tx.Exec(
		ctx,
		`INSERT INTO gw_subject_session_state (subject,state,source_event_id,source_version,updated_at)
VALUES ($1,$2,$3,$4,$5)
ON CONFLICT (subject) DO UPDATE SET state=EXCLUDED.state,source_event_id=EXCLUDED.source_event_id,
    source_version=EXCLUDED.source_version,updated_at=EXCLUDED.updated_at`,
		status.Subject,
		string(status.State),
		status.SourceEventID,
		status.SourceVersion,
		s.now(),
	); err != nil {
		return SubjectSessionStateResult{}, fmt.Errorf("oidc: persist subject session state: %w", err)
	}
	var revoked int64
	if status.State != SubjectSessionActive {
		result, err := tx.Exec(ctx, deleteSessionsBySubjectSQL, status.Subject)
		if err != nil {
			return SubjectSessionStateResult{}, fmt.Errorf("oidc: revoke sessions for subject state: %w", err)
		}
		revoked = result.RowsAffected()
	}
	if err := tx.Commit(ctx); err != nil {
		return SubjectSessionStateResult{}, fmt.Errorf("oidc: commit subject session state: %w", err)
	}
	return SubjectSessionStateResult{Revoked: revoked}, nil
}

func (s *PostgresStore) PutState(ctx context.Context, st OAuthState) error {
	if st.Flow == "" {
		st.Flow = OAuthFlowLogin
	}
	_, err := s.pool.Exec(
		ctx,
		insertStateSQL,
		st.State,
		st.Nonce,
		st.CodeVerifier,
		st.OriginalURL,
		st.ExpiresAt,
		st.Flow,
		st.ExpectedSub,
		st.PreviousSessionID,
		st.PreviousSessionBinding,
		st.StepUpRef,
		st.ContinuationRoute,
		st.ContinuationHost,
		st.ContinuationPath,
	)
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
		Scan(
			&st.Nonce,
			&st.CodeVerifier,
			&st.OriginalURL,
			&st.ExpiresAt,
			&st.Flow,
			&st.ExpectedSub,
			&st.PreviousSessionID,
			&st.PreviousSessionBinding,
			&st.StepUpRef,
			&st.ContinuationRoute,
			&st.ContinuationHost,
			&st.ContinuationPath,
		)
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
