package oidc

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestPostgresGatewayStore exercises the gw_sessions / gw_oauth_state tables
// against a real PostgreSQL instance. It is a clean no-op unless
// TEST_DATABASE_URL is set, so the default suite stays green with no database.
func TestPostgresGatewayStore(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping postgres gateway-store test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Clean slate so the run is deterministic.
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	for _, tbl := range []string{"gw_sessions", "gw_oauth_state"} {
		if _, err := pool.Exec(ctx, "DROP TABLE IF EXISTS "+tbl); err != nil {
			t.Fatalf("drop %s: %v", tbl, err)
		}
	}
	pool.Close()

	st, err := NewPostgresStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	defer st.Close()

	// Session round-trip + delete.
	sess := Session{ID: "s1", Sub: "u_admin", Email: "a@b.c", Scope: "openid email", CreatedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix()}
	if err := st.CreateSession(ctx, sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	got, ok, err := st.GetSession(ctx, "s1")
	if err != nil || !ok {
		t.Fatalf("GetSession: ok=%v err=%v", ok, err)
	}
	if got.Sub != "u_admin" || got.Email != "a@b.c" || got.Scope != "openid email" {
		t.Errorf("session round-trip mismatch: %+v", got)
	}
	if err := st.DeleteSession(ctx, "s1"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, ok, _ := st.GetSession(ctx, "s1"); ok {
		t.Error("session should be gone after delete")
	}

	// Expired session is treated as absent (lazy expiry on read).
	expired := Session{ID: "s2", Sub: "u", CreatedAt: time.Now().Add(-2 * time.Hour).Unix(), ExpiresAt: time.Now().Add(-time.Hour).Unix()}
	if err := st.CreateSession(ctx, expired); err != nil {
		t.Fatalf("CreateSession expired: %v", err)
	}
	if _, ok, _ := st.GetSession(ctx, "s2"); ok {
		t.Error("expired session should not be returned")
	}

	// State single-use.
	state := OAuthState{State: "st1", Nonce: "n", CodeVerifier: "v", OriginalURL: "/app", ExpiresAt: time.Now().Add(time.Minute).Unix()}
	if err := st.PutState(ctx, state); err != nil {
		t.Fatalf("PutState: %v", err)
	}
	got2, ok, err := st.TakeState(ctx, "st1")
	if err != nil || !ok {
		t.Fatalf("TakeState: ok=%v err=%v", ok, err)
	}
	if got2.Nonce != "n" || got2.CodeVerifier != "v" || got2.OriginalURL != "/app" {
		t.Errorf("state round-trip mismatch: %+v", got2)
	}
	if _, ok, _ := st.TakeState(ctx, "st1"); ok {
		t.Error("state must be single-use")
	}
}
