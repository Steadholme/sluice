package oidc

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
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
	for _, tbl := range []string{"gw_sessions", "gw_oauth_state", "gw_subject_session_state"} {
		if _, err := pool.Exec(ctx, "DROP TABLE IF EXISTS "+tbl); err != nil {
			t.Fatalf("drop %s: %v", tbl, err)
		}
	}
	pool.Close()

	// Production runs public and WireGuard Sluice instances against the same
	// database. Start several stores at once to prove schema initialization is
	// serialized rather than relying on CREATE ... IF NOT EXISTS races.
	type migrationResult struct {
		store *PostgresStore
		err   error
	}
	const concurrentStores = 8
	migrationStart := make(chan struct{})
	migrationResults := make(chan migrationResult, concurrentStores)
	for range concurrentStores {
		go func() {
			<-migrationStart
			store, migrateErr := NewPostgresStore(ctx, dsn)
			migrationResults <- migrationResult{store: store, err: migrateErr}
		}()
	}
	close(migrationStart)
	stores := make([]*PostgresStore, 0, concurrentStores)
	for range concurrentStores {
		result := <-migrationResults
		if result.err != nil {
			for _, store := range stores {
				store.Close()
			}
			t.Fatalf("concurrent NewPostgresStore: %v", result.err)
		}
		stores = append(stores, result.store)
	}
	defer func() {
		for _, store := range stores {
			store.Close()
		}
	}()
	st := stores[0]

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

	// Step-up replacement is a binding-aware CAS: failed binding checks and
	// successor-ID collisions leave the source session intact, while success
	// removes the weak source and inserts one strong successor atomically.
	replaceNow := time.Now().Unix()
	source := Session{
		ID: "replace-source", Sub: "u_replace", CreatedAt: replaceNow - 60,
		ExpiresAt: replaceNow + 3600, AAL: SessionAALNone,
	}
	if err := st.CreateSession(ctx, source); err != nil {
		t.Fatalf("CreateSession replacement source: %v", err)
	}
	collision := Session{
		ID: "replace-collision", Sub: source.Sub, CreatedAt: replaceNow,
		ExpiresAt: replaceNow + 3600, AAL: SessionAALNone,
	}
	if err := st.CreateSession(ctx, collision); err != nil {
		t.Fatalf("CreateSession replacement collision: %v", err)
	}
	strong := Session{
		ID: "replace-strong", Sub: source.Sub, CreatedAt: replaceNow,
		ExpiresAt: source.ExpiresAt, SessionBinding: strings.Repeat("a", 64),
		AAL: SessionMFAStrong, UV: true, AuthTime: replaceNow, FactorEpoch: 7,
	}
	if err := st.ReplaceSession(ctx, source.ID, strings.Repeat("b", 64), strong); !errors.Is(err, ErrSessionReplacementConflict) {
		t.Fatalf("replacement binding mismatch error = %v", err)
	}
	if _, ok, _ := st.GetSession(ctx, source.ID); !ok {
		t.Fatal("binding mismatch removed replacement source")
	}
	if err := st.ReplaceSession(ctx, source.ID, "", collision); !errors.Is(err, ErrSessionReplacementConflict) {
		t.Fatalf("replacement collision error = %v", err)
	}
	if _, ok, _ := st.GetSession(ctx, source.ID); !ok {
		t.Fatal("successor collision removed replacement source")
	}
	if err := st.ReplaceSession(ctx, source.ID, "", strong); err != nil {
		t.Fatalf("ReplaceSession success: %v", err)
	}
	if _, ok, _ := st.GetSession(ctx, source.ID); ok {
		t.Fatal("successful replacement retained source")
	}
	if got, ok, err := st.GetSession(ctx, strong.ID); err != nil || !ok || got.AAL != SessionMFAStrong {
		t.Fatalf("replacement strong session = (%+v,%t,%v)", got, ok, err)
	}

	// Store-time freshness is checked only after the subject lock is held. Simulate a callback
	// that was fresh before waiting but is 301 seconds old at the replacement boundary.
	staleSource := Session{
		ID: "replace-stale-source", Sub: "u_replace_stale", CreatedAt: replaceNow - 60,
		ExpiresAt: replaceNow + 3600, AAL: SessionAALNone,
	}
	if err := st.CreateSession(ctx, staleSource); err != nil {
		t.Fatalf("CreateSession stale replacement source: %v", err)
	}
	originalNow := st.now
	st.now = func() int64 { return replaceNow + 301 }
	staleStrong := Session{
		ID: "replace-stale-strong", Sub: staleSource.Sub, CreatedAt: replaceNow,
		ExpiresAt: staleSource.ExpiresAt, SessionBinding: strings.Repeat("d", 64),
		AAL: SessionMFAStrong, UV: true, AuthTime: replaceNow, FactorEpoch: 9,
	}
	if err := st.ReplaceSession(ctx, staleSource.ID, "", staleStrong); !errors.Is(err, ErrSessionReplacementAssurance) {
		t.Fatalf("stale replacement assurance error = %v", err)
	}
	if _, ok, _ := st.GetSession(ctx, staleSource.ID); !ok {
		t.Fatal("stale assurance replacement removed source session")
	}
	st.now = func() int64 { return replaceNow + 300 }
	if err := st.ReplaceSession(ctx, staleSource.ID, "", staleStrong); err != nil {
		t.Fatalf("300-second replacement boundary error = %v", err)
	}
	st.now = originalNow

	concurrentSource := Session{
		ID: "replace-concurrent-source", Sub: "u_replace_concurrent",
		CreatedAt: replaceNow - 60, ExpiresAt: replaceNow + 3600, AAL: SessionAALNone,
	}
	if err := st.CreateSession(ctx, concurrentSource); err != nil {
		t.Fatalf("CreateSession concurrent replacement source: %v", err)
	}
	startReplacement := make(chan struct{})
	replacementResults := make(chan error, 2)
	for _, id := range []string{"replace-concurrent-a", "replace-concurrent-b"} {
		id := id
		go func() {
			<-startReplacement
			replacementResults <- st.ReplaceSession(ctx, concurrentSource.ID, "", Session{
				ID: id, Sub: concurrentSource.Sub, CreatedAt: replaceNow,
				ExpiresAt: concurrentSource.ExpiresAt, SessionBinding: strings.Repeat("c", 64),
				AAL: SessionMFAStrong, UV: true, AuthTime: replaceNow, FactorEpoch: 8,
			})
		}()
	}
	close(startReplacement)
	var replacementSucceeded, replacementConflicted int
	for range 2 {
		err := <-replacementResults
		switch {
		case err == nil:
			replacementSucceeded++
		case errors.Is(err, ErrSessionReplacementConflict):
			replacementConflicted++
		default:
			t.Fatalf("concurrent ReplaceSession: %v", err)
		}
	}
	if replacementSucceeded != 1 || replacementConflicted != 1 {
		t.Fatalf(
			"concurrent replacement results: succeeded=%d conflicted=%d",
			replacementSucceeded,
			replacementConflicted,
		)
	}

	// Subject-wide delete atomically removes every device/session for the leaver
	// while retaining sessions for other identities.
	for _, sess := range []Session{
		{ID: "jml-1", Sub: "u_leaver", CreatedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix()},
		{ID: "jml-2", Sub: "u_leaver", CreatedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix()},
		{ID: "jml-other", Sub: "u_stayer", CreatedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix()},
	} {
		if err := st.CreateSession(ctx, sess); err != nil {
			t.Fatalf("CreateSession JML fixture: %v", err)
		}
	}
	result, err := st.ApplySubjectSessionState(ctx, SubjectSessionStatus{
		Subject: "u_leaver", State: SubjectSessionTerminated,
		SourceEventID: "event-7", SourceVersion: 7,
	})
	if err != nil || result.Revoked != 2 || result.Replayed {
		t.Fatalf("ApplySubjectSessionState: result=%+v err=%v", result, err)
	}
	if _, ok, _ := st.GetSession(ctx, "jml-1"); ok {
		t.Error("leaver session survived subject-wide delete")
	}
	if _, ok, _ := st.GetSession(ctx, "jml-other"); !ok {
		t.Error("other subject session was deleted")
	}
	if err := st.CreateSession(ctx, Session{ID: "jml-late", Sub: "u_leaver", CreatedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix()}); !errors.Is(err, ErrSubjectSessionBlocked) {
		t.Fatalf("late session creation error = %v, want blocked", err)
	}
	replay, err := st.ApplySubjectSessionState(ctx, SubjectSessionStatus{
		Subject: "u_leaver", State: SubjectSessionTerminated,
		SourceEventID: "event-7", SourceVersion: 7,
	})
	if err != nil || !replay.Replayed || replay.Revoked != 0 {
		t.Fatalf("subject state replay: result=%+v err=%v", replay, err)
	}
	if _, err := st.ApplySubjectSessionState(ctx, SubjectSessionStatus{
		Subject: "u_leaver", State: SubjectSessionActive,
		SourceEventID: "conflict", SourceVersion: 7,
	}); !errors.Is(err, ErrSubjectSessionStateConflict) {
		t.Fatalf("same-version conflict error = %v", err)
	}
	if _, err := st.ApplySubjectSessionState(ctx, SubjectSessionStatus{
		Subject: "u_leaver", State: SubjectSessionActive,
		SourceEventID: "event-8", SourceVersion: 8,
	}); err != nil {
		t.Fatalf("reactivate subject: %v", err)
	}
	if err := st.CreateSession(ctx, Session{ID: "jml-rehire", Sub: "u_leaver", CreatedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix()}); err != nil {
		t.Fatalf("reactivated subject session: %v", err)
	}

	// A callback racing a new freeze cannot leave a post-termination session:
	// both paths take the same subject advisory lock.
	start := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(2)
	var createErr, freezeErr error
	go func() {
		defer wait.Done()
		<-start
		createErr = st.CreateSession(ctx, Session{ID: "jml-race", Sub: "u_leaver", CreatedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix()})
	}()
	go func() {
		defer wait.Done()
		<-start
		_, freezeErr = st.ApplySubjectSessionState(ctx, SubjectSessionStatus{
			Subject: "u_leaver", State: SubjectSessionTerminated,
			SourceEventID: "event-9", SourceVersion: 9,
		})
	}()
	close(start)
	wait.Wait()
	if freezeErr != nil {
		t.Fatalf("racing freeze: %v", freezeErr)
	}
	if createErr != nil && !errors.Is(createErr, ErrSubjectSessionBlocked) {
		t.Fatalf("racing session creation: %v", createErr)
	}
	if _, ok, _ := st.GetSession(ctx, "jml-race"); ok {
		t.Fatal("callback race left a session after termination")
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
	state := OAuthState{
		State: "st1", Nonce: "n", CodeVerifier: "v", OriginalURL: "/app",
		ExpiresAt: time.Now().Add(time.Minute).Unix(), Flow: OAuthFlowStepUp,
		ExpectedSub: "u_admin", PreviousSessionID: "previous",
		PreviousSessionBinding: strings.Repeat("b", 64), StepUpRef: testStepUpRef,
		ContinuationRoute: "access-root", ContinuationHost: "access.w33d.xyz",
		ContinuationPath: "/request/scope/step-up/",
	}
	if err := st.PutState(ctx, state); err != nil {
		t.Fatalf("PutState: %v", err)
	}
	got2, ok, err := st.TakeState(ctx, "st1")
	if err != nil || !ok {
		t.Fatalf("TakeState: ok=%v err=%v", ok, err)
	}
	if got2.Nonce != "n" || got2.CodeVerifier != "v" || got2.OriginalURL != "/app" ||
		got2.Flow != OAuthFlowStepUp || got2.ExpectedSub != state.ExpectedSub ||
		got2.PreviousSessionID != state.PreviousSessionID ||
		got2.PreviousSessionBinding != state.PreviousSessionBinding ||
		got2.StepUpRef != state.StepUpRef || got2.ContinuationRoute != state.ContinuationRoute ||
		got2.ContinuationHost != state.ContinuationHost || got2.ContinuationPath != state.ContinuationPath {
		t.Errorf("state round-trip mismatch: %+v", got2)
	}
	if _, ok, _ := st.TakeState(ctx, "st1"); ok {
		t.Error("state must be single-use")
	}
}
