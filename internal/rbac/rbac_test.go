package rbac

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/holdfast/sluice/internal/auth"
)

func TestGroupsForNeverUsesExpiredAuthorizationOnVerdictFailure(t *testing.T) {
	var fail atomic.Bool
	var calls atomic.Int32
	verdict := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("Authorization = %q, want bearer service token", got)
		}
		if fail.Load() {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"objects":["group:infra-admins"]}`))
	}))
	defer verdict.Close()

	now := time.Unix(1_700_000_000, 0)
	a := New(Config{
		Enabled:    true,
		VerdictURL: verdict.URL,
		Token:      "test-token",
		TTL:        time.Minute,
	})
	a.now = func() time.Time { return now }

	groups, err := a.groupsFor(context.Background(), "user:alice")
	if err != nil {
		t.Fatalf("initial groupsFor: %v", err)
	}
	if !contains(groups, "group:infra-admins") {
		t.Fatalf("initial groups = %v, want infra-admins", groups)
	}

	// A fresh entry remains usable without another PDP round trip.
	now = now.Add(30 * time.Second)
	fail.Store(true)
	groups, err = a.groupsFor(context.Background(), "user:alice")
	if err != nil || !contains(groups, "group:infra-admins") {
		t.Fatalf("fresh cached groups = %v, err = %v", groups, err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("Verdict calls while cache fresh = %d, want 1", got)
	}

	// Once expired, the old allow is no longer evidence. A PDP outage must be
	// visible to the strict gate instead of extending the allow indefinitely.
	now = now.Add(31 * time.Second)
	groups, err = a.groupsFor(context.Background(), "user:alice")
	if err == nil {
		t.Fatalf("expired cache with unavailable Verdict returned groups %v", groups)
	}
	if groups != nil {
		t.Fatalf("expired cache returned stale groups %v", groups)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("Verdict calls after cache expiry = %d, want 2", got)
	}
}

func TestGateReturns503WhenMembershipCannotBeDetermined(t *testing.T) {
	verdict := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer verdict.Close()

	a := New(Config{
		Enabled:    true,
		VerdictURL: verdict.URL,
		Token:      "test-token",
	})
	var upstreamHits atomic.Int32
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
	handler := a.Gate("infra-admins", next)

	req := httptest.NewRequest(http.MethodGet, "https://admin.example/", nil)
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{Subject: "alice"}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Fatalf("Cache-Control = %q, want private, no-store", got)
	}
	if got := upstreamHits.Load(); got != 0 {
		t.Fatalf("upstream hits = %d, want 0", got)
	}
}
