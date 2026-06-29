package auth

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"
)

// TestJWKSPicksUpRotatedKID is the regression test for the SSO-root rotation
// gap: Keystone regenerates its RSA signing key on every restart, changing the
// JWKS kid. Sluice must pick up the rotated kid within seconds, NOT after the
// long proactive refresh interval.
//
// A healthy cache holds key A; Keystone then rotates to key B (new kid). Once
// the SHORT rotationCooldown has elapsed since the last success, the first
// request bearing a B-kid token triggers exactly one refresh and validates —
// proving the reactive path is gated by rotationCooldown, not by the 5-minute
// minRefresh.
func TestJWKSPicksUpRotatedKID(t *testing.T) {
	srv := newJWKSTestServer(t)
	srv.ready.Store(true)

	// minRefresh is the deploy value (5m); rotationCooldown is short. Pickup must
	// happen on the rotationCooldown timescale, decoupled from the 5-minute
	// proactive interval.
	cache := NewJWKSCache(srv.discoveryURL(), srv.server.Client(), 5*time.Minute,
		WithRotationCooldown(50*time.Millisecond))
	v := NewVerifier(cache, srv.issuer)

	// Warm the cache with key A -> healthy, exactly one fetch.
	tokA := mintRS256(t, srv.priv, recoveryKID, srv.issuer, time.Now().Add(time.Hour))
	if _, err := v.Validate(context.Background(), tokA); err != nil {
		t.Fatalf("initial validate (key A) failed: %v", err)
	}
	if got := srv.jwksHits.Load(); got != 1 {
		t.Fatalf("warm fetch count = %d, want 1", got)
	}

	// Keystone restarts and rotates its signing key to B (new kid).
	privB, kidB := srv.rotate(t)
	tokB := mintRS256(t, privB, kidB, srv.issuer, time.Now().Add(time.Hour))

	// Age the last success just past rotationCooldown (no sleep, deterministic),
	// while staying far inside minRefresh: the reactive path must still fire and
	// must NOT wait out the 5-minute interval.
	cache.mu.Lock()
	cache.lastSuccess = time.Now().Add(-time.Second) // > 50ms cooldown, << 5m minRefresh
	cache.mu.Unlock()

	claims, err := v.Validate(context.Background(), tokB)
	if err != nil {
		t.Fatalf("rotated-kid validate must succeed within rotationCooldown timescale, got: %v", err)
	}
	if claims.Subject != "u_admin" {
		t.Errorf("Subject = %q, want u_admin", claims.Subject)
	}
	// Exactly one additional fetch picked up the rotation (warm + rotation).
	if got := srv.jwksHits.Load(); got != 2 {
		t.Errorf("jwks fetched %d times total, want 2 (one warm + one rotation pickup)", got)
	}
}

// TestJWKSRotationSuppressedWithinCooldown proves the reactive refresh is
// genuinely gated by rotationCooldown: a rotated-kid token arriving WITHIN the
// cooldown of the last success is NOT yet refetched (the cache still only knows
// key A), so it is rejected and triggers no upstream fetch — the other half of
// the storm guard.
func TestJWKSRotationSuppressedWithinCooldown(t *testing.T) {
	srv := newJWKSTestServer(t)
	srv.ready.Store(true)

	// A long rotationCooldown keeps the request inside the cooldown window.
	cache := NewJWKSCache(srv.discoveryURL(), srv.server.Client(), 5*time.Minute,
		WithRotationCooldown(time.Hour))
	v := NewVerifier(cache, srv.issuer)

	tokA := mintRS256(t, srv.priv, recoveryKID, srv.issuer, time.Now().Add(time.Hour))
	if _, err := v.Validate(context.Background(), tokA); err != nil {
		t.Fatalf("initial validate (key A) failed: %v", err)
	}
	warmHits := srv.jwksHits.Load()

	// Rotate, then immediately present a B-kid token (well within the 1h cooldown).
	privB, kidB := srv.rotate(t)
	tokB := mintRS256(t, privB, kidB, srv.issuer, time.Now().Add(time.Hour))
	if _, err := v.Validate(context.Background(), tokB); err == nil {
		t.Fatal("rotated-kid token within cooldown must be rejected (refresh suppressed)")
	}
	if got := srv.jwksHits.Load(); got != warmHits {
		t.Errorf("refresh fired within cooldown: hits %d -> %d (want unchanged)", warmHits, got)
	}
}

// TestJWKSGarbageKIDStormSuppressedWithinCooldown proves the storm guard stays
// intact: a burst of distinct unknown ("garbage") kids against a healthy cache,
// all within rotationCooldown, triggers at most one upstream fetch, so a
// token-replay / garbage-kid storm cannot stampede Keystone.
func TestJWKSGarbageKIDStormSuppressedWithinCooldown(t *testing.T) {
	srv := newJWKSTestServer(t)
	srv.ready.Store(true)

	// A long rotationCooldown guarantees the whole burst lands inside the cooldown
	// window, isolating storm-guard behaviour from wall-clock timing.
	cache := NewJWKSCache(srv.discoveryURL(), srv.server.Client(), 5*time.Minute,
		WithRotationCooldown(time.Hour))
	v := NewVerifier(cache, srv.issuer)

	// Warm the cache -> healthy, one fetch.
	tok := mintRS256(t, srv.priv, recoveryKID, srv.issuer, time.Now().Add(time.Hour))
	if _, err := v.Validate(context.Background(), tok); err != nil {
		t.Fatalf("warm validate failed: %v", err)
	}
	warmHits := srv.jwksHits.Load()
	if warmHits != 1 {
		t.Fatalf("warm fetch count = %d, want 1", warmHits)
	}

	// Storm: many distinct unknown kids, all within rotationCooldown.
	const n = 32
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			bad := mintRS256(t, srv.priv, "garbage-kid-"+strconv.Itoa(i), srv.issuer, time.Now().Add(time.Hour))
			if _, err := v.Validate(context.Background(), bad); err == nil {
				t.Errorf("garbage kid %d unexpectedly validated", i)
			}
		}(i)
	}
	wg.Wait()

	// The storm guard must have suppressed every refetch: <= 1 fetch beyond warm.
	if extra := srv.jwksHits.Load() - warmHits; extra > 1 {
		t.Errorf("garbage-kid storm caused %d fetches, want <= 1 (storm guard intact)", extra)
	}
}
