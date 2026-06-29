package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// jwksTestServer is an httptest OIDC/JWKS server whose readiness is toggled at
// runtime: while not ready it 404s discovery and JWKS (simulating an unreachable
// Keystone); once ready it serves a valid discovery document and JWKS for the
// generated RSA key. It counts successful JWKS fetches so tests can assert
// singleflight dedup.
type jwksTestServer struct {
	server    *httptest.Server
	priv      *rsa.PrivateKey
	ready     atomic.Bool
	jwksHits  atomic.Int64
	discHits  atomic.Int64
	jwksDelay time.Duration
	issuer    string
}

func newJWKSTestServer(t *testing.T) *jwksTestServer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	s := &jwksTestServer{priv: priv}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		s.discHits.Add(1)
		if !s.ready.Load() {
			http.Error(w, "not ready", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"` + s.issuer + `","jwks_uri":"` + s.issuer + `/jwks.json"}`))
	})
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		if !s.ready.Load() {
			http.Error(w, "not ready", http.StatusNotFound)
			return
		}
		if d := s.jwksDelay; d > 0 {
			time.Sleep(d)
		}
		s.jwksHits.Add(1)
		pub := &priv.PublicKey
		nStr := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		var eBuf [4]byte
		binary.BigEndian.PutUint32(eBuf[:], uint32(pub.E))
		eBytes := eBuf[:]
		for len(eBytes) > 1 && eBytes[0] == 0 {
			eBytes = eBytes[1:]
		}
		eStr := base64.RawURLEncoding.EncodeToString(eBytes)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"` +
			recoveryKID + `","n":"` + nStr + `","e":"` + eStr + `"}]}`))
	})

	s.server = httptest.NewServer(mux)
	s.issuer = s.server.URL
	t.Cleanup(s.server.Close)
	return s
}

func (s *jwksTestServer) discoveryURL() string {
	return s.issuer + "/.well-known/openid-configuration"
}

const recoveryKID = "kid-recovery-1"

// TestJWKSColdCacheValidatesOnFirstRequest proves a brand-new (never warmed)
// cache fetches keys on the very first protected request and validates a good
// token — no warm-up required.
func TestJWKSColdCacheValidatesOnFirstRequest(t *testing.T) {
	srv := newJWKSTestServer(t)
	srv.ready.Store(true) // Keystone reachable from the start

	cache := NewJWKSCache(srv.discoveryURL(), srv.server.Client(), 30*time.Second)
	v := NewVerifier(cache, srv.issuer)

	token := mintRS256(t, srv.priv, recoveryKID, srv.issuer, time.Now().Add(time.Hour))
	claims, err := v.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("cold-cache validate should succeed, got: %v", err)
	}
	if claims.Subject != "u_admin" {
		t.Errorf("Subject = %q, want u_admin", claims.Subject)
	}
	if got := srv.jwksHits.Load(); got != 1 {
		t.Errorf("jwks fetched %d times, want exactly 1 on first miss", got)
	}
}

// TestJWKSRecoversAfterFailedWarmup is the regression test for the robustness
// bug: a failed startup warm-up (Keystone returning 404) must NOT leave
// forward-auth stuck on a stale 401. The very first protected request after
// Keystone comes back must trigger a successful refresh and validate the token,
// without waiting out any cooldown.
func TestJWKSRecoversAfterFailedWarmup(t *testing.T) {
	srv := newJWKSTestServer(t)
	srv.ready.Store(false) // Keystone unreachable at startup

	// A long minRefresh proves recovery is NOT gated by the success cooldown:
	// the old bug recorded the failed warm-up as a "refresh" and then suppressed
	// all retries for minRefresh, returning 401 long after Keystone recovered.
	cache := NewJWKSCache(srv.discoveryURL(), srv.server.Client(), time.Hour)
	v := NewVerifier(cache, srv.issuer)

	// Warm-up fails because Keystone 404s. Non-fatal by contract; the cache is
	// left cold with one recorded failure (NOT a recorded "success" that would
	// arm the minRefresh cooldown — that was the bug).
	if err := cache.Warm(context.Background()); err == nil {
		t.Fatal("warm-up should have failed while Keystone is unreachable")
	}

	token := mintRS256(t, srv.priv, recoveryKID, srv.issuer, time.Now().Add(time.Hour))

	// Keystone recovers. The very first protected request must succeed
	// immediately: the first retry after a failure is never blocked by the
	// success cooldown or by backoff. The old code stayed stuck for minRefresh
	// (here a full hour) and kept returning 401.
	srv.ready.Store(true)
	claims, err := v.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("validation must recover immediately once Keystone is back, got: %v", err)
	}
	if claims.Subject != "u_admin" {
		t.Errorf("Subject = %q, want u_admin", claims.Subject)
	}
}

// TestJWKSConcurrentMissesDedup proves a burst of concurrent misses against a
// cold cache collapses into a single JWKS fetch via singleflight.
func TestJWKSConcurrentMissesDedup(t *testing.T) {
	srv := newJWKSTestServer(t)
	srv.ready.Store(true)
	srv.jwksDelay = 50 * time.Millisecond // widen the window so calls overlap

	cache := NewJWKSCache(srv.discoveryURL(), srv.server.Client(), 30*time.Second)
	v := NewVerifier(cache, srv.issuer)
	token := mintRS256(t, srv.priv, recoveryKID, srv.issuer, time.Now().Add(time.Hour))

	const n = 16
	var wg sync.WaitGroup
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			_, errs[i] = v.Validate(context.Background(), token)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("concurrent validate[%d] failed: %v", i, err)
		}
	}
	if got := srv.jwksHits.Load(); got != 1 {
		t.Errorf("jwks fetched %d times under concurrency, want exactly 1 (singleflight dedup)", got)
	}
}

// TestJWKSBackoffOnRepeatedFailures proves repeated failures (after the first
// immediate retry) are throttled by the bounded backoff: a second consecutive
// failure within baseBackoff is short-circuited without another upstream call.
func TestJWKSBackoffOnRepeatedFailures(t *testing.T) {
	srv := newJWKSTestServer(t)
	srv.ready.Store(false)

	cache := NewJWKSCache(srv.discoveryURL(), srv.server.Client(), 30*time.Second)
	cache.baseBackoff = time.Hour // make the post-first-failure backoff effectively block
	cache.maxBackoff = time.Hour

	ctx := context.Background()
	// First attempt: real fetch, fails (failures -> 1). discovery hit once.
	if err := cache.refresh(ctx); err == nil {
		t.Fatal("expected first refresh to fail")
	}
	hitsAfter1 := srv.discHits.Load()

	// Second attempt is the first retry (failures == 1 -> backoffFor == 0): it
	// MUST attempt again (real recovery is never blocked), so discovery is hit.
	if err := cache.refresh(ctx); err == nil {
		t.Fatal("expected second refresh to fail")
	}
	hitsAfter2 := srv.discHits.Load()
	if hitsAfter2 <= hitsAfter1 {
		t.Fatalf("first retry must hit upstream: hits %d -> %d", hitsAfter1, hitsAfter2)
	}

	// Third attempt: failures == 2, within baseBackoff (1h) -> short-circuited,
	// NO upstream call.
	if err := cache.refresh(ctx); err == nil {
		t.Fatal("expected third refresh to fail (backing off)")
	}
	if hitsAfter3 := srv.discHits.Load(); hitsAfter3 != hitsAfter2 {
		t.Errorf("backoff should suppress upstream call: hits %d -> %d", hitsAfter2, hitsAfter3)
	}
}
