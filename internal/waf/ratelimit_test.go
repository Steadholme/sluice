package waf

import (
	"sync"
	"testing"
	"time"
)

// newManualLimiter builds a limiter with an injected clock so the sliding window
// is deterministic. A long window keeps the background sweeper dormant during the
// test.
func newManualLimiter(limit int, window time.Duration) (*Limiter, *manualClock) {
	mc := &manualClock{t: time.Unix(1_700_000_000, 0)}
	l := NewLimiter(limit, window)
	l.now = mc.now
	return l, mc
}

// manualClock is a settable clock for the limiter tests.
type manualClock struct {
	mu sync.Mutex
	t  time.Time
}

func (m *manualClock) now() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.t
}

func (m *manualClock) advance(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.t = m.t.Add(d)
}

// TestLimiterAllowsUnderLimit lets exactly `limit` requests through, then denies.
func TestLimiterAllowsUnderLimit(t *testing.T) {
	l, _ := newManualLimiter(3, time.Hour)
	defer l.Close()

	for i := 0; i < 3; i++ {
		if !l.Allow("1.2.3.4") {
			t.Fatalf("request %d denied, want allowed (within burst)", i+1)
		}
	}
	if l.Allow("1.2.3.4") {
		t.Error("4th request allowed, want denied (over burst)")
	}
}

// TestLimiterSlidingWindow proves entries leave the window as time advances, so a
// client throttled now is allowed again once its window drains.
func TestLimiterSlidingWindow(t *testing.T) {
	l, clk := newManualLimiter(2, time.Minute)
	defer l.Close()

	if !l.Allow("c") || !l.Allow("c") {
		t.Fatal("first two requests should be allowed")
	}
	if l.Allow("c") {
		t.Fatal("third request within the window should be denied")
	}

	// Slide past the window: the earlier timestamps expire and capacity returns.
	clk.advance(61 * time.Second)
	if !l.Allow("c") {
		t.Error("request after window slide should be allowed")
	}
}

// TestLimiterPerClientIsolation proves one client's usage never throttles another.
func TestLimiterPerClientIsolation(t *testing.T) {
	l, _ := newManualLimiter(1, time.Hour)
	defer l.Close()

	if !l.Allow("a") {
		t.Fatal("client a first request should be allowed")
	}
	if l.Allow("a") {
		t.Fatal("client a second request should be denied")
	}
	if !l.Allow("b") {
		t.Error("client b should be allowed despite client a being throttled")
	}
}

// TestLimiterDisabled proves a non-positive limit disables throttling entirely.
func TestLimiterDisabled(t *testing.T) {
	l := NewLimiter(0, time.Minute)
	defer l.Close()
	for i := 0; i < 1000; i++ {
		if !l.Allow("x") {
			t.Fatalf("disabled limiter denied request %d, want always allow", i)
		}
	}

	var nilLimiter *Limiter
	if !nilLimiter.Allow("x") {
		t.Error("nil limiter Allow = false, want true (nil-safe always-allow)")
	}
}

// TestLimiterConcurrentSafe runs Allow from many goroutines to surface races
// under -race; the exact allow/deny split is not asserted, only that it does not
// panic or deadlock and respects the burst ceiling per client.
func TestLimiterConcurrentSafe(t *testing.T) {
	l, _ := newManualLimiter(50, time.Hour)
	defer l.Close()

	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.Allow("same") {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if allowed != 50 {
		t.Errorf("allowed = %d, want exactly 50 (burst ceiling under concurrency)", allowed)
	}
}
