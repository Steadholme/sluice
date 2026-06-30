package waf

import (
	"sync"
	"time"
)

// Limiter is a sliding-window-log rate limiter keyed by client. Each client is
// allowed up to `limit` requests within any trailing `window`; the (limit+1)th
// request inside the window is denied. limit acts as the burst ceiling and
// limit/window is the sustained rate.
//
// State lives in a sync.Map of per-client *bucket, each guarded by its own mutex
// so concurrent clients never contend on a single global lock. A background
// sweeper evicts idle clients so the map cannot grow without bound.
type Limiter struct {
	limit  int
	window time.Duration
	now    func() time.Time // injectable clock for tests

	clients sync.Map // client-key string -> *bucket

	stop      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// bucket is one client's sliding window of request timestamps.
type bucket struct {
	mu    sync.Mutex
	times []time.Time
	last  time.Time
}

// NewLimiter builds a Limiter. A limit <= 0 yields a disabled limiter whose Allow
// always returns true (rate limiting off). It starts a sweeper goroutine that
// evicts clients idle for longer than the window; call Close to stop it.
func NewLimiter(limit int, window time.Duration) *Limiter {
	l := &Limiter{
		limit:  limit,
		window: window,
		now:    time.Now,
		stop:   make(chan struct{}),
	}
	if limit > 0 && window > 0 {
		l.wg.Add(1)
		go l.sweep()
	}
	return l
}

// Allow reports whether a request from client key may proceed, recording it when
// allowed. A disabled limiter (limit<=0) always allows. It is safe for concurrent
// use.
func (l *Limiter) Allow(key string) bool {
	if l == nil || l.limit <= 0 || l.window <= 0 {
		return true
	}
	now := l.now()
	cutoff := now.Add(-l.window)

	v, _ := l.clients.LoadOrStore(key, &bucket{})
	b := v.(*bucket)

	b.mu.Lock()
	defer b.mu.Unlock()

	// Drop timestamps that have slid out of the window.
	kept := b.times[:0]
	for _, t := range b.times {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	b.times = kept
	b.last = now

	if len(b.times) >= l.limit {
		return false
	}
	b.times = append(b.times, now)
	return true
}

// Close stops the background sweeper. It is idempotent and safe on a nil/disabled
// Limiter.
func (l *Limiter) Close() {
	if l == nil {
		return
	}
	l.closeOnce.Do(func() { close(l.stop) })
	l.wg.Wait()
}

// sweep periodically evicts clients with no activity within the last window so
// the client map tracks only currently-active clients.
func (l *Limiter) sweep() {
	defer l.wg.Done()
	ticker := time.NewTicker(l.window)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cutoff := l.now().Add(-l.window)
			l.clients.Range(func(key, v any) bool {
				b := v.(*bucket)
				b.mu.Lock()
				idle := b.last.Before(cutoff) && len(b.times) == 0
				// A bucket whose window has fully drained is also evictable.
				if !idle && b.last.Before(cutoff) {
					idle = true
				}
				b.mu.Unlock()
				if idle {
					l.clients.Delete(key)
				}
				return true
			})
		case <-l.stop:
			return
		}
	}
}
