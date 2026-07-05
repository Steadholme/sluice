package store

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/holdfast/sluice/internal/config"
)

// testRoutes builds a minimal, already-parsed route set. Tests inject these via
// PostgresStore.fetch, bypassing the real DB query, so the snapshot-swap and
// fail-closed logic can be exercised without a live PostgreSQL.
func testRoutes(names ...string) []config.Route {
	rs := make([]config.Route, 0, len(names))
	for _, n := range names {
		rs = append(rs, config.Route{
			Name:     n,
			Match:    config.Match{PathPrefix: "/" + n},
			Upstream: "http://127.0.0.1:8080",
		})
	}
	return rs
}

func routeNames(rs []config.Route) map[string]bool {
	m := make(map[string]bool, len(rs))
	for _, r := range rs {
		m[r.Name] = true
	}
	return m
}

// (a) After a successful reload, Routes() reflects the new row set. Swapping the
// injected fetch to return an extra route models a row being inserted in the DB;
// calling load() (what the background ticker fires) must publish it.
func TestReloadReflectsNewRoutes(t *testing.T) {
	s := &PostgresStore{}
	s.fetch = func(context.Context) ([]config.Route, error) { return testRoutes("public"), nil }

	if err := s.load(context.Background()); err != nil {
		t.Fatalf("initial load: %v", err)
	}
	if got := s.Routes(); len(got) != 1 || !routeNames(got)["public"] {
		t.Fatalf("after initial load got %v, want [public]", got)
	}

	// Simulate a newly inserted row and reload.
	s.fetch = func(context.Context) ([]config.Route, error) { return testRoutes("public", "added"), nil }
	if err := s.load(context.Background()); err != nil {
		t.Fatalf("reload: %v", err)
	}
	got := s.Routes()
	if len(got) != 2 || !routeNames(got)["added"] {
		t.Fatalf("after reload got %v, want new row 'added' present", got)
	}
}

// (b) fail-closed: when a reload errors, the last known-good snapshot is retained
// and load() surfaces the error to the caller (the reloader logs it and moves on).
func TestReloadErrorKeepsPreviousSnapshot(t *testing.T) {
	s := &PostgresStore{}
	s.fetch = func(context.Context) ([]config.Route, error) { return testRoutes("keep-me"), nil }
	if err := s.load(context.Background()); err != nil {
		t.Fatalf("initial load: %v", err)
	}

	// A failing fetch must not touch the published snapshot.
	s.fetch = func(context.Context) ([]config.Route, error) {
		return testRoutes("should-not-appear"), fmt.Errorf("boom")
	}
	if err := s.load(context.Background()); err == nil {
		t.Fatal("expected load to return the fetch error")
	}
	got := s.Routes()
	if len(got) != 1 || !routeNames(got)["keep-me"] {
		t.Fatalf("fail-closed violated: got %v, want previous snapshot [keep-me]", got)
	}
	if routeNames(got)["should-not-appear"] {
		t.Fatal("partial/failed result leaked into the published snapshot")
	}
}

// (c) Concurrent Routes() reads and load() writes must be race-free. Run with
// -race. Readers iterate the returned slice to prove a published backing array
// is never mutated in place (callers may read without further locking).
func TestReloadConcurrentReadWrite(t *testing.T) {
	s := &PostgresStore{}
	s.fetch = func(context.Context) ([]config.Route, error) { return testRoutes("seed"), nil }
	if err := s.load(context.Background()); err != nil {
		t.Fatalf("seed load: %v", err)
	}

	var counter int64
	s.fetch = func(context.Context) ([]config.Route, error) {
		n := atomic.AddInt64(&counter, 1)
		return testRoutes(fmt.Sprintf("r%d", n)), nil
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					for _, r := range s.Routes() {
						_ = r.Name
					}
				}
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					if err := s.load(context.Background()); err != nil {
						t.Errorf("concurrent load: %v", err)
						return
					}
				}
			}
		}()
	}

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// reloadLoop exits promptly when its context is cancelled (clean goroutine
// shutdown), without waiting a full reloadInterval.
func TestReloadLoopStopsOnCancel(t *testing.T) {
	s := &PostgresStore{done: make(chan struct{})}
	s.fetch = func(context.Context) ([]config.Route, error) { return testRoutes("a"), nil }

	ctx, cancel := context.WithCancel(context.Background())
	go s.reloadLoop(ctx)
	cancel()

	select {
	case <-s.done:
	case <-time.After(2 * time.Second):
		t.Fatal("reloadLoop did not exit after context cancel")
	}
}

// Close cancels the reloader and returns once the goroutine has exited (pool is
// nil here so only the reloader lifecycle is exercised).
func TestCloseStopsReloader(t *testing.T) {
	s := &PostgresStore{done: make(chan struct{})}
	s.fetch = func(context.Context) ([]config.Route, error) { return testRoutes("a"), nil }
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	go s.reloadLoop(ctx)

	returned := make(chan struct{})
	go func() { s.Close(); close(returned) }()

	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return after cancelling the reloader")
	}
	select {
	case <-s.done:
	default:
		t.Fatal("reloader goroutine still running after Close returned")
	}
}
