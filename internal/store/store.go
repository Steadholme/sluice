// Package store owns the route source abstraction.
//
// The data path (router/proxy) only ever calls RouteStore.Routes(). In v0 the
// only implementation is StaticStore, an immutable snapshot built from the
// config file. This is the marked seam: a future FusionDB/CDC-backed store can
// implement the same interface and be swapped in via config alone, with zero
// changes to the proxy or auth code.
package store

import "github.com/holdfast/sluice/internal/config"

// RouteStore is the single seam the data path depends on for routing rules.
type RouteStore interface {
	// Routes returns the current snapshot of routes. Implementations must
	// return a slice that callers may read without further locking.
	Routes() []config.Route
}

// RouteChangeNotifier is implemented by live stores that can signal a freshly
// published generation. Reloadable handlers use it instead of a second polling
// timer, so one successful store poll produces one same-cycle handler swap.
type RouteChangeNotifier interface {
	RouteChanges() <-chan uint64
}

// StaticStore is an immutable, in-memory RouteStore built once from config.
type StaticStore struct {
	routes []config.Route
}

// NewStaticStore wraps a fixed set of routes (typically config.Routes).
func NewStaticStore(routes []config.Route) *StaticStore {
	return &StaticStore{routes: routes}
}

// Routes returns the immutable snapshot.
func (s *StaticStore) Routes() []config.Route { return s.routes }

// TODO(fusiondb-seam): add a FusionDBStore that consumes the CDC change feed
// and hot-reloads routes behind the same RouteStore interface. It would hold
// an atomic snapshot updated by a background consumer; Routes() would return
// the latest snapshot. Because the data path only calls Routes(), swapping
// StaticStore for FusionDBStore is a wiring change in cmd/sluice/main.go and
// requires no changes to internal/gateway or internal/auth.
