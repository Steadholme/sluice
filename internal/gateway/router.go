package gateway

import (
	"strings"

	"github.com/holdfast/sluice/internal/config"
	"github.com/holdfast/sluice/internal/store"
)

// Router selects a Route for an incoming request from a RouteStore.
//
// Matching rule: if a route's Match.Host is set it must equal the request host
// exactly; among all host-compatible routes the one with the longest matching
// PathPrefix wins. The store is consulted on every call so a future hot-reloading
// RouteStore is picked up transparently.
type Router struct {
	store store.RouteStore
}

// NewRouter wraps a RouteStore.
func NewRouter(s store.RouteStore) *Router {
	return &Router{store: s}
}

// Match returns the best route for the given host and path, and ok=false when
// nothing matches.
func (r *Router) Match(host, path string) (config.Route, bool) {
	var best config.Route
	bestLen := -1
	found := false

	for _, route := range r.store.Routes() {
		if route.Match.Host != "" && route.Match.Host != host {
			continue
		}
		if !strings.HasPrefix(path, route.Match.PathPrefix) {
			continue
		}
		if len(route.Match.PathPrefix) > bestLen {
			best = route
			bestLen = len(route.Match.PathPrefix)
			found = true
		}
	}
	return best, found
}
