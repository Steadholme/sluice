package gateway

import (
	"strings"

	"github.com/holdfast/sluice/internal/config"
	"github.com/holdfast/sluice/internal/store"
)

// Router selects a Route for an incoming request from a RouteStore.
//
// Matching rule (Host is the PRIMARY key, for subdomain-per-service vhosts):
//   - a route's Match.Host, when set, must equal the request Host exactly to be
//     eligible; a route with an empty Host is a host-agnostic fallback eligible
//     for ANY host;
//   - an exact-Host route ALWAYS outranks a host-agnostic fallback, regardless of
//     path-prefix length (the request is routed to the vhost that owns the host);
//   - within the same host-specificity the longest matching PathPrefix wins, so a
//     service sitting at its subdomain ROOT ("/") still narrows by path when a
//     more specific prefix route is present on the same host.
//
// The store is consulted on every call so a future hot-reloading RouteStore is
// picked up transparently.
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
	bestHostSpecific := false
	bestLen := -1
	found := false

	for _, route := range r.store.Routes() {
		if route.Match.Host != "" && route.Match.Host != host {
			continue
		}
		if !strings.HasPrefix(path, route.Match.PathPrefix) {
			continue
		}
		hostSpecific := route.Match.Host != ""
		// Host is primary: an exact-host route upgrades over any host-agnostic one;
		// otherwise (same host-specificity) the longest path prefix wins.
		switch {
		case !found,
			hostSpecific && !bestHostSpecific,
			hostSpecific == bestHostSpecific && len(route.Match.PathPrefix) > bestLen:
			best = route
			bestHostSpecific = hostSpecific
			bestLen = len(route.Match.PathPrefix)
			found = true
		}
	}
	return best, found
}
