package gateway

import (
	"net/http"
	"strings"

	"github.com/holdfast/sluice/internal/accesslog"
	"github.com/holdfast/sluice/internal/auth"
	"github.com/holdfast/sluice/internal/config"
	"github.com/holdfast/sluice/internal/oidc"
	"github.com/holdfast/sluice/internal/store"
)

// routeHandler pairs a matched route with its prepared handler so the access
// log can record the chosen upstream.
type routeHandler struct {
	route   config.Route
	handler http.Handler
}

// Options carries the optional collaborators the gateway wires onto routes. All
// are nil-safe so existing call sites stay simple:
//   - Verifier validates bearer routes (required only if any route is "bearer").
//   - Provider is the OIDC relying party for "sso" routes; when nil, sso routes
//     fail closed (503) so the rest of the gateway keeps serving.
//   - Transport is the mTLS http.Transport used for https upstreams (the internal
//     Keystone hop); when nil, https upstreams use the default transport.
type Options struct {
	Verifier  *auth.Verifier
	Provider  *oidc.Provider
	Transport *http.Transport
}

// Server is the assembled Sluice HTTP handler: /healthz, the gateway-owned
// /_gw/* OIDC endpoints, route dispatch with per-route reverse proxies, and
// per-route auth (public / bearer / sso), all wrapped in the structured
// access-log handler.
type Server struct {
	router   *Router
	provider *oidc.Provider
	handlers map[string]routeHandler
}

// NewServer builds the gateway from a route store and the optional collaborators.
// Per-route proxies + auth wrappers are built once here; a future hot-reloading
// RouteStore would rebuild this map on change (the FusionDB/CDC seam), leaving
// request handling untouched.
func NewServer(s store.RouteStore, opts Options) *Server {
	srv := &Server{
		router:   NewRouter(s),
		provider: opts.Provider,
		handlers: make(map[string]routeHandler),
	}
	for _, route := range s.Routes() {
		proxy := newReverseProxy(route, opts.Transport)
		srv.handlers[routeKey(route)] = routeHandler{
			route:   route,
			handler: authWrap(route, proxy, opts),
		}
	}
	return srv
}

// authWrap selects the per-route auth handler from the route's normalized mode.
func authWrap(route config.Route, proxy http.Handler, opts Options) http.Handler {
	switch route.Auth {
	case config.AuthBearer:
		return auth.Middleware(opts.Verifier, proxy)
	case config.AuthSSO:
		if opts.Provider == nil {
			// Fail closed: SSO requested but the relying party is not configured.
			// The bearer/public paths are unaffected (safe degrade).
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "sso auth not configured", http.StatusServiceUnavailable)
			})
		}
		return opts.Provider.Middleware(proxy)
	default: // config.AuthPublic
		return proxy
	}
}

// Handler returns the top-level http.Handler with access logging applied.
func (s *Server) Handler() http.Handler {
	return accesslog.Wrap(http.HandlerFunc(s.serve))
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	}

	// Gateway-owned OIDC endpoints are served by Sluice itself and MUST be
	// intercepted before route matching so the catch-all "/" route never proxies
	// them to Keystone.
	if s.provider != nil && strings.HasPrefix(r.URL.Path, oidc.GatewayPrefix) {
		s.provider.ServeHTTP(w, r)
		return
	}

	route, ok := s.router.Match(r.Host, r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	rh, ok := s.handlers[routeKey(route)]
	if !ok {
		// Should not happen: every store route is registered at construction.
		http.NotFound(w, r)
		return
	}
	// Record the resolved upstream for the access log.
	accesslog.SetUpstream(r.Context(), rh.route.Upstream)
	rh.handler.ServeHTTP(w, r)
}

// routeKey uniquely identifies a route by its match criteria.
func routeKey(route config.Route) string {
	return route.Match.Host + "\x00" + route.Match.PathPrefix
}
