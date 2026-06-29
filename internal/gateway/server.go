package gateway

import (
	"net/http"

	"github.com/holdfast/sluice/internal/accesslog"
	"github.com/holdfast/sluice/internal/auth"
	"github.com/holdfast/sluice/internal/config"
	"github.com/holdfast/sluice/internal/store"
)

// routeHandler pairs a matched route with its prepared handler so the access
// log can record the chosen upstream.
type routeHandler struct {
	route   config.Route
	handler http.Handler
}

// Server is the assembled Sluice HTTP handler: /healthz, route dispatch with
// per-route reverse proxies, forward-auth on protected routes, all wrapped in
// the structured access-log handler.
type Server struct {
	router   *Router
	verifier *auth.Verifier
	handlers map[string]routeHandler
}

// NewServer builds the gateway from a route store and a verifier. The verifier
// may be nil only when there are no protected routes. Per-route proxies are
// built once here; a future hot-reloading RouteStore would rebuild this map on
// change (the FusionDB/CDC seam), leaving request handling untouched.
func NewServer(s store.RouteStore, verifier *auth.Verifier) *Server {
	srv := &Server{
		router:   NewRouter(s),
		verifier: verifier,
		handlers: make(map[string]routeHandler),
	}
	for _, route := range s.Routes() {
		var h http.Handler = newReverseProxy(route)
		if route.Protected {
			h = auth.Middleware(verifier, h)
		}
		srv.handlers[routeKey(route)] = routeHandler{route: route, handler: h}
	}
	return srv
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
