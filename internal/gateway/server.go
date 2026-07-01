package gateway

import (
	"net/http"
	"strings"

	"github.com/holdfast/sluice/internal/accesslog"
	"github.com/holdfast/sluice/internal/audit"
	"github.com/holdfast/sluice/internal/auth"
	"github.com/holdfast/sluice/internal/config"
	"github.com/holdfast/sluice/internal/oidc"
	"github.com/holdfast/sluice/internal/rbac"
	"github.com/holdfast/sluice/internal/store"
	"github.com/holdfast/sluice/internal/waf"
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
//   - Auditor is the non-blocking audit emitter; when nil, no audit events are
//     emitted (and the request path is identical).
//   - WAF is the inline WAF + rate limiter (Aegis); when nil (or disabled) no
//     route is wrapped and the request path is identical. Only routes with
//     Waf=true are wrapped, so the WAF is opt-in even when the engine is enabled.
type Options struct {
	Verifier  *auth.Verifier
	Provider  *oidc.Provider
	Transport *http.Transport
	Auditor   *audit.Emitter
	WAF       *waf.Engine
	// Authz is the optional Verdict-backed RBAC authorizer. When nil or disabled,
	// per-route require_group gating is a no-op (nil-safe via Enabled()).
	Authz *rbac.Authorizer
	// PublicOnly, when true, builds a PUBLIC-facing gateway that omits every
	// internal (require_group) route — the router never matches them, so they 404.
	// The companion internal instance runs with PublicOnly=false (serves all) bound
	// to the VPN interface. Default false = serve every route.
	PublicOnly bool
	// PublicOnlyAllowHosts are hosts kept on a PublicOnly gateway even when they carry a
	// require_group — their SSO + group gate still runs (authWrap is unchanged). Lets a
	// bootstrap surface (VPN enrollment vpn.w33d.xyz) be reachable over public TLS so an
	// operator can authenticate and pull credentials before being on the VPN. Empty = strict.
	PublicOnlyAllowHosts map[string]bool
	// GatewayHMACKey, when non-empty, HMAC-signs the injected identity into X-Auth-Sig
	// so backends can verify Sluice minted it. Empty = no signature (backward compatible).
	GatewayHMACKey string
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
	routes := s.Routes()
	if opts.PublicOnly {
		// Public gateway: drop internal (require_group) routes so the router never
		// matches them (they 404) — the mgmt consoles live only on the internal
		// instance. autocert HostPolicy is computed separately from the FULL store
		// in main.go, so the public instance still issues/renews their certs.
		kept := make([]config.Route, 0, len(routes))
		for _, r := range routes {
			// Non-internal routes are always public. A require_group route is normally
			// dropped (404) here, UNLESS its host is allow-listed (e.g. the VPN enrollment
			// bootstrap surface) — its gate still runs downstream in authWrap.
			if r.RequireGroup == "" || opts.PublicOnlyAllowHosts[r.Match.Host] {
				kept = append(kept, r)
			}
		}
		routes = kept
		s = store.NewStaticStore(routes)
	}
	srv := &Server{
		router:   NewRouter(s),
		provider: opts.Provider,
		handlers: make(map[string]routeHandler),
	}
	for _, route := range routes {
		proxy := newReverseProxy(route, opts.Transport, opts.GatewayHMACKey)
		// Auth wraps the proxy; the WAF (when enabled AND this route opted in)
		// wraps the auth handler so malicious traffic is rejected before auth runs.
		// opts.WAF is nil when WAF_ENABLED is off, and Middleware is a pass-through
		// for routes that did not opt in — so unflagged routes are byte-identical.
		handler := authWrap(route, proxy, opts)
		if route.Waf {
			handler = opts.WAF.Middleware(handler)
		}
		srv.handlers[routeKey(route)] = routeHandler{
			route:   route,
			handler: handler,
		}
	}
	return srv
}

// authWrap selects the per-route auth handler from the route's normalized mode.
func authWrap(route config.Route, proxy http.Handler, opts Options) http.Handler {
	switch route.Auth {
	case config.AuthBearer:
		return auth.Middleware(opts.Verifier, proxy, auth.WithAuditor(opts.Auditor))
	case config.AuthSSO:
		if opts.Provider == nil {
			// Fail closed: SSO requested but the relying party is not configured.
			// The bearer/public paths are unaffected (safe degrade).
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "sso auth not configured", http.StatusServiceUnavailable)
			})
		}
		// Optional RBAC: an sso route that names a required group is wrapped with
		// the Verdict-backed gate, which runs AFTER the SSO middleware establishes
		// identity. When the authorizer is disabled/unconfigured or the route names
		// no group, inner stays the bare proxy (byte-identical behavior).
		inner := proxy
		if opts.Authz.Enabled() {
			if route.RequireGroup != "" {
				// Gate: fail-closed membership check (also injects id.Groups).
				inner = opts.Authz.Gate(route.RequireGroup, proxy)
			} else {
				// Plain SSO route: inject the user's groups (fail-open) so the backend can
				// run its OWN group-based authorization (e.g. moderator-only actions).
				inner = opts.Authz.InjectOnly(proxy)
			}
		}
		return opts.Provider.Middleware(inner)
	default: // config.AuthPublic
		return proxy
	}
}

// Handler returns the top-level http.Handler with baseline security headers (outermost, so
// they apply to every response incl. error/redirect paths) and access logging applied.
func (s *Server) Handler() http.Handler {
	return secureHeaders(accesslog.Wrap(http.HandlerFunc(s.serve)))
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
