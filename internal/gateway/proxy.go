package gateway

import (
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/holdfast/sluice/internal/auth"
	"github.com/holdfast/sluice/internal/config"
)

// authHeaderPrefix guards the X-Auth-* family. The proxy is the single trusted
// writer of these headers: it strips any client-supplied value and re-injects
// only the verified identity from the request context.
const authHeaderPrefix = "X-Auth-"

// newReverseProxy builds a streaming reverse proxy for a single route.
//
// The Rewrite hook (Go 1.20+) runs on a clone of the inbound request and:
//   - routes it to the route's upstream (preserving method, body, headers, and
//     forwarding the full request path);
//   - sets X-Forwarded-For / X-Forwarded-Host / X-Forwarded-Proto;
//   - strips every client-supplied X-Auth-* header, then injects the verified
//     X-Auth-Subject / X-Auth-Scope from the auth context when present.
//
// Public routes have no auth context, so all X-Auth-* headers are simply
// stripped and never re-added.
func newReverseProxy(route config.Route) *httputil.ReverseProxy {
	target := route.UpstreamURL()
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.SetXForwarded()

			stripAuthHeaders(pr.Out.Header)
			if id, ok := auth.IdentityFromContext(pr.In.Context()); ok {
				pr.Out.Header.Set(auth.HeaderAuthSubject, id.Subject)
				pr.Out.Header.Set(auth.HeaderAuthScope, id.Scope)
			}
		},
	}
}

// stripAuthHeaders removes every X-Auth-* header from h.
func stripAuthHeaders(h http.Header) {
	for k := range h {
		if strings.HasPrefix(http.CanonicalHeaderKey(k), authHeaderPrefix) {
			delete(h, k)
		}
	}
}
