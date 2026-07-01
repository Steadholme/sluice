package gateway

import (
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

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
//   - sets X-Forwarded-For / X-Forwarded-Host / X-Forwarded-Proto (the latter
//     becomes "https" automatically once Sluice terminates TLS, since the inbound
//     request then carries a TLS connection state);
//   - PRESERVES the inbound Host header toward the upstream (instead of rewriting
//     it to the upstream's host) so a fronted Keystone sees the public host
//     (id.w33d.xyz) and builds correct absolute OIDC URLs;
//   - strips every client-supplied X-Auth-* header, then injects the verified
//     X-Auth-Subject / X-Auth-Scope from the auth context when present.
//
// Public routes have no auth context, so all X-Auth-* headers are simply
// stripped and never re-added.
//
// When mtls is non-nil and the upstream is https (the internal Keystone hop under
// INTERNAL_MTLS=on), the proxy uses the mTLS transport so it presents the Keyward
// client certificate; plain-http upstreams keep the default transport unchanged.
func newReverseProxy(route config.Route, mtls *http.Transport, hmacKey string) *httputil.ReverseProxy {
	target := route.UpstreamURL()
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.SetXForwarded()
			// SetURL clears Out.Host (so it would default to the upstream host);
			// re-pin it to the original inbound Host so the upstream — notably a
			// fronted Keystone — sees the public host and builds correct absolute
			// URLs. X-Forwarded-Host still carries the same value for apps that
			// prefer it.
			pr.Out.Host = pr.In.Host

			stripAuthHeaders(pr.Out.Header)
			if id, ok := auth.IdentityFromContext(pr.In.Context()); ok {
				groups := strings.Join(id.Groups, ",")
				pr.Out.Header.Set(auth.HeaderAuthSubject, id.Subject)
				pr.Out.Header.Set(auth.HeaderAuthScope, id.Scope)
				if id.Email != "" {
					pr.Out.Header.Set(auth.HeaderAuthEmail, id.Email)
				}
				if len(id.Groups) > 0 {
					pr.Out.Header.Set(auth.HeaderAuthGroups, groups)
				}
				// Cryptographically bind subject+groups to a 1-minute window so a backend
				// sharing GATEWAY_HMAC_KEY can prove Sluice minted this identity. Key unset
				// => "" => header omitted, so behavior is unchanged until the key is set.
				if sig := auth.SignIdentity(hmacKey, id.Subject, groups, time.Now().Unix()); sig != "" {
					pr.Out.Header.Set(auth.HeaderAuthSig, sig)
				}
			}
		},
	}
	if mtls != nil && target.Scheme == "https" {
		rp.Transport = mtls
	}
	return rp
}

// stripAuthHeaders removes every X-Auth-* header from h.
func stripAuthHeaders(h http.Header) {
	for k := range h {
		if strings.HasPrefix(http.CanonicalHeaderKey(k), authHeaderPrefix) {
			delete(h, k)
		}
	}
}
