package gateway

import (
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"github.com/holdfast/sluice/internal/application"
	"github.com/holdfast/sluice/internal/auth"
	"github.com/holdfast/sluice/internal/config"
)

const (
	// authHeaderPrefix guards the X-Auth-* family. The proxy is the single trusted
	// writer of these headers: it strips any client-supplied value and re-injects
	// only the verified identity from the request context.
	authHeaderPrefix = "X-Auth-"
	// gatewayZoneHeader is minted by Sluice for downstream trust decisions. Clients
	// cannot supply it because every proxied request strips and replaces the value.
	gatewayZoneHeader = "X-Gateway-Zone"
)

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
//   - strips every client-supplied X-Gateway-Zone and X-Gateway-Zone-Sig header,
//     then injects the configured zone plus a host-bound signature when configured.
//   - strips every client-supplied X-Auth-* header, then injects the verified
//     X-Auth-Subject / X-Auth-Scope from the auth context when present; PAT
//     routes also receive a route-bound X-Auth-Scope-Sig.
//   - on auth="pat" and auth="application" routes, removes Authorization after
//     introspection so the raw opaque credential terminates at Sluice.
//
// Public routes have no auth context, so all X-Auth-* headers are simply
// stripped and never re-added.
//
// When mtls is non-nil and the upstream is https (the internal Keystone hop under
// INTERNAL_MTLS=on), the proxy uses the mTLS transport so it presents the Keyward
// client certificate; plain-http upstreams keep the default transport unchanged.
func newReverseProxy(
	route config.Route,
	mtls *http.Transport,
	identityHMACKey, zoneHMACKey, authzHMACKey string,
	authzContextV2Keys auth.AuthorizationContextV2Keyring,
	gatewayZone, sessionCookie string,
) *httputil.ReverseProxy {
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

			pr.Out.Header.Del(gatewayZoneHeader)
			pr.Out.Header.Set(gatewayZoneHeader, gatewayZone)
			pr.Out.Header.Del(auth.HeaderGatewayZoneSig)
			if sig := auth.SignGatewayZone(zoneHMACKey, route.Name, route.Match.Host, gatewayZone, time.Now().Unix()); sig != "" {
				pr.Out.Header.Set(auth.HeaderGatewayZoneSig, sig)
			}

			stripAuthHeaders(pr.Out.Header)
			stripHeaderFamily(pr.Out.Header, "X-Application-")
			stripHeaderFamily(pr.Out.Header, "X-Sponsor-Assertion")
			// Opaque PAT and application credentials terminate at Sluice. Unlike the
			// existing bearer/JWT path, these routes never forward Authorization to the
			// upstream; identity and scope are conveyed only through Sluice-minted
			// X-Auth-* headers (and the optional identity HMAC).
			if route.Auth == config.AuthPAT || route.Auth == config.AuthApplication {
				pr.Out.Header.Del("Authorization")
			}
			if route.Auth == config.AuthApplication {
				pr.Out.Header.Del("Cookie")
			}
			// Non-SSO routes are untrusted from the estate's point of view — most
			// importantly the public SiteFlow-deployed sites served on *.w33d.xyz,
			// which run arbitrary repo-owner code (incl. serverless functions). The
			// browser attaches the Domain=.w33d.xyz session cookie to those same-
			// registrable-domain hosts, so strip it here: a deployed function must
			// never see (and thus never be able to exfiltrate) the estate SSO
			// session. SSO routes are trusted estate services and keep it.
			if route.Auth != config.AuthSSO {
				stripCookie(pr.Out.Header, sessionCookie)
			}
			if id, ok := auth.IdentityFromContext(pr.In.Context()); ok {
				groups := strings.Join(id.Groups, ",")
				now := time.Now().Unix()
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
				if sig := auth.SignIdentity(identityHMACKey, id.Subject, groups, now); sig != "" {
					pr.Out.Header.Set(auth.HeaderAuthSig, sig)
				}
				if route.Auth == config.AuthPAT {
					if sig := auth.SignPATScope(identityHMACKey, id.Subject, id.Scope, route.RequireScope, now); sig != "" {
						pr.Out.Header.Set(auth.HeaderAuthScopeSig, sig)
					}
				}
			}
			if decision, ok := auth.AuthorizationFromContext(pr.In.Context()); ok {
				if sig := auth.SignAuthorizationContext(authzHMACKey, decision); sig != "" {
					pr.Out.Header.Set(auth.HeaderAuthPermission, decision.Permission)
					pr.Out.Header.Set(auth.HeaderAuthObject, decision.Object)
					pr.Out.Header.Set(auth.HeaderAuthDecision, decision.Decision)
					pr.Out.Header.Set(auth.HeaderAuthDecisionID, decision.DecisionID)
					pr.Out.Header.Set(auth.HeaderAuthRevocationEpoch, strconv.FormatInt(decision.RevocationEpoch, 10))
					pr.Out.Header.Set(auth.HeaderAuthContextTime, strconv.FormatInt(decision.Timestamp, 10))
					pr.Out.Header.Set(auth.HeaderAuthContextSig, sig)
				}
				if resourceType, resourceID, validResource := strings.Cut(decision.Object, ":"); validResource {
					signed, err := auth.MintAuthorizationContextV2(authzContextV2Keys, auth.AuthorizationContextV2{
						Issuer:          auth.AuthorizationContextV2Issuer,
						Subject:         decision.Subject,
						Route:           route.Name,
						Audience:        route.Match.Host,
						Zone:            gatewayZone,
						Permission:      decision.Permission,
						ResourceVersion: "1",
						ResourceType:    resourceType,
						ResourceID:      resourceID,
						Risk:            decision.Risk,
						Decision:        decision.Decision,
						DecisionID:      decision.DecisionID,
						PolicyEpoch:     decision.RevocationEpoch,
						IssuedAt:        decision.Timestamp,
						Expiry:          decision.Timestamp + auth.AuthorizationContextV2TTL,
					})
					if err == nil {
						for header, value := range signed.Headers() {
							pr.Out.Header.Set(header, value)
						}
					}
				}
			}
			if assertion, signature, ok := auth.MFAAssertionFromContext(pr.In.Context()); ok {
				uv := "0"
				if assertion.UV {
					uv = "1"
				}
				pr.Out.Header.Set(auth.HeaderAuthMFASubject, assertion.Subject)
				pr.Out.Header.Set(auth.HeaderAuthMFAAAL, assertion.AAL)
				pr.Out.Header.Set(auth.HeaderAuthMFAUV, uv)
				pr.Out.Header.Set(auth.HeaderAuthMFAAuthTime, strconv.FormatInt(assertion.AuthTime, 10))
				pr.Out.Header.Set(auth.HeaderAuthMFASessionBinding, assertion.SessionBinding)
				pr.Out.Header.Set(auth.HeaderAuthMFAFactorEpoch, strconv.FormatInt(assertion.FactorEpoch, 10))
				pr.Out.Header.Set(auth.HeaderAuthMFARoute, assertion.Route)
				pr.Out.Header.Set(auth.HeaderAuthMFAAudience, assertion.Audience)
				pr.Out.Header.Set(auth.HeaderAuthMFAEvidence, assertion.Evidence)
				pr.Out.Header.Set(auth.HeaderAuthMFATimestamp, strconv.FormatInt(assertion.Timestamp, 10))
				pr.Out.Header.Set(auth.HeaderAuthMFASig, signature)
			}
			if route.Auth == config.AuthApplication {
				if signed, ok := application.SignedRequestFromContext(pr.In.Context()); ok {
					for name, values := range signed.Headers() {
						pr.Out.Header[name] = append([]string(nil), values...)
					}
				}
			}
			if assertion, ok := application.SponsorAssertionFromContext(pr.In.Context()); ok {
				for name, values := range assertion.Headers() {
					pr.Out.Header[name] = append([]string(nil), values...)
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

func stripHeaderFamily(h http.Header, prefix string) {
	for key := range h {
		if strings.HasPrefix(http.CanonicalHeaderKey(key), prefix) {
			delete(h, key)
		}
	}
}

// stripCookie surgically removes a single named cookie from the request Cookie
// header, preserving every other cookie (so a deployed site keeps its own
// cookies while the estate session cookie is dropped). A no-op when name is
// empty or the header carries no such cookie; the header is deleted entirely
// when nothing remains.
func stripCookie(h http.Header, name string) {
	if name == "" {
		return
	}
	const cookieHeader = "Cookie"
	raw := h.Get(cookieHeader)
	if raw == "" {
		return
	}
	parts := strings.Split(raw, ";")
	kept := parts[:0]
	for _, p := range parts {
		c := strings.TrimSpace(p)
		if c == "" {
			continue
		}
		// A cookie name is everything up to the first '=' (RFC 6265 cookie-pair).
		if eq := strings.IndexByte(c, '='); eq >= 0 && c[:eq] == name {
			continue
		}
		kept = append(kept, c)
	}
	if len(kept) == 0 {
		h.Del(cookieHeader)
		return
	}
	h.Set(cookieHeader, strings.Join(kept, "; "))
}
