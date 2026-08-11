package gateway

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/holdfast/sluice/internal/auth"
	"github.com/holdfast/sluice/internal/config"
	"github.com/holdfast/sluice/internal/oidc"
)

// trustedMFAWrap mints one route/audience-bound assertion for an authenticated
// SSO request. A strong gateway session is never sufficient by itself: Sluice
// performs an uncached Keystone lookup on every request before retaining strong
// assurance. A missing authoritative binding degrades to exact AAL_NONE;
// transport, schema, binding, freshness, or signing failures are 503.
func trustedMFAWrap(route config.Route, next http.Handler, opts Options) http.Handler {
	if !opts.TrustedMFAEnabled {
		return next
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apply after the reverse proxy has copied upstream headers so an upstream
		// cannot replace the privacy policy with a cacheable response.
		protectedWriter := &secHeaderWriter{ResponseWriter: w, forceNoStore: true}
		w = protectedWriter
		defer protectedWriter.apply()
		id, identityOK := auth.IdentityFromContext(r.Context())
		session, sessionOK := oidc.GatewaySessionFromContext(r.Context())
		target := route.UpstreamURL()
		if !identityOK || id.Subject == "" || !sessionOK || session.Sub != id.Subject ||
			route.Name == "" || target == nil || target.Hostname() == "" {
			trustedMFAUnavailable(w, opts.Log, "session-context")
			return
		}
		if opts.MFAAssertionHMACKey == "" {
			trustedMFAUnavailable(w, opts.Log, "assertion-mint")
			return
		}

		assertion := auth.MFAAssertion{
			Subject:  id.Subject,
			AAL:      auth.MFAAALNone,
			Route:    route.Name,
			Audience: target.Hostname(),
		}
		var mintedAt int64

		switch session.AAL {
		case "", oidc.SessionAALNone:
			if session.UV || session.AuthTime != 0 || session.SessionBinding != "" || session.FactorEpoch != 0 {
				trustedMFAUnavailable(w, opts.Log, "session-context")
				return
			}
			mintedAt = now().Unix()
		case oidc.SessionMFAStrong:
			if opts.AssuranceLookup == nil || !session.UV || session.AuthTime <= 0 ||
				session.SessionBinding == "" || session.FactorEpoch < 0 {
				trustedMFAUnavailable(w, opts.Log, "lookup-authority")
				return
			}
			assurance, err := opts.AssuranceLookup.LookupSessionAssurance(
				r.Context(),
				id.Subject,
				session.SessionBinding,
			)
			// The mint clock is sampled only after the authoritative lookup. A
			// response legitimately produced in the next Unix second must not be
			// rejected as future-dated merely because the network call crossed a
			// clock boundary.
			mintedAt = now().Unix()
			if err != nil || assurance.Subject != id.Subject || assurance.AsOf <= 0 ||
				assurance.AsOf > mintedAt || mintedAt-assurance.AsOf > auth.MFAAssertionFreshnessSeconds {
				trustedMFAUnavailable(w, opts.Log, "lookup-authority")
				return
			}
			if assurance.Live {
				if assurance.AAL != oidc.SessionMFAStrong || !assurance.UV ||
					assurance.SessionBinding != session.SessionBinding ||
					assurance.AuthTime != session.AuthTime ||
					assurance.FactorEpoch != session.FactorEpoch {
					trustedMFAUnavailable(w, opts.Log, "lookup-authority")
					return
				}
				if assurance.AuthTime > mintedAt {
					trustedMFAUnavailable(w, opts.Log, "lookup-authority")
					return
				}
				// A valid but old ceremony is an authentication-strength outcome,
				// not an authority outage. Mint exact AAL_NONE so the policy/UI can
				// request step-up instead of presenting an operational 503.
				if mintedAt-assurance.AuthTime <= auth.MFAAssertionFreshnessSeconds {
					assertion.AAL = auth.MFAAALStrong
					assertion.UV = true
					assertion.AuthTime = assurance.AuthTime
					assertion.SessionBinding = assurance.SessionBinding
					assertion.FactorEpoch = assurance.FactorEpoch
				}
			} else if assurance.AAL != oidc.SessionAALNone || assurance.UV ||
				assurance.SessionBinding != "" || assurance.AuthTime != 0 || assurance.FactorEpoch < 0 {
				trustedMFAUnavailable(w, opts.Log, "lookup-authority")
				return
			}
		default:
			trustedMFAUnavailable(w, opts.Log, "session-context")
			return
		}
		assertion.Timestamp = mintedAt

		evidence, err := auth.MFAEvidenceDigest(assertion)
		if err != nil {
			trustedMFAUnavailable(w, opts.Log, "assertion-mint")
			return
		}
		assertion.Evidence = evidence
		signature, err := auth.SignMFAAssertion(opts.MFAAssertionHMACKey, assertion)
		if err != nil {
			trustedMFAUnavailable(w, opts.Log, "assertion-mint")
			return
		}
		ctx := auth.ContextWithMFAAssertion(r.Context(), assertion, signature)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func trustedMFAUnavailable(w http.ResponseWriter, log *slog.Logger, reason string) {
	if log == nil {
		log = slog.Default()
	}
	log.Warn("trusted MFA unavailable", "reason", reason)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Retry-After", "5")
	http.Error(w, "trusted MFA unavailable", http.StatusServiceUnavailable)
}
