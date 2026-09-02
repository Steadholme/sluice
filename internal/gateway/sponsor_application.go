package gateway

import (
	"net/http"
	"time"

	"github.com/holdfast/sluice/internal/application"
	"github.com/holdfast/sluice/internal/auth"
	"github.com/holdfast/sluice/internal/config"
)

const maxSponsorSubmitBodyBytes = int64(64 << 10)

// sponsorAssertionWrap is intentionally live and in-process: it consumes only
// the trusted MFA context minted for this SSO request and exposes no file/input
// mechanism that could manufacture an assertion offline.
func sponsorAssertionWrap(route config.Route, next http.Handler, opts Options) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !applicationSubmitPath(r.URL.EscapedPath()) {
			next.ServeHTTP(w, r)
			return
		}
		if route.Auth != config.AuthSSO || opts.SponsorAssertionSigner == nil {
			trustedMFAUnavailable(w, opts.Log, "sponsor-signer")
			return
		}
		identity, identityOK := auth.IdentityFromContext(r.Context())
		mfa, _, mfaOK := auth.MFAAssertionFromContext(r.Context())
		now := time.Now
		if opts.Now != nil {
			now = opts.Now
		}
		mintedAt := now().Unix()
		if !identityOK || !mfaOK || identity.Subject == "" || mfa.Subject != identity.Subject || mfa.AAL != auth.MFAAALStrong || !mfa.UV || mfa.AuthTime <= 0 || mfa.AuthTime > mintedAt || mintedAt-mfa.AuthTime > application.SponsorTTLSeconds {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "fresh passkey authentication required", http.StatusUnauthorized)
			return
		}
		value, _, err := application.ParseSponsorSubmit(r, maxSponsorSubmitBodyBytes)
		if err != nil {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "invalid application request submission", http.StatusBadRequest)
			return
		}
		value.Subject = identity.Subject
		value.SessionBinding = mfa.SessionBinding
		value.AuthTime = mfa.AuthTime
		signed, err := opts.SponsorAssertionSigner.Mint(value)
		if err != nil {
			trustedMFAUnavailable(w, opts.Log, "sponsor-mint")
			return
		}
		next.ServeHTTP(w, r.WithContext(application.ContextWithSponsorAssertion(r.Context(), signed)))
	})
}

func applicationSubmitPath(path string) bool {
	return application.IsSponsorSubmitPath(path)
}
