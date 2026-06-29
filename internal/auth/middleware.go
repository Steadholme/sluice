package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/holdfast/sluice/internal/accesslog"
)

// contextKey is a private type for context keys defined in this package.
type contextKey int

const identityKey contextKey = iota

// Header names injected toward the upstream for verified requests.
const (
	HeaderAuthSubject = "X-Auth-Subject"
	HeaderAuthScope   = "X-Auth-Scope"
	HeaderAuthEmail   = "X-Auth-Email"
)

// Identity is the verified caller identity established by the bearer Middleware
// or the OIDC SSO middleware and read back by the proxy (to inject X-Auth-*
// upstream) and the access log. Email is populated on the SSO path (from the
// id_token) and is empty on the bearer path, whose access token carries no email.
type Identity struct {
	Subject string
	Email   string
	Scope   string
}

// IdentityFromContext returns the verified Identity stored on the request.
func IdentityFromContext(ctx context.Context) (*Identity, bool) {
	id, ok := ctx.Value(identityKey).(*Identity)
	return id, ok
}

// ContextWithIdentity returns a child context carrying the verified Identity.
// It is the single sanctioned writer of the identity the proxy trusts, shared by
// the bearer Middleware and the OIDC SSO middleware so both feed the proxy's
// X-Auth-* injection through one private key.
func ContextWithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, identityKey, id)
}

// SubjectFromContext returns the authenticated subject, or "" if the request
// was not authenticated. Convenience for the access log.
func SubjectFromContext(ctx context.Context) string {
	if id, ok := IdentityFromContext(ctx); ok {
		return id.Subject
	}
	return ""
}

// Middleware returns a forward-auth handler wrapping next. It requires a valid
// "Authorization: Bearer <jwt>" header verified by v. On success it stores the
// verified Identity in the request context and calls next; the proxy is the
// single writer of upstream X-Auth-* headers (it strips any client-supplied
// X-Auth-* and injects the verified values from this context), so spoofed auth
// headers can never reach the upstream. Every failure maps to a single 401 +
// WWW-Authenticate: Bearer response with no information leak, and the upstream
// is never reached.
func Middleware(v *Verifier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok {
			unauthorized(w)
			return
		}
		claims, err := v.Validate(r.Context(), raw)
		if err != nil {
			unauthorized(w)
			return
		}

		id := &Identity{Subject: claims.Subject, Scope: claims.Scope}
		// Surface the verified subject to the access log (mutable per-request
		// record installed by the outer accesslog.Wrap handler).
		accesslog.SetSubject(r.Context(), claims.Subject)

		ctx := ContextWithIdentity(r.Context(), id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// bearerToken extracts the token from an Authorization header value. The scheme
// match is case-insensitive per RFC 7235.
func bearerToken(header string) (string, bool) {
	const prefix = "bearer "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return "", false
	}
	return token, true
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
