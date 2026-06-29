package auth

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

type failingResolver struct{}

func (failingResolver) KeyByKID(context.Context, string) (*rsa.PublicKey, error) {
	return nil, fmt.Errorf("no keys")
}

func TestMiddlewareRejectsBadAuth(t *testing.T) {
	v := NewVerifier(failingResolver{}, testIssuer)

	cases := []struct {
		name   string
		header string // value of Authorization header; "" means absent
	}{
		{"missing", ""},
		{"malformed-non-bearer", "Basic abc123"},
		{"bearer-no-token", "Bearer "},
		{"bad-token", "Bearer not.a.valid.jwt"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstreamHit := false
			next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				upstreamHit = true
			})
			h := Middleware(v, next)

			req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rec.Code)
			}
			if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
				t.Errorf("WWW-Authenticate = %q, want Bearer", got)
			}
			if upstreamHit {
				t.Error("upstream handler was called on auth failure")
			}
		})
	}
}
