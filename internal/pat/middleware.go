package pat

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/holdfast/sluice/internal/accesslog"
	"github.com/holdfast/sluice/internal/auth"
)

// Middleware authenticates one isolated opaque PAT, requires exact scope
// membership, and records the resulting identity in the same private context
// used by the proxy. It always introspects; there is no positive cache.
func Middleware(introspector Introspector, requiredScope string, next http.Handler) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Missing configuration is a dependency outage, not an invalid caller
		// credential. Keep the route present but fail it closed.
		if introspector == nil {
			serviceUnavailable(w)
			return
		}

		token, ok := tokenFromAuthorization(r.Header.Values("Authorization"))
		if !ok {
			unauthorized(w)
			return
		}
		result, err := introspector.Introspect(r.Context(), token)
		if err != nil {
			if errors.Is(err, ErrInvalidToken) {
				unauthorized(w)
				return
			}
			serviceUnavailable(w)
			return
		}
		if !result.Active {
			unauthorized(w)
			return
		}
		if !hasExactScope(result.Scope, requiredScope) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		id := &auth.Identity{Subject: result.Subject, Scope: result.Scope}
		accesslog.SetSubject(r.Context(), result.Subject)
		ctx := auth.ContextWithIdentity(r.Context(), id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
	return NoStore(handler)
}

// NoStore forces the cache boundary for every PAT-route outcome, including
// local auth errors, WAF denials, proxy errors, and successful upstream
// responses. It is exported so the gateway can place it outside optional WAF
// middleware as well as the auth middleware's own direct-use protection.
func NoStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &noStoreWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		sw.apply()
	})
}

func tokenFromAuthorization(values []string) (string, bool) {
	if len(values) != 1 {
		return "", false
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || !validOpaqueToken(parts[1]) {
		return "", false
	}
	return parts[1], true
}

func hasExactScope(granted, required string) bool {
	if required == "" {
		return false
	}
	for _, scope := range strings.Fields(granted) {
		if scope == required {
			return true
		}
	}
	return false
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func serviceUnavailable(w http.ResponseWriter) {
	http.Error(w, "authentication temporarily unavailable", http.StatusServiceUnavailable)
}

type noStoreWriter struct {
	http.ResponseWriter
	done bool
}

func (w *noStoreWriter) apply() {
	if w.done {
		return
	}
	w.done = true
	h := w.Header()
	h.Set("Cache-Control", "private, no-store")
	addVaryAuthorization(h)
}

func addVaryAuthorization(h http.Header) {
	for _, value := range h.Values("Vary") {
		for _, field := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(field), "Authorization") {
				return
			}
		}
	}
	h.Add("Vary", "Authorization")
}

func (w *noStoreWriter) WriteHeader(code int) {
	w.apply()
	w.ResponseWriter.WriteHeader(code)
}

func (w *noStoreWriter) Write(body []byte) (int, error) {
	w.apply()
	return w.ResponseWriter.Write(body)
}

func (w *noStoreWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *noStoreWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.apply()
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

func (w *noStoreWriter) Flush() {
	w.apply()
	// The direct writer is normally accesslog.statusRecorder, which deliberately
	// exposes optional interfaces through Unwrap instead of implementing them.
	// ResponseController follows that chain (and nested NoStore wrappers) to the
	// real server writer.
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}
