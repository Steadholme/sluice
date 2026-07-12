// Package accesslog emits one structured slog JSON line per request.
//
// The outer Wrap handler installs a mutable per-request record in the context
// before calling the next handler. Downstream code reports the resolved
// upstream (SetUpstream) and the verified subject (SetSubject) into that record;
// after the handler returns, Wrap reads the captured status, duration, upstream
// and subject and emits a single JSON line. These logs are the feedstock the
// data plane / Probe ingest later.
package accesslog

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"
)

// logger is the JSON sink for access logs. It is a package var so tests or main
// can redirect it if needed.
var logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))

// SetLogger overrides the access-log destination (used by main / tests).
func SetLogger(l *slog.Logger) {
	if l != nil {
		logger = l
	}
}

type ctxKey int

const recordKey ctxKey = iota

// record is the mutable per-request state filled in during handling.
type record struct {
	upstream string
	subject  string
}

// SetUpstream records the resolved upstream for the current request.
func SetUpstream(ctx context.Context, upstream string) {
	if rec, ok := ctx.Value(recordKey).(*record); ok {
		rec.upstream = upstream
	}
}

// SetSubject records the verified subject for the current request.
func SetSubject(ctx context.Context, subject string) {
	if rec, ok := ctx.Value(recordKey).(*record); ok {
		rec.subject = subject
	}
}

// RedactPath removes the complete authority-bearing tail from HOLDFAST's public capability
// namespaces before a request path enters access, auth or WAF telemetry. The decision is based on
// the path rather than Host or token validity: malformed requests, a trailing-dot Host and a token
// sent to the wrong virtual host must be just as unable to disclose a secret as a valid request.
// Query strings are already excluded from the access log. The only non-secret names beneath /s/
// are the two fixed Share Room assets; every other /s/ tail is capability-bearing, including the
// nested /s/folder/{token} route.
func RedactPath(_ string, path string) string {
	switch {
	case path == "/s/share-room.css", path == "/s/share-room.js":
		return path
	case len(path) > len("/s/folder/") && path[:len("/s/folder/")] == "/s/folder/":
		return "/s/folder/[capability]"
	case len(path) > len("/review/") && path[:len("/review/")] == "/review/":
		return "/review/[capability]"
	case len(path) > len("/receipts/") && path[:len("/receipts/")] == "/receipts/":
		return "/receipts/[capability]"
	case len(path) > len("/u/") && path[:len("/u/")] == "/u/":
		return "/u/[capability]"
	case len(path) > len("/s/") && path[:len("/s/")] == "/s/":
		return "/s/[capability]"
	default:
		return path
	}
}

// Wrap returns a handler that logs one JSON line per request after next runs.
func Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &record{}
		ctx := context.WithValue(r.Context(), recordKey, rec)
		r = r.WithContext(ctx)

		sr := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(sr, r)
		durMs := float64(time.Since(start).Nanoseconds()) / 1e6

		logger.LogAttrs(r.Context(), slog.LevelInfo, "access",
			slog.String("method", r.Method),
			slog.String("path", RedactPath(r.Host, r.URL.Path)),
			slog.Int("status", sr.status),
			slog.String("upstream", rec.upstream),
			slog.Float64("duration_ms", durMs),
			slog.String("sub", rec.subject),
		)
	})
}

// statusRecorder captures the response status while remaining transparent to
// streaming (Flush/Hijack reachable via http.ResponseController through Unwrap).
type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wrote {
		s.status = code
		s.wrote = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wrote {
		s.wrote = true
	}
	return s.ResponseWriter.Write(b)
}

// Unwrap exposes the underlying ResponseWriter to http.ResponseController so
// the reverse proxy can still Flush streamed responses.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }
