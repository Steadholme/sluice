package gateway

import (
	"bufio"
	"errors"
	"net"
	"net/http"
)

// secureHeaders wraps the whole gateway handler and stamps baseline security headers on EVERY
// response, so the single public surface hardens all ~50 upstream services at once (Phantom
// flagged the estate for missing HSTS / X-Content-Type-Options).
//
// Headers are applied at WriteHeader/Write time via a wrapper so they land exactly once and
// after the reverse proxy has copied the upstream's headers: HSTS / nosniff / Referrer-Policy
// are Set (replacing any upstream value, so no duplicates), while X-Frame-Options is only set
// when the upstream did not already choose one (e.g. Echo's /embed needs SAMEORIGIN; a service
// is free to send DENY). No Content-Security-Policy is imposed — the estate's pages use inline
// <style>/<script>, so a strict CSP would break them; that is a per-service follow-up.
//
// The wrapper MUST preserve http.Hijacker (Murmur's WebSocket /ws) and http.Flusher (SSE
// streams like Klaxon's /api/stream), or those live connections break.
func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &secHeaderWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		// A handler that returned without ever writing still gets the headers on flush-less
		// 200s (rare; the stdlib writes an implicit 200 on first Write which we intercept).
		sw.apply()
	})
}

type secHeaderWriter struct {
	http.ResponseWriter
	done bool
}

// apply sets the baseline security headers exactly once, after upstream headers are present.
func (s *secHeaderWriter) apply() {
	if s.done {
		return
	}
	s.done = true
	h := s.Header()
	h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	if h.Get("X-Frame-Options") == "" {
		h.Set("X-Frame-Options", "SAMEORIGIN")
	}
}

func (s *secHeaderWriter) WriteHeader(code int) {
	s.apply()
	s.ResponseWriter.WriteHeader(code)
}

func (s *secHeaderWriter) Write(b []byte) (int, error) {
	s.apply()
	return s.ResponseWriter.Write(b)
}

// Hijack passes through so the WebSocket reverse proxy (Murmur /ws) can take over the conn.
func (s *secHeaderWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := s.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, errors.New("gateway: underlying ResponseWriter is not a http.Hijacker")
}

// Flush passes through so server-sent-event streams (e.g. Klaxon /api/stream) are not buffered.
func (s *secHeaderWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
