package gateway

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"strings"
)

// secureHeaders wraps the whole gateway handler and stamps baseline security headers on EVERY
// response, so the single public surface hardens all ~50 upstream services at once (Phantom
// flagged the estate for missing HSTS / X-Content-Type-Options).
//
// Headers are applied at WriteHeader/Write time via a wrapper so they land exactly once and
// after the reverse proxy has copied the upstream's headers: HSTS and nosniff are Set, every
// capability namespace is forced to `Referrer-Policy: no-referrer`, and an exact stronger upstream
// policy is preserved elsewhere; every other missing or weaker policy is replaced by the estate
// baseline.
// X-Frame-Options is only set when the upstream did not already choose one (e.g. Echo's /embed
// needs SAMEORIGIN; a service is free to send DENY). No Content-Security-Policy is imposed — the
// estate's pages use inline <style>/<script>, so a strict CSP would break them; that is a
// per-service follow-up.
//
// The wrapper MUST preserve http.Hijacker (Murmur's WebSocket /ws) and http.Flusher (SSE
// streams like Klaxon's /api/stream), or those live connections break.
func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &secHeaderWriter{
			ResponseWriter:  w,
			forceNoReferrer: isCapabilityNamespace(r.URL.Path),
			forceNoStore:    isCapabilityAuthorityPath(r.URL.Path),
		}
		next.ServeHTTP(sw, r)
		// A handler that returned without ever writing still gets the headers on flush-less
		// 200s (rare; the stdlib writes an implicit 200 on first Write which we intercept).
		sw.apply()
	})
}

type secHeaderWriter struct {
	http.ResponseWriter
	done            bool
	forceNoReferrer bool
	forceNoStore    bool
}

// Capability authority is carried in the path. Enforce no-referrer and no-store at the outer
// gateway layer so router misses, method errors and reverse-proxy failures receive the same privacy
// policy as a successful product response. Path-based matching is intentionally fail-safe across
// Host and token validity, matching access-log redaction. The two fixed Share Room assets keep
// their product-provided public cache policy but still receive no-referrer.
func isCapabilityNamespace(path string) bool {
	if isRSVPCapabilityPath(path) {
		return true
	}
	for _, prefix := range [...]string{"/review/", "/receipts/", "/s/", "/u/"} {
		if len(path) >= len(prefix) && path[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

func isRSVPCapabilityPath(path string) bool {
	return strings.HasPrefix(path, "/rsvp/")
}

func isCapabilityAuthorityPath(path string) bool {
	if path == "/s/share-room.css" || path == "/s/share-room.js" {
		return false
	}
	return isCapabilityNamespace(path)
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
	if s.forceNoStore {
		h.Set("Cache-Control", "private, no-store")
	}
	if s.forceNoReferrer {
		h.Set("Referrer-Policy", "no-referrer")
	} else if !strings.EqualFold(strings.TrimSpace(h.Get("Referrer-Policy")), "no-referrer") {
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	}
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
	s.apply()
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
