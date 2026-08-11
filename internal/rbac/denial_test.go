package rbac

import (
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The four browser denial pages share one renderer, so the full contract —
// exact headers, semantic structure, self-containment and no sensitive values —
// is asserted once per variant through the same helpers the gates call.
func TestDenialPages(t *testing.T) {
	for _, test := range []struct {
		name         string
		serve        func(w http.ResponseWriter)
		wantStatus   int
		wantTitle    string
		wantModifier string
		wantHeading  string
		wantLede     string
		wantLabel    string
		wantCode     string
		retryAfter   string
		wantContains []string
		wantAbsent   []string
	}{
		{
			name:         "permission 403",
			serve:        func(w http.ResponseWriter) { permissionForbidden(w, "cpa.console.enter") },
			wantStatus:   http.StatusForbidden,
			wantTitle:    "403",
			wantModifier: "danger",
			wantHeading:  "Access denied",
			wantLede:     "You're signed in. Your account doesn't have the permission this area needs yet.",
			wantLabel:    "Required permission",
			wantCode:     "cpa.console.enter",
			wantContains: []string{
				`<a class="btn btn-primary" href="https://access.w33d.xyz/request">Request access</a>`,
				`<a class="btn" href="https://w33d.xyz">Back to all apps</a>`,
				"Approved grants take effect right away",
			},
			wantAbsent: []string{`role="status"`, `href=""`, "Try again"},
		},
		{
			name:         "permission 503",
			serve:        func(w http.ResponseWriter) { permissionUnavailable(w, "cpa.console.enter") },
			wantStatus:   http.StatusServiceUnavailable,
			wantTitle:    "503",
			wantModifier: "degraded",
			wantHeading:  "Access can't be verified right now",
			wantLede:     "We couldn't check your access, so this page stayed closed. Nothing was changed.",
			wantLabel:    "Permission being checked",
			wantCode:     "cpa.console.enter",
			retryAfter:   "5",
			wantContains: []string{
				`<p class="lede" role="status">`,
				`<a class="btn btn-primary" href="">Try again</a>`,
			},
			wantAbsent: []string{"Request access", "access.w33d.xyz", "Back to all apps", `class="note"`},
		},
		{
			name:         "group 403",
			serve:        func(w http.ResponseWriter) { New(Config{}).forbidden(w, "infra-admins") },
			wantStatus:   http.StatusForbidden,
			wantTitle:    "403",
			wantModifier: "danger",
			wantHeading:  "Access restricted",
			wantLede:     "This area is limited to members of a specific group. Your account isn't a member.",
			wantLabel:    "Required group",
			wantCode:     "infra-admins",
			wantContains: []string{
				`<a class="btn" href="https://w33d.xyz">Back to all apps</a>`,
			},
			// Groups have no self-service request workflow.
			wantAbsent: []string{"Request access", "access.w33d.xyz", `role="status"`, `href=""`},
		},
		{
			name:         "group 503",
			serve:        func(w http.ResponseWriter) { New(Config{}).unavailable(w, "infra-admins") },
			wantStatus:   http.StatusServiceUnavailable,
			wantTitle:    "503",
			wantModifier: "degraded",
			wantHeading:  "Access can't be verified right now",
			wantLede:     "We couldn't check your access, so this page stayed closed. Nothing was changed.",
			wantLabel:    "Required group",
			wantCode:     "infra-admins",
			retryAfter:   "5",
			wantContains: []string{
				`<p class="lede" role="status">`,
				`<a class="btn btn-primary" href="">Try again</a>`,
			},
			wantAbsent: []string{"Request access", "access.w33d.xyz", "Back to all apps", `class="note"`},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			test.serve(recorder)

			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, test.wantStatus)
			}
			header := recorder.Header()
			for name, want := range map[string]string{
				"Content-Type":            "text/html; charset=utf-8",
				"Cache-Control":           "private, no-store",
				"Content-Security-Policy": denialCSP,
				"X-Frame-Options":         "DENY",
				"Referrer-Policy":         "no-referrer",
				"Retry-After":             test.retryAfter,
			} {
				if got := header.Get(name); got != want {
					t.Fatalf("%s = %q, want %q", name, got, want)
				}
			}

			body := recorder.Body.String()
			shared := []string{
				"<!doctype html",
				`<html lang="en">`,
				`<meta name="robots" content="noindex,nofollow">`,
				`<meta name="color-scheme" content="light dark">`,
				`<a class="skip" href="#main">Skip to content</a>`,
				`<main id="main" aria-labelledby="denial-title">`,
				`<title>` + test.wantTitle + ` · Steadholme</title>`,
				`<div class="card card--` + test.wantModifier + `">`,
				`<p class="status-code">` + test.wantTitle + `</p>`,
				`<h1 id="denial-title">` + test.wantHeading + `</h1>`,
				test.wantLede,
				`<span class="detail-label">` + test.wantLabel + `</span>`,
				`<code>` + test.wantCode + `</code>`,
				// Visual and accessibility contract markers.
				"color-scheme:light dark",
				"@media (prefers-color-scheme:dark)",
				"@media (prefers-reduced-motion:reduce)",
				"a:focus-visible",
				"min-height:40px",
				"overflow-wrap:anywhere",
				// Foundation 1.0 token fidelity spot checks.
				"#f2f0e8", "#faf9f4", "#b6422c", "#ff7559",
			}
			for _, want := range append(shared, test.wantContains...) {
				if !strings.Contains(body, want) {
					t.Fatalf("body missing %q", want)
				}
			}
			if count := strings.Count(body, "<h1"); count != 1 {
				t.Fatalf("<h1 count = %d, want exactly 1", count)
			}

			absent := []string{
				// Self-contained: no scripts or external resources of any kind.
				"<script", "<link", "<img", "@import", "url(", "src=", `href="http://`,
				// No subject, identity, decision or PDP internals ever render.
				"alice", "user:", "dec_", "no-grant-path", "store-unavailable", "group:",
				// The detail code is escaped exactly once, never twice.
				"&amp;lt;",
			}
			for _, unwanted := range append(absent, test.wantAbsent...) {
				if strings.Contains(body, unwanted) {
					t.Fatalf("body must not contain %q", unwanted)
				}
			}
		})
	}
}

// Config validation bounds the permission/group charset, but the renderer must
// still escape a hostile value as defense in depth — exactly once.
func TestDenialPageEscapesDetailCodeExactlyOnce(t *testing.T) {
	payload := `"><script>alert(1)</script>`
	escaped := html.EscapeString(payload)
	for _, test := range []struct {
		name  string
		serve func(w http.ResponseWriter)
	}{
		{"permission 403", func(w http.ResponseWriter) { permissionForbidden(w, payload) }},
		{"permission 503", func(w http.ResponseWriter) { permissionUnavailable(w, payload) }},
		{"group 403", func(w http.ResponseWriter) { New(Config{}).forbidden(w, payload) }},
		{"group 503", func(w http.ResponseWriter) { New(Config{}).unavailable(w, payload) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			test.serve(recorder)
			body := recorder.Body.String()
			if strings.Contains(body, "<script>alert(1)</script>") {
				t.Fatal("unescaped payload rendered")
			}
			if !strings.Contains(body, "<code>"+escaped+"</code>") {
				t.Fatalf("escaped payload missing from <code>: %q", escaped)
			}
			if strings.Contains(body, "&amp;lt;") {
				t.Fatal("detail code was escaped more than once")
			}
		})
	}
}
