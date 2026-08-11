// denial.go renders the browser-only authorization failure pages served by the
// SSO gates (PermissionGate and Gate). Every page is self-contained: inline
// CSS, no JavaScript, no external assets, and no reflected request content.
// The only interpolated value is the config-sourced permission or group name,
// escaped exactly once at the render boundary. Subject, email, decision IDs,
// PDP reasons and evidence stay in the logs and are never rendered. PAT and
// other machine clients get plain-text responses from their own middleware and
// never reach these pages.
package rbac

import (
	"fmt"
	"html"
	"io"
	"net/http"
)

type denialKind int

const (
	denialForbidden denialKind = iota
	denialUnavailable
)

// denialPage is the complete static specification of one denial page.
type denialPage struct {
	kind          denialKind // drives status code, Retry-After and status-code color
	heading       string
	lede          string
	detailLabel   string
	detailCode    string // permission or group name; escaped at render
	requestAccess bool   // 403 permission only: primary "Request access" call to action
	note          string // optional small print; empty omits the element
}

// denialCSP allows the inline <style> (Sluice has no static asset pipeline)
// and nothing else. The outer secheaders wrapper deliberately imposes no CSP,
// preserves an already-set X-Frame-Options and keeps this stricter
// Referrer-Policy, while it continues to add HSTS and nosniff on top.
const denialCSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// denialLayout carries no literal '%' so it can pass through fmt.Sprintf
// unchanged; visual tokens are the Odyssey Foundation 1.0 paper/basalt/oxide
// values, duplicated inline because Sluice serves no static CSS.
const denialLayout = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="robots" content="noindex,nofollow">
<title>%s · Steadholme</title>
<style>
:root{color-scheme:light dark;
--sg-bg:#f2f0e8;--sg-surface:#faf9f4;--sg-border:#cfcabd;
--sg-ink:#191c18;--sg-ink-2:#454b43;--sg-ink-3:#5f665b;
--sg-accent:#b6422c;--sg-accent-ink:#8f2f1e;--sg-on-accent:#ffffff;
--sg-ring:rgba(182,66,44,.30);--sg-down-ink:#be123c;--sg-warn-ink:#b45309;
--sg-shadow:2px 2px 0 rgba(25,28,24,.08)}
@media (prefers-color-scheme:dark){:root{
--sg-bg:#0f120f;--sg-surface:#171b17;--sg-border:#343b34;
--sg-ink:#ede9dd;--sg-ink-2:#c7c2b5;--sg-ink-3:#aaa497;
--sg-accent:#ff7559;--sg-accent-ink:#e85f45;--sg-on-accent:#191c18;
--sg-ring:rgba(255,117,89,.38);--sg-down-ink:#fda4af;--sg-warn-ink:#fcd34d;
--sg-shadow:2px 2px 0 rgba(0,0,0,.38)}}
*,*::before,*::after{box-sizing:border-box}
body{margin:0;background:var(--sg-bg);color:var(--sg-ink);font:14px/1.5 "Inter","Inter Variable",system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,"PingFang SC",sans-serif;-webkit-font-smoothing:antialiased}
.skip{position:absolute;left:12px;top:-48px;z-index:50;padding:8px 12px;background:var(--sg-surface);color:var(--sg-ink);border:1px solid var(--sg-border);border-radius:4px;text-decoration:none;transition:top 120ms ease}
.skip:focus{top:12px}
.topbar{padding:12px 16px;background:var(--sg-surface);border-bottom:1px solid var(--sg-border)}
.wordmark{font-weight:650}
main{min-height:70vh;display:flex;align-items:center;justify-content:center;padding:36px 16px}
.card{flex:1 1 auto;max-width:30rem;display:flex;flex-direction:column;gap:12px;text-align:center;background:var(--sg-surface);border:1px solid var(--sg-border);border-radius:7px;box-shadow:var(--sg-shadow);padding:24px}
.status-code{margin:0;font-family:"JetBrains Mono","SFMono-Regular",ui-monospace,"SF Mono",Menlo,Consolas,monospace;font-size:28px;font-weight:650}
.card--danger .status-code{color:var(--sg-down-ink)}
.card--degraded .status-code{color:var(--sg-warn-ink)}
h1{margin:0;font-size:24px;line-height:1.2;font-weight:650}
.lede{margin:0;color:var(--sg-ink-2)}
.detail{margin:0;display:flex;flex-direction:column;gap:6px;align-items:center}
.detail-label{font-size:12px;font-weight:650;letter-spacing:.04em;text-transform:uppercase;color:var(--sg-ink-3)}
.detail code{overflow-wrap:anywhere;word-break:break-word;font-family:"JetBrains Mono","SFMono-Regular",ui-monospace,"SF Mono",Menlo,Consolas,monospace;font-size:13px;background:var(--sg-bg);border:1px solid var(--sg-border);border-radius:4px;padding:4px 8px}
.actions{display:flex;flex-wrap:wrap;gap:8px;justify-content:center;margin-top:4px}
.btn{display:inline-flex;align-items:center;justify-content:center;min-height:40px;padding:8px 16px;border:1px solid var(--sg-border);border-radius:4px;background:var(--sg-surface);color:var(--sg-ink);font-weight:550;text-decoration:none}
.btn:hover{background:var(--sg-bg)}
.btn-primary{background:var(--sg-accent);border-color:var(--sg-accent);color:var(--sg-on-accent)}
.btn-primary:hover{background:var(--sg-accent-ink);border-color:var(--sg-accent-ink)}
.note{margin:0;font-size:12px;color:var(--sg-ink-3)}
a:focus-visible{outline:2px solid var(--sg-accent);outline-offset:2px;box-shadow:0 0 0 4px var(--sg-ring)}
@media (max-width:360px){.actions{flex-direction:column;align-items:stretch}}
@media (prefers-reduced-motion:reduce){*{transition-duration:.001ms!important;animation-duration:.001ms!important}}
</style>
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="topbar"><span class="wordmark">Steadholme</span></header>
<main id="main" aria-labelledby="denial-title">
<div class="card card--%s">
<p class="status-code">%s</p>
<h1 id="denial-title">%s</h1>
<p class="lede"%s>%s</p>
<p class="detail"><span class="detail-label">%s</span><code>%s</code></p>
<div class="actions">%s</div>
%s
</div>
</main>
</body>
</html>`

func (p denialPage) status() int {
	if p.kind == denialUnavailable {
		return http.StatusServiceUnavailable
	}
	return http.StatusForbidden
}

func (p denialPage) statusText() string {
	if p.kind == denialUnavailable {
		return "503"
	}
	return "403"
}

// renderDenial interpolates the static page fields into denialLayout. The
// single dynamic, config-sourced value is escaped exactly once here; every
// other field is a fixed English literal from the constructors below.
func renderDenial(p denialPage) string {
	modifier := "danger"
	ledeRole := ""
	if p.kind == denialUnavailable {
		modifier = "degraded"
		ledeRole = ` role="status"`
	}
	var actions string
	switch {
	case p.requestAccess:
		actions = `<a class="btn btn-primary" href="https://access.w33d.xyz/request">Request access</a>` +
			`<a class="btn" href="https://w33d.xyz">Back to all apps</a>`
	case p.kind == denialUnavailable:
		// The empty href resolves to the current document URL (RFC 3986 section
		// 5.2), so "Try again" reloads this page without reflecting any request
		// input into the response body. Intentional, not an empty-link bug.
		actions = `<a class="btn btn-primary" href="">Try again</a>`
	default:
		// Group denials offer no request workflow: membership changes are an
		// operator action, so the only exit is back to the app launcher.
		actions = `<a class="btn" href="https://w33d.xyz">Back to all apps</a>`
	}
	note := ""
	if p.note != "" {
		note = `<p class="note">` + p.note + `</p>`
	}
	return fmt.Sprintf(denialLayout,
		p.statusText(), modifier, p.statusText(),
		p.heading, ledeRole, p.lede,
		p.detailLabel, html.EscapeString(p.detailCode),
		actions, note,
	)
}

// writeDenial sets the full privacy/security header set BEFORE WriteHeader.
func writeDenial(w http.ResponseWriter, p denialPage) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "private, no-store")
	h.Set("Content-Security-Policy", denialCSP)
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	if p.kind == denialUnavailable {
		h.Set("Retry-After", "5")
	}
	w.WriteHeader(p.status())
	_, _ = io.WriteString(w, renderDenial(p))
}

// permissionDeniedPage is the 403 for an authenticated account that lacks the
// route's required permission: sign-in succeeded, authorization did not.
func permissionDeniedPage(permission string) denialPage {
	return denialPage{
		kind:          denialForbidden,
		heading:       "Access denied",
		lede:          "You're signed in. Your account doesn't have the permission this area needs yet.",
		detailLabel:   "Required permission",
		detailCode:    permission,
		requestAccess: true,
		note:          "Approved grants take effect right away — reload this page after your request is approved.",
	}
}

// groupDeniedPage is the 403 for an authenticated account outside the route's
// required group. It deliberately has no self-service request action.
func groupDeniedPage(group string) denialPage {
	return denialPage{
		kind:        denialForbidden,
		heading:     "Access restricted",
		lede:        "This area is limited to members of a specific group. Your account isn't a member.",
		detailLabel: "Required group",
		detailCode:  group,
	}
}

// accessUnverifiedPage is the shared 503 for a fail-closed PDP check: nothing
// was granted, changed or leaked, and the user can simply retry.
func accessUnverifiedPage(detailLabel, detailCode string) denialPage {
	return denialPage{
		kind:        denialUnavailable,
		heading:     "Access can't be verified right now",
		lede:        "We couldn't check your access, so this page stayed closed. Nothing was changed.",
		detailLabel: detailLabel,
		detailCode:  detailCode,
	}
}
