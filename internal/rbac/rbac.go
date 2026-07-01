// Package rbac adds per-route group authorization on top of Sluice's SSO
// identity. An `auth=sso` route may carry a required group (routes.require_group);
// when it does, the authenticated caller must be a member of that group, decided
// by consulting Verdict (the ReBAC PDP) over the internal network. It is fully
// opt-in: a route with no require_group, or a disabled/unconfigured Authorizer,
// is a byte-identical pass-through, so the public ingress behavior is unchanged
// until both the route flag and RBAC_ENABLED are set.
//
// The gate runs AFTER the SSO middleware has established identity (so the subject
// is present) and BEFORE the reverse proxy, stamping the subject's groups onto
// the request Identity so the proxy can inject the X-Auth-Groups header.
package rbac

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/holdfast/sluice/internal/auth"
)

// Config configures the Authorizer.
type Config struct {
	Enabled bool
	// VerdictURL is the base URL of the Verdict decision point, e.g.
	// http://verdict:9140. The Authorizer POSTs to {VerdictURL}/api/list-objects.
	VerdictURL string
	// Token is the VERDICT_SERVICE_TOKEN presented as a Bearer credential.
	Token string
	// TTL is the per-subject membership cache lifetime (default 5m).
	TTL time.Duration
	Log *slog.Logger
}

// Authorizer decides whether an authenticated subject may reach a group-gated
// route and looks up the subject's groups for X-Auth-Groups. Results are cached
// per subject with a short TTL; on a Verdict outage a stale cache entry is served
// (graceful) while a cold miss fails closed (deny), so a compromised or missing
// PDP never silently opens the mgmt consoles.
type Authorizer struct {
	cfg    Config
	client *http.Client
	mu     sync.Mutex
	cache  map[string]cacheEntry
}

type cacheEntry struct {
	groups []string // raw object ids, e.g. "group:infra-admins"
	at     time.Time
}

// New builds an Authorizer. It is active only when Enabled is set AND both a
// VerdictURL and Token are present; otherwise Enabled() reports false and every
// Gate is a pass-through.
func New(cfg Config) *Authorizer {
	if cfg.TTL <= 0 {
		cfg.TTL = 5 * time.Minute
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Authorizer{
		cfg:    cfg,
		client: &http.Client{Timeout: 5 * time.Second},
		cache:  make(map[string]cacheEntry),
	}
}

// Enabled reports whether group gating is active and fully configured.
func (a *Authorizer) Enabled() bool {
	return a != nil && a.cfg.Enabled && a.cfg.VerdictURL != "" && a.cfg.Token != ""
}

// Gate wraps next with a membership check for the required group. It assumes the
// SSO middleware ran first (identity in context). On deny it renders a 403; on
// allow it records the subject's groups on the Identity and calls next.
func (a *Authorizer) Gate(group string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := auth.IdentityFromContext(r.Context())
		if !ok || id.Subject == "" {
			a.forbidden(w, group, "no established identity")
			return
		}
		subject := "user:" + id.Subject
		groups, err := a.groupsFor(r.Context(), subject)
		if err != nil {
			// Fail closed: membership cannot be verified -> deny.
			a.cfg.Log.Warn("rbac deny (verdict unavailable)", "subject", id.Subject, "group", group, "error", err)
			a.forbidden(w, group, "authorization service unavailable")
			return
		}
		id.Groups = stripPrefix(groups)
		if !contains(groups, "group:"+group) {
			a.cfg.Log.Info("rbac deny (not a member)", "subject", id.Subject, "group", group)
			a.forbidden(w, group, "your account is not a member of this group")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// InjectOnly resolves the subject's group memberships and records them on the Identity
// WITHOUT any gating, so backends on plain (non-require_group) SSO routes still receive a
// trustworthy X-Auth-Groups header for their OWN fine-grained authorization (e.g. Echo's
// moderator check). Unlike Gate this FAILS OPEN: a Verdict error injects no groups but never
// blocks the request — group injection is advisory for the backend, not an access decision here.
func (a *Authorizer) InjectOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, ok := auth.IdentityFromContext(r.Context()); ok && id.Subject != "" {
			if groups, err := a.groupsFor(r.Context(), "user:"+id.Subject); err == nil {
				id.Groups = stripPrefix(groups)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// groupsFor returns the raw group object ids the subject is a member of, backed
// by a per-subject TTL cache. On a Verdict error a stale entry is returned if
// present (so a transient blip does not lock out an already-verified admin); a
// cold miss returns the error so Gate fails closed.
func (a *Authorizer) groupsFor(ctx context.Context, subject string) ([]string, error) {
	a.mu.Lock()
	ent, cached := a.cache[subject]
	fresh := cached && time.Since(ent.at) < a.cfg.TTL
	a.mu.Unlock()
	if fresh {
		return ent.groups, nil
	}
	groups, err := a.fetchGroups(ctx, subject)
	if err != nil {
		if cached {
			return ent.groups, nil // serve stale rather than lock out on a blip
		}
		return nil, err
	}
	a.mu.Lock()
	a.cache[subject] = cacheEntry{groups: groups, at: time.Now()}
	a.mu.Unlock()
	return groups, nil
}

// fetchGroups asks Verdict for every object on which subject holds "member"
// (POST /api/list-objects {relation:"member", subject} -> {objects:[...]}).
func (a *Authorizer) fetchGroups(ctx context.Context, subject string) ([]string, error) {
	body, _ := json.Marshal(map[string]string{"relation": "member", "subject": subject})
	url := strings.TrimRight(a.cfg.VerdictURL, "/") + "/api/list-objects"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.cfg.Token)
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("verdict list-objects: status %d", resp.StatusCode)
	}
	var out struct {
		Objects []string `json:"objects"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Objects, nil
}

const forbiddenHTML = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>403 · HOLDFAST</title>
<style>body{font:16px/1.5 system-ui,sans-serif;background:#f4f4f4;color:#272727;margin:0;
display:flex;min-height:100vh;align-items:center;justify-content:center}
.card{background:#fff;border:1px solid #e1e1e1;border-radius:12px;padding:40px 44px;max-width:460px;text-align:center}
h1{font-size:20px;font-weight:600;margin:0 0 8px}p{color:#6e6e6e;margin:6px 0}
code{background:#f2f3fd;color:#4c64e1;padding:2px 6px;border-radius:4px}
a{color:#4c64e1;text-decoration:none}</style></head>
<body><div class="card"><h1>403 — Access restricted</h1>
<p>This console requires membership of the <code>%s</code> group.</p>
<p>%s</p>
<p style="margin-top:20px"><a href="https://w33d.xyz">← All apps</a></p></div></body></html>`

func (a *Authorizer) forbidden(w http.ResponseWriter, group, reason string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, forbiddenHTML, html.EscapeString(group), html.EscapeString(reason))
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// stripPrefix turns raw "group:<name>" object ids into bare group names for the
// X-Auth-Groups header.
func stripPrefix(objs []string) []string {
	out := make([]string, 0, len(objs))
	for _, o := range objs {
		out = append(out, strings.TrimPrefix(o, "group:"))
	}
	return out
}
