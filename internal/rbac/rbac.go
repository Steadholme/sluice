// Package rbac adds per-route group authorization on top of Sluice's SSO
// identity. An `auth=sso` route may carry a required group (routes.require_group);
// when it does, the authenticated caller must be a member of that group, decided
// by consulting Verdict (the ReBAC PDP) over the internal network. A route with
// no require_group remains opt-in and backward compatible; a route that declares
// require_group must fail closed when the Authorizer is unavailable.
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
	// Token is the VERDICT_DECISION_TOKEN presented as a Bearer credential.
	Token string
	// TTL is the per-subject membership cache lifetime (default 5m).
	TTL time.Duration
	Log *slog.Logger
}

// Authorizer decides whether an authenticated subject may reach a group-gated
// route and looks up the subject's groups for X-Auth-Groups. Results are cached
// per subject with a short TTL. Expired entries are never authorization evidence:
// if Verdict is unavailable after expiry, the strict Gate fails closed while the
// advisory InjectOnly path simply omits group decoration.
type Authorizer struct {
	cfg    Config
	client *http.Client
	mu     sync.Mutex
	cache  map[string]cacheEntry
	now    func() time.Time
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
		now:    time.Now,
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
			a.forbidden(w, group)
			return
		}
		subject := "user:" + id.Subject
		groups, err := a.groupsFor(r.Context(), subject)
		if err != nil {
			// Fail closed without disguising an unavailable PDP as a policy deny.
			a.cfg.Log.Warn("rbac indeterminate (verdict unavailable)", "subject", id.Subject, "group", group, "error", err)
			a.unavailable(w, group)
			return
		}
		id.Groups = stripPrefix(groups)
		if !contains(groups, "group:"+group) {
			a.cfg.Log.Info("rbac deny (not a member)", "subject", id.Subject, "group", group)
			a.forbidden(w, group)
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
// by a per-subject TTL cache. Once an entry expires it cannot be used to authorize
// a request. Verdict errors are returned to the caller so Gate can fail closed;
// InjectOnly remains advisory and ignores the error.
func (a *Authorizer) groupsFor(ctx context.Context, subject string) ([]string, error) {
	now := a.now()
	a.mu.Lock()
	ent, cached := a.cache[subject]
	fresh := cached && now.Sub(ent.at) >= 0 && now.Sub(ent.at) < a.cfg.TTL
	a.mu.Unlock()
	if fresh {
		return ent.groups, nil
	}
	groups, err := a.fetchGroups(ctx, subject)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.cache[subject] = cacheEntry{groups: groups, at: a.now()}
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

func (a *Authorizer) forbidden(w http.ResponseWriter, group string) {
	writeDenial(w, groupDeniedPage(group))
}

func (a *Authorizer) unavailable(w http.ResponseWriter, group string) {
	writeDenial(w, accessUnverifiedPage("Required group", group))
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
