package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/holdfast/sluice/internal/config"
	"github.com/holdfast/sluice/internal/store"
)

// ReloadableHandler is the request-handling complement to the hot-reloading
// RouteStore. The store refreshes the route snapshot in the background; this
// rebuilds the per-route proxy/auth map (and, on the public instance, re-applies
// the PublicOnly filter) from that snapshot whenever the route set changes, then
// atomically swaps the live handler. Together they let DB route edits take
// effect without a process restart — the seam the NewServer doc anticipated.
//
// build() must produce a fresh handler from the CURRENT store snapshot (typically
// NewServer(store, opts).Handler()). Rebuilds are gated on a fingerprint of the
// route set so an unchanged table causes no proxy churn (preserving upstream
// keep-alive pools). In-flight requests keep using the handler they started on;
// the swap only affects requests that arrive after it.
type ReloadableHandler struct {
	store   store.RouteStore
	build   func() http.Handler
	log     *slog.Logger
	current atomic.Pointer[http.Handler]
	fp      atomic.Pointer[string]
}

// NewReloadableHandler builds the initial handler synchronously (so the gateway
// serves correctly the instant it is returned) and starts a background rebuilder
// that polls every interval and swaps on change. The rebuilder stops when ctx is
// cancelled.
func NewReloadableHandler(ctx context.Context, s store.RouteStore, build func() http.Handler, interval time.Duration, log *slog.Logger) *ReloadableHandler {
	h := &ReloadableHandler{store: s, build: build, log: log}
	initial := build()
	h.current.Store(&initial)
	fp := fingerprint(s.Routes())
	h.fp.Store(&fp)
	go h.loop(ctx, interval)
	return h
}

// ServeHTTP dispatches to the current handler snapshot.
func (h *ReloadableHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hp := h.current.Load()
	if hp == nil { // never happens after construction; fail closed rather than panic.
		http.Error(w, "gateway not ready", http.StatusServiceUnavailable)
		return
	}
	(*hp).ServeHTTP(w, r)
}

func (h *ReloadableHandler) loop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			next := fingerprint(h.store.Routes())
			if prev := h.fp.Load(); prev != nil && *prev == next {
				continue // route set unchanged — no rebuild, no proxy churn.
			}
			handler := h.build()
			h.current.Store(&handler)
			h.fp.Store(&next)
			if h.log != nil {
				h.log.Info("gateway routes reloaded", "routes", len(h.store.Routes()))
			}
		}
	}
}

// fingerprint is a stable digest of the full route set: it changes iff any route
// field that affects dispatch/proxying changes (add/remove/edit), and is order-
// independent so a reordered-but-identical table does not trigger a rebuild.
func fingerprint(routes []config.Route) string {
	keys := make([]string, 0, len(routes))
	for _, r := range routes {
		keys = append(keys, strings.Join([]string{
			r.Name,
			r.Match.Host,
			r.Match.PathPrefix,
			r.Upstream,
			strconv.FormatBool(r.Protected),
			r.Auth,
			strconv.FormatBool(r.Waf),
			r.RequireGroup,
		}, "\x1f"))
	}
	sort.Strings(keys)
	sum := sha256.Sum256([]byte(strings.Join(keys, "\x1e")))
	return hex.EncodeToString(sum[:])
}
