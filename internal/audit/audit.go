// Package audit emits security-relevant gateway events to Watchtower (the
// tamper-evident audit log) WITHOUT ever touching the request path.
//
// Emit is fire-and-forget: it does a single non-blocking send onto a bounded
// queue and returns immediately. A background worker drains the queue and POSTs
// each event to WATCHTOWER_URL/events with a short timeout. If the queue is full
// or Watchtower is down the event is DROPPED (and a drop counter is bumped) —
// the error is never propagated to the caller, so Watchtower being down can
// never slow, block, or fail login or proxying.
//
// The producer sends ONLY the logical fields (actor/action/target/severity/
// detail/source). Watchtower owns seq/ts/hash. Callers must keep `detail` short
// and free of secrets (no tokens, passwords, client secrets, cookies, or
// verifiers); login.failure-style records carry the username + reason only.
package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Source identifies the producing service.
const SourceSluice = "sluice"

// Severity levels. Failures and denies use warning; info is the happy path.
const (
	SeverityInfo    = "info"
	SeverityWarning = "warning"
	SeverityError   = "error"
)

// Dot-namespaced actions emitted by the gateway.
const (
	ActionForwardAuthAllow = "forward_auth.allow"
	ActionForwardAuthDeny  = "forward_auth.deny"
	ActionSSOEstablish     = "sso.session.establish"
	ActionSSODeny          = "sso.session.deny"
	ActionSSOLogout        = "sso.logout"

	// WAF (Aegis) actions. Block is emitted when a request is rejected (rule score
	// over threshold, rate limit exceeded, body too large, or upload type denied);
	// Flag is emitted when a request scores above zero but below the block
	// threshold and is allowed through.
	ActionWAFBlock = "waf.block"
	ActionWAFFlag  = "waf.flag"
)

const (
	// DefaultQueueCap bounds the in-flight queue. Past it, emits drop rather than
	// block — auditing must never apply backpressure to the request path.
	DefaultQueueCap = 1024
	// DefaultTimeout bounds a single POST to Watchtower so a slow/hung collector
	// cannot wedge the worker for long.
	DefaultTimeout = 2 * time.Second
)

// Event is the logical audit record producers send. Watchtower assigns seq/ts
// and the hash-chain link; these fields are all that cross the wire.
type Event struct {
	Actor    string `json:"actor"`
	Action   string `json:"action"`
	Target   string `json:"target"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
	Source   string `json:"source"`
}

// Config configures an Emitter. When Enabled is false (the default), New returns
// a no-op Emitter: no goroutine, no queue, Emit returns instantly.
type Config struct {
	Enabled  bool
	URL      string // Watchtower base URL, e.g. http://watchtower:8500
	Token    string // AUDIT_INGEST_TOKEN bearer credential
	Source   string // producer name stamped on events (default "sluice")
	QueueCap int    // bounded queue capacity (default DefaultQueueCap)
	Timeout  time.Duration
	Client   *http.Client // optional; defaults to a Timeout-bounded client
	Log      *slog.Logger // optional; defaults to slog.Default()
}

// Emitter is a non-blocking audit event sink. The zero value and a nil *Emitter
// are both safe: Emit is a no-op on them, so call sites need no nil checks.
type Emitter struct {
	enabled  bool
	endpoint string // URL + "/events"
	token    string
	source   string
	timeout  time.Duration
	queue    chan Event
	client   *http.Client
	log      *slog.Logger

	dropped   atomic.Uint64
	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// New builds an Emitter. With cfg.Enabled false it returns a disabled no-op
// Emitter (zero behavior change for dev/tests). With it enabled but URL or Token
// missing, it logs a warning and stays disabled rather than failing — audit
// misconfiguration must not take the gateway down. Otherwise it starts a single
// background worker that drains the queue for the process lifetime.
func New(cfg Config) *Emitter {
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	if !cfg.Enabled {
		return &Emitter{enabled: false, log: log}
	}
	if cfg.URL == "" || cfg.Token == "" {
		log.Warn("audit: AUDIT_ENABLED set but WATCHTOWER_URL or AUDIT_INGEST_TOKEN missing; auditing stays OFF")
		return &Emitter{enabled: false, log: log}
	}

	queueCap := cfg.QueueCap
	if queueCap <= 0 {
		queueCap = DefaultQueueCap
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	source := cfg.Source
	if source == "" {
		source = SourceSluice
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}

	e := &Emitter{
		enabled:  true,
		endpoint: strings.TrimRight(cfg.URL, "/") + "/events",
		token:    cfg.Token,
		source:   source,
		timeout:  timeout,
		queue:    make(chan Event, queueCap),
		client:   client,
		log:      log,
		done:     make(chan struct{}),
	}
	e.wg.Add(1)
	go e.run()
	log.Info("audit: enabled", "endpoint", e.endpoint, "queue_cap", queueCap, "source", source)
	return e
}

// Emit records an event. It NEVER blocks, errors, or panics: a single
// non-blocking send hands the event to the worker, and a full queue (or a
// disabled/nil Emitter) drops it after bumping the drop counter. This is the
// hard guarantee that auditing cannot slow or fail the auth/proxy request path.
func (e *Emitter) Emit(ev Event) {
	if e == nil || !e.enabled {
		return
	}
	if ev.Source == "" {
		ev.Source = e.source
	}
	select {
	case e.queue <- ev:
	default:
		// Queue full: the worker is behind (Watchtower slow/down). Drop rather
		// than block the request goroutine.
		n := e.dropped.Add(1)
		if n == 1 || n%1024 == 0 {
			e.log.Warn("audit: queue full, dropping event", "action", ev.Action, "dropped_total", n)
		}
	}
}

// Dropped returns the number of events dropped because the queue was full. It is
// the metric a future Probe/Vitals scrape would export.
func (e *Emitter) Dropped() uint64 {
	if e == nil {
		return 0
	}
	return e.dropped.Load()
}

// Close stops the background worker. It is best-effort: in-flight queued events
// may be dropped. It is safe to call multiple times. Emit remains safe to call
// after Close (it simply drops, never panics, because the queue is never
// closed).
func (e *Emitter) Close() {
	if e == nil || !e.enabled {
		return
	}
	e.closeOnce.Do(func() { close(e.done) })
	e.wg.Wait()
}

// run is the single consumer of the queue. The queue is deliberately never
// closed so a concurrent Emit can never send on a closed channel and panic the
// request path; shutdown is signalled via done instead.
func (e *Emitter) run() {
	defer e.wg.Done()
	for {
		select {
		case ev := <-e.queue:
			e.post(ev)
		case <-e.done:
			return
		}
	}
}

// post delivers one event to Watchtower with a bounded timeout. Any failure is
// logged and swallowed: delivery is best-effort and must never resurface.
func (e *Emitter) post(ev Event) {
	body, err := json.Marshal(ev)
	if err != nil {
		e.log.Warn("audit: marshal event failed", "error", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint, bytes.NewReader(body))
	if err != nil {
		e.log.Warn("audit: build request failed", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.token)

	resp, err := e.client.Do(req)
	if err != nil {
		// Watchtower down/unreachable: drop the event, keep serving.
		e.log.Warn("audit: post failed", "action", ev.Action, "error", err)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body) // drain so the connection can be reused
	if resp.StatusCode >= 300 {
		e.log.Warn("audit: watchtower rejected event", "action", ev.Action, "status", resp.StatusCode)
	}
}
