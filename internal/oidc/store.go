package oidc

import (
	"context"
	"errors"
	"sync"
)

var (
	ErrSubjectSessionBlocked       = errors.New("oidc: subject session creation is blocked")
	ErrSubjectSessionStateConflict = errors.New("oidc: subject session state conflicts with durable version")
	ErrSubjectSessionStateStale    = errors.New("oidc: subject session state version is stale")
	ErrSessionReplacementConflict  = errors.New("oidc: gateway session replacement conflict")
	ErrSessionReplacementAssurance = errors.New("oidc: replacement session assurance is not fresh")
)

type SubjectSessionState string

const (
	SubjectSessionActive     SubjectSessionState = "active"
	SubjectSessionFrozen     SubjectSessionState = "frozen"
	SubjectSessionTerminated SubjectSessionState = "terminated"
	SessionAALNone                               = "AAL_NONE"
	SessionMFAStrong                             = "MFA_STRONG"
)

func (state SubjectSessionState) Valid() bool {
	return state == SubjectSessionActive || state == SubjectSessionFrozen || state == SubjectSessionTerminated
}

type SubjectSessionStatus struct {
	Subject       string
	State         SubjectSessionState
	SourceEventID string
	SourceVersion int64
}

type SubjectSessionStateResult struct {
	Revoked  int64
	Replayed bool
}

// Session is a server-side gateway browser session. The opaque ID is carried
// (signed) in the __Secure-gw cookie; the rest is the identity injected upstream
// (sub/email/scope) plus lifecycle timestamps (unix seconds).
type Session struct {
	ID             string
	Sub            string
	Email          string
	Scope          string
	CreatedAt      int64
	ExpiresAt      int64
	SessionBinding string
	AAL            string
	UV             bool
	AuthTime       int64
	FactorEpoch    int64
}

type gatewaySessionContextKey struct{}

// ContextWithGatewaySession carries the authoritative gateway session alongside the verified
// identity. It remains process-local; the reverse proxy forwards only separately signed fields.
func ContextWithGatewaySession(ctx context.Context, session Session) context.Context {
	return context.WithValue(ctx, gatewaySessionContextKey{}, session)
}

// GatewaySessionFromContext returns the session resolved by Provider middleware.
func GatewaySessionFromContext(ctx context.Context) (Session, bool) {
	session, ok := ctx.Value(gatewaySessionContextKey{}).(Session)
	return session, ok
}

func normalizeSessionAssurance(session Session) Session {
	if session.AAL == "" {
		session.AAL = SessionAALNone
	}
	if session.AAL == SessionAALNone {
		session.SessionBinding = ""
		session.UV = false
		session.AuthTime = 0
		session.FactorEpoch = 0
	}
	return session
}

// validStrongReplacementSession is evaluated inside the same store critical section as the
// source-session CAS. A callback can wait behind a lifecycle transaction, so checking only in
// the HTTP handler before ReplaceSession would let that wait extend the 300-second ceremony
// window. The exact 300-second boundary remains valid; 301 seconds is rejected.
func validStrongReplacementSession(session Session, now int64) bool {
	return session.AAL == SessionMFAStrong && session.UV &&
		validLowerHex64(session.SessionBinding) && session.FactorEpoch >= 0 &&
		session.AuthTime > 0 && session.AuthTime <= now &&
		now-session.AuthTime <= strongFreshness && session.CreatedAt <= now &&
		session.ExpiresAt >= now
}

// OAuthState is the short-lived per-authorization record bound by `state`. It
// holds the CSRF/replay guards (state + nonce), the PKCE code_verifier, and the
// original URL to return the browser to after the callback completes.
type OAuthState struct {
	State                  string
	Nonce                  string
	CodeVerifier           string
	OriginalURL            string
	ExpiresAt              int64
	Flow                   string
	ExpectedSub            string
	PreviousSessionID      string
	PreviousSessionBinding string
	StepUpRef              string
	ContinuationRoute      string
	ContinuationHost       string
	ContinuationPath       string
}

const (
	OAuthFlowLogin  = "login"
	OAuthFlowStepUp = "step_up"
)

// SessionStore persists gateway sessions. Implementations must be safe for
// concurrent use.
type SessionStore interface {
	CreateSession(ctx context.Context, s Session) error
	// ReplaceSession atomically removes one exact, still-live gateway session with the
	// expected immutable assurance binding and creates its successor for the same subject.
	// Step-up callbacks use this CAS boundary so a completed ceremony cannot leave both the
	// old weak session and the new strong session active or replace a session that changed
	// while the provider exchanged the authorization code.
	ReplaceSession(ctx context.Context, expectedID, expectedBinding string, s Session) error
	GetSession(ctx context.Context, id string) (Session, bool, error)
	DeleteSession(ctx context.Context, id string) error
	// DeleteSessionsBySubject revokes every browser session owned by the exact
	// Keystone subject and returns the number of removed sessions. Implementations
	// must perform the delete atomically so a leaver cannot retain a second device.
	DeleteSessionsBySubject(ctx context.Context, subject string) (int64, error)
	// ApplySubjectSessionState is the durable, version-fenced JML boundary. A
	// frozen/terminated update and deletion of every existing session are atomic.
	ApplySubjectSessionState(
		ctx context.Context,
		status SubjectSessionStatus,
	) (SubjectSessionStateResult, error)
}

// StateStore persists in-flight OAuth state. TakeState is single-use: it returns
// and atomically removes the record so a `state` (and thus an authorization
// code) can be redeemed at the callback exactly once.
type StateStore interface {
	PutState(ctx context.Context, st OAuthState) error
	TakeState(ctx context.Context, state string) (OAuthState, bool, error)
}

// MemoryStore is an in-memory SessionStore + StateStore for tests and for the
// static (non-postgres) deployment. Expiry is enforced lazily on read.
type MemoryStore struct {
	mu       sync.Mutex
	sessions map[string]Session
	states   map[string]OAuthState
	subjects map[string]SubjectSessionStatus
	now      func() int64
}

// NewMemoryStore builds an empty in-memory store. now defaults to time.Now;
// tests may override it via the exported field for deterministic expiry.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		sessions: make(map[string]Session),
		states:   make(map[string]OAuthState),
		subjects: make(map[string]SubjectSessionStatus),
		now:      nowUnix,
	}
}

func (m *MemoryStore) CreateSession(_ context.Context, s Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if status, ok := m.subjects[s.Sub]; ok && status.State != SubjectSessionActive {
		return ErrSubjectSessionBlocked
	}
	m.sessions[s.ID] = normalizeSessionAssurance(s)
	return nil
}

func (m *MemoryStore) ReplaceSession(
	_ context.Context,
	expectedID string,
	expectedBinding string,
	s Session,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s = normalizeSessionAssurance(s)
	decisionNow := m.now()
	previous, ok := m.sessions[expectedID]
	_, successorExists := m.sessions[s.ID]
	if !ok || decisionNow > previous.ExpiresAt || previous.Sub != s.Sub ||
		previous.SessionBinding != expectedBinding || expectedID == s.ID || successorExists {
		if ok && decisionNow > previous.ExpiresAt {
			delete(m.sessions, expectedID)
		}
		return ErrSessionReplacementConflict
	}
	if status, ok := m.subjects[s.Sub]; ok && status.State != SubjectSessionActive {
		return ErrSubjectSessionBlocked
	}
	if !validStrongReplacementSession(s, decisionNow) {
		return ErrSessionReplacementAssurance
	}
	delete(m.sessions, expectedID)
	m.sessions[s.ID] = s
	return nil
}

func (m *MemoryStore) GetSession(_ context.Context, id string) (Session, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return Session{}, false, nil
	}
	if m.now() > s.ExpiresAt {
		delete(m.sessions, id)
		return Session{}, false, nil
	}
	return normalizeSessionAssurance(s), true, nil
}

func (m *MemoryStore) DeleteSession(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
	return nil
}

func (m *MemoryStore) DeleteSessionsBySubject(_ context.Context, subject string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var deleted int64
	for id, session := range m.sessions {
		if session.Sub == subject {
			delete(m.sessions, id)
			deleted++
		}
	}
	return deleted, nil
}

func (m *MemoryStore) ApplySubjectSessionState(
	_ context.Context,
	status SubjectSessionStatus,
) (SubjectSessionStateResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.subjects[status.Subject]; ok {
		if status.SourceVersion < existing.SourceVersion {
			return SubjectSessionStateResult{}, ErrSubjectSessionStateStale
		}
		if status.SourceVersion == existing.SourceVersion {
			if status.State != existing.State || status.SourceEventID != existing.SourceEventID {
				return SubjectSessionStateResult{}, ErrSubjectSessionStateConflict
			}
			return SubjectSessionStateResult{Replayed: true}, nil
		}
	}
	m.subjects[status.Subject] = status
	var revoked int64
	if status.State != SubjectSessionActive {
		for id, session := range m.sessions {
			if session.Sub == status.Subject {
				delete(m.sessions, id)
				revoked++
			}
		}
	}
	return SubjectSessionStateResult{Revoked: revoked}, nil
}

func (m *MemoryStore) PutState(_ context.Context, st OAuthState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if st.Flow == "" {
		st.Flow = OAuthFlowLogin
	}
	m.states[st.State] = st
	return nil
}

func (m *MemoryStore) TakeState(_ context.Context, state string) (OAuthState, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.states[state]
	if !ok {
		return OAuthState{}, false, nil
	}
	delete(m.states, state) // single-use, even if expired
	if m.now() > st.ExpiresAt {
		return OAuthState{}, false, nil
	}
	return st, true, nil
}
