package oidc

import (
	"context"
	"sync"
)

// Session is a server-side gateway browser session. The opaque ID is carried
// (signed) in the __Secure-gw cookie; the rest is the identity injected upstream
// (sub/email/scope) plus lifecycle timestamps (unix seconds).
type Session struct {
	ID        string
	Sub       string
	Email     string
	Scope     string
	CreatedAt int64
	ExpiresAt int64
}

// OAuthState is the short-lived per-authorization record bound by `state`. It
// holds the CSRF/replay guards (state + nonce), the PKCE code_verifier, and the
// original URL to return the browser to after the callback completes.
type OAuthState struct {
	State        string
	Nonce        string
	CodeVerifier string
	OriginalURL  string
	ExpiresAt    int64
}

// SessionStore persists gateway sessions. Implementations must be safe for
// concurrent use.
type SessionStore interface {
	CreateSession(ctx context.Context, s Session) error
	GetSession(ctx context.Context, id string) (Session, bool, error)
	DeleteSession(ctx context.Context, id string) error
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
	now      func() int64
}

// NewMemoryStore builds an empty in-memory store. now defaults to time.Now;
// tests may override it via the exported field for deterministic expiry.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		sessions: make(map[string]Session),
		states:   make(map[string]OAuthState),
		now:      nowUnix,
	}
}

func (m *MemoryStore) CreateSession(_ context.Context, s Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
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
	return s, true, nil
}

func (m *MemoryStore) DeleteSession(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
	return nil
}

func (m *MemoryStore) PutState(_ context.Context, st OAuthState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
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
