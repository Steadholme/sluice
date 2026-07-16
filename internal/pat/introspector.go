// Package pat implements the isolated opaque personal-access-token auth path.
// It intentionally does not parse or validate JWTs; auth="bearer" remains owned
// by internal/auth and retains its existing semantics.
package pat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	maxTokenBytes    = 128
	maxResponseBytes = 1 << 20
)

var (
	// ErrInvalidToken means the caller did not present a syntactically valid
	// opaque PAT. It maps to 401 and never triggers a Keystone request.
	ErrInvalidToken = errors.New("pat: invalid token")
	// ErrUnavailable covers every introspection transport, status, size, or
	// response-shape failure. Callers deliberately collapse it to 503.
	ErrUnavailable = errors.New("pat: introspection unavailable")
)

// Result is Keystone's authorization decision reduced to the fields Sluice is
// allowed to trust and forward as an Identity.
type Result struct {
	Active  bool
	Subject string
	Scope   string
}

// Introspector resolves one opaque PAT on every request. Implementations must
// not positively cache results: destructive requests need immediate revocation.
type Introspector interface {
	Introspect(context.Context, string) (Result, error)
}

// Config wires the explicit Keystone endpoint and the existing gateway OAuth
// client credentials. Client is the existing internal mTLS client when enabled.
type Config struct {
	Endpoint     string
	ClientID     string
	ClientSecret string
	Client       *http.Client
}

// KeystoneIntrospector POSTs an OAuth-style token introspection form to the
// explicitly configured internal Keystone endpoint. It contains no cache.
type KeystoneIntrospector struct {
	endpoint     string
	clientID     string
	clientSecret string
	client       *http.Client
}

// NewKeystoneIntrospector validates wiring without contacting Keystone. Missing
// or invalid configuration is returned to the caller, which leaves PAT routes
// installed but fail-closed with 503.
func NewKeystoneIntrospector(cfg Config) (*KeystoneIntrospector, error) {
	endpoint := strings.TrimSpace(cfg.Endpoint)
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("pat: invalid introspection endpoint")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("pat: introspection endpoint must use http or https")
	}
	if u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("pat: introspection endpoint must not contain userinfo or fragment")
	}
	if strings.TrimSpace(cfg.ClientID) == "" || cfg.ClientSecret == "" {
		return nil, fmt.Errorf("pat: gateway client credentials are required")
	}

	base := cfg.Client
	if base == nil {
		base = &http.Client{Timeout: 10 * time.Second}
	}
	// Reuse the exact transport (including internal mTLS) without mutating the
	// shared client. Redirects are disabled so a 307/308 cannot carry a raw PAT to
	// a different endpoint.
	client := *base
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if client.Timeout <= 0 {
		client.Timeout = 10 * time.Second
	}

	return &KeystoneIntrospector{
		endpoint:     endpoint,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		client:       &client,
	}, nil
}

type introspectionResponse struct {
	Active    *bool  `json:"active"`
	Subject   string `json:"sub"`
	Scope     string `json:"scope"`
	ExpiresAt int64  `json:"exp"`
	TokenType string `json:"token_type"`
}

// Introspect makes one uncached request. Every non-200 response, transport
// failure, oversized body, malformed JSON, or invalid active identity becomes
// ErrUnavailable; only a well-formed active=false is an authentication denial.
func (i *KeystoneIntrospector) Introspect(ctx context.Context, token string) (Result, error) {
	if !validOpaqueToken(token) {
		return Result{}, ErrInvalidToken
	}

	form := url.Values{"token": []string{token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, i.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Result{}, unavailable(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(i.clientID, i.clientSecret)

	resp, err := i.client.Do(req)
	if err != nil {
		return Result{}, unavailable(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return Result{}, unavailable(err)
	}
	if len(body) > maxResponseBytes || resp.StatusCode != http.StatusOK {
		return Result{}, ErrUnavailable
	}

	var payload introspectionResponse
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&payload); err != nil {
		return Result{}, unavailable(err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Result{}, ErrUnavailable
	}
	if payload.Active == nil {
		return Result{}, ErrUnavailable
	}
	if !*payload.Active {
		return Result{Active: false}, nil
	}
	// An active response is authoritative only while it is demonstrably live and
	// typed as a Bearer credential. An inconsistent Keystone response is a
	// dependency failure (503), never an allow or caller-facing 401.
	if payload.ExpiresAt <= time.Now().Unix() || !strings.EqualFold(payload.TokenType, "Bearer") {
		return Result{}, ErrUnavailable
	}
	if !validIdentityValue(payload.Subject, 512) || !validScopeValue(payload.Scope) {
		return Result{}, ErrUnavailable
	}
	return Result{Active: true, Subject: payload.Subject, Scope: payload.Scope}, nil
}

func unavailable(err error) error {
	return fmt.Errorf("%w: %v", ErrUnavailable, err)
}

func validOpaqueToken(token string) bool {
	if len(token) <= len("pat_") || len(token) > maxTokenBytes || !strings.HasPrefix(token, "pat_") {
		return false
	}
	for i := len("pat_"); i < len(token); i++ {
		b := token[i]
		if !((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_' || b == '-') {
			return false
		}
	}
	return true
}

func validIdentityValue(value string, max int) bool {
	if value == "" || len(value) > max || strings.TrimSpace(value) != value {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func validScopeValue(scope string) bool {
	if len(scope) > 4096 {
		return false
	}
	for i := 0; i < len(scope); i++ {
		if scope[i] != ' ' && (scope[i] < 0x21 || scope[i] > 0x7e) {
			return false
		}
	}
	return true
}
