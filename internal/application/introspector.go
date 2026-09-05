// Package application owns Sluice's isolated application-credential trust path.
// Raw app_v1_ credentials terminate here and are never treated as JWTs or PATs.
package application

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

const maxIntrospectionResponseBytes = 1 << 20

var (
	ErrInvalidToken   = errors.New("application: invalid credential")
	ErrUnavailable    = errors.New("application: authentication unavailable")
	ErrSessionInvalid = errors.New("application: bound session invalid")

	credentialPattern = regexp.MustCompile(`^app_v1_[A-Za-z0-9_-]{43}$`)
	subjectPattern    = regexp.MustCompile(`^application:[A-Za-z0-9_-]{16,128}$`)
	hexDigestPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type CredentialState string

const (
	CredentialActive  CredentialState = "active"
	CredentialOverlap CredentialState = "overlap"
)

// Result is the exact active Access introspection projection Sluice may trust.
// Inactive responses intentionally carry no identifying data.
type Result struct {
	Active                bool
	Subject               string
	ApplicationSub        string
	Scopes                []string
	ExpiresAt             int64
	ClientID              string
	CredentialID          string
	Fingerprint           string
	GrantID               string
	PackageID             string
	PackageRevisionDigest string
	Audience              string
	CredentialVersion     int64
	SubjectVersion        int64
	CredentialState       CredentialState
	OverlapUntil          *int64
	PolicyEpoch           int64
	RevocationEpoch       int64
}

type Introspector interface {
	Introspect(context.Context, string, string, bool) (Result, error)
}

type IntrospectorConfig struct {
	Endpoint     string
	ServiceToken string
	Client       *http.Client
	Now          func() time.Time
}

type AccessIntrospector struct {
	endpoint     string
	serviceToken string
	client       *http.Client
	now          func() time.Time
}

func NewAccessIntrospector(cfg IntrospectorConfig) (*AccessIntrospector, error) {
	endpoint := strings.TrimSpace(cfg.Endpoint)
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("application: invalid introspection endpoint")
	}
	if !validVisible(cfg.ServiceToken, 32, 512) {
		return nil, fmt.Errorf("application: invalid introspection service token")
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	clone := *client
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if clone.Timeout <= 0 {
		clone.Timeout = 10 * time.Second
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &AccessIntrospector{endpoint: endpoint, serviceToken: cfg.ServiceToken, client: &clone, now: now}, nil
}

type activeIntrospectionResponse struct {
	Active                *bool           `json:"active"`
	Subject               string          `json:"sub"`
	ApplicationSub        string          `json:"application_sub"`
	Scope                 string          `json:"scope"`
	ExpiresAt             int64           `json:"exp"`
	TokenType             string          `json:"token_type"`
	ClientID              string          `json:"client_id"`
	CredentialID          string          `json:"credential_id"`
	Fingerprint           string          `json:"fingerprint"`
	GrantID               string          `json:"grant_id"`
	PackageID             string          `json:"package_id"`
	PackageRevisionDigest string          `json:"package_revision_digest"`
	Audience              string          `json:"audience"`
	CredentialVersion     int64           `json:"credential_version"`
	SubjectVersion        int64           `json:"subject_version"`
	CredentialState       CredentialState `json:"credential_state"`
	OverlapUntil          *int64          `json:"overlap_until"`
	PolicyEpoch           int64           `json:"policy_epoch"`
	RevocationEpoch       int64           `json:"revocation_epoch"`
}

func (i *AccessIntrospector) Introspect(ctx context.Context, token, sessionDigest string, initialize bool) (Result, error) {
	if !credentialPattern.MatchString(token) || !hexDigestPattern.MatchString(sessionDigest) {
		return Result{}, ErrInvalidToken
	}
	form := url.Values{"mcp_session_digest": {sessionDigest}, "token": {token}}
	if initialize {
		form.Set("initialize", "true")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, i.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Result{}, unavailable(err)
	}
	req.Header.Set("Authorization", "Bearer "+i.serviceToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := i.client.Do(req)
	if err != nil {
		return Result{}, unavailable(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIntrospectionResponseBytes+1))
	if err != nil || len(body) > maxIntrospectionResponseBytes {
		return Result{}, ErrUnavailable
	}
	trimmed := bytes.TrimSpace(body)
	if resp.StatusCode == http.StatusConflict {
		if bytes.Equal(body, []byte(`{"active":false}`)) {
			return Result{}, ErrSessionInvalid
		}
		return Result{}, ErrUnavailable
	}
	if resp.StatusCode != http.StatusOK {
		return Result{}, ErrUnavailable
	}
	if bytes.Equal(body, []byte(`{"active":false}`)) {
		return Result{Active: false}, nil
	}
	if !uniqueTopLevelJSONFields(trimmed) {
		return Result{}, ErrUnavailable
	}
	var payload activeIntrospectionResponse
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return Result{}, unavailable(err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Result{}, unavailable(err)
	}
	if payload.Active == nil || !*payload.Active || !validActiveIntrospection(payload, i.now().Unix()) {
		return Result{}, ErrUnavailable
	}
	scopes := strings.Fields(payload.Scope)
	sort.Strings(scopes)
	return Result{
		Active: true, Subject: payload.Subject, ApplicationSub: payload.ApplicationSub,
		Scopes: scopes, ExpiresAt: payload.ExpiresAt, ClientID: payload.ClientID,
		CredentialID: payload.CredentialID, Fingerprint: payload.Fingerprint,
		GrantID: payload.GrantID, PackageID: payload.PackageID,
		PackageRevisionDigest: payload.PackageRevisionDigest, Audience: payload.Audience,
		CredentialVersion: payload.CredentialVersion, SubjectVersion: payload.SubjectVersion,
		CredentialState: payload.CredentialState, OverlapUntil: payload.OverlapUntil,
		PolicyEpoch: payload.PolicyEpoch, RevocationEpoch: payload.RevocationEpoch,
	}, nil
}

func validActiveIntrospection(value activeIntrospectionResponse, now int64) bool {
	if value.Subject != value.ApplicationSub || !subjectPattern.MatchString(value.Subject) ||
		value.ExpiresAt <= now || value.TokenType != "Bearer" || value.Audience != "analyze-facade" ||
		value.CredentialVersion <= 0 || value.SubjectVersion <= 0 || value.PolicyEpoch <= 0 || value.RevocationEpoch <= 0 ||
		!validOpaqueID(value.ClientID) || !validOpaqueID(value.CredentialID) || !validOpaqueID(value.GrantID) ||
		!validOpaqueID(value.PackageID) || !hexDigestPattern.MatchString(value.Fingerprint) ||
		!hexDigestPattern.MatchString(value.PackageRevisionDigest) || !validScopeString(value.Scope) {
		return false
	}
	switch value.CredentialState {
	case CredentialActive:
		return value.OverlapUntil == nil
	case CredentialOverlap:
		return value.OverlapUntil != nil && *value.OverlapUntil > now
	default:
		return false
	}
}

func validScopeString(scope string) bool {
	fields := strings.Fields(scope)
	if len(fields) == 0 || strings.Join(fields, " ") != scope {
		return false
	}
	seen := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		if !validScope(field) {
			return false
		}
		if _, exists := seen[field]; exists {
			return false
		}
		seen[field] = struct{}{}
	}
	return true
}

func validScope(value string) bool {
	switch value {
	case "analysis.create", "analysis.read", "analysis.conversation", "analysis.upload.cancel":
		return true
	default:
		return false
	}
}

func validOpaqueID(value string) bool {
	return validVisible(value, 1, 256) && !strings.ContainsAny(value, "\\/:?#@")
}

func validVisible(value string, min, max int) bool {
	if len(value) < min || len(value) > max || strings.TrimSpace(value) != value {
		return false
	}
	for i := range len(value) {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func hasScope(scopes []string, required string) bool {
	if required == "" {
		return true
	}
	for _, scope := range scopes {
		if scope == required {
			return true
		}
	}
	return false
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrUnavailable
	}
	return nil
}

func uniqueTopLevelJSONFields(value []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(value))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok {
			return false
		}
		if _, exists := seen[name]; exists {
			return false
		}
		seen[name] = struct{}{}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return false
		}
	}
	end, err := decoder.Token()
	return err == nil && end == json.Delim('}') && requireJSONEOF(decoder) == nil
}

func unavailable(err error) error { return fmt.Errorf("%w: %v", ErrUnavailable, err) }
