package oidc

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

const maxAssuranceResponseBytes = 4096

var ErrAssuranceUnavailable = errors.New("oidc: session assurance unavailable")

// SessionAssurance is the single authoritative result used immediately for one protected
// request. Strong results are never positively cached by Sluice.
type SessionAssurance struct {
	Live           bool
	Subject        string
	SessionBinding string
	AAL            string
	UV             bool
	AuthTime       int64
	FactorEpoch    int64
	AsOf           int64
}

type AssuranceLookup interface {
	LookupSessionAssurance(context.Context, string, string) (SessionAssurance, error)
}

type AssuranceClientConfig struct {
	Endpoint     string
	ServiceToken string
	Client       *http.Client
}

// KeystoneAssuranceClient performs one strict, uncached lookup for each request that may carry
// strong assurance. It reuses the caller's internal mTLS transport without mutating that client.
type KeystoneAssuranceClient struct {
	endpoint string
	token    string
	client   *http.Client
	now      func() time.Time
}

func NewKeystoneAssuranceClient(cfg AssuranceClientConfig) (*KeystoneAssuranceClient, error) {
	endpoint := strings.TrimSpace(cfg.Endpoint)
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("oidc: invalid assurance endpoint")
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil ||
		parsed.Fragment != "" || parsed.RawQuery != "" {
		return nil, fmt.Errorf("oidc: assurance endpoint must be an absolute http(s) URL without userinfo, query, or fragment")
	}
	if !validServiceCredential(cfg.ServiceToken) {
		return nil, fmt.Errorf("oidc: assurance service token must contain 32-512 visible ASCII bytes")
	}
	base := cfg.Client
	if base == nil {
		base = &http.Client{Timeout: 10 * time.Second}
	}
	client := *base
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if client.Timeout <= 0 {
		client.Timeout = 10 * time.Second
	}
	return &KeystoneAssuranceClient{
		endpoint: endpoint,
		token:    cfg.ServiceToken,
		client:   &client,
		now:      time.Now,
	}, nil
}

type assuranceLookupRequest struct {
	Subject        string `json:"subject"`
	SessionBinding string `json:"session_binding"`
}

type assuranceLookupResponse struct {
	Result         string  `json:"result"`
	Subject        string  `json:"subject"`
	SessionBinding *string `json:"session_binding"`
	AAL            string  `json:"aal"`
	UV             bool    `json:"uv"`
	AuthTime       int64   `json:"auth_time"`
	FactorEpoch    int64   `json:"factor_epoch"`
	AsOf           int64   `json:"as_of"`
}

func (c *KeystoneAssuranceClient) LookupSessionAssurance(
	ctx context.Context,
	subject string,
	sessionBinding string,
) (SessionAssurance, error) {
	if !validAssuranceSubject(subject) || !validLowerHex64(sessionBinding) {
		return SessionAssurance{}, ErrAssuranceUnavailable
	}
	body, err := json.Marshal(assuranceLookupRequest{
		Subject:        subject,
		SessionBinding: sessionBinding,
	})
	if err != nil {
		return SessionAssurance{}, assuranceUnavailable(err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return SessionAssurance{}, assuranceUnavailable(err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	response, err := c.client.Do(req)
	if err != nil {
		return SessionAssurance{}, assuranceUnavailable(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxAssuranceResponseBytes+1))
	if err != nil || len(raw) > maxAssuranceResponseBytes || response.StatusCode != http.StatusOK {
		return SessionAssurance{}, ErrAssuranceUnavailable
	}
	if !strings.Contains(strings.ToLower(response.Header.Get("Cache-Control")), "no-store") {
		return SessionAssurance{}, ErrAssuranceUnavailable
	}
	var payload assuranceLookupResponse
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return SessionAssurance{}, assuranceUnavailable(err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return SessionAssurance{}, ErrAssuranceUnavailable
	}
	now := c.now().Unix()
	if payload.Subject != subject || payload.AsOf <= 0 || payload.AsOf > now ||
		now-payload.AsOf > 300 || payload.FactorEpoch < 0 {
		return SessionAssurance{}, ErrAssuranceUnavailable
	}

	switch payload.Result {
	case "live":
		if payload.SessionBinding == nil || *payload.SessionBinding != sessionBinding ||
			payload.AAL != SessionMFAStrong || !payload.UV || payload.AuthTime <= 0 {
			return SessionAssurance{}, ErrAssuranceUnavailable
		}
		return SessionAssurance{
			Live:           true,
			Subject:        subject,
			SessionBinding: sessionBinding,
			AAL:            SessionMFAStrong,
			UV:             true,
			AuthTime:       payload.AuthTime,
			FactorEpoch:    payload.FactorEpoch,
			AsOf:           payload.AsOf,
		}, nil
	case "absent":
		if payload.SessionBinding != nil || payload.AAL != SessionAALNone || payload.UV ||
			payload.AuthTime != 0 {
			return SessionAssurance{}, ErrAssuranceUnavailable
		}
		return SessionAssurance{
			Live:        false,
			Subject:     subject,
			AAL:         SessionAALNone,
			FactorEpoch: payload.FactorEpoch,
			AsOf:        payload.AsOf,
		}, nil
	default:
		return SessionAssurance{}, ErrAssuranceUnavailable
	}
}

func validServiceCredential(value string) bool {
	return len(value) >= 32 && len(value) <= 512 && strings.TrimSpace(value) == value &&
		strings.IndexFunc(value, func(r rune) bool { return r < 0x21 || r > 0x7e }) == -1
}

func validAssuranceSubject(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, char := range []byte(value) {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '_' || char == '-') {
			return false
		}
	}
	return true
}

func assuranceUnavailable(err error) error {
	return fmt.Errorf("%w: %v", ErrAssuranceUnavailable, err)
}
