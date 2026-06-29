package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// jwksKey is a single key entry from a JWKS document (RFC 7517). Only the RSA
// fields needed for RS256 verification are decoded.
type jwksKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwksDocument struct {
	Keys []jwksKey `json:"keys"`
}

// discoveryDocument is the subset of the OIDC discovery document we consume.
type discoveryDocument struct {
	JWKSURI string `json:"jwks_uri"`
}

// JWKSCache discovers and caches Keystone's RS256 public keys.
//
// Keys are indexed by kid behind an RWMutex. On an unknown kid (key rotation)
// the cache triggers a single cooldown-gated refresh rather than fetching on
// every miss, absorbing rotation without hammering Keystone.
type JWKSCache struct {
	discoveryURL string
	httpClient   *http.Client
	minRefresh   time.Duration

	mu          sync.RWMutex
	jwksURI     string
	keys        map[string]*rsa.PublicKey
	lastRefresh time.Time
}

// NewJWKSCache constructs a cache that discovers jwks_uri from discoveryURL.
// minRefresh is the single-flight cooldown between refreshes triggered by an
// unknown kid.
func NewJWKSCache(discoveryURL string, client *http.Client, minRefresh time.Duration) *JWKSCache {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if minRefresh <= 0 {
		minRefresh = 30 * time.Second
	}
	return &JWKSCache{
		discoveryURL: discoveryURL,
		httpClient:   client,
		minRefresh:   minRefresh,
		keys:         make(map[string]*rsa.PublicKey),
	}
}

// KeyByKID returns the cached public key for kid. On a miss it performs a
// cooldown-gated refresh and retries once, so freshly-rotated keys are picked
// up without a refresh storm.
func (c *JWKSCache) KeyByKID(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if key := c.lookup(kid); key != nil {
		return key, nil
	}
	if err := c.refresh(ctx); err != nil {
		return nil, err
	}
	if key := c.lookup(kid); key != nil {
		return key, nil
	}
	return nil, fmt.Errorf("auth: no key for kid %q", kid)
}

func (c *JWKSCache) lookup(kid string) *rsa.PublicKey {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.keys[kid]
}

// refresh re-fetches the JWKS, subject to the minRefresh cooldown. A refresh
// that is skipped due to cooldown is not an error: it means another caller
// refreshed recently and the kid is genuinely unknown.
func (c *JWKSCache) refresh(ctx context.Context) error {
	c.mu.Lock()
	if !c.lastRefresh.IsZero() && time.Since(c.lastRefresh) < c.minRefresh {
		c.mu.Unlock()
		return nil
	}
	// Mark the attempt now so concurrent callers honor the cooldown even if the
	// fetch below is slow or fails.
	c.lastRefresh = time.Now()
	jwksURI := c.jwksURI
	c.mu.Unlock()

	if jwksURI == "" {
		discovered, err := c.discover(ctx)
		if err != nil {
			return err
		}
		jwksURI = discovered
	}

	doc, err := c.fetchJWKS(ctx, jwksURI)
	if err != nil {
		return err
	}
	keys, err := parseJWKS(doc)
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.jwksURI = jwksURI
	c.keys = keys
	c.mu.Unlock()
	return nil
}

// Warm eagerly performs an initial discovery + JWKS fetch. It is best-effort at
// startup; failures are returned so the caller can log but need not be fatal,
// since KeyByKID will retry lazily on first use.
func (c *JWKSCache) Warm(ctx context.Context) error {
	return c.refresh(ctx)
}

func (c *JWKSCache) discover(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.discoveryURL, nil)
	if err != nil {
		return "", fmt.Errorf("auth: build discovery request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth: fetch discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth: discovery returned status %d", resp.StatusCode)
	}
	var d discoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return "", fmt.Errorf("auth: decode discovery: %w", err)
	}
	if d.JWKSURI == "" {
		return "", fmt.Errorf("auth: discovery document missing jwks_uri")
	}
	return d.JWKSURI, nil
}

func (c *JWKSCache) fetchJWKS(ctx context.Context, jwksURI string) (*jwksDocument, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, fmt.Errorf("auth: build jwks request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth: fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth: jwks returned status %d", resp.StatusCode)
	}
	var doc jwksDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("auth: decode jwks: %w", err)
	}
	return &doc, nil
}

// parseJWKS reconstructs RSA public keys from the base64url-encoded modulus (n)
// and exponent (e) per RFC 7518. Non-RSA keys are skipped.
func parseJWKS(doc *jwksDocument) (map[string]*rsa.PublicKey, error) {
	keys := make(map[string]*rsa.PublicKey)
	for i := range doc.Keys {
		k := doc.Keys[i]
		if k.Kty != "RSA" {
			continue
		}
		pub, err := rsaPublicKeyFromNE(k.N, k.E)
		if err != nil {
			return nil, fmt.Errorf("auth: key kid %q: %w", k.Kid, err)
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("auth: jwks contained no usable RSA keys")
	}
	return keys, nil
}

// rsaPublicKeyFromNE decodes the base64url modulus and exponent into an
// *rsa.PublicKey (RFC 7517 / 7518, section 6.3.1).
func rsaPublicKeyFromNE(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}
	if len(nBytes) == 0 || len(eBytes) == 0 {
		return nil, fmt.Errorf("empty modulus or exponent")
	}
	n := new(big.Int).SetBytes(nBytes)

	// The exponent is a big-endian unsigned integer of up to 4 bytes in
	// practice; left-pad into a uint32.
	if len(eBytes) > 4 {
		return nil, fmt.Errorf("exponent too large: %d bytes", len(eBytes))
	}
	var eBuf [4]byte
	copy(eBuf[4-len(eBytes):], eBytes)
	e := int(binary.BigEndian.Uint32(eBuf[:]))
	if e == 0 {
		return nil, fmt.Errorf("zero exponent")
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}
