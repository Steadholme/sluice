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

	"golang.org/x/sync/singleflight"
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

// Backoff defaults for the recovery path. The base is the wait between the
// SECOND and later consecutive failures; the cap bounds it so recovery is never
// delayed indefinitely. The FIRST retry after a failure is always immediate
// (backoffFor returns 0 for failures <= 1) so a real recovery is never blocked.
const (
	defaultBaseBackoff = 1 * time.Second
	defaultMaxBackoff  = 30 * time.Second
)

// JWKSCache discovers and caches Keystone's RS256 public keys.
//
// Keys are indexed by kid behind an RWMutex. A kid miss triggers an on-demand
// refresh whose behaviour depends on cache health:
//
//   - Healthy cache (keys present, last refresh succeeded recently): a miss is
//     treated as a genuinely-unknown kid and refreshes are suppressed for
//     minRefresh after the last SUCCESS. This is the key-rotation / garbage-kid
//     storm guard — it never blocks recovery because a healthy cache by
//     definition already succeeded.
//   - Cold or failing cache (no keys, or the last attempt failed): the miss is a
//     recovery scenario. Refresh is NOT suppressed by the success cooldown; only
//     a bounded backoff between REPEATED failures applies, and the first retry
//     after a failure is immediate so the first real recovery is never blocked.
//
// Concurrent refreshes are collapsed into one in-flight fetch via singleflight,
// so a burst of misses (e.g. a token replay storm) costs a single upstream call.
type JWKSCache struct {
	discoveryURL string
	httpClient   *http.Client
	minRefresh   time.Duration
	baseBackoff  time.Duration
	maxBackoff   time.Duration

	sf singleflight.Group

	mu          sync.RWMutex
	jwksURI     string
	keys        map[string]*rsa.PublicKey
	lastSuccess time.Time // time of the last SUCCESSFUL refresh (drives minRefresh)
	lastAttempt time.Time // time of the last refresh attempt (drives failure backoff)
	failures    int       // consecutive failures since the last success
	lastErr     error     // last refresh error, returned while backing off
}

// NewJWKSCache constructs a cache that discovers jwks_uri from discoveryURL.
// minRefresh is the cooldown after a SUCCESSFUL refresh during which a still
// missing kid is treated as genuinely unknown (rotation guard), not as a reason
// to refetch.
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
		baseBackoff:  defaultBaseBackoff,
		maxBackoff:   defaultMaxBackoff,
		keys:         make(map[string]*rsa.PublicKey),
	}
}

// KeyByKID returns the cached public key for kid. On a miss it performs an
// on-demand refresh (deduped across concurrent callers) and retries once, so a
// freshly-rotated key or a recovered Keystone is picked up without a fetch
// storm and without ever leaving forward-auth stuck on a stale 401.
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

// refresh re-fetches the JWKS, deduping concurrent callers via singleflight so a
// burst of misses triggers at most one in-flight fetch.
func (c *JWKSCache) refresh(ctx context.Context) error {
	_, err, _ := c.sf.Do("refresh", func() (any, error) {
		return nil, c.doRefresh(ctx)
	})
	return err
}

// doRefresh decides whether to actually fetch based on cache health, then fetches.
func (c *JWKSCache) doRefresh(ctx context.Context) error {
	c.mu.Lock()
	healthy := len(c.keys) > 0 && c.failures == 0 && !c.lastSuccess.IsZero()
	if healthy {
		// Rotation / garbage-kid storm guard: a healthy cache that refreshed
		// successfully within minRefresh treats a missing kid as genuinely
		// unknown and does not refetch. This can never block recovery because a
		// healthy cache has, by definition, already recovered.
		if time.Since(c.lastSuccess) < c.minRefresh {
			c.mu.Unlock()
			return nil
		}
	} else if c.failures > 0 {
		// Recovery path: bounded backoff between REPEATED failures so a down
		// Keystone is not hammered. The first retry after a failure is immediate
		// (backoffFor(1) == 0), so the first real recovery is never blocked.
		if time.Since(c.lastAttempt) < c.backoffFor(c.failures) {
			err := c.lastErr
			c.mu.Unlock()
			return err
		}
	}
	c.lastAttempt = time.Now()
	jwksURI := c.jwksURI
	c.mu.Unlock()

	keys, resolvedURI, err := c.fetch(ctx, jwksURI)

	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.failures++
		c.lastErr = err
		return err
	}
	c.jwksURI = resolvedURI
	c.keys = keys
	c.lastSuccess = time.Now()
	c.failures = 0
	c.lastErr = nil
	return nil
}

// fetch performs discovery (if needed) and the JWKS fetch+parse without holding
// the lock. It returns the parsed keys and the resolved jwks_uri.
func (c *JWKSCache) fetch(ctx context.Context, jwksURI string) (map[string]*rsa.PublicKey, string, error) {
	if jwksURI == "" {
		discovered, err := c.discover(ctx)
		if err != nil {
			return nil, "", err
		}
		jwksURI = discovered
	}
	doc, err := c.fetchJWKS(ctx, jwksURI)
	if err != nil {
		return nil, "", err
	}
	keys, err := parseJWKS(doc)
	if err != nil {
		return nil, "", err
	}
	return keys, jwksURI, nil
}

// backoffFor returns the minimum wait between attempts after `failures`
// consecutive failures. The first retry (failures <= 1) is immediate; from the
// second failure on it grows exponentially from baseBackoff, capped at
// maxBackoff so recovery latency is always bounded.
func (c *JWKSCache) backoffFor(failures int) time.Duration {
	if failures <= 1 {
		return 0
	}
	d := c.baseBackoff << (failures - 2)
	if d <= 0 || d > c.maxBackoff {
		return c.maxBackoff
	}
	return d
}

// Warm eagerly performs an initial discovery + JWKS fetch. It is best-effort at
// startup; a failure is returned so the caller can log it, but it is not fatal:
// the recovered cache state (cold + one recorded failure) lets the very next
// protected request retry immediately and succeed once Keystone is reachable.
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
