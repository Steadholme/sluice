package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/holdfast/sluice/internal/config"
	"github.com/holdfast/sluice/internal/store"
)

// FileTLSConfig loads the certificate chain + private key for TLS_MODE=file from
// cfg.TLSCertFile / cfg.TLSKeyFile and returns a *tls.Config ready to hand to an
// http.Server. A modern floor (TLS 1.2) is enforced; the cert may be a chain
// (leaf first) and the key its matching PEM private key. A load failure is
// returned so the caller can fail fast at startup rather than serving without a
// usable certificate.
func FileTLSConfig(cfg *config.Config) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("gateway: load tls cert/key: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// AllowedHosts returns the current set of hosts Sluice is willing to terminate
// TLS for. It is consulted on every TLS handshake by the dynamic autocert
// HostPolicy, so re-reading it picks up route reloads transparently.
type AllowedHosts func() map[string]struct{}

// RouteHostSet builds an AllowedHosts that is the set of non-empty Match.Host
// values in the CURRENT route table, UNION the supplied extra hosts (typically
// the apex w33d.xyz and the legacy ACME_DOMAIN). The store is read on every call
// so a hot-reloading RouteStore refreshes the allowed-host set with no extra
// wiring. An empty extra string is ignored.
func RouteHostSet(s store.RouteStore, extra ...string) AllowedHosts {
	return func() map[string]struct{} {
		set := make(map[string]struct{})
		for _, r := range s.Routes() {
			if h := r.Match.Host; h != "" {
				set[h] = struct{}{}
			}
		}
		for _, h := range extra {
			if h != "" {
				set[h] = struct{}{}
			}
		}
		return set
	}
}

// NewACMEManager builds the autocert.Manager for TLS_MODE=acme. The HostPolicy is
// DYNAMIC: rather than a single fixed host, it accepts exactly the hosts returned
// by allowed (the live route table ∪ the apex), so the manager issues a per-host
// Let's Encrypt certificate ON DEMAND for every subdomain we actually serve and
// REJECTS the TLS-ALPN/SNI handshake for any other host (blocking scanners from
// triggering issuance for random *.w33d.xyz names). Issued certs + the account
// key are cached in ACMECacheDir (a Docker VOLUME). When ACMEDirectoryURL is set
// (e.g. Let's Encrypt staging) it overrides the default production directory so
// issuance can be exercised without burning production rate limits.
//
// manager.TLSConfig() is wired onto the :443 server and manager.HTTPHandler onto
// the :80 server (see RedirectHTTPSHandler); the actual certificate issuance
// happens lazily on the first TLS handshake / challenge, in the deploy step.
func NewACMEManager(cfg *config.Config, allowed AllowedHosts) *autocert.Manager {
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: dynamicHostPolicy(allowed),
		Cache:      autocert.DirCache(cfg.ACMECacheDir),
		Email:      cfg.ACMEEmail,
	}
	if cfg.ACMEDirectoryURL != "" {
		m.Client = &acme.Client{DirectoryURL: cfg.ACMEDirectoryURL}
	}
	return m
}

// dynamicHostPolicy is an autocert.HostPolicy that admits a host iff it is in the
// set returned by allowed at handshake time. A nil allowed set rejects every host
// (fail closed) rather than admitting all, so a wiring mistake can never turn the
// manager into an open issuer.
func dynamicHostPolicy(allowed AllowedHosts) autocert.HostPolicy {
	return func(_ context.Context, host string) error {
		if allowed != nil {
			if _, ok := allowed()[host]; ok {
				return nil
			}
		}
		return fmt.Errorf("acme: host %q not in the served route set", host)
	}
}

// RedirectHTTPSHandler 301-redirects every request to the https scheme on the
// same host + URI. It is the :80 handler in file mode and the fallback handler
// (for non-ACME-challenge traffic) wrapped by manager.HTTPHandler in acme mode.
func RedirectHTTPSHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := "https://" + stripPort(r.Host) + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}

// stripPort removes any :port suffix from a Host header value, leaving the bare
// host so the https redirect lands on the default 443.
func stripPort(host string) string {
	if i := strings.LastIndexByte(host, ':'); i != -1 {
		// Guard against IPv6 literals like "[::1]" with no port.
		if !strings.Contains(host[i:], "]") {
			return host[:i]
		}
	}
	return host
}
