package gateway

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/holdfast/sluice/internal/config"
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

// NewACMEManager builds the autocert.Manager for TLS_MODE=acme. The HostPolicy is
// whitelisted to the single ACMEDomain so the manager only ever requests a
// certificate for the expected public host; issued certs + the account key are
// cached in ACMECacheDir (a Docker VOLUME). When ACMEDirectoryURL is set (e.g.
// Let's Encrypt staging) it overrides the default production directory so
// issuance can be exercised without burning production rate limits.
//
// manager.TLSConfig() is wired onto the :443 server and manager.HTTPHandler onto
// the :80 server (see RedirectHTTPSHandler); the actual certificate issuance
// happens lazily on the first TLS handshake / challenge, in the deploy step.
func NewACMEManager(cfg *config.Config) *autocert.Manager {
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.ACMEDomain),
		Cache:      autocert.DirCache(cfg.ACMECacheDir),
		Email:      cfg.ACMEEmail,
	}
	if cfg.ACMEDirectoryURL != "" {
		m.Client = &acme.Client{DirectoryURL: cfg.ACMEDirectoryURL}
	}
	return m
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
