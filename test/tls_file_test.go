package test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/holdfast/sluice/internal/accesslog"
	"github.com/holdfast/sluice/internal/config"
	"github.com/holdfast/sluice/internal/gateway"
)

// genSelfSigned writes a self-signed cert + key (valid for 127.0.0.1) to dir and
// returns the file paths plus an x509 cert pool that trusts it, so the client
// can really verify the served chain.
func genSelfSigned(t *testing.T, dir string) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sluice-file-tls-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	pool = x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("append cert to pool")
	}
	return certFile, keyFile, pool
}

// TestFileTLSForwardAuth exercises the full HTTPS chain in TLS_MODE=file: a
// generated self-signed cert is loaded by gateway.FileTLSConfig, served on a real
// TLS listener, and the protected route's forward-auth still works end-to-end
// over HTTPS (valid token -> 200 + X-Auth-* injected; no token -> 401).
func TestFileTLSForwardAuth(t *testing.T) {
	accesslog.SetLogger(slog.New(slog.NewJSONHandler(io.Discard, nil)))

	keystone := newFakeKeystone(t)
	upstream := newEchoUpstream(t)
	handler := newSluiceHandler(t, keystone, upstream.server.URL)

	certFile, keyFile, pool := genSelfSigned(t, t.TempDir())
	cfg := &config.Config{TLSMode: config.TLSModeFile, TLSCertFile: certFile, TLSKeyFile: keyFile}
	tlsConf, err := gateway.FileTLSConfig(cfg)
	if err != nil {
		t.Fatalf("FileTLSConfig: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: handler, TLSConfig: tlsConf}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	base := "https://" + ln.Addr().String()
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
	}

	// HTTPS healthz proves the TLS listener serves the gateway.
	t.Run("https_healthz", func(t *testing.T) {
		resp, err := client.Get(base + "/healthz")
		if err != nil {
			t.Fatalf("GET healthz: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("healthz status = %d, want 200", resp.StatusCode)
		}
	})

	// Protected route with a valid token over HTTPS -> 200 + verified X-Auth-*.
	t.Run("protected_valid_token_over_tls", func(t *testing.T) {
		token := keystone.mint(t, keystone.issuer, time.Now().Add(time.Hour))
		req, _ := http.NewRequest(http.MethodGet, base+"/api/secret", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET over TLS: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		h := decodeReflected(t, resp.Body)
		if got := first(h["X-Auth-Subject"]); got != "u_admin" {
			t.Errorf("X-Auth-Subject = %q, want u_admin", got)
		}
		// X-Forwarded-Proto must be https now that Sluice terminated TLS.
		if got := first(h["X-Forwarded-Proto"]); got != "https" {
			t.Errorf("X-Forwarded-Proto = %q, want https", got)
		}
	})

	// Protected route with no token over HTTPS -> 401, upstream untouched.
	t.Run("protected_no_token_over_tls", func(t *testing.T) {
		before := upstream.hits.Load()
		resp, err := client.Get(base + "/api/secret")
		if err != nil {
			t.Fatalf("GET over TLS: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", resp.StatusCode)
		}
		if after := upstream.hits.Load(); after != before {
			t.Errorf("upstream hit on unauthenticated TLS request: before=%d after=%d", before, after)
		}
	})
}
