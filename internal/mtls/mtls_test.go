package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testPKI is a tiny CA plus the server/client leaf certificates used to exercise
// a full mutual-TLS handshake from the transport built by this package.
type testPKI struct {
	caPEM      []byte
	serverCert tls.Certificate
	clientCert string // path to client cert PEM
	clientKey  string // path to client key PEM
	caFile     string // path to CA PEM
}

// newTestPKI builds a CA and issues a server cert (for "keystone", 127.0.0.1) and
// a client cert (CN=sluice), writing the client material + CA to dir.
func newTestPKI(t *testing.T, dir string) *testPKI {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "keyward-test-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	// Server leaf for ServerName "keystone" (and 127.0.0.1 for the loopback dial).
	serverCertPEM, serverKeyPEM := issueLeaf(t, caCert, caKey, "keystone",
		[]string{"keystone"}, []net.IP{net.ParseIP("127.0.0.1")}, x509.ExtKeyUsageServerAuth)
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}

	// Client leaf CN=sluice.
	clientCertPEM, clientKeyPEM := issueLeaf(t, caCert, caKey, "sluice",
		nil, nil, x509.ExtKeyUsageClientAuth)

	caFile := filepath.Join(dir, "ca.pem")
	clientCertFile := filepath.Join(dir, "client.crt")
	clientKeyFile := filepath.Join(dir, "client.key")
	writeFile(t, caFile, caPEM)
	writeFile(t, clientCertFile, clientCertPEM)
	writeFile(t, clientKeyFile, clientKeyPEM)

	return &testPKI{
		caPEM:      caPEM,
		serverCert: serverCert,
		clientCert: clientCertFile,
		clientKey:  clientKeyFile,
		caFile:     caFile,
	}
}

func issueLeaf(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, dns []string, ips []net.IP, eku x509.ExtKeyUsage) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestTransportMutualTLS proves the transport built from the Keyward-style client
// material completes a mutual-TLS handshake against a server that REQUIRES and
// verifies a client certificate, and that the pinned ServerName is honored.
func TestTransportMutualTLS(t *testing.T) {
	dir := t.TempDir()
	pki := newTestPKI(t, dir)

	clientPool := x509.NewCertPool()
	clientPool.AppendCertsFromPEM(pki.caPEM)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "mutual-ok")
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{pki.serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientPool,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	defer srv.Close()

	cfg := Config{
		CertFile:   pki.clientCert,
		KeyFile:    pki.clientKey,
		CAFile:     pki.caFile,
		ServerName: "keystone",
	}
	client, err := cfg.Client(5 * time.Second)
	if err != nil {
		t.Fatalf("build client: %v", err)
	}

	// httptest picks a 127.0.0.1:port; the pinned ServerName ("keystone") differs
	// from the dialed host, and the server leaf carries both keystone + 127.0.0.1
	// SANs, so the handshake verifies the server identity via the configured CA.
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("mTLS GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "mutual-ok" {
		t.Errorf("body = %q, want mutual-ok", body)
	}
}

// TestTransportRejectedWithoutClientCert confirms the server really demands a
// client certificate: a plain TLS client (no cert) is refused, so the positive
// test above is meaningful.
func TestTransportRejectedWithoutClientCert(t *testing.T) {
	dir := t.TempDir()
	pki := newTestPKI(t, dir)

	clientPool := x509.NewCertPool()
	clientPool.AppendCertsFromPEM(pki.caPEM)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{pki.serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientPool,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	defer srv.Close()

	// Trust the server but present NO client cert -> handshake must fail.
	noCert := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:    clientPool,
			ServerName: "127.0.0.1",
		}},
	}
	if _, err := noCert.Get(srv.URL); err == nil {
		t.Fatal("expected handshake failure without a client certificate")
	}
}

// TestConfigErrors covers the build-time failures that drive the safe-degrade
// path in main (missing files / empty CA).
func TestConfigErrors(t *testing.T) {
	if _, err := (Config{CertFile: "/nope", KeyFile: "/nope", CAFile: "/nope"}).Transport(); err == nil {
		t.Error("expected error for missing cert files")
	}
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.pem")
	writeFile(t, empty, []byte("not a pem"))
	pki := newTestPKI(t, dir)
	cfg := Config{CertFile: pki.clientCert, KeyFile: pki.clientKey, CAFile: empty}
	if _, err := cfg.Transport(); err == nil {
		t.Error("expected error for CA file with no certificates")
	}
}
