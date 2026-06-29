package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/holdfast/sluice/internal/config"
)

// TestRedirectHTTPSHandler verifies the :80 handler 301-redirects to https,
// strips the inbound port, and preserves the request URI (path + query).
func TestRedirectHTTPSHandler(t *testing.T) {
	h := RedirectHTTPSHandler()

	cases := []struct {
		name string
		host string
		uri  string
		want string
	}{
		{"bare_host", "id.w33d.xyz", "/login?next=/account", "https://id.w33d.xyz/login?next=/account"},
		{"host_with_port", "id.w33d.xyz:80", "/authorize", "https://id.w33d.xyz/authorize"},
		{"root", "id.w33d.xyz", "/", "https://id.w33d.xyz/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://"+tc.host+tc.uri, nil)
			req.Host = tc.host
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusMovedPermanently {
				t.Fatalf("status = %d, want 301", rec.Code)
			}
			if got := rec.Header().Get("Location"); got != tc.want {
				t.Errorf("Location = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestNewACMEManagerHostPolicy proves the autocert manager is wired with a host
// whitelist restricted to ACMEDomain: the configured domain is accepted and any
// other host is rejected. This is the security-critical wiring; real issuance
// happens in the deploy step.
func TestNewACMEManagerHostPolicy(t *testing.T) {
	cfg := &config.Config{
		TLSMode:      config.TLSModeACME,
		ACMEDomain:   "id.w33d.xyz",
		ACMEEmail:    "ops@w33d.xyz",
		ACMECacheDir: t.TempDir(),
	}
	m := NewACMEManager(cfg)

	if m.HostPolicy == nil {
		t.Fatal("HostPolicy is nil; autocert would accept any host")
	}
	if err := m.HostPolicy(context.Background(), "id.w33d.xyz"); err != nil {
		t.Errorf("HostPolicy rejected the configured domain: %v", err)
	}
	if err := m.HostPolicy(context.Background(), "evil.example"); err == nil {
		t.Error("HostPolicy accepted an unexpected host; want rejection")
	}
	if m.Email != "ops@w33d.xyz" {
		t.Errorf("Email = %q, want ops@w33d.xyz", m.Email)
	}
	// TLSConfig must be obtainable (this is what the :443 server consumes) and
	// advertise the ACME TLS-ALPN-01 negotiation hook (GetCertificate set).
	if tc := m.TLSConfig(); tc == nil || tc.GetCertificate == nil {
		t.Error("manager.TLSConfig() missing GetCertificate; not wired for serving")
	}
}

// TestNewACMEManagerStagingDirectory proves ACME_DIRECTORY_URL is wired onto the
// underlying acme.Client so LE staging (or any directory) can be targeted to
// test issuance without burning production rate limits.
func TestNewACMEManagerStagingDirectory(t *testing.T) {
	const staging = "https://acme-staging-v02.api.letsencrypt.org/directory"
	cfg := &config.Config{
		TLSMode:          config.TLSModeACME,
		ACMEDomain:       "id.w33d.xyz",
		ACMECacheDir:     t.TempDir(),
		ACMEDirectoryURL: staging,
	}
	m := NewACMEManager(cfg)
	if m.Client == nil {
		t.Fatal("ACMEDirectoryURL set but manager.Client is nil")
	}
	if m.Client.DirectoryURL != staging {
		t.Errorf("DirectoryURL = %q, want %q", m.Client.DirectoryURL, staging)
	}

	// With no directory override the Client stays nil (autocert uses the LE
	// production default).
	prod := NewACMEManager(&config.Config{ACMEDomain: "id.w33d.xyz", ACMECacheDir: t.TempDir()})
	if prod.Client != nil {
		t.Errorf("Client should be nil without ACME_DIRECTORY_URL, got %+v", prod.Client)
	}
}
