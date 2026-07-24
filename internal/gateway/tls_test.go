package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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
		{"share_room_asset", "drive.w33d.xyz", "/s/share-room.css", "https://drive.w33d.xyz/s/share-room.css"},
		{"existing_review_capability", "blog.w33d.xyz", "/review/token", "https://blog.w33d.xyz/review/token"},
		{"existing_receipt_capability", "drive.w33d.xyz", "/receipts/token", "https://drive.w33d.xyz/receipts/token"},
		{"existing_share_capability", "drive.w33d.xyz", "/s/token", "https://drive.w33d.xyz/s/token"},
		{"existing_upload_capability", "drive.w33d.xyz", "/u/token", "https://drive.w33d.xyz/u/token"},
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
			if got := rec.Header().Get("Referrer-Policy"); got != "" {
				t.Errorf("Referrer-Policy = %q, want existing redirect behavior", got)
			}
			if got := rec.Header().Get("Cache-Control"); got != "" {
				t.Errorf("Cache-Control = %q, want existing redirect behavior", got)
			}
			if rec.Body.Len() == 0 {
				t.Error("redirect body is empty; want existing http.Redirect body")
			}
		})
	}
}

func TestRedirectHTTPSHandlerProtectsRSVPCapability(t *testing.T) {
	const bearer = "RAW-RSVP-CAPABILITY-SENTINEL"
	tests := []struct {
		name         string
		host         string
		uri          string
		wantLocation string
		bearer       string
	}{
		{
			name:         "nested bearer and host port",
			host:         "CAL.W33D.XYZ:80",
			uri:          "/rsvp/" + bearer + "/reply/accepted?next=%2Fcalendar",
			wantLocation: "https://CAL.W33D.XYZ/rsvp/" + bearer + "/reply/accepted?next=%2Fcalendar",
			bearer:       bearer,
		},
		{
			name:         "exact empty capability tail",
			host:         "cal.w33d.xyz",
			uri:          "/rsvp/",
			wantLocation: "https://cal.w33d.xyz/rsvp/",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://"+test.host+test.uri, nil)
			req.Host = test.host
			rec := httptest.NewRecorder()
			RedirectHTTPSHandler().ServeHTTP(rec, req)

			if rec.Code != http.StatusMovedPermanently {
				t.Fatalf("status = %d, want 301", rec.Code)
			}
			if got := rec.Header().Get("Location"); got != test.wantLocation {
				t.Fatalf("Location = %q, want exact same-URI redirect %q", got, test.wantLocation)
			}
			if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
				t.Fatalf("Referrer-Policy = %q, want no-referrer", got)
			}
			if got := rec.Header().Get("Cache-Control"); got != "private, no-store" {
				t.Fatalf("Cache-Control = %q, want private, no-store", got)
			}
			if got := rec.Body.String(); got != "" {
				t.Fatalf("body = %q, want empty capability redirect body", got)
			}
			if test.bearer != "" {
				for name, values := range rec.Header() {
					if strings.EqualFold(name, "Location") {
						continue
					}
					if strings.Contains(strings.Join(values, "\n"), test.bearer) {
						t.Fatalf("response header %q leaked RSVP capability: %q", name, values)
					}
				}
				if count := strings.Count(rec.Header().Get("Location"), test.bearer); count != 1 {
					t.Fatalf("Location contains RSVP capability %d times, want exactly once", count)
				}
			}
		})
	}
}

// staticHosts is a fixed AllowedHosts for tests.
func staticHosts(hosts ...string) AllowedHosts {
	return func() map[string]struct{} {
		set := make(map[string]struct{}, len(hosts))
		for _, h := range hosts {
			set[h] = struct{}{}
		}
		return set
	}
}

// TestNewACMEManagerHostPolicy proves the autocert manager is wired with the
// DYNAMIC host policy: a host in the allowed set is accepted and any other host is
// rejected. This is the security-critical wiring; real issuance happens in the
// deploy step.
func TestNewACMEManagerHostPolicy(t *testing.T) {
	cfg := &config.Config{
		TLSMode:      config.TLSModeACME,
		ACMEEmail:    "ops@w33d.xyz",
		ACMECacheDir: t.TempDir(),
	}
	m := NewACMEManager(cfg, staticHosts("id.w33d.xyz", "vitals.w33d.xyz"))

	if m.HostPolicy == nil {
		t.Fatal("HostPolicy is nil; autocert would accept any host")
	}
	for _, h := range []string{"id.w33d.xyz", "vitals.w33d.xyz"} {
		if err := m.HostPolicy(context.Background(), h); err != nil {
			t.Errorf("HostPolicy rejected an allowed host %q: %v", h, err)
		}
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

// TestNewACMEManagerNilHostsFailsClosed proves a nil allowed-host set rejects
// every host (fail closed) rather than turning the manager into an open issuer.
func TestNewACMEManagerNilHostsFailsClosed(t *testing.T) {
	m := NewACMEManager(&config.Config{ACMECacheDir: t.TempDir()}, nil)
	if err := m.HostPolicy(context.Background(), "id.w33d.xyz"); err == nil {
		t.Error("nil host set admitted a host; want fail-closed rejection")
	}
}

// TestRouteHostSetDerivesFromRoutesAndApex proves the autocert allowed-host set is
// exactly the route table's hosts ∪ the extra hosts (apex + legacy ACME_DOMAIN),
// and that it refreshes from the store on each call (route reload).
func TestRouteHostSetDerivesFromRoutesAndApex(t *testing.T) {
	s := mustRoutes(t, []config.Route{
		{Name: "portal", Match: config.Match{Host: "w33d.xyz", PathPrefix: "/"}, Upstream: "http://127.0.0.1:1", Auth: "sso"},
		{Name: "id", Match: config.Match{Host: "id.w33d.xyz", PathPrefix: "/"}, Upstream: "http://127.0.0.1:2"},
		{Name: "vitals", Match: config.Match{Host: "vitals.w33d.xyz", PathPrefix: "/"}, Upstream: "http://127.0.0.1:3", Auth: "sso"},
		// A host-agnostic fallback contributes NO host to the cert set.
		{Name: "fallback", Match: config.Match{PathPrefix: "/"}, Upstream: "http://127.0.0.1:4"},
	})
	set := RouteHostSet(s, "w33d.xyz", "id.w33d.xyz", "")()

	want := []string{"w33d.xyz", "id.w33d.xyz", "vitals.w33d.xyz"}
	for _, h := range want {
		if _, ok := set[h]; !ok {
			t.Errorf("allowed host set missing %q", h)
		}
	}
	if len(set) != len(want) {
		t.Errorf("allowed host set = %v, want exactly %v (no host-agnostic, no empty extra)", set, want)
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
	m := NewACMEManager(cfg, staticHosts("id.w33d.xyz"))
	if m.Client == nil {
		t.Fatal("ACMEDirectoryURL set but manager.Client is nil")
	}
	if m.Client.DirectoryURL != staging {
		t.Errorf("DirectoryURL = %q, want %q", m.Client.DirectoryURL, staging)
	}

	// With no directory override the Client stays nil (autocert uses the LE
	// production default).
	prod := NewACMEManager(&config.Config{ACMECacheDir: t.TempDir()}, staticHosts("id.w33d.xyz"))
	if prod.Client != nil {
		t.Errorf("Client should be nil without ACME_DIRECTORY_URL, got %+v", prod.Client)
	}
}

func TestNewACMEManagerHTTPHandlerComposesChallengeAndRSVPFallback(t *testing.T) {
	const host = "cal.w33d.xyz"
	const challengeToken = "deterministic-http-01-token"
	const challengeBody = challengeToken + ".deterministic-key-authorization"

	manager := NewACMEManager(
		&config.Config{ACMECacheDir: t.TempDir()},
		staticHosts(host),
	)
	if err := manager.Cache.Put(
		context.Background(),
		challengeToken+"+http-01",
		[]byte(challengeBody),
	); err != nil {
		t.Fatalf("seed ACME HTTP-01 cache: %v", err)
	}
	handler := manager.HTTPHandler(RedirectHTTPSHandler())

	t.Run("cached challenge passthrough", func(t *testing.T) {
		req := httptest.NewRequest(
			http.MethodGet,
			"http://"+host+"/.well-known/acme-challenge/"+challengeToken,
			nil,
		)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if got := rec.Body.String(); got != challengeBody {
			t.Fatalf("body = %q, want cached challenge response %q", got, challengeBody)
		}
		if got := rec.Header().Get("Location"); got != "" {
			t.Fatalf("Location = %q, want ACME challenge passthrough", got)
		}
	})

	t.Run("unknown challenge stays 404", func(t *testing.T) {
		req := httptest.NewRequest(
			http.MethodGet,
			"http://"+host+"/.well-known/acme-challenge/unknown-token",
			nil,
		)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
		if got := rec.Header().Get("Location"); got != "" {
			t.Fatalf("Location = %q, want unknown challenge handled without fallback", got)
		}
		if got := rec.Header().Get("Referrer-Policy"); got != "" {
			t.Fatalf("Referrer-Policy = %q, want unknown challenge handled without fallback", got)
		}
		if got := rec.Header().Get("Cache-Control"); got != "" {
			t.Fatalf("Cache-Control = %q, want unknown challenge handled without fallback", got)
		}
	})

	t.Run("RSVP fallback privacy", func(t *testing.T) {
		const bearer = "RAW-CACHED-COMPOSITION-RSVP-BEARER"
		const uri = "/rsvp/" + bearer + "/reply/declined?source=email"
		req := httptest.NewRequest(http.MethodGet, "http://"+host+uri, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusMovedPermanently {
			t.Fatalf("status = %d, want 301", rec.Code)
		}
		if got, want := rec.Header().Get("Location"), "https://"+host+uri; got != want {
			t.Fatalf("Location = %q, want %q", got, want)
		}
		if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
			t.Fatalf("Referrer-Policy = %q, want no-referrer", got)
		}
		if got := rec.Header().Get("Cache-Control"); got != "private, no-store" {
			t.Fatalf("Cache-Control = %q, want private, no-store", got)
		}
		if got := rec.Body.String(); got != "" {
			t.Fatalf("body = %q, want empty RSVP fallback body", got)
		}
		for name, values := range rec.Header() {
			if strings.EqualFold(name, "Location") {
				continue
			}
			if strings.Contains(strings.Join(values, "\n"), bearer) {
				t.Fatalf("response header %q leaked RSVP capability: %q", name, values)
			}
		}
	})
}
