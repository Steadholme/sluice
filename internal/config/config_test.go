package config

import (
	"path/filepath"
	"testing"
)

func TestLoadExampleConfig(t *testing.T) {
	path := filepath.Join("..", "..", "config.example.json")
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile(%s) error: %v", path, err)
	}
	if cfg.ListenAddr != "127.0.0.1:9090" {
		t.Errorf("ListenAddr = %q, want 127.0.0.1:9090", cfg.ListenAddr)
	}
	if cfg.KeystoneIssuer != "http://127.0.0.1:8080" {
		t.Errorf("KeystoneIssuer = %q", cfg.KeystoneIssuer)
	}
	if len(cfg.Routes) != 2 {
		t.Fatalf("got %d routes, want 2", len(cfg.Routes))
	}
	// Upstream URLs must be parsed during Validate.
	for _, r := range cfg.Routes {
		if r.UpstreamURL() == nil {
			t.Errorf("route %q: UpstreamURL not parsed", r.Name)
		}
	}
	// One public and one protected route per the seed table.
	var pub, prot int
	for _, r := range cfg.Routes {
		if r.Protected {
			prot++
		} else {
			pub++
		}
	}
	if pub != 1 || prot != 1 {
		t.Errorf("want 1 public + 1 protected, got %d public / %d protected", pub, prot)
	}
}

func TestValidateRejectsMissingUpstream(t *testing.T) {
	c := &Config{
		KeystoneIssuer: "http://127.0.0.1:8080",
		Routes: []Route{
			{Name: "bad", Match: Match{PathPrefix: "/api"}, Upstream: ""},
		},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for missing upstream, got nil")
	}
}

func TestValidateRejectsMissingPathPrefix(t *testing.T) {
	c := &Config{
		KeystoneIssuer: "http://127.0.0.1:8080",
		Routes: []Route{
			{Name: "bad", Match: Match{PathPrefix: ""}, Upstream: "http://127.0.0.1:8081"},
		},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for missing path_prefix, got nil")
	}
}

func TestValidateRejectsRelativeUpstream(t *testing.T) {
	c := &Config{
		KeystoneIssuer: "http://127.0.0.1:8080",
		Routes: []Route{
			{Name: "bad", Match: Match{PathPrefix: "/api"}, Upstream: "not-a-url"},
		},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for non-absolute upstream, got nil")
	}
}

func TestDiscoveryURLDerivedFromIssuer(t *testing.T) {
	c := &Config{
		KeystoneIssuer: "http://127.0.0.1:8080",
		Routes: []Route{
			{Name: "ok", Match: Match{PathPrefix: "/api"}, Upstream: "http://127.0.0.1:8081"},
		},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate error: %v", err)
	}
	want := "http://127.0.0.1:8080/.well-known/openid-configuration"
	if c.DiscoveryURL != want {
		t.Errorf("DiscoveryURL = %q, want %q", c.DiscoveryURL, want)
	}
}

func TestDiscoveryURLOverrideRespected(t *testing.T) {
	c := &Config{
		KeystoneIssuer: "http://127.0.0.1:8080",
		DiscoveryURL:   "http://example.test/custom-discovery",
		Routes: []Route{
			{Name: "ok", Match: Match{PathPrefix: "/api"}, Upstream: "http://127.0.0.1:8081"},
		},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate error: %v", err)
	}
	if c.DiscoveryURL != "http://example.test/custom-discovery" {
		t.Errorf("DiscoveryURL override not respected: %q", c.DiscoveryURL)
	}
}
