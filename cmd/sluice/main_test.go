package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/holdfast/sluice/internal/config"
)

func TestBuildPATIntrospectorSupportsPostgresHotAddedRoute(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"active":true,"sub":"u_hot","scope":"scope:delete","exp":%d,"token_type":"Bearer"}`, time.Now().Add(time.Hour).Unix())
	}))
	defer server.Close()

	// The startup config intentionally has no PAT route: production routes may be
	// loaded or added later through PostgreSQL hot reload.
	cfg := &config.Config{
		PATIntrospectionURL: server.URL,
		GWClientID:          "gw-sluice",
		GWClientSecret:      "secret",
		Routes: []config.Route{{
			Name: "public", Auth: config.AuthPublic,
		}},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	introspector := buildPATIntrospector(cfg, server.Client(), log)
	if introspector == nil {
		t.Fatal("configured introspector is nil when initial static routes contain no PAT route")
	}
	result, err := introspector.Introspect(context.Background(), "pat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if !result.Active || result.Subject != "u_hot" {
		t.Fatalf("result = %+v", result)
	}
}

func TestBuildPATIntrospectorMissingEndpointLeavesPATFailClosed(t *testing.T) {
	cfg := &config.Config{
		GWClientID:     "gw-sluice",
		GWClientSecret: "secret",
		Routes: []config.Route{{
			Name: "pat", Auth: config.AuthPAT, RequireScope: "scope:delete",
		}},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if got := buildPATIntrospector(cfg, nil, log); got != nil {
		t.Fatal("missing PAT_INTROSPECTION_URL unexpectedly built an introspector")
	}
}

func TestBuildAssuranceLookupDisabled(t *testing.T) {
	cfg := &config.Config{
		KeystoneAssuranceURL:          "http://keystone.test/internal/v1/session-assurance",
		KeystoneAssuranceServiceToken: "test-assurance-service-token-0001",
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	if got := buildAssuranceLookup(cfg, http.DefaultClient, log); got != nil {
		t.Fatal("disabled trusted MFA unexpectedly built an assurance lookup")
	}
}

func TestBuildAssuranceLookupExplicitMTLSWithoutClientFailsClosed(t *testing.T) {
	cfg := &config.Config{
		TrustedMFAEnabled:             true,
		InternalMTLS:                  true,
		KeystoneAssuranceURL:          "https://keystone.test/internal/v1/session-assurance",
		KeystoneAssuranceServiceToken: "test-assurance-service-token-0001",
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	if got := buildAssuranceLookup(cfg, nil, log); got != nil {
		t.Fatal("trusted MFA with explicit mTLS and no client unexpectedly built an assurance lookup")
	}
}

func TestBuildAssuranceLookupExplicitMTLSRejectsHTTPDowngrade(t *testing.T) {
	cfg := &config.Config{
		TrustedMFAEnabled:             true,
		InternalMTLS:                  true,
		KeystoneAssuranceURL:          "http://keystone.test/internal/v1/session-assurance",
		KeystoneAssuranceServiceToken: "test-assurance-service-token-0001",
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if got := buildAssuranceLookup(cfg, http.DefaultClient, log); got != nil {
		t.Fatal("explicit mTLS accepted a plaintext assurance URL")
	}
}

func TestBuildAssuranceLookupValidHTTPConfig(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	cfg := &config.Config{
		TrustedMFAEnabled:             true,
		KeystoneAssuranceURL:          server.URL + "/internal/v1/session-assurance",
		KeystoneAssuranceServiceToken: "test-assurance-service-token-0001",
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	if got := buildAssuranceLookup(cfg, server.Client(), log); got == nil {
		t.Fatal("valid trusted MFA config did not build an assurance lookup")
	}
}

func TestBuildAssuranceLookupRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		token    string
	}{
		{
			name:     "endpoint",
			endpoint: "://invalid",
			token:    "test-assurance-service-token-0001",
		},
		{
			name:     "token",
			endpoint: "http://keystone.test/internal/v1/session-assurance",
			token:    "too-short",
		},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				TrustedMFAEnabled:             true,
				KeystoneAssuranceURL:          tt.endpoint,
				KeystoneAssuranceServiceToken: tt.token,
			}
			if got := buildAssuranceLookup(cfg, http.DefaultClient, log); got != nil {
				t.Fatal("invalid trusted MFA config unexpectedly built an assurance lookup")
			}
		})
	}
}
