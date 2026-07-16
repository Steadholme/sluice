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
