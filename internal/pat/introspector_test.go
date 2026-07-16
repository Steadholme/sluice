package pat

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testPAT = "pat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func newTestIntrospector(t *testing.T, server *httptest.Server) *KeystoneIntrospector {
	t.Helper()
	introspector, err := NewKeystoneIntrospector(Config{
		Endpoint:     server.URL,
		ClientID:     "gw-sluice",
		ClientSecret: "gateway-secret",
		Client:       server.Client(),
	})
	if err != nil {
		t.Fatalf("NewKeystoneIntrospector: %v", err)
	}
	return introspector
}

func TestIntrospectorPostsOnlyTokenWithBasicAuthAndNeverCaches(t *testing.T) {
	var calls atomic.Int32
	// TLS plus server.Client() proves the supplied internal client transport is
	// reused; the default client would reject this test server's certificate.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q", got)
		}
		clientID, secret, ok := r.BasicAuth()
		if !ok || clientID != "gw-sluice" || secret != "gateway-secret" {
			t.Errorf("Basic auth = (%q, %q, %v)", clientID, secret, ok)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		if len(r.PostForm) != 1 || r.PostForm.Get("token") != testPAT {
			t.Errorf("form fields = %#v, want only token", r.PostForm)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"active":true,"sub":"u_test","scope":"profile corvid:temp-mail:delete","exp":%d,"token_type":"Bearer"}`, time.Now().Add(time.Hour).Unix())
	}))
	defer server.Close()

	introspector := newTestIntrospector(t, server)
	for range 2 {
		result, err := introspector.Introspect(context.Background(), testPAT)
		if err != nil {
			t.Fatalf("Introspect: %v", err)
		}
		if !result.Active || result.Subject != "u_test" || result.Scope != "profile corvid:temp-mail:delete" {
			t.Fatalf("result = %+v", result)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("introspection calls = %d, want 2 (no positive cache)", got)
	}
}

func TestIntrospectorInactiveIsAuthenticationDecision(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"active":false}`))
	}))
	defer server.Close()

	result, err := newTestIntrospector(t, server).Introspect(context.Background(), testPAT)
	if err != nil {
		t.Fatalf("Introspect inactive: %v", err)
	}
	if result.Active || result.Subject != "" || result.Scope != "" {
		t.Fatalf("inactive result = %+v", result)
	}
}

func TestIntrospectorFailuresAreUnavailable(t *testing.T) {
	future := time.Now().Add(time.Hour).Unix()
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{name: "non-200", status: http.StatusUnauthorized, body: `{"active":false}`},
		{name: "keystone-5xx", status: http.StatusServiceUnavailable, body: `{"active":false}`},
		{name: "malformed-json", status: http.StatusOK, body: `{"active":`},
		{name: "trailing-json", status: http.StatusOK, body: `{"active":false}{}`},
		{name: "missing-active", status: http.StatusOK, body: `{}`},
		{name: "active-missing-sub", status: http.StatusOK, body: fmt.Sprintf(`{"active":true,"scope":"corvid:temp-mail:delete","exp":%d,"token_type":"Bearer"}`, future)},
		{name: "active-expired", status: http.StatusOK, body: `{"active":true,"sub":"u_test","scope":"corvid:temp-mail:delete","exp":1,"token_type":"Bearer"}`},
		{name: "active-missing-exp", status: http.StatusOK, body: `{"active":true,"sub":"u_test","scope":"corvid:temp-mail:delete","token_type":"Bearer"}`},
		{name: "active-wrong-token-type", status: http.StatusOK, body: fmt.Sprintf(`{"active":true,"sub":"u_test","scope":"corvid:temp-mail:delete","exp":%d,"token_type":"mac"}`, future)},
		{name: "active-padded-token-type", status: http.StatusOK, body: fmt.Sprintf(`{"active":true,"sub":"u_test","scope":"corvid:temp-mail:delete","exp":%d,"token_type":" Bearer "}`, future)},
		{name: "active-control-in-scope", status: http.StatusOK, body: fmt.Sprintf("{\"active\":true,\"sub\":\"u_test\",\"scope\":\"bad\\nvalue\",\"exp\":%d,\"token_type\":\"Bearer\"}", future)},
		{name: "oversized-response", status: http.StatusOK, body: strings.Repeat("x", maxResponseBytes+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			_, err := newTestIntrospector(t, server).Introspect(context.Background(), testPAT)
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("error = %v, want ErrUnavailable", err)
			}
		})
	}
}

func TestIntrospectorNetworkFailureAndRedirectAreUnavailable(t *testing.T) {
	t.Run("network", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		introspector := newTestIntrospector(t, server)
		server.Close()
		_, err := introspector.Introspect(context.Background(), testPAT)
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("error = %v, want ErrUnavailable", err)
		}
	})

	t.Run("redirect-does-not-forward-token", func(t *testing.T) {
		var redirected atomic.Bool
		target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			redirected.Store(true)
		}))
		defer target.Close()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
		}))
		defer server.Close()

		_, err := newTestIntrospector(t, server).Introspect(context.Background(), testPAT)
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("error = %v, want ErrUnavailable", err)
		}
		if redirected.Load() {
			t.Fatal("introspection redirect was followed; raw PAT could leak")
		}
	})
}

func TestInvalidOpaquePATIsRejectedBeforeNetwork(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()
	introspector := newTestIntrospector(t, server)

	invalid := []string{
		"",
		"pat_",
		"PAT_AAAA",
		"pat_with.dot",
		"pat_with=padding",
		"pat_with space",
		"pat_ümlaut",
		"pat_" + strings.Repeat("A", maxTokenBytes),
	}
	for _, token := range invalid {
		if _, err := introspector.Introspect(context.Background(), token); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("token %q: error = %v, want ErrInvalidToken", token, err)
		}
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("invalid tokens reached Keystone %d times", got)
	}
}

func TestNewKeystoneIntrospectorRequiresExplicitSafeWiring(t *testing.T) {
	cases := []Config{
		{},
		{Endpoint: "keystone/internal", ClientID: "gw", ClientSecret: "secret"},
		{Endpoint: "ftp://keystone/introspect", ClientID: "gw", ClientSecret: "secret"},
		{Endpoint: "https://user@keystone/introspect", ClientID: "gw", ClientSecret: "secret"},
		{Endpoint: "https://keystone/introspect#fragment", ClientID: "gw", ClientSecret: "secret"},
		{Endpoint: "https://keystone/introspect", ClientID: "", ClientSecret: "secret"},
		{Endpoint: "https://keystone/introspect", ClientID: "gw", ClientSecret: ""},
	}
	for _, cfg := range cases {
		if _, err := NewKeystoneIntrospector(cfg); err == nil {
			t.Errorf("NewKeystoneIntrospector(%+v) unexpectedly succeeded", cfg)
		}
	}
}
