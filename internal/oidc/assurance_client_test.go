package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const testAssuranceServiceToken = "keystone-assurance-test-token-0000000001"

func TestKeystoneAssuranceClientLiveAndAbsent(t *testing.T) {
	const (
		subject = "u_admin"
		binding = "1e0007c3bba79f5c4f0c6f61e4081ed08ed2e1698268a86eaf96ebe903dd4b7f"
		now     = int64(1_754_400_123)
	)
	mode := "live"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+testAssuranceServiceToken {
			t.Fatalf("unexpected assurance request: method=%s auth=%q", r.Method, r.Header.Get("Authorization"))
		}
		var request assuranceLookupRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if request.Subject != subject || request.SessionBinding != binding {
			t.Fatalf("unexpected lookup tuple: %+v", request)
		}
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("Content-Type", "application/json")
		if mode == "live" {
			_, _ = w.Write([]byte(`{"result":"live","subject":"u_admin","session_binding":"` + binding + `","aal":"MFA_STRONG","uv":true,"auth_time":1754400000,"factor_epoch":7,"as_of":1754400123}`))
			return
		}
		_, _ = w.Write([]byte(`{"result":"absent","subject":"u_admin","aal":"AAL_NONE","uv":false,"auth_time":0,"factor_epoch":8,"as_of":1754400123}`))
	}))
	defer server.Close()

	client, err := NewKeystoneAssuranceClient(AssuranceClientConfig{
		Endpoint:     server.URL,
		ServiceToken: testAssuranceServiceToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return time.Unix(now, 0) }

	live, err := client.LookupSessionAssurance(context.Background(), subject, binding)
	if err != nil {
		t.Fatalf("live lookup: %v", err)
	}
	if !live.Live || live.AAL != SessionMFAStrong || live.SessionBinding != binding ||
		live.FactorEpoch != 7 || live.AuthTime != 1_754_400_000 {
		t.Fatalf("unexpected live result: %+v", live)
	}

	mode = "absent"
	absent, err := client.LookupSessionAssurance(context.Background(), subject, binding)
	if err != nil {
		t.Fatalf("absent lookup: %v", err)
	}
	if absent.Live || absent.AAL != SessionAALNone || absent.SessionBinding != "" ||
		absent.AuthTime != 0 || absent.FactorEpoch != 8 {
		t.Fatalf("unexpected absent result: %+v", absent)
	}
}

func TestKeystoneAssuranceClientFailsClosedOnAuthorityDrift(t *testing.T) {
	const binding = "1e0007c3bba79f5c4f0c6f61e4081ed08ed2e1698268a86eaf96ebe903dd4b7f"
	tests := map[string]func(http.ResponseWriter){
		"redirect": func(w http.ResponseWriter) {
			w.Header().Set("Location", "https://elsewhere.invalid/")
			w.WriteHeader(http.StatusTemporaryRedirect)
		},
		"missing no-store": func(w http.ResponseWriter) {
			_, _ = w.Write([]byte(`{"result":"absent","subject":"u_admin","aal":"AAL_NONE","uv":false,"auth_time":0,"factor_epoch":8,"as_of":1754400123}`))
		},
		"unknown field": func(w http.ResponseWriter) {
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write([]byte(`{"result":"absent","subject":"u_admin","aal":"AAL_NONE","uv":false,"auth_time":0,"factor_epoch":8,"as_of":1754400123,"extra":true}`))
		},
		"trailing json": func(w http.ResponseWriter) {
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write([]byte(`{"result":"absent","subject":"u_admin","aal":"AAL_NONE","uv":false,"auth_time":0,"factor_epoch":8,"as_of":1754400123}{}`))
		},
		"subject mismatch": func(w http.ResponseWriter) {
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write([]byte(`{"result":"absent","subject":"u_other","aal":"AAL_NONE","uv":false,"auth_time":0,"factor_epoch":8,"as_of":1754400123}`))
		},
		"stale authority": func(w http.ResponseWriter) {
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write([]byte(`{"result":"absent","subject":"u_admin","aal":"AAL_NONE","uv":false,"auth_time":0,"factor_epoch":8,"as_of":1754399000}`))
		},
		"live downgrade": func(w http.ResponseWriter) {
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write([]byte(`{"result":"live","subject":"u_admin","session_binding":"` + binding + `","aal":"AAL_NONE","uv":false,"auth_time":0,"factor_epoch":7,"as_of":1754400123}`))
		},
	}
	for name, respond := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				respond(w)
			}))
			defer server.Close()
			client, err := NewKeystoneAssuranceClient(AssuranceClientConfig{
				Endpoint:     server.URL,
				ServiceToken: testAssuranceServiceToken,
			})
			if err != nil {
				t.Fatal(err)
			}
			client.now = func() time.Time { return time.Unix(1_754_400_123, 0) }
			_, err = client.LookupSessionAssurance(context.Background(), "u_admin", binding)
			if !errors.Is(err, ErrAssuranceUnavailable) {
				t.Fatalf("expected unavailable, got %v", err)
			}
		})
	}
}

func TestKeystoneAssuranceClientRejectsInvalidConfigurationAndTuple(t *testing.T) {
	if _, err := NewKeystoneAssuranceClient(AssuranceClientConfig{
		Endpoint:     "ftp://keystone/lookup",
		ServiceToken: testAssuranceServiceToken,
	}); err == nil {
		t.Fatal("expected non-http endpoint rejection")
	}
	if _, err := NewKeystoneAssuranceClient(AssuranceClientConfig{
		Endpoint:     "https://keystone/lookup",
		ServiceToken: "short",
	}); err == nil {
		t.Fatal("expected short service token rejection")
	}
	client, err := NewKeystoneAssuranceClient(AssuranceClientConfig{
		Endpoint:     "https://keystone/lookup",
		ServiceToken: testAssuranceServiceToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.LookupSessionAssurance(context.Background(), "bad subject", "not-a-binding")
	if !errors.Is(err, ErrAssuranceUnavailable) {
		t.Fatalf("invalid tuple must fail before transport: %v", err)
	}
}
