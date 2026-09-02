package application

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const testApplicationToken = "app_v1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestApplicationIntrospectionRequiresEqualSubjectEpochsAndCredentialState(t *testing.T) {
	const sessionDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodPost || r.URL.Path != "/internal/v1/application-credentials/introspect" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer independent-introspection-token-0123456789" {
			t.Fatalf("Authorization = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Fatalf("Content-Type = %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			t.Fatal(err)
		}
		if len(form) != 2 || len(form["token"]) != 1 || len(form["mcp_session_digest"]) != 1 || form.Get("token") != testApplicationToken || form.Get("mcp_session_digest") != sessionDigest {
			t.Fatalf("form = %#v", form)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"active":true,"sub":"application:abcdefghijklmnop","application_sub":"application:abcdefghijklmnop","scope":"analysis.create analysis.read","exp":2000000000,"token_type":"Bearer","client_id":"client_abcdefghijklmnop","credential_id":"cred_abcdefghijklmnop","fingerprint":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","grant_id":"grant_abcdefghijklmnop","package_id":"pkg_analyze_mcp_client","package_revision_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","audience":"analyze-facade","credential_version":3,"subject_version":7,"credential_state":"active","overlap_until":null,"policy_epoch":11,"revocation_epoch":13}`)
	}))
	defer server.Close()

	client, err := NewAccessIntrospector(IntrospectorConfig{
		Endpoint:     server.URL + "/internal/v1/application-credentials/introspect",
		ServiceToken: "independent-introspection-token-0123456789",
		Client:       server.Client(),
		Now:          func() time.Time { return time.Unix(1_900_000_000, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		result, err := client.Introspect(context.Background(), testApplicationToken, sessionDigest)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Active || result.Subject != result.ApplicationSub || result.SubjectVersion != 7 || result.PolicyEpoch != 11 || result.RevocationEpoch != 13 || result.CredentialState != CredentialActive {
			t.Fatalf("result = %+v", result)
		}
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want two uncached calls", requests)
	}
}

func TestApplicationIntrospectionInactiveIsExactAndFailuresAreUnavailable(t *testing.T) {
	responses := []string{
		`{"active":false}`,
		"{\"active\":false}\n",
		`{"active":false,"sub":"application:abcdefghijklmnop"}`,
		`{"active":true,"sub":"application:abcdefghijklmnop","application_sub":"application:differentdifferent","scope":"analysis.read","exp":2000000000,"token_type":"Bearer","client_id":"client_abcdefghijklmnop","credential_id":"cred_abcdefghijklmnop","fingerprint":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","grant_id":"grant_abcdefghijklmnop","package_id":"pkg_analyze_mcp_client","package_revision_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","audience":"analyze-facade","credential_version":1,"subject_version":1,"credential_state":"active","overlap_until":null,"policy_epoch":1,"revocation_epoch":1}`,
		`{"active":true,"active":true,"sub":"application:abcdefghijklmnop","application_sub":"application:abcdefghijklmnop","scope":"analysis.read","exp":2000000000,"token_type":"Bearer","client_id":"client_abcdefghijklmnop","credential_id":"cred_abcdefghijklmnop","fingerprint":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","grant_id":"grant_abcdefghijklmnop","package_id":"pkg_analyze_mcp_client","package_revision_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","audience":"analyze-facade","credential_version":1,"subject_version":1,"credential_state":"active","overlap_until":null,"policy_epoch":1,"revocation_epoch":1}`,
		`{"active":true,"sub":"application:abcdefghijklmnop","application_sub":"application:abcdefghijklmnop","scope":"analysis.read","exp":2000000000,"token_type":"Bearer","client_id":"client_abcdefghijklmnop","credential_id":"cred_abcdefghijklmnop","fingerprint":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","grant_id":"grant_abcdefghijklmnop","package_id":"pkg_analyze_mcp_client","package_revision_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","audience":"analyze-facade","credential_version":1,"subject_version":1,"credential_state":"active","overlap_until":null,"policy_epoch":1,"revocation_epoch":1,"unknown":true}`,
	}
	for index, response := range responses {
		t.Run(string(rune('a'+index)), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, response)
			}))
			defer server.Close()
			client, err := NewAccessIntrospector(IntrospectorConfig{
				Endpoint: server.URL, ServiceToken: strings.Repeat("s", 32), Client: server.Client(),
				Now: func() time.Time { return time.Unix(1_900_000_000, 0) },
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.Introspect(context.Background(), testApplicationToken, strings.Repeat("a", 64))
			if index == 0 {
				if err != nil || result.Active {
					t.Fatalf("inactive result=%+v err=%v", result, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), ErrUnavailable.Error()) {
				t.Fatalf("err = %v, want unavailable", err)
			}
		})
	}
}

func TestApplicationIntrospectionAcceptsOnlyEligibleOriginalSessionOverlap(t *testing.T) {
	responses := []string{
		`{"active":true,"sub":"application:abcdefghijklmnop","application_sub":"application:abcdefghijklmnop","scope":"analysis.read","exp":2000000000,"token_type":"Bearer","client_id":"client_abcdefghijklmnop","credential_id":"cred_abcdefghijklmnop","fingerprint":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","grant_id":"grant_abcdefghijklmnop","package_id":"pkg_analyze_mcp_client","package_revision_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","audience":"analyze-facade","credential_version":3,"subject_version":7,"credential_state":"overlap","overlap_until":1900000030,"policy_epoch":11,"revocation_epoch":13}`,
		`{"active":true,"sub":"application:abcdefghijklmnop","application_sub":"application:abcdefghijklmnop","scope":"analysis.read","exp":2000000000,"token_type":"Bearer","client_id":"client_abcdefghijklmnop","credential_id":"cred_abcdefghijklmnop","fingerprint":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","grant_id":"grant_abcdefghijklmnop","package_id":"pkg_analyze_mcp_client","package_revision_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","audience":"analyze-facade","credential_version":3,"subject_version":7,"credential_state":"overlap","overlap_until":1900000000,"policy_epoch":11,"revocation_epoch":13}`,
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, responses[requests])
		requests++
	}))
	defer server.Close()
	client, err := NewAccessIntrospector(IntrospectorConfig{
		Endpoint: server.URL, ServiceToken: strings.Repeat("s", 32), Client: server.Client(),
		Now: func() time.Time { return time.Unix(1_900_000_000, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Introspect(context.Background(), testApplicationToken, strings.Repeat("a", 64))
	if err != nil || result.CredentialState != CredentialOverlap || result.OverlapUntil == nil || *result.OverlapUntil != 1_900_000_030 {
		t.Fatalf("eligible overlap result=%+v err=%v", result, err)
	}
	if _, err := client.Introspect(context.Background(), testApplicationToken, strings.Repeat("a", 64)); err == nil || !strings.Contains(err.Error(), ErrUnavailable.Error()) {
		t.Fatalf("expired overlap err=%v", err)
	}
}

func TestApplicationIntrospectionMapsOnlyExactConflictInactiveToInvalidSession(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want error
	}{
		{name: "exact", body: `{"active":false}`, want: ErrSessionInvalid},
		{name: "not-byte-exact", body: "{\"active\":false}\n", want: ErrUnavailable},
		{name: "identifying-data", body: `{"active":false,"sub":"application:abcdefghijklmnop"}`, want: ErrUnavailable},
		{name: "malformed", body: `{"active":false`, want: ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusConflict)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			client, err := NewAccessIntrospector(IntrospectorConfig{
				Endpoint: server.URL, ServiceToken: strings.Repeat("s", 32), Client: server.Client(),
				Now: func() time.Time { return time.Unix(1_900_000_000, 0) },
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Introspect(context.Background(), testApplicationToken, strings.Repeat("a", 64))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err=%v want=%v", err, tc.want)
			}
		})
	}
}
