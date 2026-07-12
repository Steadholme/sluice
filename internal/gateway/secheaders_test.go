package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecureHeadersUsesEstateReferrerBaseline(t *testing.T) {
	t.Parallel()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://app.example/", nil)
	secureHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(recorder, request)

	if got := recorder.Header().Get("Referrer-Policy"); got != "strict-origin-when-cross-origin" {
		t.Fatalf("Referrer-Policy = %q, want estate baseline", got)
	}
}

func TestSecureHeadersPreservesCapabilityNoReferrer(t *testing.T) {
	t.Parallel()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://blog.w33d.xyz/review/token", nil)
	secureHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(recorder, request)

	if got := recorder.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("Referrer-Policy = %q, want capability policy preserved", got)
	}
}

func TestSecureHeadersForcesNoReferrerForEveryCapabilityOutcome(t *testing.T) {
	t.Parallel()
	paths := []string{
		"/review/",
		"/review/token/extra",
		"/receipts/malformed;x",
		"/s/folder/token",
		"/u/token",
	}
	for _, path := range paths {
		path := path
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "https://wrong.example"+path, nil)
			secureHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				// Model a router/method/proxy-generated response with no product privacy header.
				w.Header().Set("Referrer-Policy", "unsafe-url")
				w.WriteHeader(http.StatusBadGateway)
			})).ServeHTTP(recorder, request)

			if got := recorder.Header().Get("Referrer-Policy"); got != "no-referrer" {
				t.Fatalf("Referrer-Policy = %q, want capability policy", got)
			}
			if got := recorder.Header().Get("Cache-Control"); got != "private, no-store" {
				t.Fatalf("Cache-Control = %q, want capability policy", got)
			}
		})
	}
}

func TestSecureHeadersPreservesShareRoomAssetCache(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/s/share-room.css", "/s/share-room.js"} {
		path := path
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "https://drive.w33d.xyz"+path, nil)
			secureHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Cache-Control", "public, max-age=300")
				w.WriteHeader(http.StatusOK)
			})).ServeHTTP(recorder, request)

			if got := recorder.Header().Get("Cache-Control"); got != "public, max-age=300" {
				t.Fatalf("Cache-Control = %q, want asset cache preserved", got)
			}
			if got := recorder.Header().Get("Referrer-Policy"); got != "no-referrer" {
				t.Fatalf("Referrer-Policy = %q, want namespace privacy", got)
			}
		})
	}
}

func TestSecureHeadersReplacesWeakerUpstreamReferrerPolicy(t *testing.T) {
	t.Parallel()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://app.example/", nil)
	secureHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Referrer-Policy", "unsafe-url")
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(recorder, request)

	if got := recorder.Header().Get("Referrer-Policy"); got != "strict-origin-when-cross-origin" {
		t.Fatalf("Referrer-Policy = %q, want weaker policy replaced", got)
	}
}
