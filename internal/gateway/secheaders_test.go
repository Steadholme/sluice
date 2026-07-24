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

func TestSecureHeadersForcesRSVPPrivacyForEveryApplicationOutcome(t *testing.T) {
	t.Parallel()
	const bearer = "RAW-RSVP-CAPABILITY-SENTINEL"
	tests := []struct {
		name   string
		host   string
		path   string
		status int
	}{
		{name: "success", host: "cal.w33d.xyz", path: "/rsvp/" + bearer, status: http.StatusOK},
		{name: "redirect trailing dot host", host: "cal.w33d.xyz.", path: "/rsvp/" + bearer, status: http.StatusSeeOther},
		{name: "malformed wrong host", host: "wrong.w33d.xyz", path: "/rsvp/!" + bearer + "!", status: http.StatusNotFound},
		{name: "empty capability tail host with port", host: "CAL.W33D.XYZ:443", path: "/rsvp/", status: http.StatusMethodNotAllowed},
		{name: "nested proxy failure", host: "cal.w33d.xyz", path: "/rsvp/" + bearer + "/reply/accepted", status: http.StatusBadGateway},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "https://"+test.host+test.path, nil)
			request.Host = test.host
			secureHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Referrer-Policy", "unsafe-url")
				w.Header().Set("Cache-Control", "public, max-age=300")
				if test.status == http.StatusOK {
					if _, err := w.Write([]byte("implicit 200")); err != nil {
						t.Errorf("write implicit 200 response: %v", err)
					}
					return
				}
				w.WriteHeader(test.status)
			})).ServeHTTP(recorder, request)

			result := recorder.Result()
			defer result.Body.Close()
			if result.StatusCode != test.status {
				t.Fatalf("status = %d, want %d", result.StatusCode, test.status)
			}
			if got := result.Header.Get("Referrer-Policy"); got != "no-referrer" {
				t.Fatalf("Referrer-Policy = %q, want no-referrer", got)
			}
			if got := result.Header.Get("Cache-Control"); got != "private, no-store" {
				t.Fatalf("Cache-Control = %q, want private, no-store", got)
			}
		})
	}
}

func TestSecureHeadersAppliesRSVPPrivacyBeforeFlush(t *testing.T) {
	t.Parallel()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodGet,
		"https://cal.w33d.xyz/rsvp/flush-first-capability",
		nil,
	)
	secureHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Referrer-Policy", "unsafe-url")
		w.Header().Set("Cache-Control", "public, max-age=300")
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("secure response writer does not implement http.Flusher")
		}
		flusher.Flush()
	})).ServeHTTP(recorder, request)

	result := recorder.Result()
	defer result.Body.Close()
	if result.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want implicit 200", result.StatusCode)
	}
	if !recorder.Flushed {
		t.Fatal("underlying response writer was not flushed")
	}
	if got := result.Header.Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("Referrer-Policy = %q, want no-referrer before flush", got)
	}
	if got := result.Header.Get("Cache-Control"); got != "private, no-store" {
		t.Fatalf("Cache-Control = %q, want private, no-store before flush", got)
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
