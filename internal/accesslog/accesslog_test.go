package accesslog

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRedactPathCapabilityNamespaces(t *testing.T) {
	t.Parallel()
	token := strings.Repeat("a", 64)
	tests := []struct {
		name string
		host string
		path string
		want string
	}{
		{name: "blog review", host: "blog.w33d.xyz", path: "/review/" + token, want: "/review/[capability]"},
		{name: "blog port", host: "BLOG.W33D.XYZ:443", path: "/review/" + token, want: "/review/[capability]"},
		{name: "blog malformed suffix", host: "blog.w33d.xyz", path: "/review/" + token + ".", want: "/review/[capability]"},
		{name: "blog trailing dot host", host: "blog.w33d.xyz.", path: "/review/" + token, want: "/review/[capability]"},
		{name: "drive receipt", host: "drive.w33d.xyz", path: "/receipts/" + token, want: "/receipts/[capability]"},
		{name: "drive receipt malformed", host: "drive.w33d.xyz", path: "/receipts/" + token + ";x", want: "/receipts/[capability]"},
		{name: "drive share suffix", host: "drive.w33d.xyz", path: "/s/" + token + "/download", want: "/s/[capability]"},
		{name: "drive folder share", host: "drive.w33d.xyz", path: "/s/folder/" + token, want: "/s/folder/[capability]"},
		{name: "drive upload", host: "drive.w33d.xyz", path: "/u/" + token, want: "/u/[capability]"},
		{name: "same path wrong host", host: "forum.w33d.xyz", path: "/review/" + token, want: "/review/[capability]"},
		{name: "public asset", host: "drive.w33d.xyz", path: "/s/share-room.css", want: "/s/share-room.css"},
		{name: "public script", host: "drive.w33d.xyz", path: "/s/share-room.js", want: "/s/share-room.js"},
		{name: "empty suffix", host: "drive.w33d.xyz", path: "/u/", want: "/u/"},
		{name: "invalid segment", host: "blog.w33d.xyz", path: "/review/" + strings.Repeat("a", 24) + ".html", want: "/review/[capability]"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := RedactPath(test.host, test.path); got != test.want {
				t.Fatalf("RedactPath(%q, %q) = %q, want %q", test.host, test.path, got, test.want)
			}
		})
	}
}

func TestWrapNeverEmitsRawCapability(t *testing.T) {
	token := strings.Repeat("b", 64)
	var output bytes.Buffer
	original := logger
	SetLogger(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { logger = original })

	handler := Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "https://blog.w33d.xyz/review/"+token, nil)
	req.Host = "blog.w33d.xyz"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if strings.Contains(output.String(), token) {
		t.Fatalf("access log contains the raw capability: %s", output.String())
	}
	var event map[string]any
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatalf("decode access log: %v", err)
	}
	if got := event["path"]; got != "/review/[capability]" {
		t.Fatalf("logged path = %#v, want redacted capability path", got)
	}
}
