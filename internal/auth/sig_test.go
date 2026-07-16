package auth

import "testing"

// Cross-language contract vectors — the Rust backends MUST reproduce these exact hex digests
// (keep sluice/internal/auth/sig.go and the backends' verify helper byte-identical).
func TestSignIdentityVectors(t *testing.T) {
	cases := []struct {
		key, subject, groups string
		unix                 int64
		want                 string
	}{
		{
			key: "test-key", subject: "usr_alice", groups: "admins,devs", unix: 90, // window=1
			want: "ddc77236dcfb03dd9f462f7c84e1b25e58f5fc380997695a689e6c3ac4bb3777",
		},
		{
			key: "test-key", subject: "usr_bob", groups: "", unix: 120, // window=2, no groups
			want: "930f82fb1224e69c9c5bc46e545c3b108b1eeb6c9078c7a33fc24f30c595f658",
		},
	}
	for _, c := range cases {
		if got := SignIdentity(c.key, c.subject, c.groups, c.unix); got != c.want {
			t.Errorf("SignIdentity(%q,%q,%q,%d) = %s, want %s", c.key, c.subject, c.groups, c.unix, got, c.want)
		}
	}
}

func TestSignIdentityEmptyKeyIsBlank(t *testing.T) {
	if got := SignIdentity("", "usr_alice", "admins", 90); got != "" {
		t.Errorf("empty key must yield empty signature, got %s", got)
	}
}

func TestSignPATScopeVector(t *testing.T) {
	const want = "405cea451b81706349a89dfcccb4db503e972d7afe8019c4cf54beedebd530aa"
	got := SignPATScope(
		"test-key",
		"usr_alice",
		"profile corvid:temp-mail:manage",
		"corvid:temp-mail:manage",
		90,
	)
	if got != want {
		t.Fatalf("SignPATScope() = %s, want %s", got, want)
	}
}

func TestSignPATScopeBindsEveryAuthorizationField(t *testing.T) {
	const (
		key      = "test-key"
		subject  = "usr_alice"
		granted  = "profile corvid:temp-mail:manage"
		required = "corvid:temp-mail:manage"
	)
	want := SignPATScope(key, subject, granted, required, 90)
	tests := []struct {
		name, subject, granted, required string
	}{
		{name: "subject", subject: "usr_mallory", granted: granted, required: required},
		{name: "granted scope", subject: subject, granted: "profile", required: required},
		{name: "required scope", subject: subject, granted: granted, required: "corvid:temp-mail:delete"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := SignPATScope(key, test.subject, test.granted, test.required, 90); got == want {
				t.Fatal("tampered authorization field produced the original signature")
			}
		})
	}
}

func TestSignPATScopeWindowRotationAndEmptyKey(t *testing.T) {
	a := SignPATScope("k", "s", "g", "r", 90)
	b := SignPATScope("k", "s", "g", "r", 119)
	c := SignPATScope("k", "s", "g", "r", 120)
	if a != b {
		t.Error("same minute must produce the same PAT scope signature")
	}
	if a == c {
		t.Error("a new minute must rotate the PAT scope signature")
	}
	if got := SignPATScope("", "s", "g", "r", 90); got != "" {
		t.Errorf("empty key must yield empty PAT scope signature, got %s", got)
	}
}

func TestSignGatewayZoneVectors(t *testing.T) {
	cases := []struct {
		routeName string
		host      string
		zone      string
		unix      int64
		want      string
	}{
		{routeName: "portal-root", host: "w33d.xyz", zone: "internal", unix: 90, want: "3467eb3d618ce5a1d3a0c703f78f3f89f3fb5d80586b78a258fb07352b53f4e3"},
		{routeName: "status-root", host: "status.w33d.xyz", zone: "external", unix: 120, want: "2dbfd816d00da99ff7608e8a72d8a6ff038aab2a1f92997014272a9edcb4998d"},
	}
	for _, test := range cases {
		if got := SignGatewayZone("test-key", test.routeName, test.host, test.zone, test.unix); got != test.want {
			t.Errorf("SignGatewayZone(%q,%q,%q,%d) = %s, want %s", test.routeName, test.host, test.zone, test.unix, got, test.want)
		}
	}
	if got := SignGatewayZone("", "portal-root", "w33d.xyz", "internal", 90); got != "" {
		t.Errorf("empty key must yield empty zone signature, got %s", got)
	}

	sig := SignGatewayZone("test-key", "portal-root", "w33d.xyz", "internal", 90)
	if replay := SignGatewayZone("test-key", "portal-root", "other.w33d.xyz", "internal", 90); replay == sig {
		t.Fatal("gateway-zone signature must be bound to its target host")
	}
	if replay := SignGatewayZone("test-key", "other-root", "w33d.xyz", "internal", 90); replay == sig {
		t.Fatal("gateway-zone signature must be bound to its target route")
	}
}

// The same identity in the same minute is stable; a new minute rotates the signature.
func TestSignIdentityWindowRotation(t *testing.T) {
	a := SignIdentity("k", "s", "g", 90)  // window 1
	b := SignIdentity("k", "s", "g", 119) // still window 1
	c := SignIdentity("k", "s", "g", 120) // window 2
	if a != b {
		t.Error("same minute must produce the same signature")
	}
	if a == c {
		t.Error("a new minute must rotate the signature")
	}
}
