package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

// HeaderAuthSig carries the HMAC that cryptographically binds the gateway-injected
// identity (X-Auth-Subject + X-Auth-Groups) to a 1-minute time window. A backend that
// shares GATEWAY_HMAC_KEY can prove the identity was minted by Sluice — a rogue peer on
// the internal network can no longer forge X-Auth-* by dialing the backend directly.
const HeaderAuthSig = "X-Auth-Sig"

// HeaderAuthScopeSig carries a domain-separated HMAC that binds the verified
// PAT identity and granted scopes to the scope required by the matched route.
// Backends must verify it independently from HeaderAuthSig before trusting
// X-Auth-Scope for PAT authorization.
const HeaderAuthScopeSig = "X-Auth-Scope-Sig"

// HeaderGatewayZoneSig binds Sluice's injected X-Gateway-Zone, route, and target host to a short
// time window. It uses a dedicated key and is deliberately separate from HeaderAuthSig so existing
// backend identity verifiers remain byte-compatible while Estate can authenticate its viewer
// context without accepting a signature minted for another upstream.
const HeaderGatewayZoneSig = "X-Gateway-Zone-Sig"

const (
	patScopeSignatureDomain    = "holdfast.pat-scope.v1"
	gatewayZoneSignatureDomain = "holdfast.gateway-zone.v1"
)

// SigWindow is the epoch-minute bucket a signature is valid for.
func SigWindow(unix int64) int64 { return unix / 60 }

// SignIdentity returns the lowercase-hex HMAC-SHA256 over the canonical message
//
//	subject "\n" groups "\n" window
//
// where `groups` is the exact comma-joined X-Auth-Groups value ("" when none) and
// `window` is the decimal epoch-minute. The Rust backends recompute this byte-for-byte
// for the current and previous window, so the canonical form MUST stay identical on both
// sides. An empty key yields "" — callers skip the header, preserving today's behavior.
func SignIdentity(key, subject, groups string, unix int64) string {
	if key == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(subject))
	mac.Write([]byte("\n"))
	mac.Write([]byte(groups))
	mac.Write([]byte("\n"))
	mac.Write([]byte(strconv.FormatInt(SigWindow(unix), 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

// SignPATScope returns the lowercase-hex HMAC-SHA256 over
//
//	domain "\n" subject "\n" granted_scope "\n" required_scope "\n" window
//
// granted_scope is the exact X-Auth-Scope value returned by PAT introspection;
// required_scope is the canonical value from the matched route configuration.
// The separate domain prevents a signature minted for another gateway purpose
// from being accepted as PAT authorization. An empty key yields "".
func SignPATScope(key, subject, grantedScope, requiredScope string, unix int64) string {
	if key == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(patScopeSignatureDomain))
	mac.Write([]byte("\n"))
	mac.Write([]byte(subject))
	mac.Write([]byte("\n"))
	mac.Write([]byte(grantedScope))
	mac.Write([]byte("\n"))
	mac.Write([]byte(requiredScope))
	mac.Write([]byte("\n"))
	mac.Write([]byte(strconv.FormatInt(SigWindow(unix), 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

// SignGatewayZone returns the lowercase-hex HMAC-SHA256 over
//
//	domain "\n" route_name "\n" host "\n" zone "\n" window
//
// Route name and host are part of the capability boundary: a signature exposed to another
// upstream, including one sharing the host under a different path, cannot be replayed to Estate.
// Callers must provide the canonical configured route values, not untrusted request headers. An
// empty key yields "".
func SignGatewayZone(key, routeName, host, zone string, unix int64) string {
	if key == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(gatewayZoneSignatureDomain))
	mac.Write([]byte("\n"))
	mac.Write([]byte(routeName))
	mac.Write([]byte("\n"))
	mac.Write([]byte(host))
	mac.Write([]byte("\n"))
	mac.Write([]byte(zone))
	mac.Write([]byte("\n"))
	mac.Write([]byte(strconv.FormatInt(SigWindow(unix), 10)))
	return hex.EncodeToString(mac.Sum(nil))
}
