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
