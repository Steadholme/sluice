package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

const (
	HeaderAuthContextV2KID             = "X-Auth-Ctx2-Kid"
	HeaderAuthContextV2Issuer          = "X-Auth-Ctx2-Issuer"
	HeaderAuthContextV2Subject         = "X-Auth-Ctx2-Subject"
	HeaderAuthContextV2Route           = "X-Auth-Ctx2-Route"
	HeaderAuthContextV2Audience        = "X-Auth-Ctx2-Audience"
	HeaderAuthContextV2Zone            = "X-Auth-Ctx2-Zone"
	HeaderAuthContextV2Permission      = "X-Auth-Ctx2-Permission"
	HeaderAuthContextV2ResourceVersion = "X-Auth-Ctx2-Resource-Ver"
	HeaderAuthContextV2ResourceType    = "X-Auth-Ctx2-Resource-Type"
	HeaderAuthContextV2ResourceID      = "X-Auth-Ctx2-Resource-Id"
	HeaderAuthContextV2Risk            = "X-Auth-Ctx2-Risk"
	HeaderAuthContextV2Decision        = "X-Auth-Ctx2-Decision"
	HeaderAuthContextV2DecisionID      = "X-Auth-Ctx2-Decision-Id"
	HeaderAuthContextV2PolicyEpoch     = "X-Auth-Ctx2-Policy-Epoch"
	HeaderAuthContextV2IssuedAt        = "X-Auth-Ctx2-Issued-At"
	HeaderAuthContextV2Expiry          = "X-Auth-Ctx2-Expiry"
	HeaderAuthContextV2Signature       = "X-Auth-Ctx2-Sig"

	AuthorizationContextV2Issuer = "sluice"
	AuthorizationContextV2TTL    = int64(90)
	authorizationContextV2Domain = "holdfast.authz-context.v2"
)

var (
	ErrAuthorizationContextV2Invalid = errors.New("authorization context v2 is invalid")
	// ErrAuthorizationContextV2Unavailable corresponds to E9: the presented KID
	// cannot be resolved against a complete verifier configuration.
	ErrAuthorizationContextV2Unavailable = errors.New("authorization context v2 verifier is unavailable")

	authorizationContextV2KIDPattern          = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	authorizationContextV2RoutePattern        = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	authorizationContextV2AudiencePattern     = regexp.MustCompile(`^[a-z0-9.-]{1,253}$`)
	authorizationContextV2ZonePattern         = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	authorizationContextV2PermissionPattern   = regexp.MustCompile(`^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*){2}(\.[a-z0-9_-]+)?$`)
	authorizationContextV2ResourceTypePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	authorizationContextV2DecisionIDPattern   = regexp.MustCompile(`^dec_[0-9a-f]{32}$`)
)

// AuthorizationContextV2Key is one immutable KID-to-key binding. Keys are raw
// visible ASCII, not base64; KIDs are public selectors and never key material.
type AuthorizationContextV2Key struct {
	KID string
	Key string
}

// AuthorizationContextV2Keyring models the atomic current/previous rotation
// snapshot. Minting always uses Current; verification accepts either binding.
type AuthorizationContextV2Keyring struct {
	Current  AuthorizationContextV2Key
	Previous AuthorizationContextV2Key
}

func (k AuthorizationContextV2Keyring) Enabled() bool {
	return k.Current.KID != "" && k.Current.Key != ""
}

// ValidateAuthorizationContextV2Keyring rejects torn rotation state. It is used
// both at configuration load and defensively at the signing boundary.
func ValidateAuthorizationContextV2Keyring(keyring AuthorizationContextV2Keyring) error {
	if (keyring.Current.KID == "") != (keyring.Current.Key == "") {
		return fmt.Errorf("current KID and key must be configured together")
	}
	if !keyring.Enabled() {
		if keyring.Previous.KID != "" || keyring.Previous.Key != "" {
			return fmt.Errorf("previous KID and key require a current binding")
		}
		return nil
	}
	if err := validateAuthorizationContextV2Key("current", keyring.Current); err != nil {
		return err
	}
	if (keyring.Previous.KID == "") != (keyring.Previous.Key == "") {
		return fmt.Errorf("previous KID and key must be configured together")
	}
	if keyring.Previous.KID == "" {
		return nil
	}
	if err := validateAuthorizationContextV2Key("previous", keyring.Previous); err != nil {
		return err
	}
	if keyring.Current.KID == keyring.Previous.KID {
		return fmt.Errorf("current and previous KID must be distinct")
	}
	if keyring.Current.Key == keyring.Previous.Key {
		return fmt.Errorf("current and previous key material must be distinct")
	}
	return nil
}

func validateAuthorizationContextV2Key(label string, key AuthorizationContextV2Key) error {
	if !authorizationContextV2KIDPattern.MatchString(key.KID) {
		return fmt.Errorf("%s KID is invalid", label)
	}
	if len(key.Key) < 32 || len(key.Key) > 512 {
		return fmt.Errorf("%s key must contain between 32 and 512 bytes", label)
	}
	for i := 0; i < len(key.Key); i++ {
		if key.Key[i] < 0x21 || key.Key[i] > 0x7e {
			return fmt.Errorf("%s key must contain only visible ASCII bytes", label)
		}
	}
	return nil
}

// AuthorizationContextV2 is the complete signed wire value. ResourceVersion
// and Decision are explicit so a verifier can reject any non-canonical value.
type AuthorizationContextV2 struct {
	KID             string
	Issuer          string
	Subject         string
	Route           string
	Audience        string
	Zone            string
	Permission      string
	ResourceVersion string
	ResourceType    string
	ResourceID      string
	Risk            string
	Decision        string
	DecisionID      string
	PolicyEpoch     int64
	IssuedAt        int64
	Expiry          int64
}

// SignedAuthorizationContextV2 is returned by MintAuthorizationContextV2 so
// callers cannot accidentally put a different KID in the headers than the one
// covered by the signature.
type SignedAuthorizationContextV2 struct {
	Context   AuthorizationContextV2
	Signature string
}

// MintAuthorizationContextV2 fills the current KID and returns a byte-exact
// HMAC-SHA256 signature over the frozen 17-line preimage.
func MintAuthorizationContextV2(keyring AuthorizationContextV2Keyring, value AuthorizationContextV2) (SignedAuthorizationContextV2, error) {
	if err := ValidateAuthorizationContextV2Keyring(keyring); err != nil || !keyring.Enabled() {
		return SignedAuthorizationContextV2{}, ErrAuthorizationContextV2Unavailable
	}
	value.KID = keyring.Current.KID
	canonical, err := value.canonical()
	if err != nil {
		return SignedAuthorizationContextV2{}, err
	}
	return SignedAuthorizationContextV2{
		Context:   value,
		Signature: authorizationContextV2MAC(keyring.Current.Key, canonical),
	}, nil
}

// VerifyAuthorizationContextV2 accepts the current or previous binding. An
// unknown KID is configuration-unavailable (E9), while malformed content or a
// bad HMAC is invalid (E5).
func VerifyAuthorizationContextV2(keyring AuthorizationContextV2Keyring, value AuthorizationContextV2, signature string) error {
	if err := ValidateAuthorizationContextV2Keyring(keyring); err != nil || !keyring.Enabled() {
		return ErrAuthorizationContextV2Unavailable
	}
	canonical, err := value.canonical()
	if err != nil {
		return err
	}
	presented, err := hex.DecodeString(signature)
	if err != nil || len(presented) != sha256.Size {
		return ErrAuthorizationContextV2Invalid
	}

	currentMAC := authorizationContextV2MACBytes(keyring.Current.Key, canonical)
	currentKID := hmac.Equal([]byte(value.KID), []byte(keyring.Current.KID))
	currentValid := currentKID && hmac.Equal(presented, currentMAC)

	previousKID := false
	previousValid := false
	if keyring.Previous.KID != "" {
		// Compute both candidates during an overlap window before selecting by KID.
		previousMAC := authorizationContextV2MACBytes(keyring.Previous.Key, canonical)
		previousKID = hmac.Equal([]byte(value.KID), []byte(keyring.Previous.KID))
		previousValid = previousKID && hmac.Equal(presented, previousMAC)
	}
	if !currentKID && !previousKID {
		return ErrAuthorizationContextV2Unavailable
	}
	if !currentValid && !previousValid {
		return ErrAuthorizationContextV2Invalid
	}
	return nil
}

// Headers returns all 17 single-value wire headers. The proxy calls Header.Set
// after stripping the complete X-Auth-* family, so client duplicates cannot
// survive into the trusted hop.
func (signed SignedAuthorizationContextV2) Headers() map[string]string {
	value := signed.Context
	return map[string]string{
		HeaderAuthContextV2KID:             value.KID,
		HeaderAuthContextV2Issuer:          value.Issuer,
		HeaderAuthContextV2Subject:         value.Subject,
		HeaderAuthContextV2Route:           value.Route,
		HeaderAuthContextV2Audience:        value.Audience,
		HeaderAuthContextV2Zone:            value.Zone,
		HeaderAuthContextV2Permission:      value.Permission,
		HeaderAuthContextV2ResourceVersion: value.ResourceVersion,
		HeaderAuthContextV2ResourceType:    value.ResourceType,
		HeaderAuthContextV2ResourceID:      value.ResourceID,
		HeaderAuthContextV2Risk:            value.Risk,
		HeaderAuthContextV2Decision:        value.Decision,
		HeaderAuthContextV2DecisionID:      value.DecisionID,
		HeaderAuthContextV2PolicyEpoch:     strconv.FormatInt(value.PolicyEpoch, 10),
		HeaderAuthContextV2IssuedAt:        strconv.FormatInt(value.IssuedAt, 10),
		HeaderAuthContextV2Expiry:          strconv.FormatInt(value.Expiry, 10),
		HeaderAuthContextV2Signature:       signed.Signature,
	}
}

func (value AuthorizationContextV2) canonical() (string, error) {
	if err := value.validate(); err != nil {
		return "", err
	}
	return strings.Join([]string{
		authorizationContextV2Domain,
		value.KID,
		value.Issuer,
		value.Subject,
		value.Route,
		value.Audience,
		value.Zone,
		value.Permission,
		value.ResourceVersion,
		value.ResourceType,
		value.ResourceID,
		value.Risk,
		value.Decision,
		value.DecisionID,
		strconv.FormatInt(value.PolicyEpoch, 10),
		strconv.FormatInt(value.IssuedAt, 10),
		strconv.FormatInt(value.Expiry, 10),
	}, "\n"), nil
}

func (value AuthorizationContextV2) validate() error {
	fields := []string{
		value.KID, value.Issuer, value.Subject, value.Route, value.Audience, value.Zone,
		value.Permission, value.ResourceVersion, value.ResourceType, value.ResourceID,
		value.Risk, value.Decision, value.DecisionID,
	}
	for _, field := range fields {
		if len(field) == 0 || len(field) > 512 || !fieldIsASCII(field) || strings.ContainsAny(field, "\r\n\x00") {
			return ErrAuthorizationContextV2Invalid
		}
	}
	if !authorizationContextV2KIDPattern.MatchString(value.KID) ||
		value.Issuer != AuthorizationContextV2Issuer ||
		len(value.Subject) > 256 || !strings.HasPrefix(value.Subject, "user:") || len(value.Subject) == len("user:") ||
		!fieldIsVisibleASCIIWithoutSpace(value.Subject) ||
		!authorizationContextV2RoutePattern.MatchString(value.Route) ||
		!authorizationContextV2AudiencePattern.MatchString(value.Audience) ||
		!authorizationContextV2ZonePattern.MatchString(value.Zone) ||
		!authorizationContextV2PermissionPattern.MatchString(value.Permission) ||
		value.ResourceVersion != "1" ||
		!authorizationContextV2ResourceTypePattern.MatchString(value.ResourceType) || value.ResourceType == "any" ||
		!validAuthorizationContextV2ResourceID(value.ResourceID) ||
		!validAuthorizationContextV2Risk(value.Risk) ||
		value.Decision != "Allow" ||
		!authorizationContextV2DecisionIDPattern.MatchString(value.DecisionID) ||
		value.PolicyEpoch < 0 || value.IssuedAt <= 0 || value.IssuedAt > math.MaxInt64-AuthorizationContextV2TTL ||
		value.Expiry != value.IssuedAt+AuthorizationContextV2TTL {
		return ErrAuthorizationContextV2Invalid
	}
	return nil
}

func validAuthorizationContextV2ResourceID(value string) bool {
	if value == "" || len(value) > 256 || strings.Contains(value, "://") {
		return false
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		if (b < 'a' || b > 'z') && (b < 'A' || b > 'Z') && (b < '0' || b > '9') &&
			b != '-' && b != '_' && b != '.' && b != ':' && b != '@' {
			return false
		}
	}
	return true
}

func validAuthorizationContextV2Risk(value string) bool {
	switch value {
	case "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

func fieldIsASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] > 0x7f {
			return false
		}
	}
	return true
}

func fieldIsVisibleASCIIWithoutSpace(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func authorizationContextV2MAC(key, canonical string) string {
	return hex.EncodeToString(authorizationContextV2MACBytes(key, canonical))
}

func authorizationContextV2MACBytes(key, canonical string) []byte {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(canonical))
	return mac.Sum(nil)
}
