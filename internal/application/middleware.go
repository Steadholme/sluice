package application

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"unicode/utf8"
)

const maxApplicationBodyBytes = 9 << 20

type RequestIdentity struct {
	Result
	BodySHA256       string
	RequestID        string
	CorrelationID    string
	MCPSessionDigest string
}

type identityContextKey struct{}

func ContextWithIdentity(ctx context.Context, identity RequestIdentity) context.Context {
	return context.WithValue(ctx, identityContextKey{}, identity)
}

func IdentityFromContext(ctx context.Context) (RequestIdentity, bool) {
	value, ok := ctx.Value(identityContextKey{}).(RequestIdentity)
	return value, ok
}

func Middleware(introspector Introspector, requiredAudience, requiredScope string, next http.Handler) http.Handler {
	return MiddlewareWithSigner(introspector, nil, "application-test", requiredAudience, requiredScope, next)
}

func MiddlewareWithSigner(introspector Introspector, signer *ContextSigner, routeName, requiredAudience, requiredScope string, next http.Handler) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if routeName == "analyze-mcp" {
			origins := r.Header.Values("Origin")
			if len(origins) > 0 && (len(origins) != 1 || origins[0] != "https://analyze.w33d.xyz") {
				writeError(w, http.StatusForbidden, "authorization_denied", false)
				return
			}
		}
		if introspector == nil {
			writeError(w, http.StatusServiceUnavailable, "authentication_unavailable", true)
			return
		}
		token, ok := tokenFromAuthorization(r.Header.Values("Authorization"))
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthenticated", false)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxApplicationBodyBytes+1))
		if err != nil || len(body) > maxApplicationBodyBytes {
			writeError(w, http.StatusBadRequest, "invalid_request", false)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		sessionID, ok := applicationSessionIdentifier(r.Header)
		inboundSession := ok
		if !ok {
			if len(r.Header.Values("Mcp-Session-Id")) != 0 || !validMcpInitialize(r, routeName, body) {
				writeError(w, http.StatusUnauthorized, "unauthenticated", false)
				return
			}
			sessionID, err = randomIdentifier("mcps_")
			if err != nil {
				writeError(w, http.StatusServiceUnavailable, "authentication_unavailable", true)
				return
			}
			r.Header.Set("Mcp-Session-Id", sessionID)
		}
		sessionHash := sha256.Sum256([]byte(sessionID))
		sessionDigest := hex.EncodeToString(sessionHash[:])
		result, err := introspector.Introspect(r.Context(), token, sessionDigest)
		if err != nil {
			switch {
			case errors.Is(err, ErrInvalidToken):
				writeError(w, http.StatusUnauthorized, "unauthenticated", false)
			case errors.Is(err, ErrSessionInvalid) && inboundSession:
				writeError(w, http.StatusNotFound, "invalid_session", false)
			case errors.Is(err, ErrSessionInvalid):
				writeError(w, http.StatusUnauthorized, "unauthenticated", false)
			default:
				writeError(w, http.StatusServiceUnavailable, "authentication_unavailable", true)
			}
			return
		}
		if !result.Active {
			writeError(w, http.StatusUnauthorized, "unauthenticated", false)
			return
		}
		if result.Audience != requiredAudience || !hasScope(result.Scopes, requiredScope) {
			writeError(w, http.StatusForbidden, "insufficient_scope", false)
			return
		}
		requestID, ok := requestIdentifier(r.Header, "X-Request-Id")
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid_request", false)
			return
		}
		correlationID, ok := requestIdentifier(r.Header, "X-Correlation-Id")
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid_request", false)
			return
		}
		if requestID == "" {
			requestID, err = randomIdentifier("req_")
			if err != nil {
				writeError(w, http.StatusServiceUnavailable, "authentication_unavailable", true)
				return
			}
		}
		if correlationID == "" {
			correlationID = requestID
		}
		bodyHash := sha256.Sum256(body)
		if signer == nil {
			writeError(w, http.StatusServiceUnavailable, "authentication_unavailable", true)
			return
		}
		identity := RequestIdentity{Result: result, BodySHA256: hex.EncodeToString(bodyHash[:]), RequestID: requestID, CorrelationID: correlationID, MCPSessionDigest: sessionDigest}
		path := r.URL.EscapedPath()
		if path == "" {
			path = "/"
		}
		signed, err := signer.Mint(ContextV1{
			Issuer: "sluice", Audience: identity.Audience, ApplicationSub: identity.ApplicationSub,
			ClientID: identity.ClientID, CredentialID: identity.CredentialID,
			CredentialVersion: identity.CredentialVersion, GrantID: identity.GrantID,
			PackageID: identity.PackageID, PackageRevisionDigest: identity.PackageRevisionDigest,
			Scopes: identity.Scopes, Method: r.Method, NormalizedPath: path, Route: routeName,
			BodySHA256: identity.BodySHA256, RequestID: identity.RequestID,
			CorrelationID: identity.CorrelationID, MCPSessionDigest: identity.MCPSessionDigest,
			CredentialState: identity.CredentialState, OverlapUntil: identity.OverlapUntil,
			PolicyEpoch: identity.PolicyEpoch, RevocationEpoch: identity.RevocationEpoch,
		})
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "authentication_unavailable", true)
			return
		}
		ctx := ContextWithIdentity(r.Context(), identity)
		ctx = ContextWithSignedRequest(ctx, signed)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
	return NoStore(handler)
}

func tokenFromAuthorization(values []string) (string, bool) {
	if len(values) != 1 {
		return "", false
	}
	parts := strings.Fields(values[0])
	returnValue := ""
	if len(parts) == 2 {
		returnValue = parts[1]
	}
	return returnValue, len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && credentialPattern.MatchString(returnValue)
}

func optionalSingleHeader(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	if len(values) == 0 {
		return "", true
	}
	if len(values) != 1 || !validVisible(values[0], 1, 256) {
		return "", false
	}
	return values[0], true
}

func requestIdentifier(header http.Header, name string) (string, bool) {
	value, ok := optionalSingleHeader(header, name)
	if !ok || (value != "" && !validOpaqueID(value)) {
		return "", false
	}
	return value, true
}

func applicationSessionIdentifier(header http.Header) (string, bool) {
	values := header.Values("Mcp-Session-Id")
	returnValue := ""
	if len(values) == 1 {
		returnValue = values[0]
	}
	return returnValue, len(values) == 1 && validVisible(returnValue, 1, 256)
}

func validMcpInitialize(r *http.Request, routeName string, body []byte) bool {
	if routeName != "analyze-mcp" || r.Method != http.MethodPost || r.URL.EscapedPath() != "/mcp" || r.URL.RawQuery != "" ||
		len(body) > 1<<20 || !utf8.Valid(body) || !uniqueTopLevelJSONFields(body) {
		return false
	}
	contentTypes := r.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/json" {
		return false
	}
	acceptsJSON, acceptsStream := false, false
	for _, header := range r.Header.Values("Accept") {
		for _, value := range strings.Split(header, ",") {
			kind, _, err := mime.ParseMediaType(strings.TrimSpace(value))
			if err != nil {
				return false
			}
			acceptsJSON = acceptsJSON || kind == "application/json"
			acceptsStream = acceptsStream || kind == "text/event-stream"
		}
	}
	versions := r.Header.Values("Mcp-Protocol-Version")
	if !acceptsJSON || !acceptsStream || (len(versions) != 0 && (len(versions) != 1 || versions[0] != "2025-11-25")) {
		return false
	}
	var request struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	if json.Unmarshal(body, &request) != nil || request.JSONRPC != "2.0" || request.Method != "initialize" || !uniqueTopLevelJSONFields(request.Params) {
		return false
	}
	var id any
	if json.Unmarshal(request.ID, &id) != nil {
		return false
	}
	switch id.(type) {
	case string, float64:
	default:
		return false
	}
	var params struct {
		ProtocolVersion string                     `json:"protocolVersion"`
		Capabilities    map[string]json.RawMessage `json:"capabilities"`
		ClientInfo      struct {
			Name    *string `json:"name"`
			Version *string `json:"version"`
		} `json:"clientInfo"`
	}
	return json.Unmarshal(request.Params, &params) == nil && params.ProtocolVersion == "2025-11-25" &&
		params.Capabilities != nil && params.ClientInfo.Name != nil && params.ClientInfo.Version != nil
}

func randomIdentifier(prefix string) (string, error) {
	value := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(value), nil
}

func NoStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("Vary", "Authorization")
		next.ServeHTTP(w, r)
	})
}

func writeError(w http.ResponseWriter, status int, code string, retryable bool) {
	w.Header().Set("Content-Type", "application/json")
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	if retryable {
		w.Header().Set("Retry-After", "5")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code, "retryable": retryable}})
}
