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
	"net/http"
	"strings"
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
		if introspector == nil {
			writeError(w, http.StatusServiceUnavailable, "authentication_unavailable", true)
			return
		}
		token, ok := tokenFromAuthorization(r.Header.Values("Authorization"))
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthenticated", false)
			return
		}
		sessionID, ok := applicationSessionIdentifier(r.Header)
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthenticated", false)
			return
		}
		sessionHash := sha256.Sum256([]byte(sessionID))
		sessionDigest := hex.EncodeToString(sessionHash[:])
		body, err := io.ReadAll(io.LimitReader(r.Body, maxApplicationBodyBytes+1))
		if err != nil || len(body) > maxApplicationBodyBytes {
			writeError(w, http.StatusBadRequest, "invalid_request", false)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		result, err := introspector.Introspect(r.Context(), token, sessionDigest)
		if err != nil {
			switch {
			case errors.Is(err, ErrInvalidToken):
				writeError(w, http.StatusUnauthorized, "unauthenticated", false)
			case errors.Is(err, ErrSessionInvalid):
				writeError(w, http.StatusNotFound, "invalid_session", false)
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
