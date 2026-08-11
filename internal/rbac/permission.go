package rbac

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/holdfast/sluice/internal/auth"
)

type permissionCheckRequest struct {
	Subject    string                    `json:"subject"`
	Permission string                    `json:"permission"`
	Resource   permissionResource        `json:"resource"`
	Context    permissionDecisionContext `json:"context"`
	Risk       string                    `json:"risk"`
}

type permissionResource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type permissionDecisionContext struct {
	Zone       string  `json:"zone"`
	MFA        bool    `json:"mfa"`
	IP         *string `json:"ip"`
	RequestID  *string `json:"request_id"`
	BreakGlass bool    `json:"break_glass"`
}

type permissionCheckResponse struct {
	Decision      string               `json:"decision"`
	Reason        string               `json:"reason"`
	Epoch         int64                `json:"epoch"`
	EvaluatedAt   int64                `json:"evaluated_at"`
	DecisionID    string               `json:"decision_id,omitempty"`
	Evidence      []permissionEvidence `json:"evidence"`
	SourceGrantID string               `json:"-"`
}

type permissionEvidence struct {
	EdgeID          string   `json:"edge_id"`
	SourceGrantID   string   `json:"source_grant_id"`
	Effect          string   `json:"effect"`
	Path            []string `json:"path"`
	ConditionResult string   `json:"condition_result"`
}

const (
	maxVerdictResponseBytes = 64 * 1024
	maxVerdictEvidenceItems = 64
	maxVerdictEvidencePath  = 8
	maxVerdictEvidenceField = 512
)

type permissionAuthorityError struct {
	ECode  string
	Reason string
}

func (e *permissionAuthorityError) Error() string {
	return "permission authority unavailable (" + e.ECode + "/" + e.Reason + ")"
}

// PermissionGate enforces one opaque Verdict v2 entitlement. It never treats a
// PDP outage or malformed response as a policy deny: those are 503; an explicit
// 200/Deny is 403. Only Allow reaches next and receives a signed context.
func (a *Authorizer) PermissionGate(permission, resource, risk, zone string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := auth.IdentityFromContext(r.Context())
		if !ok || id.Subject == "" {
			permissionForbidden(w, permission)
			return
		}
		kind, resourceID, ok := strings.Cut(resource, ":")
		if !ok || kind == "" || resourceID == "" {
			permissionUnavailable(w, permission)
			return
		}
		request := permissionCheckRequest{
			Subject:    "user:" + id.Subject,
			Permission: permission,
			Resource: permissionResource{
				Type: kind,
				ID:   resourceID,
			},
			Context: permissionDecisionContext{
				Zone:       zone,
				MFA:        auth.HasStrongMFAAt(r.Context(), id.Subject, a.now().Unix()),
				IP:         nil,
				RequestID:  nil,
				BreakGlass: false,
			},
			Risk: risk,
		}
		decision, err := a.checkPermission(r, request)
		if err != nil {
			a.cfg.Log.Warn("permission authorization indeterminate", "subject", id.Subject, "permission", permission, "error", err)
			permissionUnavailable(w, permission)
			return
		}
		switch decision.Decision {
		case "Deny":
			a.cfg.Log.Info("permission authorization denied", "subject", id.Subject, "permission", permission, "decision_id", permissionDecisionID(request, decision))
			permissionForbidden(w, permission)
			return
		case "Allow":
			contextTime := a.now().Unix()
			context := auth.AuthorizationContext{
				Permission:      permission,
				Object:          resource,
				Decision:        "Allow",
				DecisionID:      permissionDecisionID(request, decision),
				RevocationEpoch: decision.Epoch,
				Timestamp:       contextTime,
				Subject:         request.Subject,
				Risk:            risk,
			}
			next.ServeHTTP(w, r.WithContext(auth.ContextWithAuthorization(r.Context(), context)))
			return
		default:
			permissionUnavailable(w, permission)
			return
		}
	})
}

func (a *Authorizer) checkPermission(r *http.Request, request permissionCheckRequest) (permissionCheckResponse, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return permissionCheckResponse{}, err
	}
	url := strings.TrimRight(a.cfg.VerdictURL, "/") + "/api/v2/check"
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return permissionCheckResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.cfg.Token)
	response, err := a.client.Do(req)
	if err != nil {
		return permissionCheckResponse{}, &permissionAuthorityError{ECode: "E7", Reason: "transport-failure"}
	}
	defer response.Body.Close()
	bodyBytes, err := io.ReadAll(io.LimitReader(response.Body, maxVerdictResponseBytes+1))
	if err != nil {
		return permissionCheckResponse{}, &permissionAuthorityError{ECode: "E7", Reason: "transport-failure"}
	}
	if len(bodyBytes) > maxVerdictResponseBytes {
		return permissionCheckResponse{}, &permissionAuthorityError{ECode: "E7", Reason: "malformed-authority-response"}
	}
	decision, err := decodePermissionCheckResponse(bodyBytes)
	if err != nil {
		return permissionCheckResponse{}, err
	}

	switch response.StatusCode {
	case http.StatusOK:
		switch decision.Decision {
		case "Allow", "Deny":
			return decision, nil
		case "Indeterminate":
			return decision, permissionIndeterminateError(decision.Reason)
		default:
			return permissionCheckResponse{}, &permissionAuthorityError{ECode: "E7", Reason: "malformed-authority-response"}
		}
	case http.StatusServiceUnavailable:
		if decision.Decision != "Indeterminate" {
			return permissionCheckResponse{}, &permissionAuthorityError{ECode: "E7", Reason: "malformed-authority-response"}
		}
		return decision, permissionIndeterminateError(decision.Reason)
	default:
		// Authentication failures and unexpected upstream statuses are dependency
		// failures, never policy Deny. The parsed safe body is retained for a future
		// immutable audit sink, while the raw body is discarded here.
		return decision, &permissionAuthorityError{ECode: "E7", Reason: "unexpected-authority-status"}
	}
}

func decodePermissionCheckResponse(body []byte) (permissionCheckResponse, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var decision permissionCheckResponse
	if err := decoder.Decode(&decision); err != nil {
		return permissionCheckResponse{}, &permissionAuthorityError{ECode: "E7", Reason: "malformed-authority-response"}
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return permissionCheckResponse{}, &permissionAuthorityError{ECode: "E7", Reason: "malformed-authority-response"}
	}
	if decision.Epoch < 0 || decision.EvaluatedAt <= 0 || !validVerdictReason(decision.Reason) ||
		(decision.DecisionID != "" && !boundedSafeVerdictText(decision.DecisionID, 128)) ||
		!validVerdictDecisionReason(decision.Decision, decision.Reason) || !validVerdictEvidence(decision.Evidence) ||
		!validVerdictDecisionEvidence(decision.Decision, decision.Evidence) {
		return permissionCheckResponse{}, &permissionAuthorityError{ECode: "E7", Reason: "malformed-authority-response"}
	}
	if len(decision.Evidence) > 0 {
		decision.SourceGrantID = decision.Evidence[0].SourceGrantID
	}
	return decision, nil
}

func permissionIndeterminateError(reason string) error {
	switch reason {
	case "unknown-condition", "malformed-policy":
		return &permissionAuthorityError{ECode: "E10", Reason: "policy-drift"}
	case "store-unavailable", "epoch-inconsistent":
		return &permissionAuthorityError{ECode: "E7", Reason: "authority-unavailable"}
	default:
		return &permissionAuthorityError{ECode: "E7", Reason: "malformed-authority-response"}
	}
}

func validVerdictReason(reason string) bool {
	if len(reason) == 0 || len(reason) > 64 || !boundedSafeVerdictText(reason, 64) {
		return false
	}
	switch reason {
	case "allow-direct", "allow-userset", "deny-override", "no-grant-path",
		"subject-frozen", "subject-terminated", "mfa-required", "store-unavailable",
		"epoch-inconsistent", "unknown-condition", "malformed-policy":
		return true
	default:
		return false
	}
}

func validVerdictDecisionReason(decision, reason string) bool {
	switch decision {
	case "Allow":
		return reason == "allow-direct" || reason == "allow-userset"
	case "Deny":
		switch reason {
		case "deny-override", "no-grant-path", "subject-frozen", "subject-terminated", "mfa-required":
			return true
		default:
			return false
		}
	case "Indeterminate":
		switch reason {
		case "store-unavailable", "epoch-inconsistent", "unknown-condition", "malformed-policy":
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func validVerdictDecisionEvidence(decision string, evidence []permissionEvidence) bool {
	switch decision {
	case "Allow":
		for _, item := range evidence {
			if item.Effect != "allow" {
				return false
			}
		}
		return true
	case "Deny":
		// deny-override evidence is complete and may include lower-priority Allow edges.
		return true
	case "Indeterminate":
		return len(evidence) == 0
	default:
		return false
	}
}

func validVerdictEvidence(evidence []permissionEvidence) bool {
	if len(evidence) > maxVerdictEvidenceItems {
		return false
	}
	for _, item := range evidence {
		if !boundedSafeVerdictText(item.EdgeID, maxVerdictEvidenceField) ||
			!boundedSafeVerdictText(item.SourceGrantID, maxVerdictEvidenceField) ||
			(item.Effect != "allow" && item.Effect != "deny") ||
			len(item.Path) > maxVerdictEvidencePath ||
			!boundedSafeVerdictText(item.ConditionResult, 64) ||
			(item.ConditionResult != "matched" && item.ConditionResult != "not_present") {
			return false
		}
		for _, part := range item.Path {
			if !boundedSafeVerdictText(part, maxVerdictEvidenceField) {
				return false
			}
		}
	}
	return true
}

func boundedSafeVerdictText(value string, maxBytes int) bool {
	if value == "" || len(value) > maxBytes || !isASCII(value) || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	return true
}

func isASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] > 0x7f {
			return false
		}
	}
	return true
}

func permissionDecisionID(request permissionCheckRequest, decision permissionCheckResponse) string {
	canonical := strings.Join([]string{
		request.Subject,
		request.Permission,
		request.Resource.Type + ":" + request.Resource.ID,
		request.Risk,
		decision.Decision,
		decision.Reason,
		fmt.Sprintf("%d", decision.Epoch),
		fmt.Sprintf("%d", decision.EvaluatedAt),
	}, "\n")
	digest := sha256.Sum256([]byte(canonical))
	return "dec_" + hex.EncodeToString(digest[:16])
}

func permissionForbidden(w http.ResponseWriter, permission string) {
	writeDenial(w, permissionDeniedPage(permission))
}

func permissionUnavailable(w http.ResponseWriter, permission string) {
	writeDenial(w, accessUnverifiedPage("Permission being checked", permission))
}
