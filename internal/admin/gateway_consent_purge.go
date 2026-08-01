package admin

import (
	"net/http"
	"os"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

// consentPurgeDoc points operators at progressive consent residual honesty
// (same pointer as CLI gateway consent-purge).
const consentPurgeDoc = "docs/gateway/README.md § progressive consent residual"

// consentPurgeRequest is POST /admin/v1/gateway/consent-purge body.
// Metadata-only identity for purge actions — never tokens. Unknown fields
// (e.g. token) are ignored by the decoder and never treated as credentials.
type consentPurgeRequest struct {
	// Action is purge_expired (default) | delete_session | clear_all.
	Action string `json:"action"`
	// SessionID is required for delete_session (metadata correlation id only).
	SessionID string `json:"session_id"`
	// ClearAll is the explicit flag required for clear_all (mirrors CLI --all).
	// Also accepted when Action is "clear_all".
	ClearAll bool `json:"clear_all"`
	// Path optionally overrides JENKINS_MCP_CONSENT_STORE_PATH / XDG default.
	// Never returned in full in the response (basename residual only).
	Path string `json:"path"`
}

// handleGatewayConsentPurge is POST /admin/v1/gateway/consent-purge
// (HOST-007 Mode C progressive consent metadata purge residual lite).
//
// Mirrors CLI `jenkins-mcp gateway consent-purge` / `consent-expire` semantics:
//   - OpenConsentSessionStoreForPurge(path | env | XDG)
//   - purge_expired (default) | delete_session + session_id | clear_all (explicit)
//   - Secret-free summary: deleted_count, remaining_count, residual notes
//   - Never tokens; never echo session_id; never full path values
//
// Requires gateway_ops (operator or policy_admin). Same-host file
// reload-before-persist Done* lite; multi-pod residual; browser 3LO not automated.
func (s *server) handleGatewayConsentPurge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	if !CheckPermission(w, r, PermGatewayOps) {
		return
	}
	_ = s

	var req consentPurgeRequest
	if err := decodeOpsBody(r, &req); err != nil {
		writeAppErr(w, err)
		return
	}

	action, sessionID, err := resolveConsentPurgeAction(req)
	if err != nil {
		writeAppErr(w, err)
		return
	}

	store, err := gateway.OpenConsentSessionStoreForPurge(strings.TrimSpace(req.Path), os.Getenv)
	if err != nil {
		writeAppErr(w, err)
		return
	}

	deleted := 0
	switch action {
	case "clear_all":
		// Honest deleted_count includes expired + live entries present before clear.
		deleted = store.EntryCount()
		store.Clear()
	case "delete_session":
		if store.DeleteSession(sessionID) {
			deleted = 1
		}
	default: // purge_expired
		deleted = store.PurgeExpired()
	}

	remaining := len(store.List())
	// Path residual: basename only (never dump full path that may embed home).
	filePath := strings.TrimSpace(store.FilePath)
	fileBasename := consentFileBasename(filePath)
	pathConfigured := strings.TrimSpace(os.Getenv(gateway.EnvConsentSessionStorePath)) != "" ||
		strings.TrimSpace(req.Path) != ""

	out := map[string]any{
		"action":                           action,
		"deleted_count":                    deleted,
		"remaining_count":                  remaining,
		"metadata_only":                    true,
		"stores_tokens":                    false,
		"process_local":                    true,
		"multi_replica_shared":             false,
		"browser_3lo_automated":            false,
		"durable_agentcore_vault_residual": true,
		"file_backed":                      filePath != "",
		"file_basename":                    fileBasename,
		// Path value never returned — only whether env/body path was configured.
		"consent_store_path_configured": pathConfigured || filePath != "",
		// Honesty: file-backed consent store reloads under flock before every
		// mutate/write (OAUTH-010 same-host Done* lite) so admin/CLI purge is not
		// resurrected by a concurrent serve Put of stale memory. Multi-pod /
		// multi-replica shared store still residual (HOST-008). Memory-only
		// serve (no FilePath) is a separate process and is not cleared by admin BFF.
		"residual_note": "consent metadata purge only (OAUTH-010 residual); never tokens; same-host file reload-before-persist Done* lite (admin/CLI purge not resurrected by serve Put); not multi-replica HA; browser 3LO not automated; memory-only serve process not cleared by admin BFF unless shared FilePath",
		"doc":           consentPurgeDoc,
		"admin_note":    "mirrors CLI gateway consent-purge; set JENKINS_MCP_CONSENT_STORE_PATH (or body path) to same file as MCP serve for same-host share (HOST-008 lite); multi-pod residual",
	}
	// Defense: never echo session_id (may be secret-shaped); CLI omits it too.

	writeJSON(w, http.StatusOK, out)
}

// resolveConsentPurgeAction maps body fields to a purge action.
// clear_all requires explicit clear_all:true or action:"clear_all".
// clear_all and session_id are mutually exclusive (CLI --all vs --session-id).
func resolveConsentPurgeAction(req consentPurgeRequest) (action, sessionID string, err error) {
	sid := strings.TrimSpace(req.SessionID)
	rawAction := strings.TrimSpace(strings.ToLower(req.Action))
	wantClear := req.ClearAll || rawAction == "clear_all"
	wantDelete := sid != "" || rawAction == "delete_session"

	if wantClear && wantDelete {
		return "", "", apperr.New(apperr.CodeInvalidArgument,
			"consent-purge: clear_all and session_id are mutually exclusive")
	}
	// clear_all only via clear_all:true or action:"clear_all" (never default).
	if wantClear {
		return "clear_all", "", nil
	}
	if rawAction == "delete_session" || sid != "" {
		if sid == "" {
			return "", "", apperr.New(apperr.CodeInvalidArgument,
				"consent-purge: delete_session requires session_id")
		}
		if rawAction != "" && rawAction != "delete_session" {
			return "", "", apperr.New(apperr.CodeInvalidArgument,
				"consent-purge: unknown or conflicting action "+rawAction)
		}
		return "delete_session", sid, nil
	}
	if rawAction == "" || rawAction == "purge_expired" {
		return "purge_expired", "", nil
	}
	return "", "", apperr.New(apperr.CodeInvalidArgument,
		"consent-purge: action must be purge_expired, delete_session, or clear_all")
}

// consentFileBasename returns the last path segment only (never home-embedding full path).
func consentFileBasename(filePath string) string {
	filePath = strings.TrimSpace(filePath)
	if filePath == "" {
		return ""
	}
	if i := strings.LastIndexAny(filePath, `/\`); i >= 0 && i+1 < len(filePath) {
		return filePath[i+1:]
	}
	return filePath
}
