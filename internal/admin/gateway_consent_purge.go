package admin

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

// consentPurgeDoc points operators at progressive consent residual honesty
// (same pointer as CLI gateway consent-purge).
const consentPurgeDoc = "docs/gateway/README.md § progressive consent residual"

// ConsentClearAllConfirmToken is the exact body.confirm string required for
// destructive clear_all (HOST-007 residual lite; parity with cache EVICT).
// SPA and operators must type this token; purge_expired / delete_session do not.
const ConsentClearAllConfirmToken = "CLEAR_ALL"

// consentPurgeRequest is POST /admin/v1/gateway/consent-purge body.
// Metadata-only identity for purge actions — never tokens. Unknown fields
// (e.g. token) are ignored by the decoder and never treated as credentials.
type consentPurgeRequest struct {
	// Action is purge_expired (default) | delete_session | clear_all.
	Action string `json:"action"`
	// SessionID is required for delete_session (metadata correlation id only).
	SessionID string `json:"session_id"`
	// ClearAll is the explicit flag required for clear_all (mirrors CLI --all).
	// Also accepted when Action is "clear_all". clear_all also requires Confirm.
	ClearAll bool `json:"clear_all"`
	// Confirm must be exactly ConsentClearAllConfirmToken for clear_all
	// (parity with cache confirm:"EVICT"). Ignored for other actions.
	Confirm string `json:"confirm"`
	// Path optionally overrides the basename under the configured consent store
	// directory (JENKINS_MCP_CONSENT_STORE_PATH / XDG default). Absolute only;
	// must stay under that directory (admin BFF path jail — fail closed). Never
	// returned in full in the response (basename residual only).
	Path string `json:"path"`
}

// handleGatewayConsentPurge is POST /admin/v1/gateway/consent-purge
// (HOST-007 Mode C progressive consent metadata purge residual lite).
//
// Mirrors CLI `jenkins-mcp gateway consent-purge` / `consent-expire` semantics:
//   - OpenConsentSessionStoreForPurge(path | env | XDG)
//   - purge_expired (default) | delete_session + session_id | clear_all (explicit)
//   - clear_all requires confirm exactly "CLEAR_ALL" (parity with cache EVICT)
//   - Secret-free summary: deleted_count, remaining_count, residual notes
//   - Never tokens; never echo session_id; never full path values
//
// Body path is jailed under the configured consent store directory so a
// gateway_ops caller cannot use admin BFF to overwrite arbitrary files.
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
	// Destructive clear_all: require exact confirm token (fail closed).
	// purge_expired / delete_session are unchanged (no confirm).
	if action == "clear_all" && req.Confirm != ConsentClearAllConfirmToken {
		writeAppErr(w, apperr.New(apperr.CodeInvalidArgument,
			`consent-purge: clear_all requires confirm exactly "CLEAR_ALL"`))
		return
	}

	pathOverride, err := validateConsentPurgePathOverride(req.Path, os.Getenv)
	if err != nil {
		writeAppErr(w, err)
		return
	}

	store, err := gateway.OpenConsentSessionStoreForPurge(pathOverride, os.Getenv)
	if err != nil {
		writeAppErr(w, err)
		return
	}

	deleted := 0
	switch action {
	case "clear_all":
		// Honest deleted_count includes expired + live entries present before clear.
		deleted = store.EntryCount()
		// Fail closed: 500 with secret-free message when file-backed persist fails.
		if err := store.Clear(); err != nil {
			writeAppErr(w, err)
			return
		}
	case "delete_session":
		ok, err := store.DeleteSession(sessionID)
		if err != nil {
			writeAppErr(w, err)
			return
		}
		if ok {
			deleted = 1
		}
	default: // purge_expired
		n, err := store.PurgeExpired()
		if err != nil {
			writeAppErr(w, err)
			return
		}
		deleted = n
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
		"admin_note":    "mirrors CLI gateway consent-purge; set JENKINS_MCP_CONSENT_STORE_PATH (or body path under that directory) to same file as MCP serve for same-host share (HOST-008 lite); multi-pod residual",
	}
	// Defense: never echo session_id (may be secret-shaped); CLI omits it too.

	writeJSON(w, http.StatusOK, out)
}

// validateConsentPurgePathOverride jails optional admin body path under the
// configured consent store directory (dir of JENKINS_MCP_CONSENT_STORE_PATH or
// XDG default). Fail closed: relative paths, empty basename, and paths outside
// the store directory are rejected. Empty override is allowed (use env/XDG).
//
// Security: OpenConsentSessionStoreForPurge + Clear/write can create/overwrite
// files; without a jail, gateway_ops on non-local admin could point path at
// arbitrary locations. Full path is never returned in error messages.
func validateConsentPurgePathOverride(pathOverride string, getenv func(string) string) (string, error) {
	path := strings.TrimSpace(pathOverride)
	if path == "" {
		return "", nil
	}
	if getenv == nil {
		getenv = os.Getenv
	}
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return "", apperr.New(apperr.CodeInvalidArgument,
			"consent-purge: path must be absolute")
	}
	baseName := filepath.Base(clean)
	if baseName == "" || baseName == "." || baseName == string(filepath.Separator) {
		return "", apperr.New(apperr.CodeInvalidArgument,
			"consent-purge: path must include a file basename")
	}
	// Root of jail: directory of the env/XDG configured consent store file.
	// Operators set JENKINS_MCP_CONSENT_STORE_PATH for same-host share; body path
	// may only select another basename (or the same file) under that directory.
	configured := gateway.ConsentSessionPathFromEnviron(getenv)
	root := filepath.Clean(filepath.Dir(configured))
	if root == "" || root == "." || root == string(filepath.Separator) {
		return "", apperr.New(apperr.CodeInvalidArgument,
			"consent-purge: consent store directory is invalid")
	}
	rel, err := filepath.Rel(root, clean)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", apperr.New(apperr.CodeInvalidArgument,
			"consent-purge: path must be under the configured consent store directory")
	}
	if rel == "." {
		return "", apperr.New(apperr.CodeInvalidArgument,
			"consent-purge: path must be a file under the consent store directory")
	}
	// Reject nested escapes via intermediate ".." segments that Clean already
	// collapsed; Rel check above is authoritative. Also reject multi-segment
	// relative paths that leave the immediate store dir (no subdirs).
	if strings.Contains(rel, string(filepath.Separator)) {
		return "", apperr.New(apperr.CodeInvalidArgument,
			"consent-purge: path must be a direct file under the consent store directory")
	}
	return clean, nil
}

// resolveConsentPurgeAction maps body fields to a purge action.
// clear_all requires explicit clear_all:true or action:"clear_all" (and, in the
// handler, confirm exactly ConsentClearAllConfirmToken).
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
