package admin

import (
	"net/http"
	"os"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

// subjectInvalidateDoc points operators at force re-auth residual honesty
// (same pointer as CLI gateway subject-invalidate).
const subjectInvalidateDoc = "docs/gateway/README.md § force re-auth residual lite"

// subjectInvalidateRequest is POST /admin/v1/gateway/subject-invalidate body.
// Never includes tokens — only identity key parts. Unknown fields (e.g. token)
// are ignored by the decoder; never accepted as credentials.
type subjectInvalidateRequest struct {
	// SubjectKey is tenant|subject|profile (preferred when set).
	SubjectKey string `json:"subject_key"`
	// Tenant / SubjectID / Profile compose the key when SubjectKey is empty.
	Tenant    string `json:"tenant"`
	SubjectID string `json:"subject_id"`
	Profile   string `json:"profile"`
	// Workload is optional exact CacheKey fallback (usually unused with
	// FileTokenCache subject-namespace purge).
	Workload string `json:"workload"`
}

// handleGatewaySubjectInvalidate is POST /admin/v1/gateway/subject-invalidate
// (HOST-007 force re-auth residual lite).
//
// Mirrors CLI `jenkins-mcp gateway subject-invalidate` semantics:
//   - PrincipalStore: FilePrincipalCache when JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH
//     is set; otherwise ProcessPrincipalCache (this admin process only)
//   - TokenCache: FileTokenCache when JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH is set;
//     otherwise residual note only (serve MemoryTokenCache not reachable)
//
// Requires gateway_ops (operator or policy_admin). Never accepts or returns
// tokens; never logs secrets or cache path values. Multi-pod fan-out residual.
func (s *server) handleGatewaySubjectInvalidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	if !CheckPermission(w, r, PermGatewayOps) {
		return
	}
	_ = s

	var req subjectInvalidateRequest
	if err := decodeOpsBody(r, &req); err != nil {
		writeAppErr(w, err)
		return
	}

	sk, err := resolveSubjectInvalidateKey(req.SubjectKey, req.Tenant, req.SubjectID, req.Profile)
	if err != nil {
		writeAppErr(w, err)
		return
	}

	// Principal cache: process-local ProcessPrincipalCache, or FilePrincipalCache
	// when PRINCIPAL_CACHE_PATH is set (same-host share with serve).
	var principals gateway.PrincipalStore
	principalPath := strings.TrimSpace(os.Getenv(gateway.EnvGatewayPrincipalCachePath))
	principalPathConfigured := principalPath != ""
	if principalPathConfigured {
		fpc, ferr := gateway.NewFilePrincipalCache(principalPath)
		if ferr != nil {
			writeAppErr(w, apperr.Wrap(apperr.CodeInvalidArgument, "gateway subject-invalidate principal cache path", ferr))
			return
		}
		principals = fpc
	} else {
		principals = gateway.ProcessPrincipalCache()
	}

	// Optional same-host FileTokenCache when env path is set.
	var tokens gateway.TokenCache
	tokenPath := strings.TrimSpace(os.Getenv(gateway.EnvGatewayTokenCachePath))
	tokenPathConfigured := tokenPath != ""
	if tokenPathConfigured {
		ftc, ferr := gateway.NewFileTokenCache(tokenPath, 0)
		if ferr != nil {
			writeAppErr(w, apperr.Wrap(apperr.CodeInvalidArgument, "gateway subject-invalidate token cache path", ferr))
			return
		}
		tokens = ftc
	}

	res, ierr := gateway.InvalidateSubjectKeyLocal(sk, req.Workload, principals, tokens)
	if ierr != nil {
		writeAppErr(w, ierr)
		return
	}

	// Secret-free StatusMap parity with CLI + admin path-config honesty.
	// Never print path values; only whether env was set.
	out := res.StatusMap()
	out["doc"] = subjectInvalidateDoc
	out["token_cache_path_configured"] = tokenPathConfigured
	out["principal_cache_path_configured"] = principalPathConfigured
	if !tokenPathConfigured {
		out["token_cache_admin_note"] = "JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH unset — serve MemoryTokenCache not reachable from admin BFF"
	} else {
		out["token_cache_admin_note"] = "FileTokenCache subject-namespace purge attempted (same-host flock lite; multi-pod residual)"
	}
	if principalPathConfigured {
		out["principal_process_note"] = "FilePrincipalCache Delete attempted (same-host flock lite shared with serve when path matches; multi-pod residual)"
	} else {
		out["principal_process_note"] = "PrincipalCache clear is process-local to this admin serve process; set JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH to share with MCP serve (HOST-008 lite)"
	}

	writeJSON(w, http.StatusOK, out)
}

// resolveSubjectInvalidateKey accepts an explicit tenant|subject|profile key or
// composes from parts. Fail closed on empty/malformed keys (exactly three fields).
func resolveSubjectInvalidateKey(subjectKey, tenant, subjectID, profile string) (string, error) {
	explicit := strings.TrimSpace(subjectKey)
	if explicit != "" {
		if err := gateway.ValidateSubjectKey(explicit); err != nil {
			return "", err
		}
		// Force re-auth keys must be tenant|subject|profile (exactly three fields).
		if _, _, _, err := gateway.SplitSubjectKey(explicit); err != nil {
			return "", err
		}
		return explicit, nil
	}
	if strings.TrimSpace(subjectID) == "" {
		return "", apperr.New(apperr.CodeInvalidArgument,
			"gateway subject-invalidate requires subject_key or subject_id (optionally tenant/profile)")
	}
	composed := gateway.SubjectKeyParts(tenant, subjectID, profile)
	if composed == "" {
		return "", apperr.New(apperr.CodeInvalidArgument,
			"gateway subject-invalidate requires subject_key or subject_id (optionally tenant/profile)")
	}
	if err := gateway.ValidateSubjectKey(composed); err != nil {
		return "", err
	}
	if _, _, _, err := gateway.SplitSubjectKey(composed); err != nil {
		return "", err
	}
	return composed, nil
}
