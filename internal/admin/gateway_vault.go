package admin

import (
	"context"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/auth"
	"github.com/simonfxr/go-jenkins-mcp/internal/diagnostics"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

// gatewayVaultResponse is GET /admin/v1/gateway/vault (HOST-011 / HOST-009 residual).
//
// Secret-free forever: never includes API tokens, raw vault file bytes, or
// Authorization material. Subject inventory is SubjectKeyHash only.
type gatewayVaultResponse struct {
	// Mode is the HOST-011 primary credential mode.
	Mode string `json:"mode"`
	// EnabledModes is the allow-list (primary-only when ENABLED_MODES unset).
	EnabledModes []string `json:"enabledModes"`
	// MultiUserEnabled is true when JENKINS_MCP_GATEWAY_MULTI_USER is truthy
	// (foundation residual; not a production GO pin). Secret-free bool only.
	MultiUserEnabled bool `json:"multiUserEnabled"`
	// HAMultiReplica is always false (HOST-008 Tier A single-replica default).
	HAMultiReplica bool `json:"haMultiReplica"`
	// SessionAffinityRecommended is true when multi-user env is set (HOST-008
	// sticky Service scaffold honesty). Not multi-replica Done.
	SessionAffinityRecommended bool `json:"sessionAffinityRecommended"`
	// MultiPodVaultResidual is always true (HOST-008 multi-pod durable vault residual).
	MultiPodVaultResidual bool `json:"multiPodVaultResidual"`
	// KubernetesEnvDetected is true when KUBERNETES_SERVICE_HOST is set.
	KubernetesEnvDetected bool `json:"kubernetesEnvDetected"`
	// RateEnabled is secret-free HOST-006 residual (env parse only; process-local).
	// Empty rate env → true (default); explicit 0 → false. Not multi-replica shared rate.
	RateEnabled bool `json:"rateEnabled"`
	// RatePerMinute is resolved bootstrap tools/min (default or env); 0 when disabled.
	RatePerMinute int `json:"ratePerMinute"`
	// RateBurst is resolved bootstrap burst; 0 when rate disabled. Never tokens.
	RateBurst int `json:"rateBurst"`
	// SharedSubjectRateFile is true when JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH is
	// non-empty (HOST-008 same-host FileSubjectRateLimiter lite). Not multi-pod HA.
	// Path value is never returned (bool only; secret-free).
	SharedSubjectRateFile bool `json:"sharedSubjectRateFile"`
	// SharedPrincipalCacheFile is true when JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH
	// is non-empty (HOST-008 same-host FilePrincipalCache lite). Not multi-pod HA.
	// Path value is never returned (bool only; secret-free; never tokens).
	SharedPrincipalCacheFile bool `json:"sharedPrincipalCacheFile"`
	// SharedJwksFile is true when JENKINS_MCP_HTTP_JWKS_CACHE_PATH is non-empty
	// (HOST-001 / HOST-008 same-host public JWKS snapshot lite). Not multi-pod
	// external JWKS HA. Path value is never returned (bool only; public keys only).
	SharedJwksFile bool `json:"sharedJwksFile"`
	// VaultConfigured is true when the Mode A vault file exists on disk.
	VaultConfigured bool `json:"vaultConfigured"`
	// EntryCount is the number of subject entries (0 when missing/unreadable).
	EntryCount int `json:"entryCount"`
	// Subjects are SubjectKeyHash values only (never raw subject keys or tokens).
	Subjects []string `json:"subjects"`
	// Residual is set for Mode B/C notes or vault CLI-only write residual.
	Residual string `json:"residual,omitempty"`
}

// handleGatewayVault returns secret-free Mode A vault inventory + HOST-011 mode
// matrix. Requires read (viewer/operator/policy_admin). No write from SPA.
func (s *server) handleGatewayVault(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	// All roles with read may view status; write remains CLI-only.
	if !CheckPermission(w, r, PermRead) {
		return
	}
	writeJSON(w, http.StatusOK, s.gatewayVaultStatus(r.Context()))
}

func (s *server) gatewayVaultStatus(ctx context.Context) gatewayVaultResponse {
	_ = s
	if ctx == nil {
		ctx = context.Background()
	}
	multiUser := gateway.MultiUserEnabled(os.Getenv)
	rateEnabled, ratePerMinute, rateBurst := gateway.SubjectRateConfigFromEnviron(os.Getenv)
	sharedSubjectRateFile := gateway.SubjectRatePathConfiguredFromEnviron(os.Getenv)
	sharedPrincipalCacheFile := gateway.PrincipalCachePathConfiguredFromEnviron(os.Getenv)
	sharedJwksFile := auth.JWKSCachePathConfiguredFromEnviron(os.Getenv)
	mp := diagnostics.MultiPodResidualFromEnviron(os.Getenv)
	resp := gatewayVaultResponse{
		Subjects:                   []string{},
		EnabledModes:               []string{},
		MultiUserEnabled:           multiUser,
		HAMultiReplica:             false, // HOST-008 Tier A; no multi-replica runtime
		SessionAffinityRecommended: multiUser,
		MultiPodVaultResidual:      true, // HOST-008 multi-pod vault residual honesty
		KubernetesEnvDetected:      mp.KubernetesEnvDetected,
		RateEnabled:                rateEnabled,
		RatePerMinute:              ratePerMinute,
		RateBurst:                  rateBurst,
		SharedSubjectRateFile:      sharedSubjectRateFile,
		SharedPrincipalCacheFile:   sharedPrincipalCacheFile,
		SharedJwksFile:             sharedJwksFile,
		// HOST-006 rate: process-local default; optional same-host file when path set.
		// HOST-007 parity: shared*File bools only — never path values (HOST-008 lite).
		// Multi-pod shared rate residual (HOST-008). Never tokens.
		Residual: "vault write is CLI-only: jenkins-mcp gateway vault put|delete (never put tokens in the browser); subject rate default process-local (HOST-006); optional same-host FileSubjectRateLimiter when path set (HOST-008 lite); multi-pod shared rate residual; multiPodVaultResidual=true",
	}
	if resp.SharedSubjectRateFile {
		resp.Residual = "sharedSubjectRateFile=true (same-host file rate lite only — not multi-pod HA); " + resp.Residual
	}
	if resp.SharedPrincipalCacheFile {
		resp.Residual = "sharedPrincipalCacheFile=true (same-host FilePrincipalCache lite only — not multi-pod HA); " + resp.Residual
	}
	if resp.SharedJwksFile {
		resp.Residual = "sharedJwksFile=true (same-host public JWKS file lite only — not multi-pod external JWKS HA); " + resp.Residual
	}
	if multiUser {
		// Secret-free; SPA residual banner (no embed rebuild). host008_single_replica honesty.
		resp.Residual = "JENKINS_MCP_GATEWAY_MULTI_USER is set (foundation residual; not production multi-user GO; haMultiReplica=false HOST-008; sessionAffinityRecommended=true scaffold only); " + resp.Residual
	}
	if mp.KubernetesEnvDetected {
		resp.Residual = "kubernetes env detected (KUBERNETES_SERVICE_HOST): multi-pod residual (sticky, shared vault, rate, Obtain cache — HOST-008; haMultiReplica=false); " + resp.Residual
	}

	mx, err := gateway.ModeMatrixFromEnviron(os.Getenv)
	if err != nil {
		// Fail closed on invalid mode config: still return a safe status body
		// so the SPA can show residual rather than 500 (operator can fix env).
		resp.Mode = string(gateway.CredentialModeFromEnviron(os.Getenv))
		if !gateway.CredentialMode(resp.Mode).Valid() {
			resp.Mode = ""
		}
		resp.Residual = "gateway credential mode config invalid: " + err.Error() +
			"; vault write is CLI-only (jenkins-mcp gateway vault put)"
		return resp
	}
	resp.Mode = mx.Primary.String()
	for _, m := range mx.Enabled {
		resp.EnabledModes = append(resp.EnabledModes, m.String())
	}
	if mx.Residual != "" {
		resp.Residual = mx.Residual + "; " + resp.Residual
	}

	path := gateway.VaultPathFromEnviron(os.Getenv)
	vault, err := gateway.NewFileAPITokenVault(path)
	if err != nil {
		resp.Residual = strings.TrimSpace(resp.Residual + "; vault path not usable")
		return resp
	}
	resp.VaultConfigured = vault.FileExists()
	keys, err := vault.ListSubjectKeys(ctx)
	if err != nil {
		// Corrupt vault: report not configured inventory; do not leak file body.
		resp.VaultConfigured = vault.FileExists()
		resp.Residual = strings.TrimSpace(resp.Residual + "; vault unreadable (corrupt or permission); use CLI to inspect")
		return resp
	}
	resp.EntryCount = len(keys)
	hashes := make([]string, 0, len(keys))
	for _, k := range keys {
		hashes = append(hashes, gateway.SubjectKeyHash(k))
	}
	sort.Strings(hashes)
	resp.Subjects = hashes
	return resp
}
