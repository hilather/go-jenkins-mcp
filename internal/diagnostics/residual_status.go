package diagnostics

import (
	"os"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

// ResidualStatusHonestyNote is the unified operator residual honesty sentence
// (never tokens/subjects). Points operators at the live pin runbook.
// Shared by CLI `gateway residual-status` and admin GET /admin/v1/gateway/residual-status.
const ResidualStatusHonestyNote = "unified gateway residual snapshot (env/static honesty only): offline Mode A/B/C foundations Done*; optional same-host FileSubjectRateLimiter / FileTokenCache / FilePrincipalCache / vault flock lite when paths set; live Entra / jwt-auth-filter / AgentCore / multi-pod shared rate+vault+principal HA residual — never production GO from this surface; see docs/gateway/live-pin-blockers.md"

// ResidualStatusDoc is the primary operator pointer for residual honesty.
const ResidualStatusDoc = "docs/gateway/live-pin-blockers.md"

// PrincipalCacheProcessNote is a secret-free honesty sentence for
// principal_cache_entries. When PRINCIPAL_CACHE_PATH is set, residual-status
// opens the file store for Len() only (same-host lite). When unset, count is
// this process memory map (CLI/admin ≠ remote serve unless that process
// installed the same file store). Never subjects/tokens/path values.
const PrincipalCacheProcessNote = "principal_cache_entries: file Len() when PRINCIPAL_CACHE_PATH set (same-host lite); else this process memory only (CLI/admin ≠ serve unless same file path installed)"

// BuildGatewayResidualStatus assembles the unified secret-free residual snapshot
// used by `jenkins-mcp gateway residual-status` and
// GET /admin/v1/gateway/residual-status (HOST-007).
//
// Env/static only — no Obtain, vault open, or browser. Never tokens, vault
// bytes, Authorization material, or raw subjects. getenv nil → os.Getenv.
//
// Field names match the CLI JSON contract (snake_case for residual honesty
// fields; rate knobs use admin health names rateEnabled/ratePerMinute/rateBurst).
func BuildGatewayResidualStatus(getenv func(string) string) map[string]any {
	if getenv == nil {
		getenv = os.Getenv
	}

	multiUser := gateway.MultiUserEnabled(getenv)
	rateEnabled, ratePerMinute, rateBurst := gateway.SubjectRateConfigFromEnviron(getenv)
	mp := MultiPodResidualFromEnviron(getenv)
	pc := gateway.NewProgressiveConsentResidual()

	modeA, modeB, modeC := false, false, false
	modeResidual := ""
	enabledIDs := []string{}
	primary := ""
	var modeMatrix map[string]any
	if mx, err := gateway.ModeMatrixFromEnviron(getenv); err == nil {
		primary = string(mx.Primary)
		modeResidual = mx.Residual
		for _, m := range mx.Enabled {
			enabledIDs = append(enabledIDs, string(m))
			switch m {
			case gateway.CredentialModeAPITokenVault:
				modeA = true
			case gateway.CredentialModeJWTRSBearer:
				modeB = true
			case gateway.CredentialModeAgentCore:
				modeC = true
			}
		}
		modeMatrix = map[string]any{
			"primary":  primary,
			"enabled":  enabledIDs,
			"residual": modeResidual,
		}
	} else {
		// Soft residual when matrix invalid: still surface primary intent without secrets.
		mode := string(gateway.CredentialModeFromEnviron(getenv))
		if !gateway.CredentialMode(mode).Valid() {
			mode = ""
		}
		primary = mode
		switch gateway.CredentialMode(mode) {
		case gateway.CredentialModeAPITokenVault:
			modeA = true
		case gateway.CredentialModeJWTRSBearer:
			modeB = true
		case gateway.CredentialModeAgentCore:
			modeC = true
		}
		if mode != "" {
			enabledIDs = []string{mode}
		}
		modeResidual = "mode matrix invalid or incomplete — fix JENKINS_MCP_GATEWAY_CREDENTIAL_MODE / ENABLED_MODES; live mode pins residual"
		modeMatrix = map[string]any{
			"primary":  primary,
			"enabled":  enabledIDs,
			"residual": modeResidual,
			"valid":    false,
		}
	}

	// Structured residual ids (REL lite honesty; never claim production GO).
	// Mode B residual id oauth009_offline is always advertised for operator
	// grepping; mode_b_enabled reflects env enablement only.
	residualIDs := []string{
		"multi_user_offline",
		"oauth009_offline",
		"oauth010_offline",
		"progressive_consent_offline",
		"host008_single_replica",
		"gateway_modes_live",
	}

	out := map[string]any{
		"mode_matrix":                     modeMatrix,
		"mode_matrix_residual":            modeResidual,
		"mode_a_enabled":                  modeA,
		"mode_b_enabled":                  modeB,
		"mode_c_enabled":                  modeC,
		"mode_a_live_obtain_qualified":    false,
		"mode_b_live_rs_qualified":        false,
		"mode_c_live_agentcore_qualified": false,
		// Mode B residual id (OAUTH-009) — offline foundation only.
		"residual_id":                  "oauth009_offline",
		"oauth009_offline":             true,
		"oauth009_offline_only":        true,
		"residual_ids":                 residualIDs,
		"multi_user_enabled":           multiUser,
		"gateway_ready":                false, // residual: Ready only on serve /readyz
		"ha_multi_replica":             false, // HOST-008 Tier A single-replica default
		"session_affinity_recommended": multiUser,
		// HOST-008 multi-pod residual (always vault residual true).
		"multi_pod_vault_residual":      mp.MultiPodVaultResidual,
		"kubernetes_env_detected":       mp.KubernetesEnvDetected,
		"vault_path_emptydir_heuristic": mp.VaultEmptyDirHeuristic,
		"replicas_env_residual":         mp.ReplicasEnvResidual,
		// Progressive consent residual (OAUTH-010 / GWY-001).
		"progressive_consent": pc.StatusMap(),
		// HOST-006 subject rate knobs (admin health field names).
		// shared_subject_rate_file=true only when JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH
		// set (HOST-008 same-host lite); multi-pod shared rate still residual.
		"rateEnabled":              rateEnabled,
		"ratePerMinute":            ratePerMinute,
		"rateBurst":                rateBurst,
		"shared_subject_rate_file": gateway.SubjectRatePathConfiguredFromEnviron(getenv),
		// Principal cache: entry count + optional hygiene knobs from env
		// (never subjects/tokens/principal inventory/path value). Multi-pod residual.
		// shared_principal_cache_file=true only when PRINCIPAL_CACHE_PATH set (HOST-008 lite).
		// When path set, Len() is from FilePrincipalCache open (read/flock only).
		"principal_cache_entries":      principalCacheEntriesForResidual(getenv),
		"principal_cache_process_note": PrincipalCacheProcessNote,
		"shared_principal_cache_file":  gateway.PrincipalCachePathConfiguredFromEnviron(getenv),
		"residual_note":                ResidualStatusHonestyNote,
		"doc":                          ResidualStatusDoc,
	}
	// Optional PrincipalCache hygiene residual lite (env/static; empty = unlimited / no TTL).
	if pcMax, pcTTL, err := gateway.PrincipalCacheConfigFromEnviron(getenv); err == nil {
		if pcMax > 0 {
			out["principal_cache_max_entries"] = pcMax
		}
		if pcTTL > 0 {
			out["principal_cache_ttl_seconds"] = int(pcTTL / time.Second)
		}
	}
	// Optional subject-rate map hygiene residual lite (empty = unlimited).
	// Process-local / file-local only — multi-pod shared rate residual.
	if maxSubj, err := gateway.SubjectRateMaxSubjectsFromEnviron(getenv); err == nil && maxSubj > 0 {
		out["subject_rate_max_subjects"] = maxSubj
	}
	if mp.Checklist != "" {
		out["multi_pod_residual_checklist"] = mp.Checklist
	}
	if modeC {
		out["progressive_consent_residual"] = pc.ResidualNote
		out["progressive_consent_surfaces"] = pc.Surfaces
	}
	return out
}

// principalCacheEntriesForResidual returns a secret-free entry count for residual-status.
// When JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH is set, opens FilePrincipalCache for
// Len() only (same-host flock lite; never returns path). On open failure → 0
// (fail soft for residual CLI; path residual still advertised via shared_* bool).
// When path unset, uses ProcessPrincipalCache().Len() (this process memory).
func principalCacheEntriesForResidual(getenv func(string) string) int {
	if getenv == nil {
		getenv = os.Getenv
	}
	path := strings.TrimSpace(getenv(gateway.EnvGatewayPrincipalCachePath))
	if path == "" {
		return gateway.ProcessPrincipalCache().Len()
	}
	// Hygiene env optional for Len(); zero limits = unlimited on open.
	maxEntries, ttl, err := gateway.PrincipalCacheConfigFromEnviron(getenv)
	if err != nil {
		// Invalid hygiene env: still try open with unlimited for residual Len.
		maxEntries, ttl = 0, 0
	}
	fpc, err := gateway.NewFilePrincipalCacheWithLimits(path, maxEntries, ttl)
	if err != nil {
		return 0
	}
	return fpc.Len()
}
