package diagnostics

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

// Kubernetes injects KUBERNETES_SERVICE_HOST into every pod (secret-free env residual).
const envKubernetesServiceHost = "KUBERNETES_SERVICE_HOST"

// Residual-only replicas env names (not product knobs). When set to an integer > 1,
// doctor surfaces multi-pod honesty (still ha_multi_replica=false).
var multiPodReplicasEnvKeys = []string{
	"JENKINS_MCP_GATEWAY_REPLICAS",
	"REPLICAS",
}

// multiPodResidualChecklist is the secret-free operator summary for HOST-008 Tier B.
// Never embed vault paths, subjects, or tokens.
const multiPodResidualChecklist = "multi-pod residual checklist (HOST-008): sticky sessions or shared session store; durable shared vault (not emptyDir); shared subject rate; shared Obtain/token cache; ha_multi_replica=false until runtime HA — see docs/gateway/deployment.md §9"

// MultiPodResidual is secret-free HOST-008 multi-pod residual posture (env/heuristic only).
// MultiPodVaultResidual is always true: multi-pod durable vault is residual (never Done from
// flock lite, sticky Service scaffold, or k8s env alone).
type MultiPodResidual struct {
	// MultiPodVaultResidual is always true (honesty: multi-pod vault not implemented).
	MultiPodVaultResidual bool
	// KubernetesEnvDetected is true when KUBERNETES_SERVICE_HOST is non-empty.
	KubernetesEnvDetected bool
	// VaultEmptyDirHeuristic is true when Mode A/B vault path looks emptyDir-ish
	// (/tmp, /var/run, /dev/shm, or path segment "emptydir"). Heuristic residual only.
	VaultEmptyDirHeuristic bool
	// ReplicasEnvResidual is true when a residual replicas-like env parses as int > 1.
	ReplicasEnvResidual bool
	// Checklist is a secret-free residual summary when any multi-pod signal is present.
	Checklist string
}

// MultiPodResidualFromEnviron reports HOST-008 multi-pod residual posture from env.
// getenv nil → os.Getenv. Never returns tokens, vault bytes, or full vault paths.
func MultiPodResidualFromEnviron(getenv func(string) string) MultiPodResidual {
	if getenv == nil {
		getenv = os.Getenv
	}
	out := MultiPodResidual{
		// Always true: multi-pod durable vault remains residual (HOST-008 honesty).
		MultiPodVaultResidual: true,
	}
	if strings.TrimSpace(getenv(envKubernetesServiceHost)) != "" {
		out.KubernetesEnvDetected = true
	}
	if vaultPathEmptyDirHeuristic(gateway.VaultPathFromEnviron(getenv)) ||
		vaultPathEmptyDirHeuristic(gateway.JWTVaultPathFromEnviron(getenv)) {
		out.VaultEmptyDirHeuristic = true
	}
	if replicasEnvResidual(getenv) {
		out.ReplicasEnvResidual = true
	}
	if out.KubernetesEnvDetected || out.VaultEmptyDirHeuristic || out.ReplicasEnvResidual {
		out.Checklist = multiPodResidualChecklist
	}
	return out
}

// pathHasDirPrefix reports whether p is exactly dir or a path under dir/ (slash form).
func pathHasDirPrefix(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, dir+"/")
}

// vaultPathEmptyDirHeuristic is a path-shape residual only (no FS mount inspection).
// True for common pod-local / emptyDir-ish locations. Does not prove volume type.
func vaultPathEmptyDirHeuristic(path string) bool {
	p := filepath.Clean(strings.TrimSpace(path))
	if p == "" || p == "." {
		return false
	}
	// Normalize to slash for portable prefix / segment checks.
	// Use path-boundary prefixes so "/tmpfoo" does not match "/tmp".
	slash := filepath.ToSlash(p)
	lower := strings.ToLower(slash)
	if pathHasDirPrefix(slash, "/tmp") || pathHasDirPrefix(slash, "/var/run") ||
		pathHasDirPrefix(slash, "/dev/shm") {
		return true
	}
	// Windows residual labs (not Tier-1): temp-like prefixes.
	if pathHasDirPrefix(lower, "c:/windows/temp") || pathHasDirPrefix(lower, "c:/temp") {
		return true
	}
	for _, seg := range strings.Split(lower, "/") {
		if seg == "emptydir" || seg == "empty_dir" {
			return true
		}
	}
	return false
}

// replicasEnvResidual is true when a residual replicas-like env is an int > 1.
// Not a product scale knob; honesty only if operators set these by mistake or lab.
func replicasEnvResidual(getenv func(string) string) bool {
	if getenv == nil {
		getenv = os.Getenv
	}
	for _, key := range multiPodReplicasEnvKeys {
		raw := strings.TrimSpace(getenv(key))
		if raw == "" {
			continue
		}
		n, err := strconv.Atoi(raw)
		if err == nil && n > 1 {
			return true
		}
	}
	return false
}

// checkGatewayStatus reports secret-free gateway/multi-user residual fields from
// process env (HOST-008 doctor residual). Never tokens, vault bytes, or subjects.
//
// Unifies modes A/B/C residual honesty with multi-user / HA fields:
// gateway_ready is always false here (offline doctor does not hold a live
// CredentialProvider; MCP serve /readyz is the Ready probe). ha_multi_replica
// is always false (Tier A single-replica default; multi-replica not implemented).
// session_affinity_recommended is true when multi-user env is set (HOST-008
// sticky scaffold honesty — not multi-replica Done).
// multi_pod_vault_residual is always true (multi-pod durable vault residual).
// When KUBERNETES_SERVICE_HOST is set, status is warn with multi-pod checklist.
//
// Mode B residual: offline vault only (OAUTH-009 live pin open).
// Mode C residual: offline Live=false / mock Fetcher (OAUTH-010 live pin open).
//
// getenv nil → os.Getenv (DoctorOptions.Getenv when available).
func checkGatewayStatus(getenv func(string) string) Check {
	const name = "gateway_status"
	if getenv == nil {
		getenv = os.Getenv
	}
	multiUser := gateway.MultiUserEnabled(getenv)
	mode := string(gateway.CredentialModeFromEnviron(getenv))
	if !gateway.CredentialMode(mode).Valid() {
		mode = ""
	}
	liveEnv := gateway.LiveEnabledFromEnviron(getenv)

	modeA, modeB, modeC := false, false, false
	modeResidual := ""
	enabledIDs := []string{}
	if mx, err := gateway.ModeMatrixFromEnviron(getenv); err == nil {
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
	} else {
		// Soft residual when matrix invalid: still surface primary intent without secrets.
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
	}

	mp := MultiPodResidualFromEnviron(getenv)

	details := map[string]any{
		"multi_user_enabled": multiUser,
		"gateway_ready":      false, // offline residual: Ready only on serve /readyz
		"credential_mode":    mode,
		"ha_multi_replica":   false, // HOST-008: single-replica Tier A default
		// HOST-008: recommend sticky Service affinity when multi-user lab env is set
		// (scaffold honesty only — multi-replica runtime still residual).
		"session_affinity_recommended": multiUser,
		// HOST-008 multi-pod vault residual: always true (honest residual, not multi-replica Done).
		"multi_pod_vault_residual":      mp.MultiPodVaultResidual,
		"kubernetes_env_detected":       mp.KubernetesEnvDetected,
		"vault_path_emptydir_heuristic": mp.VaultEmptyDirHeuristic,
		"replicas_env_residual":         mp.ReplicasEnvResidual,
		"gateway_live_env":              liveEnv,
		"mode_a_enabled":                modeA,
		"mode_b_enabled":                modeB,
		"mode_c_enabled":                modeC,
		// Aliases for residual test / older check consumers.
		"gateway_mode_c_enabled": modeC,
		// Offline never claims live pins (unified residual honesty).
		"mode_a_live_obtain_qualified":    false,
		"mode_b_live_rs_qualified":        false,
		"mode_c_live_agentcore_qualified": false,
		"oauth009_offline_only":           true, // oauth009_offline residual id (REL lite)
	}
	if mp.Checklist != "" {
		details["multi_pod_residual_checklist"] = mp.Checklist
	}
	if modeResidual != "" {
		details["mode_matrix_residual"] = modeResidual
	}
	if len(enabledIDs) > 0 {
		details["enabled_modes"] = strings.Join(enabledIDs, ",")
	}

	// Mode C progressive consent residual (OAUTH-010 / GWY-001): env/static only.
	// When ConsentRequired would apply, only auth URL + session_id surface;
	// browser 3LO is not automated (metadata path Done*).
	pc := gateway.NewProgressiveConsentResidual()
	details["progressive_consent_browser_3lo_automated"] = pc.Browser3LOAutomated
	details["progressive_consent_metadata_path_done_star"] = pc.MetadataPathDoneStar
	details["progressive_consent_last_would_apply"] = pc.LastConsentWouldApply
	if modeC {
		details["progressive_consent_residual"] = pc.ResidualNote
		details["progressive_consent_surfaces"] = pc.Surfaces
	}

	msg := fmt.Sprintf("multi_user=%v credential_mode=%s modes_a/b/c=%v/%v/%v gateway_ready=false ha_multi_replica=false multi_pod_vault_residual=true",
		multiUser, nonEmpty(mode, "(default/unset)"), modeA, modeB, modeC)
	if multiUser {
		msg += " (multi-user env set: foundation residual, not production GO; session_affinity_recommended=true scaffold only; no tokens in this check)"
	}
	if modeB {
		msg += " (mode B offline vault only; live jwt-auth-filter/Entra residual OAUTH-009)"
	}
	if modeC && !modeB {
		msg += " (mode C Live=false foundation; live AgentCore residual; progressive consent metadata Done*)"
	}
	if modeA && !modeB && !modeC {
		msg += " (mode A offline vault foundation; live multi-user Obtain residual)"
	}

	// Info-level residual: never fail doctor solely for multi-user env, mode enablement, or single-replica.
	status := StatusOK
	if multiUser || modeB || modeC {
		// Multi-user or modes that commonly imply live residual (B/C) → warn for honesty.
		status = StatusWarn
	}
	// Mode C residual honesty (OAUTH-010): elevate warn when operator explicitly
	// selected agentcore or LIVE, or multi-user (gateway path). Empty default
	// Mode C still gets residual details above without forcing warn alone.
	explicitModeC := strings.TrimSpace(getenv(gateway.EnvGatewayCredentialMode)) != "" && modeC
	if modeC && (explicitModeC || liveEnv || multiUser) {
		status = StatusWarn
		msg = "gateway Mode C (agentcore_3lo_obo): offline Live=false/mock Fetcher foundation only; live Entra 3LO/OBO + AgentCore pin residual (OAUTH-010); progressive consent metadata path Done* (browser 3LO not automated)"
		if multiUser {
			msg += "; multi_user foundation residual"
		}
		if liveEnv {
			msg += "; GATEWAY_LIVE set (HTTPTokenFetcher wire only — not production AgentCore)"
		}
	}

	// HOST-008 multi-pod residual: k8s env, emptyDir-ish vault path, or replicas>1 residual env.
	// Always multi_pod_vault_residual=true in details; warn when any multi-pod signal fires.
	if mp.KubernetesEnvDetected || mp.VaultEmptyDirHeuristic || mp.ReplicasEnvResidual {
		status = StatusWarn
		parts := []string{}
		if mp.KubernetesEnvDetected {
			parts = append(parts, "KUBERNETES_SERVICE_HOST set (in-cluster residual)")
		}
		if mp.VaultEmptyDirHeuristic {
			// Path shape only — never embed the vault path (secret-free residual).
			parts = append(parts, "vault path emptyDir-ish heuristic")
		}
		if mp.ReplicasEnvResidual {
			parts = append(parts, "replicas-like env >1 residual")
		}
		msg += "; multi-pod residual: " + strings.Join(parts, ", ") +
			" — sticky/shared vault/rate/Obtain cache residual (ha_multi_replica=false; not multi-replica Done; see deployment.md §9)"
	}

	return SanitizeCheck(Check{
		Name:    name,
		Status:  status,
		Message: msg,
		Details: details,
	})
}
