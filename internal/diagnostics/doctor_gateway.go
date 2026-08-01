package diagnostics

import (
	"fmt"
	"os"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

// checkGatewayStatus reports secret-free gateway/multi-user residual fields from
// process env (HOST-008 doctor residual). Never tokens, vault bytes, or subjects.
//
// Unifies modes A/B/C residual honesty with multi-user / HA fields:
// gateway_ready is always false here (offline doctor does not hold a live
// CredentialProvider; MCP serve /readyz is the Ready probe). ha_multi_replica
// is always false (Tier A single-replica default; multi-replica not implemented).
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

	details := map[string]any{
		"multi_user_enabled": multiUser,
		"gateway_ready":      false, // offline residual: Ready only on serve /readyz
		"credential_mode":    mode,
		"ha_multi_replica":   false, // HOST-008: single-replica Tier A default
		"gateway_live_env":   liveEnv,
		"mode_a_enabled":     modeA,
		"mode_b_enabled":     modeB,
		"mode_c_enabled":     modeC,
		// Aliases for residual test / older check consumers.
		"gateway_mode_c_enabled": modeC,
		// Offline never claims live pins (unified residual honesty).
		"mode_a_live_obtain_qualified":    false,
		"mode_b_live_rs_qualified":        false,
		"mode_c_live_agentcore_qualified": false,
		"oauth009_offline_only":           true, // oauth009_offline residual id (REL lite)
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

	msg := fmt.Sprintf("multi_user=%v credential_mode=%s modes_a/b/c=%v/%v/%v gateway_ready=false ha_multi_replica=false",
		multiUser, nonEmpty(mode, "(default/unset)"), modeA, modeB, modeC)
	if multiUser {
		msg += " (multi-user env set: foundation residual, not production GO; no tokens in this check)"
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
	return SanitizeCheck(Check{
		Name:    name,
		Status:  status,
		Message: msg,
		Details: details,
	})
}
