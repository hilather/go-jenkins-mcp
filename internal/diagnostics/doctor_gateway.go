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
func checkGatewayStatus() Check {
	const name = "gateway_status"
	multiUser := gateway.MultiUserEnabled(os.Getenv)
	mode := string(gateway.CredentialModeFromEnviron(os.Getenv))
	if !gateway.CredentialMode(mode).Valid() {
		mode = ""
	}

	modeA, modeB, modeC := false, false, false
	modeResidual := ""
	enabledIDs := []string{}
	if mx, err := gateway.ModeMatrixFromEnviron(os.Getenv); err == nil {
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
		"mode_a_enabled":     modeA,
		"mode_b_enabled":     modeB,
		"mode_c_enabled":     modeC,
		// Offline never claims live pins (unified residual honesty).
		"mode_a_live_obtain_qualified": false,
		"mode_b_live_rs_qualified":     false,
		"mode_c_live_agentcore_qualified": false,
		"oauth009_offline_only":        true, // oauth009_offline residual id (REL lite)
	}
	if modeResidual != "" {
		details["mode_matrix_residual"] = modeResidual
	}
	if len(enabledIDs) > 0 {
		details["enabled_modes"] = strings.Join(enabledIDs, ",")
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
		msg += " (mode C Live=false foundation; live AgentCore residual)"
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
	return SanitizeCheck(Check{
		Name:    name,
		Status:  status,
		Message: msg,
		Details: details,
	})
}
