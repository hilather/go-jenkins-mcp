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
// gateway_ready is always false here: offline doctor does not hold a live
// CredentialProvider (MCP serve /readyz is the Ready probe). ha_multi_replica
// is always false (Tier A single-replica default; multi-replica not implemented).
//
// When Mode C (agentcore_3lo_obo) is primary/enabled, surfaces OAUTH-010 honesty:
// offline Live=false / mock Fetcher matrix is not a live Entra/AgentCore pin
// (similar to Mode B residual on rs_auth).
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
	modeC, modeCResidual := gatewayModeCResidual(getenv)
	details := map[string]any{
		"multi_user_enabled":     multiUser,
		"gateway_ready":          false, // offline residual: Ready only on serve /readyz
		"credential_mode":        mode,
		"ha_multi_replica":       false, // HOST-008: single-replica Tier A default
		"gateway_live_env":       liveEnv,
		"gateway_mode_c_enabled": modeC,
	}
	if modeC {
		// Offline doctor never claims live AgentCore / Entra pin (OAUTH-010).
		details["mode_c_live_agentcore_qualified"] = false
		details["gateway_mode_matrix_residual"] = modeCResidual
	}
	msg := fmt.Sprintf("multi_user=%v credential_mode=%s gateway_ready=false ha_multi_replica=false",
		multiUser, nonEmpty(mode, "(default/unset)"))
	if multiUser {
		msg += " (multi-user env set: foundation residual, not production GO; no tokens in this check)"
	}
	// Info-level residual: never fail doctor solely for multi-user env or single-replica.
	status := StatusOK
	if multiUser {
		status = StatusWarn
	}
	// Mode C residual honesty (OAUTH-010): elevate warn when operator explicitly
	// selected agentcore or LIVE, or multi-user (gateway path). Empty default
	// Mode C still gets residual details above without forcing warn alone.
	explicitModeC := strings.TrimSpace(getenv(gateway.EnvGatewayCredentialMode)) != "" && modeC
	if modeC && (explicitModeC || liveEnv || multiUser) {
		status = StatusWarn
		msg = "gateway Mode C (agentcore_3lo_obo): offline Live=false/mock Fetcher foundation only; live Entra 3LO/OBO + AgentCore pin residual (OAUTH-010)"
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

// gatewayModeCResidual reports whether gateway Mode C (agentcore_3lo_obo) is the
// primary or in the enabled list, plus ModeMatrix residual text (OAUTH-010).
// getenv nil → os.Getenv. Invalid mode env returns false (start fail is separate).
func gatewayModeCResidual(getenv func(string) string) (enabled bool, residual string) {
	if getenv == nil {
		getenv = os.Getenv
	}
	mx, err := gateway.ModeMatrixFromEnviron(getenv)
	if err != nil {
		// Soft residual: if env explicitly sets agentcore but matrix fails
		// (e.g. primary not in ENABLED_MODES), still surface Mode C intent.
		raw := strings.TrimSpace(getenv(gateway.EnvGatewayCredentialMode))
		enabledRaw := strings.TrimSpace(getenv(gateway.EnvGatewayEnabledModes))
		if strings.Contains(raw, string(gateway.CredentialModeAgentCore)) ||
			strings.Contains(raw, "agentcore") ||
			strings.Contains(enabledRaw, string(gateway.CredentialModeAgentCore)) {
			return true, "agentcore_3lo_obo referenced in env; mode matrix invalid — fix ENABLED_MODES; live Entra/AgentCore pin residual (OAUTH-010)"
		}
		return false, ""
	}
	if gateway.ModeEnabledIn(gateway.CredentialModeAgentCore, mx.Enabled, mx.Primary) {
		res := mx.Residual
		if res == "" || !strings.Contains(res, "OAUTH-010") {
			res = "agentcore_3lo_obo offline Live=false/mock Fetcher/consent matrix (OAUTH-010); live Entra 3LO/OBO + AgentCore pin residual (not production)"
		}
		return true, res
	}
	return false, ""
}
