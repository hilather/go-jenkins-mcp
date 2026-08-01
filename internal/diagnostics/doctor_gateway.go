package diagnostics

import (
	"fmt"
	"os"

	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

// checkGatewayStatus reports secret-free gateway/multi-user residual fields from
// process env (HOST-008 doctor residual). Never tokens, vault bytes, or subjects.
//
// gateway_ready is always false here: offline doctor does not hold a live
// CredentialProvider (MCP serve /readyz is the Ready probe). ha_multi_replica
// is always false (Tier A single-replica default; multi-replica not implemented).
func checkGatewayStatus() Check {
	const name = "gateway_status"
	multiUser := gateway.MultiUserEnabled(os.Getenv)
	mode := string(gateway.CredentialModeFromEnviron(os.Getenv))
	if !gateway.CredentialMode(mode).Valid() {
		mode = ""
	}
	details := map[string]any{
		"multi_user_enabled": multiUser,
		"gateway_ready":      false, // offline residual: Ready only on serve /readyz
		"credential_mode":    mode,
		"ha_multi_replica":   false, // HOST-008: single-replica Tier A default
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
	return SanitizeCheck(Check{
		Name:    name,
		Status:  status,
		Message: msg,
		Details: details,
	})
}
