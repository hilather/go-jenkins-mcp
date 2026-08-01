package fleet

import (
	"os"
	"strings"
)

// Environment variable names (MGR-002).
const (
	// EnvTelemetry enables fleet telemetry when truthy (1/true/yes/on).
	// Disabled by default when unset or falsey.
	EnvTelemetry = "JENKINS_MCP_TELEMETRY"
	// EnvTelemetryURL is the optional HTTPS endpoint for export POSTs.
	// Empty ⇒ local queue only (no network). http:// and userinfo are rejected.
	EnvTelemetryURL = "JENKINS_MCP_TELEMETRY_URL"
)

// EnabledFromEnv reports whether fleet telemetry is enabled via env.
// Default is false (disabled).
func EnabledFromEnv() bool {
	return truthy(os.Getenv(EnvTelemetry))
}

// ExportURLFromEnv returns the configured export URL, or empty when unset.
func ExportURLFromEnv() string {
	return strings.TrimSpace(os.Getenv(EnvTelemetryURL))
}

// EffectiveEnabled resolves enablement from env and optional force-off.
// forceOff models the enterprise policy pin (overlay fleet_telemetry_force_off /
// CollectorConfig.ForceOff). When forceOff is true, telemetry is always disabled
// regardless of JENKINS_MCP_TELEMETRY (fail closed; never elevates).
func EffectiveEnabled(forceOff bool) bool {
	if forceOff {
		return false
	}
	return EnabledFromEnv()
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
