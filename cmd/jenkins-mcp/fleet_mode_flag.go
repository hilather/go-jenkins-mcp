package main

import "strings"

// fleetModeResolveFlag maps CLI --fleet-mode (bool) to ResolveConfig ModeFlag.
// When the CLI flag is set, return "1". When unset, return "" so env
// JENKINS_MCP_FLEET_MODE can still enable fleet mode (truthy).
//
// Using flag.Bool (not String) is required so bare --fleet-mode does not
// consume the next argv token (e.g. --fleet-member-id).
func fleetModeResolveFlag(cliBool bool) string {
	if cliBool {
		return "1"
	}
	return ""
}

// fleetModeEnvTruthy reports whether the fleet mode env is an explicit enable.
func fleetModeEnvTruthy(envVal string) bool {
	switch strings.ToLower(strings.TrimSpace(envVal)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
