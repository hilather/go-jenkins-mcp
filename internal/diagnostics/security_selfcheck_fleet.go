package diagnostics

import (
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/telemetry/fleet"
)

// checkFleetTelemetryForceOffResidual is Wave 46 Track C / MGR-002 residual honesty:
// proves offline that CollectorConfig.ForceOff and fleet.EffectiveEnabled(true)
// disable telemetry without network or ambient env dependence for the force-off
// path, while documenting that signed-policy enterprise pin of ForceOff remains residual.
//
// Pure offline: no network, no secrets, no real fleet export, no ambient env
// assertions. ForceOff path is pure (does not read JENKINS_MCP_TELEMETRY);
// env enable path presence is asserted via the EnvTelemetry constant only.
// Status OK when ForceOff lite holds; Details mark policy_overlay_pin=false.
func checkFleetTelemetryForceOffResidual() SelfCheckItem {
	const (
		name    = "fleet_telemetry_force_off_residual"
		control = "MGR-002"
	)
	fail := func(msg string) SelfCheckItem {
		return SelfCheckItem{
			Name:    name,
			Status:  SelfCheckFail,
			Message: msg,
			Control: control,
		}
	}

	// --- ForceOff wins on pure enablement resolver (no env read when forceOff=true) ---
	if fleet.EffectiveEnabled(true) {
		return fail("EffectiveEnabled(true) must be false (force-off wins)")
	}
	// Do not assert EffectiveEnabled(false): that path reads ambient process env.
	// Self-check must remain deterministic without t.Setenv.

	// --- Env enable path present (constant only; no os.Getenv) ---
	if strings.TrimSpace(fleet.EnvTelemetry) == "" {
		return fail("EnvTelemetry constant missing (env enable path not present)")
	}

	// --- Collector ForceOff: Enabled override true + ForceOff → nil (disabled) ---
	// Early return before queue/paths/network; no real export is started.
	on := true
	c, err := fleet.NewCollector(fleet.CollectorConfig{
		Enabled:  &on,
		ForceOff: true,
	})
	if err != nil {
		return fail("NewCollector with ForceOff must not return error")
	}
	if c != nil {
		return fail("NewCollector with ForceOff true must return nil collector even when Enabled=true")
	}
	// Nil-safe Enabled reports inactive.
	if c.Enabled() {
		return fail("nil collector Enabled must be false")
	}

	// Residual honesty: signed enterprise policy overlay pin of ForceOff is not wired.
	// MVP remains env enable + optional in-process ForceOff (future policy pin).
	return SelfCheckItem{
		Name:    name,
		Status:  SelfCheckOK,
		Message: "fleet ForceOff lite works offline; signed-policy enterprise pin residual",
		Control: control,
		Details: map[string]any{
			"force_off_disables":          true,
			"policy_overlay_pin":          false, // residual: signed policy pin not wired
			"env_enable_path_present":     true,
			"collector_force_off_nil":     true,
			"effective_enabled_force_off": true, // EffectiveEnabled(true)==false proved
		},
	}
}
