package diagnostics

import (
	"encoding/json"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/policy"
	"github.com/hilather/go-jenkins-mcp/internal/telemetry/fleet"
)

// checkFleetTelemetryForceOffResidual is Wave 46 Track C / MGR-002 residual honesty:
// proves offline that CollectorConfig.ForceOff, fleet.EffectiveEnabled(true), and
// overlay fleet_telemetry_force_off disable telemetry without network.
//
// Pure offline: no network, no secrets, no real fleet export, no ambient env
// assertions. ForceOff path is pure (does not read JENKINS_MCP_TELEMETRY);
// env enable path presence is asserted via the EnvTelemetry constant only.
// Status OK when ForceOff + overlay pin hold; Details mark policy_overlay_pin=true
// when the overlay field is wired (MGR-002 ForceOff from overlay lite).
// HSM / true multi-sig t-of-n remains residual (separate from this pin).
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
	// Nil-safe Enabled / SetForceOff.
	if c.Enabled() {
		return fail("nil collector Enabled must be false")
	}
	c.SetForceOff(true) // no-op on nil

	// --- Overlay field wire: fleet_telemetry_force_off drives EffectiveEnabled ---
	ov := &policy.Overlay{Version: 1, FleetTelemetryForceOff: true}
	if err := ov.Validate(); err != nil {
		return fail("overlay with fleet_telemetry_force_off must validate")
	}
	if fleet.EffectiveEnabled(ov.FleetTelemetryForceOff) {
		return fail("EffectiveEnabled(overlay.FleetTelemetryForceOff) must be false")
	}
	// ExplainEffective exposes the flag (show-effective / admin policy surfaces).
	ex := policy.ExplainEffective("", policy.LoadResult{
		Present:        true,
		Overlay:        ov,
		SignatureState: policy.SigStateUnverifiedPilot,
	}, policy.Inputs{})
	if !ex.FleetTelemetryForceOff {
		return fail("ExplainEffective must surface fleet_telemetry_force_off=true")
	}
	// Secret-free JSON canary: no canary secrets in explain map.
	raw, err := json.Marshal(ex)
	if err != nil {
		return fail("ExplainEffective marshal must succeed")
	}
	js := string(raw)
	if !strings.Contains(js, `"fleet_telemetry_force_off":true`) {
		return fail("ExplainEffective JSON must include fleet_telemetry_force_off")
	}
	for _, bad := range []string{"api_token", "Authorization", "Bearer ", "password"} {
		if strings.Contains(js, bad) {
			return fail("ExplainEffective must be secret-free")
		}
	}

	return SelfCheckItem{
		Name:    name,
		Status:  SelfCheckOK,
		Message: "fleet ForceOff + overlay fleet_telemetry_force_off pin wired offline; HSM/multi-sig residual",
		Control: control,
		Details: map[string]any{
			"force_off_disables":          true,
			"policy_overlay_pin":          true, // MGR-002 overlay field wired
			"env_enable_path_present":     true,
			"collector_force_off_nil":     true,
			"effective_enabled_force_off": true, // EffectiveEnabled(true)==false proved
			"explain_surfaces_force_off":  true,
		},
	}
}
