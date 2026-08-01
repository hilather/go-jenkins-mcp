package diagnostics

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

// checkGatewayResidualStatusHonesty is QA residual lite / GWY-003: pure offline
// proof that BuildGatewayResidualStatus (CLI `gateway residual-status`, doctor
// embed, admin residual-status, support-bundle member) stays honest:
// residual_ids present, ha_multi_replica=false, live mode pins false,
// oauth009_offline, shared_*_file default false (empty environ), secret-free.
//
// Same spirit as gateway qualify case gateway_residual_status_offline_honesty.
// Not live Entra / AgentCore / multi-pod HA / multi-user production GO.
//
// Status OK when honesty holds. When multi_user env is set, status is warn
// (multi-user offline residual — never claims live multi-user GO). Fail closed
// if residual honesty regresses.
//
// getenv is used only for the multi_user residual warn path (nil → os.Getenv).
// Core honesty assertions use an empty environ so shared_*_file defaults are
// independent of the operator host's path env.
func checkGatewayResidualStatusHonesty(getenv func(string) string) SelfCheckItem {
	const (
		name    = "gateway_residual_status_honesty"
		control = "GWY-003"
	)
	fail := func(msg string) SelfCheckItem {
		return SelfCheckItem{
			Name:    name,
			Status:  SelfCheckFail,
			Message: msg,
			Control: control,
		}
	}

	// Empty environ → default residual honesty (same as qualify offline case).
	empty := func(string) string { return "" }
	out := BuildGatewayResidualStatus(empty)
	if out == nil {
		return fail("BuildGatewayResidualStatus returned nil")
	}

	// residual_ids must be present and include REL/GWY residual honesty ids.
	wantIDs := []string{
		"multi_user_offline",
		"oauth009_offline",
		"oauth010_offline",
		"progressive_consent_offline",
		"host008_single_replica",
		"gateway_modes_live",
	}
	rawIDs, ok := out["residual_ids"]
	if !ok {
		return fail("residual_ids missing from BuildGatewayResidualStatus")
	}
	idSet := map[string]bool{}
	switch ids := rawIDs.(type) {
	case []string:
		if len(ids) == 0 {
			return fail("residual_ids empty")
		}
		for _, id := range ids {
			idSet[id] = true
		}
	case []any:
		if len(ids) == 0 {
			return fail("residual_ids empty")
		}
		for _, id := range ids {
			s, _ := id.(string)
			if s != "" {
				idSet[s] = true
			}
		}
	default:
		return fail("residual_ids has unexpected type")
	}
	for _, want := range wantIDs {
		if !idSet[want] {
			return fail("residual_ids missing " + want)
		}
	}

	// Mode B residual id + oauth009_offline flag always advertised offline.
	if rid, _ := out["residual_id"].(string); rid != "oauth009_offline" {
		return fail("residual_id must be oauth009_offline offline")
	}
	if out["oauth009_offline"] != true {
		return fail("oauth009_offline must be true offline")
	}
	if out["oauth009_offline_only"] != true {
		return fail("oauth009_offline_only must be true offline")
	}

	// Live mode pins stay false (never production GO from residual-status).
	for _, k := range []string{
		"mode_a_live_obtain_qualified",
		"mode_b_live_rs_qualified",
		"mode_c_live_agentcore_qualified",
	} {
		if out[k] != false {
			return fail(k + " must be false (live pin residual)")
		}
	}

	// HOST-008 Tier A: single-replica default; Ready only on serve /readyz.
	if out["ha_multi_replica"] != false {
		return fail("ha_multi_replica must be false")
	}
	if out["gateway_ready"] != false {
		return fail("gateway_ready must be false on residual-status")
	}
	if out["multi_pod_vault_residual"] != true {
		return fail("multi_pod_vault_residual must always be true (residual)")
	}

	// shared_*_file default false when paths unset (HOST-008 lite residual).
	for _, k := range []string{
		"shared_subject_rate_file",
		"shared_principal_cache_file",
		"shared_jwks_file",
	} {
		if out[k] != false {
			return fail(k + " default false when path unset")
		}
	}

	// Progressive consent residual object: browser 3LO not automated.
	pc, ok := out["progressive_consent"].(map[string]any)
	if !ok {
		return fail("progressive_consent object required")
	}
	if pc["browser_3lo_automated"] != false {
		return fail("browser_3lo_automated must be false")
	}

	// Secret-free: canary + token markers never appear in residual map JSON.
	// residualSelfCheckCanary is also planted via getenv in unit tests; keep it
	// in the deny-list so a future accidental env dump fails closed here.
	const residualSelfCheckCanary = "GWY003_SELFCHECK_RESIDUAL_CANARY_token_must_never_appear_a7c1"
	blob, err := json.Marshal(out)
	if err != nil {
		return fail("marshal residual-status map failed")
	}
	s := string(blob)
	for _, bad := range []string{
		residualSelfCheckCanary,
		securityCanary,
		"access_token=",
		"refresh_token=",
		"client_secret=",
		"Bearer " + residualSelfCheckCanary,
		"Authorization: Bearer",
	} {
		if strings.Contains(s, bad) {
			return fail("residual-status surface contained secret-shaped material")
		}
	}
	if strings.Contains(strings.ToLower(s), "production go complete") {
		return fail("must not claim production GO complete")
	}

	// Operator pointer to live pin runbook.
	note, _ := out["residual_note"].(string)
	doc, _ := out["doc"].(string)
	if !strings.Contains(note, "live-pin-blockers") && !strings.Contains(doc, "live-pin-blockers") {
		return fail("want live-pin-blockers pointer in residual_note or doc")
	}

	// Multi-user residual warn: env set does not mean live multi-user GO.
	if getenv == nil {
		getenv = os.Getenv
	}
	// Defense-in-depth: never pass raw secrets into BuildGatewayResidualStatus
	// details; only bool multi_user_enabled from known env key.
	multiUser := gateway.MultiUserEnabled(getenv)

	details := map[string]any{
		"residual_ids_present":                   true,
		"residual_id_count":                      len(idSet),
		"ha_multi_replica":                       false,
		"gateway_ready":                          false,
		"live_mode_pins_false":                   true,
		"oauth009_offline":                       true,
		"shared_subject_rate_file_default_false": true,
		"shared_principal_cache_file_default_false": true,
		"shared_jwks_file_default_false":         true,
		"secret_free":                            true,
		"residual_live_go":                       false,
		"multi_user_env_set":                     multiUser,
		"multi_pod_vault_residual":               true,
	}

	if multiUser {
		return SelfCheckItem{
			Name:    name,
			Status:  SelfCheckWarn,
			Message: "GWY-003 residual-status honesty offline (residual_ids, ha_multi_replica=false, live pins false, shared_*_file default false); multi_user env set — offline residual not live multi-user GO",
			Control: control,
			Details: details,
		}
	}

	return SelfCheckItem{
		Name:    name,
		Status:  SelfCheckOK,
		Message: "GWY-003 residual-status honesty offline; residual_ids + ha_multi_replica=false + live pins false + shared_*_file default false; not live Entra/AgentCore GO",
		Control: control,
		Details: details,
	}
}
