package diagnostics_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/diagnostics"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
	"github.com/simonfxr/go-jenkins-mcp/internal/profile"
	// Blank import registers Wave 38 hard_max_resolve_residual + Wave 43
	// operator_caps_snapshot canaries (tools init).
	_ "github.com/simonfxr/go-jenkins-mcp/internal/tools"
)

func TestSecuritySelfCheck_OfflineCanaries(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	rep, err := diagnostics.RunSecuritySelfCheck(ctx, diagnostics.SelfCheckOptions{
		Version: "test",
		Commit:  "deadbeef",
		Now:     func() time.Time { return time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC) },
		PolicyResult: &policy.LoadResult{
			Present:        false,
			SignatureState: policy.SigStateAbsent,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.IndependentReviewRequired {
		t.Fatal("must declare independent review required")
	}
	if rep.Overall == diagnostics.SelfCheckFail {
		t.Fatalf("unexpected fail: %+v", rep.Items)
	}
	// Wave 34 residuals (HTTP loopback, RS live lab) may elevate overall to warn.
	if rep.Overall != diagnostics.SelfCheckOK && rep.Overall != diagnostics.SelfCheckWarn {
		t.Fatalf("overall=%s", rep.Overall)
	}
	names := map[string]diagnostics.SelfCheckItem{}
	for _, it := range rep.Items {
		names[it.Name] = it
		if strings.Contains(it.Message, "QA005_SELFCHECK_CANARY") {
			t.Fatalf("canary leaked in message: %s", it.Message)
		}
		// Details must also be secret-free.
		if it.Details != nil {
			b, _ := json.Marshal(it.Details)
			if strings.Contains(string(b), "QA005_SELFCHECK_CANARY") {
				t.Fatalf("canary leaked in details %s: %s", it.Name, b)
			}
		}
	}
	for _, want := range []string{
		"redaction_canary",
		"writer_split_line_canary",
		"support_bundle_canary",
		"policy_signature_mode",
		"oidc_profile_structural",
		"rs_qualification",
		"http_require_token_residual",
		"http_allowed_hosts_residual",
		"telemetry_default_off",
		"read_only_default",
		"mutations_opt_in_default",
		"hard_max_resolve_residual",
		"operator_caps_snapshot",
		"listfilter_deny_only_residual",
		"policy_resource_deny_residual",
		"policy_multisig_lite_residual",
		"adapter_framework_residual",
		"adapter_allowlist_provenance_lite",
		"jenkins_resilience_residual",
		"fleet_telemetry_force_off_residual",
		"update_lkg_residual",
		"mutation_confirm_cooldown_residual",
		"gateway_residual_status_honesty",
		"origin_tls_posture",
		"jenkins_origin_pin_residual",
		"report_canary_leak",
	} {
		if _, ok := names[want]; !ok {
			t.Errorf("missing check %s", want)
		}
	}

	// Wave 38 / MCP-001: absolute hard-max ceiling enforced.
	hm := names["hard_max_resolve_residual"]
	if hm.Status != diagnostics.SelfCheckOK {
		t.Fatalf("hard_max_resolve_residual: %+v", hm)
	}
	if hm.Control != "MCP-001" {
		t.Fatalf("hard_max control: %s", hm.Control)
	}
	if hm.Details["over_cap_flag_rejected"] != true || hm.Details["over_cap_env_rejected"] != true {
		t.Fatalf("hard_max details: %+v", hm.Details)
	}
	if hm.Details["default_ok"] != true || hm.Details["at_cap_ok"] != true {
		t.Fatalf("hard_max default/at_cap: %+v", hm.Details)
	}

	// Wave 43 / MCP-001: secret-free operator caps snapshot (live getters + constants).
	caps := names["operator_caps_snapshot"]
	if caps.Status != diagnostics.SelfCheckOK && caps.Status != diagnostics.SelfCheckInfo {
		t.Fatalf("operator_caps_snapshot: %+v", caps)
	}
	if caps.Control != "MCP-001" {
		t.Fatalf("operator_caps control: %s", caps.Control)
	}
	if !strings.Contains(caps.Message, "operator caps snapshot") {
		t.Fatalf("operator_caps message: %s", caps.Message)
	}
	for _, k := range []string{
		"default_hard_max_bytes",
		"absolute_max_hard_max_bytes",
		"list_jobs_collect_max_pages",
		"absolute_max_list_jobs_collect_max_pages",
		"nodes_collect_max_pages",
		"absolute_max_nodes_collect_max_pages",
		"views_collect_max_pages",
		"absolute_max_views_collect_max_pages",
		"artifacts_hard_cap",
		"absolute_max_artifacts_hard_cap",
		// Wave 44 Track B: live/default/absolute artifact list body bytes.
		"artifacts_list_body_bytes",
		"default_artifacts_list_body_bytes",
		"absolute_max_artifacts_list_body_bytes",
		// Wave 45 Track B: HTTP body + identity reverify TTL constants.
		"default_http_max_body_bytes",
		"absolute_max_http_max_body_bytes",
		"min_identity_reverify_ttl_seconds",
		"max_identity_reverify_ttl_seconds",
		"default_identity_reverify_ttl_seconds",
		// Wave 46 Track B: Jenkins NET-003 resilience constants.
		"default_max_json_body_bytes",
		"absolute_max_json_body_bytes",
		"default_max_retries",
		"default_circuit_failure_threshold",
		// Wave 48 Track B: absolute retries/circuit + open duration.
		"absolute_max_retries",
		"absolute_max_circuit_failure_threshold",
		"default_circuit_open_duration_seconds",
		// Wave 49 Track B
		"min_circuit_open_duration_seconds",
		"absolute_max_circuit_open_duration_seconds",
		// Wave 47 Track B: soft target budget constants.
		"default_target_bytes",
		"absolute_max_target_bytes",
		// Wave 50 Track B
		"absolute_max_concurrent",
		"default_initial_backoff_ms",
		"default_max_backoff_ms",
		// Wave 52 Track B: Wave 51 backoff resolve bounds + mutation honesty.
		"min_initial_backoff_ms",
		"absolute_max_initial_backoff_ms",
		"min_max_backoff_ms",
		"absolute_max_max_backoff_ms",
		"default_mutation_confirm_cooldown_ms",
		"default_mutation_max_previews_per_minute",
		"default_mutation_token_ttl_ms",
		// Wave 53 Track B: Wave 52–53 mutation operator-resolve bounds honesty.
		"min_mutation_confirm_cooldown_ms",
		"absolute_max_mutation_confirm_cooldown_ms",
		"absolute_max_mutation_max_previews_per_minute",
		"min_mutation_token_ttl_ms",
		"absolute_max_mutation_token_ttl_ms",
		// Wave 51 Track B: survey/diagnose package hard ceilings.
		"default_survey_max_total_builds",
		"hard_survey_max_total_builds",
		"default_survey_max_jobs",
		"hard_survey_max_jobs",
		"default_survey_max_log_bytes_total",
		"hard_survey_max_log_bytes_total",
		"default_survey_max_wall_seconds",
		"hard_survey_max_wall_seconds",
		"default_diagnose_log_bytes",
		"hard_diagnose_log_bytes",
		"default_diagnose_max_findings",
		"hard_diagnose_max_findings",
	} {
		n, ok := asInt(caps.Details[k])
		if !ok || n <= 0 {
			t.Fatalf("operator_caps detail %s missing/non-positive: %+v", k, caps.Details[k])
		}
	}
	// default_max_concurrent is 0 (unlimited) by design — non-negative only.
	if n, ok := asInt(caps.Details["default_max_concurrent"]); !ok || n < 0 {
		t.Fatalf("default_max_concurrent missing/negative: %+v", caps.Details["default_max_concurrent"])
	}
	if caps.Details["max_concurrent_unlimited_default"] != true {
		t.Fatalf("max_concurrent_unlimited_default: %+v", caps.Details["max_concurrent_unlimited_default"])
	}
	if caps.Details["live_hard_max_available_offline"] != false {
		t.Fatalf("live_hard_max_available_offline must be false offline: %+v", caps.Details)
	}
	// Wave 53 Track B: mutation resolve bounds ordering + known defaults.
	minConfirm, okMin := asInt(caps.Details["min_mutation_confirm_cooldown_ms"])
	defConfirm, okDefC := asInt(caps.Details["default_mutation_confirm_cooldown_ms"])
	absConfirm, okAbsC := asInt(caps.Details["absolute_max_mutation_confirm_cooldown_ms"])
	defPrev, okDefP := asInt(caps.Details["default_mutation_max_previews_per_minute"])
	absPrev, okAbsP := asInt(caps.Details["absolute_max_mutation_max_previews_per_minute"])
	defTTL, okTTL := asInt(caps.Details["default_mutation_token_ttl_ms"])
	if !okMin || !okDefC || !okAbsC || !okDefP || !okAbsP || !okTTL {
		t.Fatalf("mutation bound keys missing: details=%+v", caps.Details)
	}
	if minConfirm != 1000 || defConfirm != 5000 || absConfirm != 300000 {
		t.Fatalf("mutation confirm cooldown ms want min=1000 default=5000 abs=300000 got min=%d default=%d abs=%d",
			minConfirm, defConfirm, absConfirm)
	}
	if defPrev != 30 || absPrev != 300 {
		t.Fatalf("mutation max previews want default=30 abs=300 got default=%d abs=%d", defPrev, absPrev)
	}
	if defTTL != 120000 {
		t.Fatalf("default_mutation_token_ttl_ms want 120000 got %d", defTTL)
	}
	if minConfirm > defConfirm || defConfirm > absConfirm {
		t.Fatalf("confirm cooldown ordering min≤default≤abs failed: %d ≤ %d ≤ %d",
			minConfirm, defConfirm, absConfirm)
	}
	if defPrev < 1 || defPrev > absPrev {
		t.Fatalf("max previews ordering 1≤default≤abs failed: default=%d abs=%d", defPrev, absPrev)
	}
	if defConfirm >= defTTL {
		t.Fatalf("default confirm cooldown %d must be < default token TTL %d", defConfirm, defTTL)
	}
	// Wave 53 Track A Done*: TokenTTL min/abs keys hard-required.
	minTTL, okMinTTL := asInt(caps.Details["min_mutation_token_ttl_ms"])
	absTTL, okAbsTTL := asInt(caps.Details["absolute_max_mutation_token_ttl_ms"])
	if !okMinTTL || !okAbsTTL {
		t.Fatalf("token TTL bound keys missing: details=%+v", caps.Details)
	}
	if minTTL != 10000 || absTTL != 900000 { // 10s / 15m
		t.Fatalf("mutation token TTL ms want min=10000 abs=900000 got min=%d abs=%d", minTTL, absTTL)
	}
	if minTTL > defTTL || defTTL > absTTL {
		t.Fatalf("token TTL ordering min≤default≤abs failed: %d ≤ %d ≤ %d",
			minTTL, defTTL, absTTL)
	}
	// Details must be integer/bool only (no secret-looking strings).
	for k, v := range caps.Details {
		switch v.(type) {
		case int, int64, float64, bool:
			// ok (json may float64; native map is int/bool)
		default:
			t.Fatalf("operator_caps detail %s type %T not int/bool: %v", k, v, v)
		}
	}

	// Wave 39 / POL-004 (+ Wave 40 polish): listfilter deny-only + all list-row Deny* helpers.
	lf := names["listfilter_deny_only_residual"]
	if lf.Status != diagnostics.SelfCheckOK {
		t.Fatalf("listfilter_deny_only_residual: %+v", lf)
	}
	if lf.Control != "POL-004" {
		t.Fatalf("listfilter control: %s", lf.Control)
	}
	if lf.Details["empty_patterns_deny_nothing"] != true || lf.Details["view_patterns_copy_out"] != true {
		t.Fatalf("listfilter details: %+v", lf.Details)
	}
	// Wave 40: document list policy filters for nodes/jobs/views/artifacts/branches.
	for _, k := range []string{
		"node_patterns_copy_out",
		"job_prefix_patterns_copy_out",
		"artifact_path_patterns_copy_out",
		"branch_patterns_copy_out",
		"list_filters_nodes_jobs_views_artifacts",
	} {
		if lf.Details[k] != true {
			t.Fatalf("listfilter detail %s missing/false: %+v", k, lf.Details)
		}
	}
	prd := names["policy_resource_deny_residual"]
	if prd.Status != diagnostics.SelfCheckOK {
		t.Fatalf("policy_resource_deny_residual: %+v", prd)
	}
	if prd.Control != "POL-004" {
		t.Fatalf("policy_resource control: %s", prd.Control)
	}
	if prd.Details["empty_overlay_no_denials"] != true || prd.Details["deny_view_names_copied"] != true ||
		prd.Details["deny_artifact_paths_copied"] != true || prd.Details["deny_branch_names_copied"] != true ||
		prd.Details["no_grant_elevation"] != true {
		t.Fatalf("policy_resource details: %+v", prd.Details)
	}

	// Wave 42 / MGR-001: multi-sig lite MinSignatures offline canary + residual honesty.
	ms := names["policy_multisig_lite_residual"]
	if ms.Status != diagnostics.SelfCheckOK {
		t.Fatalf("policy_multisig_lite_residual: %+v", ms)
	}
	// Wave 43: adapter residual canary present and ok.
	if ad, ok := names["adapter_framework_residual"]; !ok {
		t.Fatal("missing adapter_framework_residual")
	} else if ad.Status != diagnostics.SelfCheckOK {
		t.Fatalf("adapter_framework_residual: %+v", ad)
	}
	// Wave 44 / INT-001: allowlist Ed25519 provenance lite offline canary.
	if al, ok := names["adapter_allowlist_provenance_lite"]; !ok {
		t.Fatal("missing adapter_allowlist_provenance_lite")
	} else if al.Status != diagnostics.SelfCheckOK {
		t.Fatalf("adapter_allowlist_provenance_lite: %+v", al)
	} else {
		if al.Control != "INT-001" {
			t.Fatalf("allowlist provenance control: %s", al.Control)
		}
		if al.Details["allowlist_ed25519_lite"] != true || al.Details["sign_verify_ok"] != true {
			t.Fatalf("allowlist provenance details: %+v", al.Details)
		}
		if al.Details["bad_sig_fail_closed"] != true || al.Details["signed_without_keys_fail_closed"] != true {
			t.Fatalf("allowlist fail-closed details: %+v", al.Details)
		}
		if al.Details["residual_cosign"] != false || al.Details["residual_hsm"] != false ||
			al.Details["residual_sbom"] != false || al.Details["residual_multi_party_provenance"] != false {
			t.Fatalf("allowlist residual honesty flags: %+v", al.Details)
		}
		// Wave 45 dual-control MinSignatures lite canary.
		if al.Details["allowlist_min_signatures_lite"] != true ||
			al.Details["min_signatures_2of2_verified"] != true ||
			al.Details["min_signatures_1of2_fail_closed"] != true {
			t.Fatalf("allowlist MinSignatures lite details: %+v", al.Details)
		}
		msgLower := strings.ToLower(al.Message)
		if !strings.Contains(msgLower, "ed25519") ||
			(!strings.Contains(msgLower, "cosign") && !strings.Contains(msgLower, "min")) {
			t.Fatalf("allowlist message must note Ed25519 lite + residual: %s", al.Message)
		}
		if !strings.Contains(msgLower, "min") && !strings.Contains(msgLower, "dual") {
			// Prefer dual-control / MinSignatures honesty when Wave 45 landed.
			t.Logf("allowlist message (optional dual-control wording): %s", al.Message)
		}
	}
	// Wave 45 Track C / NET-003: resilience lite offline canary (GET/HEAD + circuit).
	if jr, ok := names["jenkins_resilience_residual"]; !ok {
		t.Fatal("missing jenkins_resilience_residual")
	} else if jr.Status != diagnostics.SelfCheckOK {
		t.Fatalf("jenkins_resilience_residual: %+v", jr)
	} else {
		if jr.Control != "NET-003" {
			t.Fatalf("resilience control: %s", jr.Control)
		}
		if jr.Details["get_head_retry_eligible"] != true {
			t.Fatalf("get_head_retry_eligible: %+v", jr.Details)
		}
		if jr.Details["post_auto_retry"] != false {
			t.Fatalf("post_auto_retry must be false: %+v", jr.Details)
		}
		if jr.Details["circuit_breaker_present"] != true || jr.Details["circuit_starts_closed"] != true {
			t.Fatalf("circuit details: %+v", jr.Details)
		}
		if jr.Details["default_resilience_ok"] != true {
			t.Fatalf("default_resilience_ok: %+v", jr.Details)
		}
		if jr.Details["residual_live_chaos"] != false || jr.Details["residual_live_network_matrix"] != false {
			t.Fatalf("resilience residual honesty flags: %+v", jr.Details)
		}
		if n, ok := asInt(jr.Details["max_json_body_bytes"]); !ok || n <= 0 {
			t.Fatalf("max_json_body_bytes: %+v", jr.Details["max_json_body_bytes"])
		}
		if n, ok := asInt(jr.Details["circuit_failure_threshold"]); !ok || n <= 0 {
			t.Fatalf("circuit_failure_threshold: %+v", jr.Details["circuit_failure_threshold"])
		}
		// Bool/int details only (secret-free).
		for k, v := range jr.Details {
			switch v.(type) {
			case int, int64, float64, bool:
				// ok
			default:
				t.Fatalf("resilience detail %s type %T not int/bool: %v", k, v, v)
			}
		}
		if !strings.Contains(jr.Message, "NET-003") || !strings.Contains(strings.ToLower(jr.Message), "residual") {
			t.Fatalf("resilience message must note NET-003 + residual: %s", jr.Message)
		}
		if !strings.Contains(jr.Message, "GET/HEAD") {
			t.Fatalf("resilience message must mention GET/HEAD: %s", jr.Message)
		}
	}
	// Wave 46 Track C / MGR-002: fleet ForceOff + overlay fleet_telemetry_force_off pin.
	if ft, ok := names["fleet_telemetry_force_off_residual"]; !ok {
		t.Fatal("missing fleet_telemetry_force_off_residual")
	} else if ft.Status != diagnostics.SelfCheckOK {
		t.Fatalf("fleet_telemetry_force_off_residual: %+v", ft)
	} else {
		if ft.Control != "MGR-002" {
			t.Fatalf("fleet force-off control: %s", ft.Control)
		}
		if ft.Details["force_off_disables"] != true {
			t.Fatalf("force_off_disables: %+v", ft.Details)
		}
		// Overlay pin is wired (MGR-002 ForceOff from overlay lite).
		if ft.Details["policy_overlay_pin"] != true {
			t.Fatalf("policy_overlay_pin must be true (overlay field wired): %+v", ft.Details)
		}
		if ft.Details["env_enable_path_present"] != true {
			t.Fatalf("env_enable_path_present: %+v", ft.Details)
		}
		if ft.Details["collector_force_off_nil"] != true || ft.Details["effective_enabled_force_off"] != true {
			t.Fatalf("fleet force-off proof details: %+v", ft.Details)
		}
		if ft.Details["explain_surfaces_force_off"] != true {
			t.Fatalf("explain_surfaces_force_off: %+v", ft.Details)
		}
		// Bool details only (secret-free).
		for k, v := range ft.Details {
			switch v.(type) {
			case int, int64, float64, bool:
				// ok
			default:
				t.Fatalf("fleet force-off detail %s type %T not int/bool: %v", k, v, v)
			}
		}
		msgLower := strings.ToLower(ft.Message)
		if !strings.Contains(msgLower, "forceoff") && !strings.Contains(msgLower, "force off") {
			t.Fatalf("fleet force-off message must note ForceOff: %s", ft.Message)
		}
		// HSM / multi-sig residual honesty remains; overlay pin is no longer residual.
		if !strings.Contains(msgLower, "residual") {
			t.Fatalf("fleet force-off message must note residual (HSM/multi-sig): %s", ft.Message)
		}
		if !strings.Contains(msgLower, "overlay") && !strings.Contains(msgLower, "fleet_telemetry_force_off") {
			t.Fatalf("fleet force-off message must note overlay pin: %s", ft.Message)
		}
	}
	// Wave 47 Track C / UPD-001: LKG residual honesty offline (metadata only, not auto-install).
	if ul, ok := names["update_lkg_residual"]; !ok {
		t.Fatal("missing update_lkg_residual")
	} else if ul.Status != diagnostics.SelfCheckOK {
		t.Fatalf("update_lkg_residual: %+v", ul)
	} else {
		if ul.Control != "UPD-001" {
			t.Fatalf("update_lkg control: %s", ul.Control)
		}
		if ul.Details["lkg_is_metadata_only"] != true {
			t.Fatalf("lkg_is_metadata_only: %+v", ul.Details)
		}
		if ul.Details["install_rollback_operator_owned"] != true {
			t.Fatalf("install_rollback_operator_owned: %+v", ul.Details)
		}
		if ul.Details["residual_auto_install"] != false {
			t.Fatalf("residual_auto_install must be false: %+v", ul.Details)
		}
		if ul.Details["verify_lkg_absent_fail_closed"] != true {
			t.Fatalf("verify_lkg_absent_fail_closed: %+v", ul.Details)
		}
		if ul.Details["residual_note_nonempty"] != true {
			t.Fatalf("residual_note_nonempty: %+v", ul.Details)
		}
		// Bool details only (secret-free).
		for k, v := range ul.Details {
			switch v.(type) {
			case int, int64, float64, bool:
				// ok
			default:
				t.Fatalf("update_lkg detail %s type %T not int/bool: %v", k, v, v)
			}
		}
		msgLower := strings.ToLower(ul.Message)
		if !strings.Contains(msgLower, "lkg") || !strings.Contains(msgLower, "metadata") {
			t.Fatalf("update_lkg message must note LKG metadata: %s", ul.Message)
		}
		if !strings.Contains(msgLower, "not auto-install") && !strings.Contains(msgLower, "not auto install") {
			t.Fatalf("update_lkg message must note not auto-install: %s", ul.Message)
		}
		if !strings.Contains(msgLower, "residual") {
			t.Fatalf("update_lkg message must note residual honesty: %s", ul.Message)
		}
	}
	// Wave 48 Track C / MUT-001: confirm cooldown + token TTL lite offline canary.
	if mc, ok := names["mutation_confirm_cooldown_residual"]; !ok {
		t.Fatal("missing mutation_confirm_cooldown_residual")
	} else if mc.Status != diagnostics.SelfCheckOK {
		t.Fatalf("mutation_confirm_cooldown_residual: %+v", mc)
	} else {
		if mc.Control != "MUT-001" {
			t.Fatalf("mutation cooldown control: %s", mc.Control)
		}
		if mc.Details["cooldown_enforced"] != true {
			t.Fatalf("cooldown_enforced: %+v", mc.Details)
		}
		if mc.Details["mutations_opt_in_default"] != true {
			t.Fatalf("mutations_opt_in_default honesty: %+v", mc.Details)
		}
		if n, ok := asInt(mc.Details["default_token_ttl_seconds"]); !ok || n <= 0 {
			t.Fatalf("default_token_ttl_seconds: %+v", mc.Details["default_token_ttl_seconds"])
		}
		if n, ok := asInt(mc.Details["default_confirm_cooldown_seconds"]); !ok || n <= 0 {
			t.Fatalf("default_confirm_cooldown_seconds: %+v", mc.Details["default_confirm_cooldown_seconds"])
		}
		if mc.Details["residual_gateway_multi_tenant"] != false {
			t.Fatalf("residual_gateway_multi_tenant must be false: %+v", mc.Details)
		}
		if mc.Details["residual_live_remote_mutation"] != false {
			t.Fatalf("residual_live_remote_mutation must be false: %+v", mc.Details)
		}
		// Bool/int details only (secret-free); no confirmation tokens in details.
		for k, v := range mc.Details {
			switch v.(type) {
			case int, int64, float64, bool:
				// ok
			default:
				t.Fatalf("mutation cooldown detail %s type %T not int/bool: %v", k, v, v)
			}
		}
		msgLower := strings.ToLower(mc.Message)
		if !strings.Contains(msgLower, "mut-001") || !strings.Contains(msgLower, "cooldown") {
			t.Fatalf("mutation cooldown message must note MUT-001 + cooldown: %s", mc.Message)
		}
		if !strings.Contains(msgLower, "opt-in") && !strings.Contains(msgLower, "opt in") {
			t.Fatalf("mutation cooldown message must note mutations remain opt-in: %s", mc.Message)
		}
		if !strings.Contains(msgLower, "residual") {
			t.Fatalf("mutation cooldown message must note residual honesty: %s", mc.Message)
		}
	}
	// GWY-003 residual lite: BuildGatewayResidualStatus honesty (same spirit as
	// qualify gateway_residual_status_offline_honesty). Pure offline; not live GO.
	if gr, ok := names["gateway_residual_status_honesty"]; !ok {
		t.Fatal("missing gateway_residual_status_honesty")
	} else if gr.Status != diagnostics.SelfCheckOK && gr.Status != diagnostics.SelfCheckWarn {
		// Warn only when multi_user env is set (host-dependent); still honesty ok.
		t.Fatalf("gateway_residual_status_honesty: %+v", gr)
	} else {
		if gr.Control != "GWY-003" {
			t.Fatalf("gateway residual control: %s", gr.Control)
		}
		if gr.Details["residual_ids_present"] != true {
			t.Fatalf("residual_ids_present: %+v", gr.Details)
		}
		if gr.Details["ha_multi_replica"] != false {
			t.Fatalf("ha_multi_replica must be false: %+v", gr.Details)
		}
		if gr.Details["live_mode_pins_false"] != true {
			t.Fatalf("live_mode_pins_false: %+v", gr.Details)
		}
		if gr.Details["oauth009_offline"] != true {
			t.Fatalf("oauth009_offline: %+v", gr.Details)
		}
		if gr.Details["shared_subject_rate_file_default_false"] != true ||
			gr.Details["shared_principal_cache_file_default_false"] != true ||
			gr.Details["shared_jwks_file_default_false"] != true {
			t.Fatalf("shared_*_file default false: %+v", gr.Details)
		}
		if gr.Details["secret_free"] != true {
			t.Fatalf("secret_free: %+v", gr.Details)
		}
		if gr.Details["residual_live_go"] != false {
			t.Fatalf("residual_live_go must be false: %+v", gr.Details)
		}
		if gr.Details["multi_pod_vault_residual"] != true {
			t.Fatalf("multi_pod_vault_residual: %+v", gr.Details)
		}
		if n, ok := asInt(gr.Details["residual_id_count"]); !ok || n < 6 {
			t.Fatalf("residual_id_count want >=6: %+v", gr.Details["residual_id_count"])
		}
		// Bool/int details only (secret-free).
		for k, v := range gr.Details {
			switch v.(type) {
			case int, int64, float64, bool:
				// ok
			default:
				t.Fatalf("gateway residual detail %s type %T not int/bool: %v", k, v, v)
			}
		}
		msgLower := strings.ToLower(gr.Message)
		if !strings.Contains(msgLower, "gwy-003") {
			t.Fatalf("gateway residual message must note GWY-003: %s", gr.Message)
		}
		if !strings.Contains(msgLower, "residual") {
			t.Fatalf("gateway residual message must note residual honesty: %s", gr.Message)
		}
		if !strings.Contains(msgLower, "not live") && !strings.Contains(msgLower, "offline residual") {
			t.Fatalf("gateway residual message must not claim live GO: %s", gr.Message)
		}
		// Secret canaries must never appear in message/details.
		for _, bad := range []string{
			"QA005_SELFCHECK_CANARY",
			"GWY003_SELFCHECK_RESIDUAL_CANARY",
			"access_token=",
			"refresh_token=",
			"client_secret=",
			"Bearer ",
		} {
			if strings.Contains(gr.Message, bad) {
				t.Fatalf("gateway residual message leaked %q: %s", bad, gr.Message)
			}
			if b, _ := json.Marshal(gr.Details); strings.Contains(string(b), bad) {
				t.Fatalf("gateway residual details leaked %q: %s", bad, b)
			}
		}
	}
	// Wave 50 Track C / NET-001: pure offline origin pin (NormalizeBaseURL+SameOrigin).
	if op, ok := names["jenkins_origin_pin_residual"]; !ok {
		t.Fatal("missing jenkins_origin_pin_residual")
	} else if op.Status != diagnostics.SelfCheckOK {
		t.Fatalf("jenkins_origin_pin_residual: %+v", op)
	} else {
		if op.Control != "NET-001" {
			t.Fatalf("origin pin control: %s", op.Control)
		}
		if op.Details["normalize_base_ok"] != true {
			t.Fatalf("normalize_base_ok: %+v", op.Details)
		}
		if op.Details["same_origin_accept"] != true {
			t.Fatalf("same_origin_accept: %+v", op.Details)
		}
		if op.Details["cross_origin_reject"] != true {
			t.Fatalf("cross_origin_reject: %+v", op.Details)
		}
		if op.Details["whoami_path_present"] != true {
			t.Fatalf("whoami_path_present: %+v", op.Details)
		}
		if op.Details["residual_live_reverse_proxy"] != false {
			t.Fatalf("residual_live_reverse_proxy must be false: %+v", op.Details)
		}
		// Bool details only (secret-free).
		for k, v := range op.Details {
			switch v.(type) {
			case int, int64, float64, bool:
				// ok
			default:
				t.Fatalf("origin pin detail %s type %T not int/bool: %v", k, v, v)
			}
		}
		msgLower := strings.ToLower(op.Message)
		if !strings.Contains(msgLower, "net-001") {
			t.Fatalf("origin pin message must note NET-001: %s", op.Message)
		}
		if !strings.Contains(msgLower, "normalizebaseurl") && !strings.Contains(msgLower, "normalize") {
			t.Fatalf("origin pin message must note NormalizeBaseURL: %s", op.Message)
		}
		if !strings.Contains(msgLower, "sameorigin") && !strings.Contains(msgLower, "same origin") {
			t.Fatalf("origin pin message must note SameOrigin: %s", op.Message)
		}
		if !strings.Contains(msgLower, "reverse-proxy") && !strings.Contains(msgLower, "reverse proxy") {
			t.Fatalf("origin pin message must note reverse-proxy residual: %s", op.Message)
		}
		if !strings.Contains(msgLower, "residual") {
			t.Fatalf("origin pin message must note residual honesty: %s", op.Message)
		}
	}
	// NET-004: TLS posture canary remains separate (diagnostic insecure env).
	if tls, ok := names["origin_tls_posture"]; !ok {
		t.Fatal("missing origin_tls_posture")
	} else if tls.Status != diagnostics.SelfCheckOK && tls.Status != diagnostics.SelfCheckWarn {
		t.Fatalf("origin_tls_posture: %+v", tls)
	} else if tls.Control != "NET-004" {
		t.Fatalf("origin_tls_posture control want NET-004: %s", tls.Control)
	}
	// Wave 43: operator caps snapshot present and ok.
	if oc, ok := names["operator_caps_snapshot"]; !ok {
		t.Fatal("missing operator_caps_snapshot")
	} else if oc.Status != diagnostics.SelfCheckOK {
		t.Fatalf("operator_caps_snapshot: %+v", oc)
	}
	if ms.Control != "MGR-001" {
		t.Fatalf("multisig control: %s", ms.Control)
	}
	if ms.Details["multi_sig_lite"] != true {
		t.Fatalf("multi_sig_lite: %+v", ms.Details)
	}
	if ms.Details["min_signatures_2of2_verified"] != true || ms.Details["min_signatures_1of2_fail_closed"] != true {
		t.Fatalf("MinSignatures canary details: %+v", ms.Details)
	}
	// Residual honesty: true threshold crypto / HSM not implemented (false flags).
	if ms.Details["residual_true_threshold"] != false {
		t.Fatalf("residual_true_threshold must be false: %+v", ms.Details)
	}
	if ms.Details["residual_hsm"] != false {
		t.Fatalf("residual_hsm must be false: %+v", ms.Details)
	}
	if !strings.Contains(ms.Message, "multi-sig lite") || !strings.Contains(strings.ToLower(ms.Message), "threshold") {
		t.Fatalf("multisig message must note lite + threshold residual: %s", ms.Message)
	}
	if !strings.Contains(strings.ToLower(ms.Message), "hsm") {
		t.Fatalf("multisig message must note HSM residual: %s", ms.Message)
	}
	// Secret-free: no PEM / private-key markers / base64 signature dump heuristics.
	for _, bad := range []string{
		"BEGIN PRIVATE", "BEGIN PUBLIC", "PRIVATE KEY",
		"selfcheck-not-a-real-secret",
	} {
		if strings.Contains(ms.Message, bad) {
			t.Fatalf("multisig message leaked material %q: %s", bad, ms.Message)
		}
	}
	if b, _ := json.Marshal(ms.Details); strings.Contains(string(b), "BEGIN ") {
		t.Fatalf("multisig details leaked PEM: %s", b)
	}

	// Writer split-line canary (Wave 33/34 line buffer).
	ws := names["writer_split_line_canary"]
	if ws.Status != diagnostics.SelfCheckOK {
		t.Fatalf("writer_split_line_canary: %+v", ws)
	}
	if ws.Control != "SEC-002" {
		t.Fatalf("writer control: %s", ws.Control)
	}

	// HTTP require-token residual (KD-008).
	httpItem := names["http_require_token_residual"]
	if httpItem.Status != diagnostics.SelfCheckWarn {
		t.Fatalf("http residual should warn (loopback residual honesty): %+v", httpItem)
	}
	if httpItem.Control != "KD-008" {
		t.Fatalf("http control: %s", httpItem.Control)
	}
	if httpItem.Details["non_local_empty_token_rejected"] != true {
		t.Fatalf("http details: %+v", httpItem.Details)
	}
	if httpItem.Details["allowed_hosts_required"] != true {
		t.Fatalf("http residual must note AllowedHosts for non-local token probe: %+v", httpItem.Details)
	}
	if !strings.Contains(httpItem.Message, "loopback") || !strings.Contains(httpItem.Message, "residual") {
		t.Fatalf("http message must note loopback residual: %s", httpItem.Message)
	}
	// Wave 41: residual warn must mention opt-in deny-anonymous / require-token env names (no secrets).
	if !strings.Contains(httpItem.Message, "JENKINS_MCP_HTTP_DENY_ANONYMOUS") ||
		!strings.Contains(httpItem.Message, "JENKINS_MCP_HTTP_REQUIRE_TOKEN") {
		t.Fatalf("http message must mention deny-anonymous / require-token envs: %s", httpItem.Message)
	}
	if httpItem.Details["deny_anonymous_default_off"] != true {
		t.Fatalf("http residual must note deny_anonymous_default_off: %+v", httpItem.Details)
	}

	// Wave 36: AllowedHosts fail-closed independent of token (KD-008).
	hostsItem := names["http_allowed_hosts_residual"]
	if hostsItem.Status != diagnostics.SelfCheckOK {
		t.Fatalf("http_allowed_hosts_residual: %+v", hostsItem)
	}
	if hostsItem.Control != "KD-008" {
		t.Fatalf("hosts control: %s", hostsItem.Control)
	}
	if hostsItem.Details["non_local_empty_hosts_rejected"] != true {
		t.Fatalf("hosts details empty reject: %+v", hostsItem.Details)
	}
	if hostsItem.Details["non_local_complete_accepted"] != true {
		t.Fatalf("hosts details complete ok: %+v", hostsItem.Details)
	}
	// Probe token used only inside ValidateHTTPConfig must never appear.
	if strings.Contains(hostsItem.Message, "selfcheck-not-a-real-secret") {
		t.Fatal("hosts message leaked probe token")
	}

	// Mutations opt-in default false.
	mut := names["mutations_opt_in_default"]
	if mut.Status != diagnostics.SelfCheckOK {
		t.Fatalf("mutations_opt_in_default: %+v", mut)
	}
	if mut.Details["allow_mutations_opt_in"] != false {
		t.Fatalf("mutations details: %+v", mut.Details)
	}

	// RS offline matrix floor + live lab residual.
	rs := names["rs_qualification"]
	if rs.Status != diagnostics.SelfCheckOK && rs.Status != diagnostics.SelfCheckWarn {
		t.Fatalf("rs_qualification status: %+v", rs)
	}
	if rs.Control != "OAUTH-009" {
		t.Fatalf("control: %s", rs.Control)
	}
	if rs.Details["inventory_ok"] != true {
		t.Fatalf("inventory_ok details: %+v", rs.Details)
	}
	if rs.Details["fallthrough_must_deny"] != true {
		t.Fatalf("fallthrough details: %+v", rs.Details)
	}
	// json.Unmarshal numbers as float64 when using map[string]any via re-encode;
	// details are native Go map — int may be int.
	fixtureCount, ok := asInt(rs.Details["fallthrough_fixture_count"])
	if !ok || fixtureCount < 12 {
		t.Fatalf("fallthrough_fixture_count: %+v", rs.Details["fallthrough_fixture_count"])
	}
	if rs.Details["live_lab_still_required"] != true {
		t.Fatalf("live_lab_still_required: %+v", rs.Details)
	}
	if rs.Details["classifier_matrix_done_star"] != true {
		t.Fatalf("classifier_matrix_done_star: %+v", rs.Details)
	}
	if !strings.Contains(rs.Message, "live_lab_still_required") && !strings.Contains(rs.Message, "live lab") {
		t.Fatalf("rs message must note live lab residual: %s", rs.Message)
	}

	// Residual honesty in top-level residuals.
	joined := strings.Join(rep.Residuals, " ")
	if !strings.Contains(joined, "jwt-auth-filter") && !strings.Contains(joined, "OAUTH-009") {
		t.Fatalf("residuals must mention live RS lab: %v", rep.Residuals)
	}
	if !strings.Contains(joined, "KD-008") && !strings.Contains(joined, "http-require-token") {
		t.Fatalf("residuals must mention HTTP require-token residual: %v", rep.Residuals)
	}

	// report_canary_leak overall plant still works.
	if names["report_canary_leak"].Status != diagnostics.SelfCheckOK {
		t.Fatalf("report_canary_leak: %+v", names["report_canary_leak"])
	}

	// JSON round-trip secret free.
	var buf bytes.Buffer
	if err := diagnostics.FormatSelfCheckJSON(&buf, rep); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "QA005_SELFCHECK_CANARY") {
		t.Fatal("canary in JSON output")
	}
	if strings.Contains(buf.String(), "selfcheck-not-a-real-secret") {
		t.Fatal("AllowedHosts probe token must never appear in JSON report")
	}
	var decoded diagnostics.SelfCheckReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
}

func asInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	default:
		return 0, false
	}
}

func TestSecuritySelfCheck_OIDCStructural(t *testing.T) {
	t.Parallel()
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com/",
		AuthMethod:    profile.AuthMethodOIDC,
		OIDC: &profile.OIDCConfig{
			Issuer:          "https://login.example.com/tenant/v2.0",
			ClientID:        "public-client",
			JenkinsAudience: "api://jenkins-api",
		},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	rep, err := diagnostics.RunSecuritySelfCheck(context.Background(), diagnostics.SelfCheckOptions{
		Profile: p,
		PolicyResult: &policy.LoadResult{
			Present:        true,
			SignatureState: policy.SigStateVerified,
			KeyID:          "corp-2026",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var oidc, rs diagnostics.SelfCheckItem
	for _, it := range rep.Items {
		if it.Name == "oidc_profile_structural" {
			oidc = it
		}
		if it.Name == "rs_qualification" {
			rs = it
		}
		if it.Name == "policy_signature_mode" && it.Status != diagnostics.SelfCheckOK {
			t.Fatalf("verified policy: %+v", it)
		}
		if strings.Contains(it.Message, "QA005_SELFCHECK_CANARY") {
			t.Fatalf("canary leak: %s", it.Message)
		}
	}
	if oidc.Status != diagnostics.SelfCheckOK {
		t.Fatalf("oidc: %+v", oidc)
	}
	if rs.Status != diagnostics.SelfCheckWarn {
		t.Fatalf("oidc_bearer rs_qualification should warn live residual: %+v", rs)
	}
	if rs.Details["auth_method"] != string(profile.AuthMethodOIDC) {
		t.Fatalf("auth_method: %+v", rs.Details)
	}
	if rs.Details["live_lab_still_required"] != true {
		t.Fatalf("live_lab_still_required: %+v", rs.Details)
	}
	if rep.ProfileID != "corp" {
		t.Fatalf("profile_id=%s", rep.ProfileID)
	}
}

func TestSecuritySelfCheck_TextFormat(t *testing.T) {
	t.Parallel()
	rep, err := diagnostics.RunSecuritySelfCheck(context.Background(), diagnostics.SelfCheckOptions{
		SkipSupportBundleCanary: true,
		PolicyResult: &policy.LoadResult{
			SignatureState: policy.SigStateUnverifiedPilot,
			Present:        true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	diagnostics.FormatSelfCheckText(&buf, rep)
	out := buf.String()
	if !strings.Contains(out, "independent_review_required") {
		t.Fatal(out)
	}
	if !strings.Contains(out, "security-review-checklist") {
		t.Fatal("must point operators at checklist")
	}
	if !strings.Contains(out, "writer_split_line_canary") {
		t.Fatal("text must list writer_split_line_canary")
	}
	if !strings.Contains(out, "http_require_token_residual") {
		t.Fatal("text must list http_require_token_residual")
	}
	if !strings.Contains(out, "http_allowed_hosts_residual") {
		t.Fatal("text must list http_allowed_hosts_residual")
	}
	if !strings.Contains(out, "mutations_opt_in_default") {
		t.Fatal("text must list mutations_opt_in_default")
	}
	if !strings.Contains(out, "hard_max_resolve_residual") {
		t.Fatal("text must list hard_max_resolve_residual")
	}
	if !strings.Contains(out, "operator_caps_snapshot") {
		t.Fatal("text must list operator_caps_snapshot")
	}
	if !strings.Contains(out, "listfilter_deny_only_residual") {
		t.Fatal("text must list listfilter_deny_only_residual")
	}
	if !strings.Contains(out, "policy_resource_deny_residual") {
		t.Fatal("text must list policy_resource_deny_residual")
	}
	if !strings.Contains(out, "policy_multisig_lite_residual") {
		t.Fatal("text must list policy_multisig_lite_residual")
	}
	if !strings.Contains(out, "adapter_framework_residual") {
		t.Fatal("text must list adapter_framework_residual")
	}
	if !strings.Contains(out, "adapter_allowlist_provenance_lite") {
		t.Fatal("text must list adapter_allowlist_provenance_lite")
	}
	if !strings.Contains(out, "jenkins_resilience_residual") {
		t.Fatal("text must list jenkins_resilience_residual")
	}
	if !strings.Contains(out, "fleet_telemetry_force_off_residual") {
		t.Fatal("text must list fleet_telemetry_force_off_residual")
	}
	if !strings.Contains(out, "update_lkg_residual") {
		t.Fatal("text must list update_lkg_residual")
	}
	if !strings.Contains(out, "mutation_confirm_cooldown_residual") {
		t.Fatal("text must list mutation_confirm_cooldown_residual")
	}
	if !strings.Contains(out, "gateway_residual_status_honesty") {
		t.Fatal("text must list gateway_residual_status_honesty")
	}
	if !strings.Contains(out, "jenkins_origin_pin_residual") {
		t.Fatal("text must list jenkins_origin_pin_residual")
	}
	if !strings.Contains(out, "origin_tls_posture") {
		t.Fatal("text must list origin_tls_posture")
	}
	if strings.Contains(out, "selfcheck-not-a-real-secret") {
		t.Fatal("probe token must never appear in text report")
	}
	if strings.Contains(out, "BEGIN PRIVATE") || strings.Contains(out, "BEGIN PUBLIC") {
		t.Fatal("PEM material must never appear in text report")
	}
	if strings.Contains(out, "QA005_SELFCHECK_CANARY") {
		t.Fatal("canary in text")
	}
}

// Regression: planted canary used only for canaries must never appear in full report JSON.
func TestSecuritySelfCheck_ReportCanaryNeverInOutput(t *testing.T) {
	t.Parallel()
	rep, err := diagnostics.RunSecuritySelfCheck(context.Background(), diagnostics.SelfCheckOptions{
		PolicyResult: &policy.LoadResult{SignatureState: policy.SigStateAbsent},
	})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := diagnostics.FormatSelfCheckJSON(&buf, rep); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "QA005_SELFCHECK_CANARY") {
		t.Fatal("Regression: canary plant leaked into report JSON")
	}
	// Text format as well.
	buf.Reset()
	diagnostics.FormatSelfCheckText(&buf, rep)
	if strings.Contains(buf.String(), "QA005_SELFCHECK_CANARY") {
		t.Fatal("Regression: canary plant leaked into report text")
	}
}

// GWY-003 residual lite: multi_user env elevates gateway_residual_status_honesty
// to warn without claiming live multi-user GO. Core residual honesty still holds.
// Regression: secret canaries never appear in residual honesty item.
func TestSecuritySelfCheck_GatewayResidualStatusHonesty_MultiUserWarn(t *testing.T) {
	t.Parallel()
	const canary = "GWY003_SELFCHECK_RESIDUAL_CANARY_token_must_never_appear_a7c1"
	getenv := func(k string) string {
		// Multi-user residual warn path.
		if k == "JENKINS_MCP_GATEWAY_MULTI_USER" {
			return "1"
		}
		// Plant secret-shaped values for unrelated keys — must never appear.
		if strings.Contains(strings.ToLower(k), "token") ||
			strings.Contains(strings.ToLower(k), "secret") ||
			strings.Contains(strings.ToLower(k), "password") {
			return canary
		}
		return canary // default unknown keys also canary (should not dump)
	}
	rep, err := diagnostics.RunSecuritySelfCheck(context.Background(), diagnostics.SelfCheckOptions{
		SkipSupportBundleCanary: true,
		Getenv:                  getenv,
		PolicyResult: &policy.LoadResult{
			Present:        false,
			SignatureState: policy.SigStateAbsent,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var gr diagnostics.SelfCheckItem
	for _, it := range rep.Items {
		if it.Name == "gateway_residual_status_honesty" {
			gr = it
			break
		}
		if strings.Contains(it.Message, canary) || strings.Contains(it.Message, "QA005_SELFCHECK_CANARY") {
			t.Fatalf("canary leak in %s: %s", it.Name, it.Message)
		}
	}
	if gr.Name == "" {
		t.Fatal("gateway_residual_status_honesty missing")
	}
	if gr.Status != diagnostics.SelfCheckWarn {
		t.Fatalf("multi_user env want warn: %+v", gr)
	}
	if gr.Control != "GWY-003" {
		t.Fatalf("control %s", gr.Control)
	}
	if gr.Details["multi_user_env_set"] != true {
		t.Fatalf("multi_user_env_set: %+v", gr.Details)
	}
	if gr.Details["residual_live_go"] != false {
		t.Fatalf("must not claim live GO: %+v", gr.Details)
	}
	if gr.Details["ha_multi_replica"] != false {
		t.Fatalf("ha_multi_replica must stay false: %+v", gr.Details)
	}
	if gr.Details["live_mode_pins_false"] != true {
		t.Fatalf("live pins: %+v", gr.Details)
	}
	if !strings.Contains(strings.ToLower(gr.Message), "multi_user") &&
		!strings.Contains(strings.ToLower(gr.Message), "multi-user") {
		t.Fatalf("warn message must note multi_user residual: %s", gr.Message)
	}
	if !strings.Contains(strings.ToLower(gr.Message), "not live") {
		t.Fatalf("warn message must not claim live GO: %s", gr.Message)
	}
	// Full report JSON must never contain planted residual canary.
	blob, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), canary) {
		t.Fatal("Regression: residual self-check canary leaked into report")
	}
	if strings.Contains(string(blob), "access_token=") ||
		strings.Contains(string(blob), "client_secret=") {
		t.Fatal("Regression: secret markers in residual honesty report")
	}
}

// Empty getenv: residual honesty OK (no multi_user warn).
func TestSecuritySelfCheck_GatewayResidualStatusHonesty_DefaultOK(t *testing.T) {
	t.Parallel()
	rep, err := diagnostics.RunSecuritySelfCheck(context.Background(), diagnostics.SelfCheckOptions{
		SkipSupportBundleCanary: true,
		Getenv:                  func(string) string { return "" },
		PolicyResult: &policy.LoadResult{
			Present:        false,
			SignatureState: policy.SigStateAbsent,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var gr diagnostics.SelfCheckItem
	for _, it := range rep.Items {
		if it.Name == "gateway_residual_status_honesty" {
			gr = it
			break
		}
	}
	if gr.Name == "" {
		t.Fatal("gateway_residual_status_honesty missing")
	}
	if gr.Status != diagnostics.SelfCheckOK {
		t.Fatalf("empty getenv want ok: %+v", gr)
	}
	if gr.Details["multi_user_env_set"] != false {
		t.Fatalf("multi_user_env_set want false: %+v", gr.Details)
	}
	if gr.Details["residual_ids_present"] != true || gr.Details["secret_free"] != true {
		t.Fatalf("honesty details: %+v", gr.Details)
	}
}

// OAUTH-009: Mode B env elevates rs_qualification warn with honest residual.
func TestSecuritySelfCheck_ModeB_RSResidual(t *testing.T) {
	t.Parallel()
	getenv := func(k string) string {
		if k == "JENKINS_MCP_GATEWAY_CREDENTIAL_MODE" {
			return "jwt_rs_bearer"
		}
		return ""
	}
	rep, err := diagnostics.RunSecuritySelfCheck(context.Background(), diagnostics.SelfCheckOptions{
		SkipSupportBundleCanary: true,
		Getenv:                  getenv,
		PolicyResult: &policy.LoadResult{
			Present:        true,
			SignatureState: policy.SigStateUnverifiedPilot,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var rs diagnostics.SelfCheckItem
	for _, it := range rep.Items {
		if it.Name == "rs_qualification" {
			rs = it
			break
		}
	}
	if rs.Name == "" {
		t.Fatal("rs_qualification missing")
	}
	if rs.Status != diagnostics.SelfCheckWarn {
		t.Fatalf("Mode B rs_qualification want warn: %+v", rs)
	}
	if rs.Control != "OAUTH-009" {
		t.Fatalf("control %s", rs.Control)
	}
	if rs.Details["gateway_mode_b_enabled"] != true {
		t.Fatalf("gateway_mode_b_enabled: %+v", rs.Details)
	}
	if rs.Details["mode_b_live_rs_qualified"] != false {
		t.Fatalf("must not claim live qualified: %+v", rs.Details)
	}
	if rs.Details["live_lab_still_required"] != true {
		t.Fatalf("live_lab_still_required: %+v", rs.Details)
	}
	if rs.Details["id_jwt_never_api_credential"] != true {
		t.Fatalf("id_jwt note: %+v", rs.Details)
	}
	if rs.Details["residual_id"] != "oauth009_offline" {
		t.Fatalf("Mode B residual_id want oauth009_offline: %+v", rs.Details)
	}
	if rs.Details["oauth009_offline"] != true {
		t.Fatalf("oauth009_offline flag: %+v", rs.Details)
	}
	if !strings.Contains(rs.Message, "Mode B") && !strings.Contains(rs.Message, "jwt_rs_bearer") {
		t.Fatalf("message: %s", rs.Message)
	}
	if !strings.Contains(rs.Message, "oauth009_offline") && !strings.Contains(rs.Message, "OAUTH-009") {
		t.Fatalf("message must link residual_id oauth009_offline: %s", rs.Message)
	}
}
