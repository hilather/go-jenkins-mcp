package diagnostics_test

import (
	"context"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/diagnostics"
)

// Wave 52 / QA-005 + MCP-001 + NET-001 + NET-003 + MUT-001 + DIAG conformance (Track D):
//   - Hard-assert Wave 51 Done* self-check items (jenkins_origin_pin_residual +
//     operator_caps absolute concurrent + backoff ms + survey/diagnose ceilings)
//     — must pass on current main
//   - Soft residual progressive for Wave 52 Track B operator_caps min/abs
//     backoff ms keys (if present → assert positive; if missing → t.Log only —
//     never fail when B not landed)

// TestWave52_Wave51Done_Hard hard-asserts Wave 51 Done*:
// jenkins_origin_pin_residual (NET-001 pure offline), operator_caps_snapshot
// (incl. absolute_max_concurrent + backoff ms + concurrent default 0 + Wave 51
// survey/diagnose ceilings), and related retention canaries.
func TestWave52_Wave51Done_Hard(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rep, err := diagnostics.RunSecuritySelfCheck(ctx, diagnostics.SelfCheckOptions{SkipSupportBundleCanary: true})
	if err != nil {
		t.Fatal(err)
	}

	need := map[string]bool{
		"operator_caps_snapshot":             false,
		"mutation_confirm_cooldown_residual": false,
		"jenkins_origin_pin_residual":        false,
		"update_lkg_residual":                false,
		"fleet_telemetry_force_off_residual": false,
		"jenkins_resilience_residual":        false,
	}
	var caps *diagnostics.SelfCheckItem
	var origin *diagnostics.SelfCheckItem
	for i := range rep.Items {
		item := &rep.Items[i]
		if _, ok := need[item.Name]; ok {
			need[item.Name] = true
		}
		switch item.Name {
		case "operator_caps_snapshot":
			caps = item
			if item.Status != diagnostics.SelfCheckOK {
				t.Fatalf("operator_caps_snapshot status=%s msg=%s", item.Status, item.Message)
			}
			if item.Control != "MCP-001" {
				t.Fatalf("operator_caps_snapshot control=%s", item.Control)
			}
			// Wave 43–51 detail keys (positive ints) including Wave 50 concurrent +
			// backoff and Wave 51 survey/diagnose ceilings.
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
				"artifacts_list_body_bytes",
				"default_artifacts_list_body_bytes",
				"absolute_max_artifacts_list_body_bytes",
				// Wave 45 Track B
				"default_http_max_body_bytes",
				"absolute_max_http_max_body_bytes",
				"min_identity_reverify_ttl_seconds",
				"max_identity_reverify_ttl_seconds",
				"default_identity_reverify_ttl_seconds",
				// Wave 46 Track B
				"default_max_json_body_bytes",
				"absolute_max_json_body_bytes",
				"default_circuit_failure_threshold",
				// Wave 47 Track B
				"default_target_bytes",
				"absolute_max_target_bytes",
				// Wave 48 Track B
				"absolute_max_retries",
				"absolute_max_circuit_failure_threshold",
				"default_circuit_open_duration_seconds",
				// Wave 49 Track B
				"min_circuit_open_duration_seconds",
				"absolute_max_circuit_open_duration_seconds",
				// Wave 50 Track B
				"absolute_max_concurrent",
				"default_initial_backoff_ms",
				"default_max_backoff_ms",
				// Wave 51 Track B survey/diagnose ceilings
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
				if !detailPositiveIntWave52(item.Details, k) {
					t.Fatalf("operator_caps_snapshot detail %s missing/non-positive: %+v", k, item.Details[k])
				}
			}
			// Retries ≥ 0 (0 disables auto-retry).
			if !detailNonNegativeIntWave52(item.Details, "default_max_retries") {
				t.Fatalf("default_max_retries missing/negative: %+v", item.Details["default_max_retries"])
			}
			// Wave 49/50: MaxConcurrent default 0 = unlimited.
			if !detailNonNegativeIntWave52(item.Details, "default_max_concurrent") {
				t.Fatalf("default_max_concurrent missing/negative: %+v", item.Details["default_max_concurrent"])
			}
			if n, ok := asIntWave52(item.Details["default_max_concurrent"]); !ok || n != 0 {
				t.Fatalf("default_max_concurrent want 0 (unlimited), got %+v", item.Details["default_max_concurrent"])
			}
			if item.Details["max_concurrent_unlimited_default"] != true {
				t.Fatalf("max_concurrent_unlimited_default must be true: %+v", item.Details)
			}
			// Wave 50 contracts: absolute concurrent 256; backoff 100/5000 ms.
			if n, ok := asIntWave52(item.Details["absolute_max_concurrent"]); !ok || n != 256 {
				t.Fatalf("absolute_max_concurrent want 256, got %+v", item.Details["absolute_max_concurrent"])
			}
			if n, ok := asIntWave52(item.Details["default_initial_backoff_ms"]); !ok || n != 100 {
				t.Fatalf("default_initial_backoff_ms want 100, got %+v", item.Details["default_initial_backoff_ms"])
			}
			if n, ok := asIntWave52(item.Details["default_max_backoff_ms"]); !ok || n != 5000 {
				t.Fatalf("default_max_backoff_ms want 5000, got %+v", item.Details["default_max_backoff_ms"])
			}
			// Soft target absolute must report 64 MiB (Wave 51 Track C).
			if n, ok := asIntWave52(item.Details["absolute_max_target_bytes"]); !ok || n != 64<<20 {
				t.Fatalf("absolute_max_target_bytes want 64MiB, got %+v", item.Details["absolute_max_target_bytes"])
			}
			if item.Details["live_hard_max_available_offline"] != false {
				t.Fatalf("live_hard_max_available_offline must be false offline: %+v", item.Details)
			}
			if item.Details["live_target_bytes_available_offline"] != false {
				t.Fatalf("live_target_bytes_available_offline must be false offline: %+v", item.Details)
			}
			// Secret-free: integer/bool details only.
			for k, v := range item.Details {
				switch v.(type) {
				case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float64, bool:
					// ok
				default:
					t.Fatalf("operator_caps_snapshot detail %s type %T not int/bool (secret-free): %v", k, v, v)
				}
			}
		case "jenkins_origin_pin_residual":
			origin = item
			if item.Status != diagnostics.SelfCheckOK {
				t.Fatalf("jenkins_origin_pin_residual status=%s msg=%s", item.Status, item.Message)
			}
			if item.Control != "NET-001" {
				t.Fatalf("jenkins_origin_pin_residual control=%s want NET-001", item.Control)
			}
			// Wave 50 Track C pure offline origin pin honesty details.
			for _, k := range []string{
				"normalize_base_ok",
				"same_origin_accept",
				"cross_origin_reject",
				"whoami_path_present",
			} {
				if item.Details[k] != true {
					t.Fatalf("jenkins_origin_pin_residual %s: %+v", k, item.Details)
				}
			}
			if item.Details["residual_live_reverse_proxy"] != false {
				t.Fatalf("residual_live_reverse_proxy must be false offline: %+v", item.Details)
			}
		case "mutation_confirm_cooldown_residual":
			if item.Status != diagnostics.SelfCheckOK {
				t.Fatalf("mutation_confirm_cooldown_residual status=%s msg=%s", item.Status, item.Message)
			}
			if item.Details["cooldown_enforced"] != true {
				t.Fatalf("cooldown_enforced: %+v", item.Details)
			}
			if item.Details["mutations_opt_in_default"] != true {
				t.Fatalf("mutations_opt_in_default: %+v", item.Details)
			}
		case "update_lkg_residual":
			if item.Status != diagnostics.SelfCheckOK {
				t.Fatalf("update_lkg_residual status=%s msg=%s", item.Status, item.Message)
			}
			if item.Details["lkg_is_metadata_only"] != true || item.Details["residual_auto_install"] != false {
				t.Fatalf("update_lkg_residual details: %+v", item.Details)
			}
		case "fleet_telemetry_force_off_residual":
			if item.Status != diagnostics.SelfCheckOK {
				t.Fatalf("fleet_telemetry_force_off_residual status=%s msg=%s", item.Status, item.Message)
			}
			if item.Details["force_off_disables"] != true {
				t.Fatalf("force_off_disables: %+v", item.Details)
			}
		case "jenkins_resilience_residual":
			if item.Status != diagnostics.SelfCheckOK {
				t.Fatalf("jenkins_resilience_residual status=%s msg=%s", item.Status, item.Message)
			}
			if item.Details["get_head_retry_eligible"] != true {
				t.Fatalf("get_head_retry_eligible: %+v", item.Details)
			}
			if item.Details["post_auto_retry"] != false {
				t.Fatalf("POST must not be auto-retry eligible: %+v", item.Details)
			}
			if item.Details["circuit_breaker_present"] != true || item.Details["circuit_starts_closed"] != true {
				t.Fatalf("circuit details: %+v", item.Details)
			}
			if item.Details["residual_live_chaos"] != false || item.Details["residual_live_network_matrix"] != false {
				t.Fatalf("live residual honesty flags: %+v", item.Details)
			}
		}
	}
	for k, v := range need {
		if !v {
			t.Fatalf("missing self-check item %s", k)
		}
	}
	if caps == nil {
		t.Fatal("operator_caps_snapshot not found")
	}
	if origin == nil {
		t.Fatal("jenkins_origin_pin_residual not found")
	}
}

// TestWave52_SoftResidual_TrackB_MinAbsBackoffMsKeys progressive soft residual for
// Wave 52 Track B operator_caps min/absolute backoff ms honesty keys. If present →
// assert positive; if missing → t.Log only. Never fails for absence (Track B
// planned; not claimed Done* by Track D). Does not call missing package symbols.
func TestWave52_SoftResidual_TrackB_MinAbsBackoffMsKeys(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rep, err := diagnostics.RunSecuritySelfCheck(ctx, diagnostics.SelfCheckOptions{SkipSupportBundleCanary: true})
	if err != nil {
		t.Fatal(err)
	}

	var caps *diagnostics.SelfCheckItem
	for i := range rep.Items {
		if rep.Items[i].Name == "operator_caps_snapshot" {
			caps = &rep.Items[i]
			break
		}
	}
	if caps == nil || caps.Details == nil {
		t.Log("Wave 52 soft residual Track B: operator_caps_snapshot unavailable for optional key probe")
		return
	}

	progressivePositive := []string{
		"min_initial_backoff_ms",
		"min_max_backoff_ms",
		"absolute_max_initial_backoff_ms",
		"absolute_max_max_backoff_ms",
		"absolute_max_backoff_ms",
		"min_initial_backoff_milliseconds",
		"min_max_backoff_milliseconds",
		"absolute_max_initial_backoff_milliseconds",
		"absolute_max_max_backoff_milliseconds",
		"absolute_max_backoff_milliseconds",
	}

	found := 0
	seen := map[string]bool{}
	for _, k := range progressivePositive {
		v, ok := caps.Details[k]
		if !ok || seen[k] {
			continue
		}
		seen[k] = true
		found++
		t.Logf("Wave 52 progressive Track B: operator_caps key %s=%v", k, v)
		if !detailPositiveIntWave52(caps.Details, k) {
			t.Fatalf("Wave 52 Track B key %s present but non-positive: %+v", k, v)
		}
	}
	if found == 0 {
		t.Log("Wave 52 soft residual Track B: min/absolute backoff ms " +
			"operator_caps keys not yet present " +
			"(Track B planned/in progress; not a failure)")
	}
}

// TestWave52_SoftResidual_TrackA_C_MutationOperatorResolveNote records that Wave 52
// Tracks A/C mutation operator resolve (ResolveConfirmCooldown / EnvConfirmCooldown,
// ResolveMaxPreviewsPerMinute) are mutation-package concerns. Soft residual only;
// never fails for absence and never references those symbols (compile-safe).
func TestWave52_SoftResidual_TrackA_C_MutationOperatorResolveNote(t *testing.T) {
	t.Parallel()
	t.Log("Wave 52 soft residual (diagnostics): mutation_confirm_cooldown_residual " +
		"hard-asserted above; Track A ResolveConfirmCooldown / EnvConfirmCooldown and " +
		"Track C ResolveMaxPreviewsPerMinute operator resolve are mutation residuals " +
		"(planned/in progress; not claimed Done* by Track D; not a failure)")
}

func detailPositiveIntWave52(details map[string]any, key string) bool {
	if details == nil {
		return false
	}
	v, ok := details[key]
	if !ok {
		return false
	}
	switch n := v.(type) {
	case int:
		return n > 0
	case int64:
		return n > 0
	case float64:
		return n > 0
	default:
		return false
	}
}

func detailNonNegativeIntWave52(details map[string]any, key string) bool {
	if details == nil {
		return false
	}
	v, ok := details[key]
	if !ok {
		return false
	}
	switch n := v.(type) {
	case int:
		return n >= 0
	case int64:
		return n >= 0
	case float64:
		return n >= 0
	default:
		return false
	}
}

func asIntWave52(v any) (int, bool) {
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
