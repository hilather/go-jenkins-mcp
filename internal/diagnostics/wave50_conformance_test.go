package diagnostics_test

import (
	"context"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/diagnostics"
)

// Wave 50 / QA-005 + MCP-001 + NET-003 + MUT-001 + NET-001 conformance (Track D):
//   - Hard-assert Wave 49 Done* self-check items (mutation_confirm_cooldown_residual
//     + operator_caps open-duration min/abs + concurrent default 0) — must pass
//     on current main
//   - Soft residual progressive for Wave 50 Track C origin pin residual canary
//     (if present → assert; if missing → t.Log only — never fail when C not landed)

// TestWave50_Wave49Done_Hard hard-asserts Wave 49 Done*:
// mutation_confirm_cooldown_residual, operator_caps_snapshot (incl. open-duration
// min/abs + concurrent honesty), and related retention canaries.
func TestWave50_Wave49Done_Hard(t *testing.T) {
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
			// Wave 43–49 detail keys (positive ints) including Wave 49 open duration.
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
				"absolute_max_concurrent",
				"default_initial_backoff_ms",
				"default_max_backoff_ms",
			} {
				if !detailPositiveIntWave50(item.Details, k) {
					t.Fatalf("operator_caps_snapshot detail %s missing/non-positive: %+v", k, item.Details[k])
				}
			}
			// Retries ≥ 0 (0 disables auto-retry).
			if !detailNonNegativeIntWave50(item.Details, "default_max_retries") {
				t.Fatalf("default_max_retries missing/negative: %+v", item.Details["default_max_retries"])
			}
			// Wave 49: MaxConcurrent default 0 = unlimited.
			if !detailNonNegativeIntWave50(item.Details, "default_max_concurrent") {
				t.Fatalf("default_max_concurrent missing/negative: %+v", item.Details["default_max_concurrent"])
			}
			if n, ok := asIntWave50(item.Details["default_max_concurrent"]); !ok || n != 0 {
				t.Fatalf("default_max_concurrent want 0 (unlimited), got %+v", item.Details["default_max_concurrent"])
			}
			if item.Details["max_concurrent_unlimited_default"] != true {
				t.Fatalf("max_concurrent_unlimited_default must be true: %+v", item.Details)
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
}

// TestWave50_SoftResidual_TrackC_OriginPin progressive soft residual for Wave 50
// Track C jenkins_origin_pin residual offline self-check canary. If present →
// assert OK/Info/Warn (not Fail) + secret-free details; if missing → t.Log only.
// Never fails for absence (Track C planned; not claimed Done* by Track D).
func TestWave50_SoftResidual_TrackC_OriginPin(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rep, err := diagnostics.RunSecuritySelfCheck(ctx, diagnostics.SelfCheckOptions{SkipSupportBundleCanary: true})
	if err != nil {
		t.Fatal(err)
	}

	var item *diagnostics.SelfCheckItem
	for i := range rep.Items {
		switch rep.Items[i].Name {
		case "jenkins_origin_pin_residual",
			"origin_pin_residual",
			"jenkins_origin_pin",
			"net001_origin_pin_residual",
			"origin_pin_canary":
			item = &rep.Items[i]
		}
	}
	if item == nil {
		t.Log("Wave 50 soft residual Track C: jenkins_origin_pin_residual not yet present " +
			"(Track C planned/in progress; not a failure)")
		return
	}

	t.Logf("Wave 50 progressive Track C: self-check item %s status=%s", item.Name, item.Status)
	switch item.Status {
	case diagnostics.SelfCheckOK, diagnostics.SelfCheckInfo, diagnostics.SelfCheckWarn:
		// acceptable offline residual honesty
	case diagnostics.SelfCheckFail:
		t.Fatalf("Wave 50 Track C origin pin residual present but Fail: msg=%s details=%+v",
			item.Message, item.Details)
	default:
		t.Fatalf("Wave 50 Track C origin pin residual unexpected status=%s", item.Status)
	}
	// Secret-free: integer/bool details only when details present.
	for k, v := range item.Details {
		switch v.(type) {
		case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float64, bool:
			// ok
		case string:
			// Short non-secret reason codes are allowed for residual canaries.
			if len(v.(string)) > 256 {
				t.Fatalf("origin pin residual detail %s string too long (possible leak): %d", k, len(v.(string)))
			}
		default:
			t.Fatalf("origin pin residual detail %s type %T not secret-free: %v", k, v, v)
		}
	}
}

func detailPositiveIntWave50(details map[string]any, key string) bool {
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

func detailNonNegativeIntWave50(details map[string]any, key string) bool {
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

func asIntWave50(v any) (int, bool) {
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
