package diagnostics_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/diagnostics"
)

// Wave 45 / QA-005 + MCP-001 conformance (Track D):
//   - Hard-assert Wave 44 Done* self-check items (must pass on current main)
//   - Soft residual progressive for Wave 45 Track A MinSignatures dual-control
//     details and Track C jenkins_resilience_residual (if present → assert OK;
//     if missing → t.Log only — never fail when A/C not landed)

// TestWave45_Wave44Done_Hard hard-asserts Wave 44 Done*:
// operator_caps_snapshot, adapter_allowlist_provenance_lite, adapter_framework_residual
// present with OK status, secret-free details, and Wave 44 body-bytes keys.
func TestWave45_Wave44Done_Hard(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rep, err := diagnostics.RunSecuritySelfCheck(ctx, diagnostics.SelfCheckOptions{SkipSupportBundleCanary: true})
	if err != nil {
		t.Fatal(err)
	}

	need := map[string]bool{
		"operator_caps_snapshot":            false,
		"adapter_framework_residual":        false,
		"adapter_allowlist_provenance_lite": false,
		"policy_multisig_lite_residual":     false,
		"jenkins_resilience_residual":       false,
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
			if !strings.Contains(item.Message, "operator caps snapshot") {
				t.Fatalf("operator_caps_snapshot message: %s", item.Message)
			}
			// Wave 43–47 detail keys (positive ints).
			for _, k := range []string{
				"default_hard_max_bytes",
				"absolute_max_hard_max_bytes",
				// Wave 47 Track B soft target
				"default_target_bytes",
				"absolute_max_target_bytes",
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
				// Wave 46 Track B / NET-003 Jenkins resilience constants
				"default_max_json_body_bytes",
				"absolute_max_json_body_bytes",
				"default_max_retries",
				"default_circuit_failure_threshold",
			} {
				if !detailPositiveIntWave45(item.Details, k) {
					t.Fatalf("operator_caps_snapshot detail %s missing/non-positive: %+v", k, item.Details[k])
				}
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
		case "adapter_framework_residual":
			if item.Status != diagnostics.SelfCheckOK {
				t.Fatalf("adapter_framework_residual status=%s msg=%s", item.Status, item.Message)
			}
			if item.Details != nil {
				if item.Details["default_deny"] != true {
					t.Fatalf("adapter_framework_residual default_deny: %+v", item.Details)
				}
				if item.Details["production_otlp"] == true {
					t.Fatalf("adapter_framework_residual production_otlp must not claim true: %+v", item.Details)
				}
			}
		case "adapter_allowlist_provenance_lite":
			if item.Status != diagnostics.SelfCheckOK {
				t.Fatalf("adapter_allowlist_provenance_lite status=%s msg=%s", item.Status, item.Message)
			}
			if item.Details["allowlist_ed25519_lite"] != true {
				t.Fatalf("allowlist_ed25519_lite: %+v", item.Details)
			}
			// Wave 45 Track A MinSignatures dual-control lite.
			if item.Details["allowlist_min_signatures_lite"] != true ||
				item.Details["min_signatures_2of2_verified"] != true ||
				item.Details["min_signatures_1of2_fail_closed"] != true {
				t.Fatalf("allowlist MinSignatures lite details: %+v", item.Details)
			}
			if item.Details["residual_cosign"] != false || item.Details["residual_hsm"] != false {
				t.Fatalf("allowlist residual honesty: %+v", item.Details)
			}
			// True multi-party / cosign / HSM still residual even with MinSignatures lite.
			if item.Details["residual_multi_party_provenance"] != false {
				t.Fatalf("residual_multi_party_provenance must stay false (lite only): %+v", item.Details)
			}
			// Secret-free string canary on allowlist details.
			for k, v := range item.Details {
				if s, ok := v.(string); ok {
					lower := strings.ToLower(s)
					if strings.Contains(lower, "private") || strings.Contains(lower, "secret") ||
						strings.Contains(lower, "bearer ") || strings.Contains(lower, "-----begin") {
						t.Fatalf("adapter_allowlist_provenance_lite detail %s looks secret-bearing: %q", k, s)
					}
				}
			}
		case "policy_multisig_lite_residual":
			if item.Status != diagnostics.SelfCheckOK && item.Status != diagnostics.SelfCheckInfo {
				t.Fatalf("policy_multisig_lite_residual status=%s msg=%s", item.Status, item.Message)
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

// TestWave45_SoftResidual_TrackA_MinSignatures progressive soft residual for
// Wave 45 Track A allowlist MinSignatures dual-control lite.
// If adapter_allowlist grows MinSignatures detail keys or a dedicated canary
// appears → assert OK / residual honesty; if missing → t.Log only.
func TestWave45_SoftResidual_TrackA_MinSignatures(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rep, err := diagnostics.RunSecuritySelfCheck(ctx, diagnostics.SelfCheckOptions{SkipSupportBundleCanary: true})
	if err != nil {
		t.Fatal(err)
	}

	var (
		provenance *diagnostics.SelfCheckItem
		minSigItem *diagnostics.SelfCheckItem
	)
	for i := range rep.Items {
		item := &rep.Items[i]
		switch item.Name {
		case "adapter_allowlist_provenance_lite":
			provenance = item
		case "adapter_allowlist_minsignatures_lite",
			"adapter_allowlist_min_signatures_lite",
			"adapter_allowlist_dual_control_lite":
			minSigItem = item
		}
	}

	// Progressive: dedicated Track A self-check item.
	if minSigItem != nil {
		if minSigItem.Status != diagnostics.SelfCheckOK && minSigItem.Status != diagnostics.SelfCheckInfo {
			t.Fatalf("Track A MinSignatures canary %s status=%s msg=%s",
				minSigItem.Name, minSigItem.Status, minSigItem.Message)
		}
		t.Logf("Wave 45 progressive Track A: found canary %s status=%s", minSigItem.Name, minSigItem.Status)
	} else {
		t.Log("Wave 45 soft residual Track A: dedicated MinSignatures dual-control " +
			"self-check item not yet present (Track A planned/in progress; not a failure)")
	}

	// Progressive: MinSignatures-related detail keys on existing provenance canary.
	if provenance == nil || provenance.Details == nil {
		return
	}
	progressiveKeys := []string{
		"allowlist_min_signatures",
		"min_signatures",
		"min_signatures_lite",
		"dual_control_lite",
		"allowlist_dual_control_lite",
	}
	found := 0
	for _, k := range progressiveKeys {
		v, ok := provenance.Details[k]
		if !ok {
			continue
		}
		found++
		t.Logf("Wave 45 progressive Track A: provenance detail %s=%v", k, v)
		// If residual_multi_party_provenance flips to true without dual-control details, fail.
		// When dual-control lands, residual_multi_party may stay false if still incomplete —
		// only assert secret-free types.
		switch v.(type) {
		case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float64, bool, string:
			// ok
		default:
			t.Fatalf("Track A detail %s type %T not secret-free scalar: %v", k, v, v)
		}
	}
	if found == 0 && minSigItem == nil {
		// Wave 44 honesty still documents residual multi-party provenance.
		if provenance.Details["residual_multi_party_provenance"] != false {
			t.Fatalf("without Track A dual-control, residual_multi_party_provenance must stay false: %+v",
				provenance.Details)
		}
		t.Log("Wave 45 soft residual Track A: no MinSignatures dual-control details yet " +
			"(residual_multi_party_provenance=false as Wave 44 honesty)")
	}
}

// TestWave45_SoftResidual_TrackC_JenkinsResilience progressive soft residual for
// Wave 45 Track C NET-003 offline canary jenkins_resilience_residual.
// If present → assert OK/Info (not Fail); if missing → t.Log only.
func TestWave45_SoftResidual_TrackC_JenkinsResilience(t *testing.T) {
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
		case "jenkins_resilience_residual",
			"jenkins_resilience_offline",
			"net003_resilience_residual":
			item = &rep.Items[i]
		}
	}
	if item == nil {
		t.Log("Wave 45 soft residual Track C: jenkins_resilience_residual not yet present " +
			"(Track C planned/in progress; not a failure)")
		return
	}
	if item.Status != diagnostics.SelfCheckOK && item.Status != diagnostics.SelfCheckInfo &&
		item.Status != diagnostics.SelfCheckWarn {
		t.Fatalf("jenkins_resilience canary %s status=%s msg=%s", item.Name, item.Status, item.Message)
	}
	// Secret-free canary on details.
	for k, v := range item.Details {
		if s, ok := v.(string); ok {
			lower := strings.ToLower(s)
			if strings.Contains(lower, "private") || strings.Contains(lower, "secret") ||
				strings.Contains(lower, "bearer ") || strings.Contains(lower, "-----begin") {
				t.Fatalf("%s detail %s looks secret-bearing: %q", item.Name, k, s)
			}
		}
	}
	t.Logf("Wave 45 progressive Track C: found %s status=%s", item.Name, item.Status)
}

func detailPositiveIntWave45(details map[string]any, key string) bool {
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
