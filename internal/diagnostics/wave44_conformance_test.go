package diagnostics_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/diagnostics"
)

// Wave 44 / QA-005 + MCP-001 conformance (Track D):
//   - Hard-assert Wave 43 Done* self-check items (must pass on current main)
//   - Soft residual probes for Wave 44 Track A/B items when present:
//     adapter_allowlist_provenance_lite; operator_caps artifacts_list_body_bytes
//     Soft residual logs when missing; hard-asserts when landed (progressive).

// TestWave44_OperatorCapsAndAdapter_Hard hard-asserts Wave 43 Done*:
// operator_caps_snapshot and adapter_framework_residual present with OK status,
// secret-free details, and policy_multisig_lite_residual still present.
func TestWave44_OperatorCapsAndAdapter_Hard(t *testing.T) {
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
		"policy_multisig_lite_residual":     false,
		"adapter_allowlist_provenance_lite": false,
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
			// Wave 43 + Wave 44 Track B required detail keys (positive ints).
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
				// Wave 45 Track B: HTTP body + identity re-verify TTL constants.
				"default_http_max_body_bytes",
				"absolute_max_http_max_body_bytes",
				"min_identity_reverify_ttl_seconds",
				"max_identity_reverify_ttl_seconds",
				"default_identity_reverify_ttl_seconds",
				// Wave 46 Track B / NET-003 Jenkins resilience constants.
				"default_max_json_body_bytes",
				"absolute_max_json_body_bytes",
				"default_max_retries",
				"default_circuit_failure_threshold",
			} {
				if !detailPositiveInt(item.Details, k) {
					t.Fatalf("operator_caps_snapshot detail %s missing/non-positive: %+v", k, item.Details[k])
				}
			}
			if item.Details["live_hard_max_available_offline"] != false {
				t.Fatalf("live_hard_max_available_offline must be false offline: %+v", item.Details)
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
			// Residual honesty booleans (Wave 43 Done*).
			if item.Details != nil {
				if item.Details["default_deny"] != true {
					t.Fatalf("adapter_framework_residual default_deny: %+v", item.Details)
				}
				if item.Details["production_otlp"] == true {
					t.Fatalf("adapter_framework_residual production_otlp must not claim true: %+v", item.Details)
				}
			}
		case "policy_multisig_lite_residual":
			if item.Status != diagnostics.SelfCheckOK && item.Status != diagnostics.SelfCheckInfo {
				t.Fatalf("policy_multisig_lite_residual status=%s msg=%s", item.Status, item.Message)
			}
		case "adapter_allowlist_provenance_lite":
			if item.Status != diagnostics.SelfCheckOK {
				t.Fatalf("adapter_allowlist_provenance_lite status=%s msg=%s", item.Status, item.Message)
			}
			if item.Details["allowlist_ed25519_lite"] != true {
				t.Fatalf("allowlist_ed25519_lite: %+v", item.Details)
			}
			if item.Details["residual_cosign"] != false || item.Details["residual_hsm"] != false {
				t.Fatalf("allowlist residual honesty: %+v", item.Details)
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

// TestWave44_TrackAB_Hard re-asserts Wave 44 Track A/B Done* after merge
// (allowlist provenance lite + operator_caps body-bytes fields).
func TestWave44_TrackAB_Hard(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rep, err := diagnostics.RunSecuritySelfCheck(ctx, diagnostics.SelfCheckOptions{SkipSupportBundleCanary: true})
	if err != nil {
		t.Fatal(err)
	}

	var (
		provenance *diagnostics.SelfCheckItem
		caps       *diagnostics.SelfCheckItem
	)
	for i := range rep.Items {
		item := &rep.Items[i]
		switch item.Name {
		case "adapter_allowlist_provenance_lite":
			provenance = item
		case "operator_caps_snapshot":
			caps = item
		}
	}

	if provenance == nil {
		t.Fatal("adapter_allowlist_provenance_lite missing (Wave 44 Track A Done*)")
	}
	if provenance.Status != diagnostics.SelfCheckOK {
		t.Fatalf("adapter_allowlist_provenance_lite status=%s msg=%s", provenance.Status, provenance.Message)
	}
	for k, v := range provenance.Details {
		if s, ok := v.(string); ok {
			lower := strings.ToLower(s)
			if strings.Contains(lower, "private") || strings.Contains(lower, "secret") ||
				strings.Contains(lower, "bearer ") || strings.Contains(lower, "-----begin") {
				t.Fatalf("adapter_allowlist_provenance_lite detail %s looks secret-bearing: %q", k, s)
			}
		}
	}

	if caps == nil {
		t.Fatal("operator_caps_snapshot missing (Wave 43 Done* hard path)")
	}
	if !detailPositiveInt(caps.Details, "artifacts_list_body_bytes") {
		t.Fatalf("Wave 44 Track B: artifacts_list_body_bytes missing/non-positive: %+v", caps.Details)
	}
	if !detailPositiveInt(caps.Details, "absolute_max_artifacts_list_body_bytes") {
		t.Fatalf("Wave 44 Track B: absolute_max_artifacts_list_body_bytes missing: %+v", caps.Details)
	}
	if !detailPositiveInt(caps.Details, "default_artifacts_list_body_bytes") {
		t.Fatalf("Wave 44 Track B: default_artifacts_list_body_bytes missing: %+v", caps.Details)
	}
}

func detailPositiveInt(details map[string]any, key string) bool {
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
