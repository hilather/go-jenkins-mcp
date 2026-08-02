package tools

import (
	"context"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/diagnostics"
)

// Wave 46 / POL-005 + MCP-001 + NET-003 conformance (Track D):
//   - Hard-assert Wave 45 Done* (operator_caps HTTP/TTL keys; jenkins_resilience_residual;
//     allowlist MinSignatures dual-control lite details)
//   - Soft residual for Wave 46 Track B operator_caps resilience constants
//     (JSON body default/absolute, retries, circuit threshold) — never fail if missing

// TestWave46_Wave45Done_OperatorCapsHTTPAndTTL_Hard hard-asserts Wave 45 Track B
// Done*: operator_caps_snapshot carries HTTP MaxBody + identity reverify TTL keys.
func TestWave46_Wave45Done_OperatorCapsHTTPAndTTL_Hard(t *testing.T) {
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
	if caps == nil {
		t.Fatal("operator_caps_snapshot missing (Wave 43–45 Done* hard path)")
	}
	if caps.Status != diagnostics.SelfCheckOK {
		t.Fatalf("operator_caps_snapshot status=%s msg=%s", caps.Status, caps.Message)
	}
	for _, k := range []string{
		// Wave 44 body-bytes still present
		"artifacts_list_body_bytes",
		"default_artifacts_list_body_bytes",
		"absolute_max_artifacts_list_body_bytes",
		// Wave 45 Track B HTTP + identity reverify TTL
		"default_http_max_body_bytes",
		"absolute_max_http_max_body_bytes",
		"min_identity_reverify_ttl_seconds",
		"max_identity_reverify_ttl_seconds",
		"default_identity_reverify_ttl_seconds",
	} {
		if !detailPositiveIntTools(caps.Details, k) {
			t.Fatalf("Wave 45 operator_caps key %s missing/non-positive: %+v", k, caps.Details[k])
		}
	}
}

// TestWave46_Wave45Done_JenkinsResilienceResidual_Hard hard-asserts Wave 45
// Track C Done*: jenkins_resilience_residual offline canary OK with GET/HEAD
// retry + circuit honesty and POST never auto-retry.
func TestWave46_Wave45Done_JenkinsResilienceResidual_Hard(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rep, err := diagnostics.RunSecuritySelfCheck(ctx, diagnostics.SelfCheckOptions{SkipSupportBundleCanary: true})
	if err != nil {
		t.Fatal(err)
	}

	var item *diagnostics.SelfCheckItem
	for i := range rep.Items {
		if rep.Items[i].Name == "jenkins_resilience_residual" {
			item = &rep.Items[i]
			break
		}
	}
	if item == nil {
		t.Fatal("jenkins_resilience_residual missing (Wave 45 Track C Done* hard path)")
	}
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

// TestWave46_Wave45Done_AllowlistMinSignatures_Hard hard-asserts Wave 45 Track A
// Done*: adapter_allowlist_provenance_lite reports MinSignatures dual-control lite.
func TestWave46_Wave45Done_AllowlistMinSignatures_Hard(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rep, err := diagnostics.RunSecuritySelfCheck(ctx, diagnostics.SelfCheckOptions{SkipSupportBundleCanary: true})
	if err != nil {
		t.Fatal(err)
	}

	var item *diagnostics.SelfCheckItem
	for i := range rep.Items {
		if rep.Items[i].Name == "adapter_allowlist_provenance_lite" {
			item = &rep.Items[i]
			break
		}
	}
	if item == nil {
		t.Fatal("adapter_allowlist_provenance_lite missing (Wave 44/45 Done* hard path)")
	}
	if item.Status != diagnostics.SelfCheckOK {
		t.Fatalf("adapter_allowlist_provenance_lite status=%s msg=%s", item.Status, item.Message)
	}
	if item.Details["allowlist_ed25519_lite"] != true {
		t.Fatalf("allowlist_ed25519_lite: %+v", item.Details)
	}
	if item.Details["allowlist_min_signatures_lite"] != true ||
		item.Details["min_signatures_2of2_verified"] != true ||
		item.Details["min_signatures_1of2_fail_closed"] != true {
		t.Fatalf("allowlist MinSignatures lite details: %+v", item.Details)
	}
	if item.Details["residual_cosign"] != false || item.Details["residual_hsm"] != false {
		t.Fatalf("allowlist residual honesty: %+v", item.Details)
	}
	if item.Details["residual_multi_party_provenance"] != false {
		t.Fatalf("residual_multi_party_provenance must stay false (lite only): %+v", item.Details)
	}
}

// TestWave46_TrackB_OperatorCapsResilienceKeys_Hard hard-asserts Wave 46 Track B
// operator_caps resilience constants (JSON body default/absolute, retries, circuit).
func TestWave46_TrackB_OperatorCapsResilienceKeys_Hard(t *testing.T) {
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
		t.Fatal("operator_caps_snapshot missing (Wave 43+ Done*)")
	}

	for _, k := range []string{
		"default_max_json_body_bytes",
		"absolute_max_json_body_bytes",
		"default_circuit_failure_threshold",
		// Wave 48 Track B
		"absolute_max_retries",
		"absolute_max_circuit_failure_threshold",
		"default_circuit_open_duration_seconds",
	} {
		if !detailPositiveIntTools(caps.Details, k) {
			t.Fatalf("Wave 46 Track B key %s missing/non-positive: %+v", k, caps.Details[k])
		}
	}
	// Retries default is 2; allow non-negative (0 would mean no auto-retry).
	if !detailNonNegativeIntTools(caps.Details, "default_max_retries") {
		t.Fatalf("default_max_retries missing/negative: %+v", caps.Details["default_max_retries"])
	}
}

func detailNonNegativeIntTools(details map[string]any, key string) bool {
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
