package tools

import (
	"context"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/diagnostics"
)

// Wave 49 / POL-005 + MCP-001 + NET-003 conformance (Track D):
//   - Hard-assert Wave 48 Done* operator_caps absolute_max_retries + circuit
//     absolute + open duration default keys
//   - Soft residual for Wave 49 Track B operator_caps circuit open min/absolute
//     + max concurrent honesty keys — never fail if missing (Track B planned /
//     not claimed Done* by Track D)

// TestWave49_Wave48Done_OperatorCapsAbsResilience_Hard hard-asserts Wave 48
// Track B Done*: absolute_max_retries, absolute_max_circuit_failure_threshold,
// and default_circuit_open_duration_seconds are present and positive offline.
// Must remain true after Wave 49 parallel tracks merge.
func TestWave49_Wave48Done_OperatorCapsAbsResilience_Hard(t *testing.T) {
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
		t.Fatal("operator_caps_snapshot missing (Wave 43–48 Done* hard path)")
	}
	if caps.Status != diagnostics.SelfCheckOK {
		t.Fatalf("operator_caps_snapshot status=%s msg=%s", caps.Status, caps.Message)
	}

	for _, k := range []string{
		// Wave 48 Track B absolute resilience + open duration default
		"absolute_max_retries",
		"absolute_max_circuit_failure_threshold",
		"default_circuit_open_duration_seconds",
		// Retention: Wave 47 soft target + Wave 46 resilience defaults
		"default_target_bytes",
		"absolute_max_target_bytes",
		"default_max_json_body_bytes",
		"absolute_max_json_body_bytes",
		"default_circuit_failure_threshold",
		"default_http_max_body_bytes",
		"absolute_max_http_max_body_bytes",
	} {
		if !detailPositiveIntTools(caps.Details, k) {
			t.Fatalf("Wave 48/47/46 operator_caps key %s missing/non-positive: %+v", k, caps.Details[k])
		}
	}
	// Retries default is 2; allow non-negative (0 would mean no auto-retry).
	if !detailNonNegativeIntTools(caps.Details, "default_max_retries") {
		t.Fatalf("default_max_retries missing/negative: %+v", caps.Details["default_max_retries"])
	}
	if caps.Details["live_target_bytes_available_offline"] != false {
		t.Fatalf("live_target_bytes_available_offline must be false offline: %+v", caps.Details)
	}
}

// TestWave49_SoftResidual_TrackB_CircuitOpenMinAbsMaxConcurrent progressive soft
// residual for Wave 49 Track B operator_caps circuit open min/absolute duration
// and max concurrent honesty keys. If present → assert non-negative/positive as
// appropriate; if missing → t.Log only. Never fails for absence (Track B planned;
// not claimed Done* by Track D).
func TestWave49_SoftResidual_TrackB_CircuitOpenMinAbsMaxConcurrent(t *testing.T) {
	t.Parallel()
	// Soft residual graduated after Track B merge — hard asserts live in
	// TestWave49_OperatorCapsOpenDuration_Hard / diagnostics hard path.
	t.Log("Wave 49 Track B soft residual graduated; see hard operator_caps open-duration tests")
}

// TestWave49_OperatorCapsOpenDuration_Hard hard-asserts Wave 49 Track B circuit open min/abs + concurrent honesty.
func TestWave49_OperatorCapsOpenDuration_Hard(t *testing.T) {
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
		t.Fatal("operator_caps_snapshot missing")
	}
	for _, k := range []string{"min_circuit_open_duration_seconds", "absolute_max_circuit_open_duration_seconds"} {
		if !detailPositiveIntTools(caps.Details, k) {
			t.Fatalf("%s: %+v", k, caps.Details[k])
		}
	}
	if !detailNonNegativeIntTools(caps.Details, "default_max_concurrent") {
		t.Fatalf("default_max_concurrent: %+v", caps.Details["default_max_concurrent"])
	}
	if caps.Details["max_concurrent_unlimited_default"] != true {
		t.Fatalf("max_concurrent_unlimited_default: %+v", caps.Details)
	}
}
