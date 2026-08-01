package tools

import (
	"context"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/diagnostics"
)

// Wave 51 / POL-005 + MCP-001 + NET-003 + DIAG conformance (Track D + harden):
//   - Hard-assert Wave 50 Done* operator_caps absolute_max_concurrent + backoff
//     ms keys
//   - Hard-assert Wave 51 Track C AbsoluteMaxTargetBytes = AbsoluteMaxHardMaxBytes
//   - Hard-assert Wave 51 Track B operator_caps survey/diagnose ceiling keys

// TestWave51_Wave50Done_OperatorCapsAbsConcurrentBackoff_Hard hard-asserts
// Wave 50 Track B Done*: absolute_max_concurrent + default initial/max backoff
// ms keys present and well-formed offline, plus concurrent default 0 honesty
// retention. Must remain true after Wave 51 parallel tracks merge.
func TestWave51_Wave50Done_OperatorCapsAbsConcurrentBackoff_Hard(t *testing.T) {
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
		t.Fatal("operator_caps_snapshot missing (Wave 43–50 Done* hard path)")
	}
	if caps.Status != diagnostics.SelfCheckOK {
		t.Fatalf("operator_caps_snapshot status=%s msg=%s", caps.Status, caps.Message)
	}

	for _, k := range []string{
		// Wave 50 Track B absolute concurrent + backoff honesty
		"absolute_max_concurrent",
		"default_initial_backoff_ms",
		"default_max_backoff_ms",
		// Retention: Wave 49 circuit open min/absolute + open default
		"min_circuit_open_duration_seconds",
		"absolute_max_circuit_open_duration_seconds",
		"default_circuit_open_duration_seconds",
		// Retention: Wave 48 absolute resilience
		"absolute_max_retries",
		"absolute_max_circuit_failure_threshold",
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
			t.Fatalf("Wave 50/49/48/47/46 operator_caps key %s missing/non-positive: %+v", k, caps.Details[k])
		}
	}
	// Retries default is 2; allow non-negative (0 would mean no auto-retry).
	if !detailNonNegativeIntTools(caps.Details, "default_max_retries") {
		t.Fatalf("default_max_retries missing/negative: %+v", caps.Details["default_max_retries"])
	}
	// Wave 49/50: MaxConcurrent default 0 = unlimited honesty.
	if !detailNonNegativeIntTools(caps.Details, "default_max_concurrent") {
		t.Fatalf("default_max_concurrent missing/negative: %+v", caps.Details["default_max_concurrent"])
	}
	if n, ok := asIntTools(caps.Details["default_max_concurrent"]); !ok || n != 0 {
		t.Fatalf("default_max_concurrent want 0 (unlimited), got %+v", caps.Details["default_max_concurrent"])
	}
	if caps.Details["max_concurrent_unlimited_default"] != true {
		t.Fatalf("max_concurrent_unlimited_default: %+v", caps.Details["max_concurrent_unlimited_default"])
	}
	// Absolute concurrent ceiling must be 256 (Wave 50 Track A/B contract).
	if n, ok := asIntTools(caps.Details["absolute_max_concurrent"]); !ok || n != 256 {
		t.Fatalf("absolute_max_concurrent want 256, got %+v", caps.Details["absolute_max_concurrent"])
	}
	// Backoff defaults: initial 100 ms, max 5000 ms (Wave 50 Track B).
	if n, ok := asIntTools(caps.Details["default_initial_backoff_ms"]); !ok || n != 100 {
		t.Fatalf("default_initial_backoff_ms want 100, got %+v", caps.Details["default_initial_backoff_ms"])
	}
	if n, ok := asIntTools(caps.Details["default_max_backoff_ms"]); !ok || n != 5000 {
		t.Fatalf("default_max_backoff_ms want 5000, got %+v", caps.Details["default_max_backoff_ms"])
	}
	if caps.Details["live_target_bytes_available_offline"] != false {
		t.Fatalf("live_target_bytes_available_offline must be false offline: %+v", caps.Details)
	}
}

// TestWave51_TrackC_TargetBytesResolve_Hard hard-asserts Wave 51 Track C Done*:
// AbsoluteMaxTargetBytes = AbsoluteMaxHardMaxBytes (64 MiB), default 64 KiB,
// flag wins, fail-closed over absolute; former 1 MiB soft absolute still resolves.
func TestWave51_TrackC_TargetBytesResolve_Hard(t *testing.T) {
	t.Parallel()

	if DefaultTargetBytes != 64*1024 {
		t.Fatalf("DefaultTargetBytes=%d want 64KiB", DefaultTargetBytes)
	}
	if AbsoluteMaxHardMaxBytes != 64<<20 {
		t.Fatalf("AbsoluteMaxHardMaxBytes=%d want 64MiB", AbsoluteMaxHardMaxBytes)
	}
	if AbsoluteMaxTargetBytes != AbsoluteMaxHardMaxBytes {
		t.Fatalf("AbsoluteMaxTargetBytes=%d want AbsoluteMaxHardMaxBytes=%d",
			AbsoluteMaxTargetBytes, AbsoluteMaxHardMaxBytes)
	}
	if AbsoluteMaxTargetBytes != 64<<20 {
		t.Fatalf("AbsoluteMaxTargetBytes=%d want 64MiB", AbsoluteMaxTargetBytes)
	}
	if AbsoluteMaxTargetBytes < DefaultTargetBytes {
		t.Fatalf("absolute %d must be >= default %d",
			AbsoluteMaxTargetBytes, DefaultTargetBytes)
	}
	if EnvTargetBytes != "JENKINS_MCP_TARGET_BYTES" {
		t.Fatalf("env name drift: %q", EnvTargetBytes)
	}

	n, err := ResolveTargetBytes("", "")
	if err != nil || n != DefaultTargetBytes {
		t.Fatalf("default resolve: n=%d err=%v want %d", n, err, DefaultTargetBytes)
	}
	n, err = ResolveTargetBytes("", "131072") // 128 KiB env
	if err != nil || n != 131072 {
		t.Fatalf("env: n=%d err=%v", n, err)
	}
	n, err = ResolveTargetBytes("98304", "131072") // flag wins
	if err != nil || n != 98304 {
		t.Fatalf("flag wins: n=%d err=%v", n, err)
	}
	n, err = ResolveTargetBytes("0", "131072")
	if err != nil || n != DefaultTargetBytes {
		t.Fatalf("flag 0 → default: n=%d err=%v", n, err)
	}
	// Former 1 MiB soft absolute still resolves under 64 MiB.
	n, err = ResolveTargetBytes("1048576", "")
	if err != nil || n != 1048576 {
		t.Fatalf("former 1MiB soft abs: n=%d err=%v", n, err)
	}
	n, err = ResolveTargetBytes("1048577", "") // 1MiB+1
	if err != nil || n != 1048577 {
		t.Fatalf("above old 1MiB soft abs: n=%d err=%v", n, err)
	}
	n, err = ResolveTargetBytes("67108864", "") // at absolute (64 MiB)
	if err != nil || n != AbsoluteMaxTargetBytes {
		t.Fatalf("at absolute: n=%d err=%v want %d", n, err, AbsoluteMaxTargetBytes)
	}
	if _, err := ResolveTargetBytes("67108865", ""); err == nil {
		t.Fatal("above AbsoluteMaxTargetBytes must fail closed")
	}
	if _, err := ResolveTargetBytes("nope", ""); err == nil {
		t.Fatal("invalid parse must fail closed")
	}
}

// TestWave51_TrackB_SurveyDiagnoseCeilings_Hard hard-asserts Wave 51 Track B
// Done*: operator_caps survey/diagnose package hard ceiling keys are present
// offline and positive.
func TestWave51_TrackB_SurveyDiagnoseCeilings_Hard(t *testing.T) {
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
		t.Fatal("operator_caps_snapshot missing (Track B requires offline snapshot)")
	}

	for _, k := range []string{
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
		if !detailPositiveIntTools(caps.Details, k) {
			t.Fatalf("Wave 51 Track B operator_caps key %s missing/non-positive: %+v", k, caps.Details[k])
		}
	}
}
