package tools

import (
	"context"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/diagnostics"
)

// Wave 50 / POL-005 + MCP-001 + NET-003 conformance (Track D):
//   - Hard-assert Wave 49 Done* operator_caps open-duration min/abs + concurrent
//     default 0 honesty keys
//   - Soft residual for Wave 50 Track B operator_caps absolute_max_concurrent +
//     backoff ms honesty keys — never fail if missing (Track B planned /
//     not claimed Done* by Track D)

// TestWave50_Wave49Done_OperatorCapsOpenDuration_Hard hard-asserts Wave 49
// Track B Done*: min/absolute circuit open duration seconds and MaxConcurrent
// honesty (default 0 = unlimited). Must remain true after Wave 50 parallel
// tracks merge.
func TestWave50_Wave49Done_OperatorCapsOpenDuration_Hard(t *testing.T) {
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
		t.Fatal("operator_caps_snapshot missing (Wave 43–49 Done* hard path)")
	}
	if caps.Status != diagnostics.SelfCheckOK {
		t.Fatalf("operator_caps_snapshot status=%s msg=%s", caps.Status, caps.Message)
	}

	for _, k := range []string{
		// Wave 49 Track B circuit open min/absolute + open default retention
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
			t.Fatalf("Wave 49/48/47/46 operator_caps key %s missing/non-positive: %+v", k, caps.Details[k])
		}
	}
	// Retries default is 2; allow non-negative (0 would mean no auto-retry).
	if !detailNonNegativeIntTools(caps.Details, "default_max_retries") {
		t.Fatalf("default_max_retries missing/negative: %+v", caps.Details["default_max_retries"])
	}
	// Wave 49: MaxConcurrent default 0 = unlimited honesty.
	if !detailNonNegativeIntTools(caps.Details, "default_max_concurrent") {
		t.Fatalf("default_max_concurrent missing/negative: %+v", caps.Details["default_max_concurrent"])
	}
	if n, ok := asIntTools(caps.Details["default_max_concurrent"]); !ok || n != 0 {
		t.Fatalf("default_max_concurrent want 0 (unlimited), got %+v", caps.Details["default_max_concurrent"])
	}
	if caps.Details["max_concurrent_unlimited_default"] != true {
		t.Fatalf("max_concurrent_unlimited_default: %+v", caps.Details["max_concurrent_unlimited_default"])
	}
	if caps.Details["live_target_bytes_available_offline"] != false {
		t.Fatalf("live_target_bytes_available_offline must be false offline: %+v", caps.Details)
	}
}

// TestWave50_SoftResidual_TrackB_AbsoluteMaxConcurrentBackoff progressive soft
// residual for Wave 50 Track B operator_caps absolute_max_concurrent + backoff
// ms honesty keys. If present → assert non-negative/positive as appropriate;
// if missing → t.Log only. Never fails for absence (Track B planned; not
// claimed Done* by Track D).
func TestWave50_SoftResidual_TrackB_AbsoluteMaxConcurrentBackoff(t *testing.T) {
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
		t.Log("Wave 50 soft residual Track B: operator_caps_snapshot unavailable for optional key probe")
		return
	}

	// Progressive keys Track B may add once absolute max concurrent + backoff
	// honesty exposure lands (Wave 50 Track B).
	// Backoff durations (ms) must be positive when exposed.
	progressivePositive := []string{
		"default_initial_backoff_ms",
		"default_max_backoff_ms",
		"absolute_max_initial_backoff_ms",
		"absolute_max_backoff_ms",
		"min_initial_backoff_ms",
		"min_max_backoff_ms",
		"default_initial_backoff_milliseconds",
		"default_max_backoff_milliseconds",
		"absolute_max_initial_backoff_milliseconds",
		"absolute_max_backoff_milliseconds",
	}
	// Concurrent absolute: non-negative only (0 may mean unlimited ceiling residual).
	progressiveNonNeg := []string{
		"absolute_max_concurrent",
		"max_concurrent_absolute",
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
		t.Logf("Wave 50 progressive Track B: operator_caps key %s=%v", k, v)
		if !detailPositiveIntTools(caps.Details, k) {
			t.Fatalf("Wave 50 Track B key %s present but non-positive: %+v", k, v)
		}
	}
	for _, k := range progressiveNonNeg {
		v, ok := caps.Details[k]
		if !ok || seen[k] {
			continue
		}
		seen[k] = true
		found++
		t.Logf("Wave 50 progressive Track B: operator_caps key %s=%v", k, v)
		if !detailNonNegativeIntTools(caps.Details, k) {
			t.Fatalf("Wave 50 Track B key %s present but negative: %+v", k, v)
		}
	}
	if found == 0 {
		t.Log("Wave 50 soft residual Track B: absolute_max_concurrent / backoff " +
			"ms operator_caps keys not yet present " +
			"(Track B planned/in progress; not a failure)")
	}
}

func asIntTools(v any) (int, bool) {
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
