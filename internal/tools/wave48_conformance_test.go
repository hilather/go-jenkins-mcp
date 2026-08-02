package tools

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/diagnostics"
)

// Wave 48 / POL-005 + MCP-001 + NET-003 conformance (Track D):
//   - Hard-assert Wave 47 Done* TargetBytes resolve + operator_caps soft-target keys
//   - Soft residual for Wave 48 Track B absolute retries/circuit/open-duration
//     operator_caps keys — never fail if missing (Track B planned / not claimed Done*)

// TestWave48_Wave47Done_TargetBytesResolve_Hard hard-asserts Wave 47 Track B
// Done* (absolute lifted Wave 51 Track C): ResolveTargetBytes default 64 KiB,
// absolute 64 MiB (= AbsoluteMaxHardMaxBytes), env name, flag/env precedence,
// fail-closed over absolute. Must remain true after parallel track merges.
func TestWave48_Wave47Done_TargetBytesResolve_Hard(t *testing.T) {
	t.Parallel()

	if DefaultTargetBytes != 64*1024 {
		t.Fatalf("DefaultTargetBytes=%d want 64KiB", DefaultTargetBytes)
	}
	if AbsoluteMaxTargetBytes != AbsoluteMaxHardMaxBytes {
		t.Fatalf("AbsoluteMaxTargetBytes=%d want AbsoluteMaxHardMaxBytes=%d",
			AbsoluteMaxTargetBytes, AbsoluteMaxHardMaxBytes)
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
	// Former soft absolute (1 MiB) still resolves (now well under 64 MiB).
	n, err = ResolveTargetBytes("1048576", "")
	if err != nil || n != 1048576 {
		t.Fatalf("1 MiB target: n=%d err=%v", n, err)
	}
	// At new absolute (64 MiB).
	n, err = ResolveTargetBytes(strconv.Itoa(AbsoluteMaxTargetBytes), "")
	if err != nil || n != AbsoluteMaxTargetBytes {
		t.Fatalf("at absolute: n=%d err=%v want %d", n, err, AbsoluteMaxTargetBytes)
	}
	if _, err := ResolveTargetBytes(strconv.Itoa(AbsoluteMaxTargetBytes+1), ""); err == nil {
		t.Fatal("above AbsoluteMaxTargetBytes must fail closed")
	}
	if _, err := ResolveTargetBytes("nope", ""); err == nil {
		t.Fatal("invalid parse must fail closed")
	}
}

// TestWave48_Wave47Done_OperatorCapsTargetKeys_Hard hard-asserts Wave 47 Track B
// Done*: operator_caps_snapshot carries soft-target offline constants and
// retains Wave 46 resilience keys (retries non-negative, circuit positive).
func TestWave48_Wave47Done_OperatorCapsTargetKeys_Hard(t *testing.T) {
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
		t.Fatal("operator_caps_snapshot missing (Wave 43–47 Done* hard path)")
	}
	if caps.Status != diagnostics.SelfCheckOK {
		t.Fatalf("operator_caps_snapshot status=%s msg=%s", caps.Status, caps.Message)
	}

	for _, k := range []string{
		// Wave 47 Track B soft target offline constants
		"default_target_bytes",
		"absolute_max_target_bytes",
		// Wave 46 resilience retention
		"default_max_json_body_bytes",
		"absolute_max_json_body_bytes",
		"default_circuit_failure_threshold",
		// HTTP retention
		"default_http_max_body_bytes",
		"absolute_max_http_max_body_bytes",
	} {
		if !detailPositiveIntTools(caps.Details, k) {
			t.Fatalf("Wave 47/46 operator_caps key %s missing/non-positive: %+v", k, caps.Details[k])
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

// TestWave48_SoftResidual_TrackB_AbsoluteRetriesCircuitKeys progressive soft
// residual for Wave 48 Track B operator_caps absolute retries / circuit /
// open-duration keys. If present → assert non-negative/positive as appropriate;
// if missing → t.Log only. Never fails for absence (Track B planned; not
// claimed Done* by Track D).
func TestWave48_SoftResidual_TrackB_AbsoluteRetriesCircuitKeys(t *testing.T) {
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
		t.Log("Wave 48 soft residual Track B: operator_caps_snapshot unavailable for optional key probe")
		return
	}

	// Progressive keys Track B may add once absolute retries/circuit/open-duration
	// operator_caps exposure lands (Wave 48–49 Track B keys included).
	progressivePositive := []string{
		"absolute_max_retries",
		"absolute_max_circuit_failure_threshold",
		"default_circuit_open_duration_seconds",
		"absolute_max_circuit_open_duration_seconds",
		"min_circuit_open_duration_seconds",
		"circuit_open_duration_seconds",
		"absolute_circuit_failure_threshold",
		"default_circuit_open_duration_ms",
		"absolute_max_circuit_open_duration_ms",
	}
	// Non-negative only (0 may mean unset / unlimited depending on knob semantics).
	progressiveNonNeg := []string{
		"circuit_open_duration",
		"default_max_concurrent",
	}

	found := 0
	for _, k := range progressivePositive {
		v, ok := caps.Details[k]
		if !ok {
			continue
		}
		found++
		t.Logf("Wave 48 progressive Track B: operator_caps key %s=%v", k, v)
		if !detailPositiveIntTools(caps.Details, k) {
			t.Fatalf("Wave 48 Track B key %s present but non-positive: %+v", k, v)
		}
	}
	for _, k := range progressiveNonNeg {
		v, ok := caps.Details[k]
		if !ok {
			continue
		}
		found++
		t.Logf("Wave 48 progressive Track B: operator_caps key %s=%v", k, v)
		if !detailNonNegativeIntTools(caps.Details, k) {
			t.Fatalf("Wave 48 Track B key %s present but negative: %+v", k, v)
		}
	}
	if found == 0 {
		t.Log("Wave 48 soft residual Track B: absolute_max_retries / circuit " +
			"open-duration operator_caps keys not yet present " +
			"(Track B planned/in progress; not a failure)")
	}
}

// TestWave48_OperatorCapsAbsResilience_Hard hard-asserts Wave 48 Track B absolute keys
// and Wave 49 Track B circuit-open min/absolute + MaxConcurrent honesty keys.
func TestWave48_OperatorCapsAbsResilience_Hard(t *testing.T) {
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
	for _, k := range []string{
		"absolute_max_retries",
		"absolute_max_circuit_failure_threshold",
		"default_circuit_open_duration_seconds",
		// Wave 49 Track B
		"min_circuit_open_duration_seconds",
		"absolute_max_circuit_open_duration_seconds",
	} {
		if !detailPositiveIntTools(caps.Details, k) {
			t.Fatalf("%s missing/non-positive: %+v", k, caps.Details[k])
		}
	}
	if !detailNonNegativeIntTools(caps.Details, "default_max_concurrent") {
		t.Fatalf("default_max_concurrent missing/negative: %+v", caps.Details["default_max_concurrent"])
	}
	if caps.Details["max_concurrent_unlimited_default"] != true {
		t.Fatalf("max_concurrent_unlimited_default must be true: %+v", caps.Details)
	}
}
