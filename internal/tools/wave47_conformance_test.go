package tools

import (
	"context"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/diagnostics"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
)

// Wave 47 / POL-005 + MCP-001 + NET-003 conformance (Track D):
//   - Hard-assert Wave 46 Done* MaxJSON resolve (jenkins.ResolveMaxJSONBodyBytes)
//     and operator_caps resilience keys (JSON body default/absolute, retries, circuit)
//   - Soft residual for Wave 47 Track B ResolveTargetBytes soft-budget operator_caps
//     keys — never fail if missing (Track B planned / not claimed Done*)

// TestWave47_Wave46Done_MaxJSONResolve_Hard hard-asserts Wave 46 Track A Done*:
// jenkins.ResolveMaxJSONBodyBytes default 32 MiB, absolute 128 MiB fail-closed,
// env name, and flag/env precedence. Must remain true after Wave 47 parallel merge.
func TestWave47_Wave46Done_MaxJSONResolve_Hard(t *testing.T) {
	t.Parallel()

	if jenkins.DefaultMaxJSONBodyBytes != 32<<20 {
		t.Fatalf("DefaultMaxJSONBodyBytes=%d want 32MiB", jenkins.DefaultMaxJSONBodyBytes)
	}
	if jenkins.AbsoluteMaxJSONBodyBytes != 128<<20 {
		t.Fatalf("AbsoluteMaxJSONBodyBytes=%d want 128MiB", jenkins.AbsoluteMaxJSONBodyBytes)
	}
	if jenkins.AbsoluteMaxJSONBodyBytes <= jenkins.DefaultMaxJSONBodyBytes {
		t.Fatalf("absolute %d must exceed default %d",
			jenkins.AbsoluteMaxJSONBodyBytes, jenkins.DefaultMaxJSONBodyBytes)
	}
	if jenkins.EnvMaxJSONBodyBytes != "JENKINS_MCP_MAX_JSON_BODY_BYTES" {
		t.Fatalf("env name drift: %q", jenkins.EnvMaxJSONBodyBytes)
	}

	n, err := jenkins.ResolveMaxJSONBodyBytes("", "")
	if err != nil || n != jenkins.DefaultMaxJSONBodyBytes {
		t.Fatalf("default resolve: n=%d err=%v want %d", n, err, jenkins.DefaultMaxJSONBodyBytes)
	}
	n, err = jenkins.ResolveMaxJSONBodyBytes("", "67108864") // 64 MiB env
	if err != nil || n != 64<<20 {
		t.Fatalf("env: n=%d err=%v", n, err)
	}
	n, err = jenkins.ResolveMaxJSONBodyBytes("50331648", "67108864") // flag wins
	if err != nil || n != 48<<20 {
		t.Fatalf("flag wins: n=%d err=%v", n, err)
	}
	n, err = jenkins.ResolveMaxJSONBodyBytes("0", "67108864")
	if err != nil || n != jenkins.DefaultMaxJSONBodyBytes {
		t.Fatalf("flag 0 → default: n=%d err=%v", n, err)
	}
	n, err = jenkins.ResolveMaxJSONBodyBytes("134217728", "") // at absolute
	if err != nil || n != jenkins.AbsoluteMaxJSONBodyBytes {
		t.Fatalf("at absolute: n=%d err=%v want %d", n, err, jenkins.AbsoluteMaxJSONBodyBytes)
	}
	if _, err := jenkins.ResolveMaxJSONBodyBytes("134217729", ""); err == nil { // 128MiB+1
		t.Fatal("above AbsoluteMaxJSONBodyBytes must fail closed")
	}
	if _, err := jenkins.ResolveMaxJSONBodyBytes("nope", ""); err == nil {
		t.Fatal("invalid parse must fail closed")
	}
}

// TestWave47_Wave46Done_OperatorCapsResilienceKeys_Hard hard-asserts Wave 46
// Track B Done*: operator_caps_snapshot carries Jenkins NET-003 resilience
// package constants (JSON body default/absolute, max retries, circuit threshold).
func TestWave47_Wave46Done_OperatorCapsResilienceKeys_Hard(t *testing.T) {
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
		t.Fatal("operator_caps_snapshot missing (Wave 43–46 Done* hard path)")
	}
	if caps.Status != diagnostics.SelfCheckOK {
		t.Fatalf("operator_caps_snapshot status=%s msg=%s", caps.Status, caps.Message)
	}

	for _, k := range []string{
		"default_max_json_body_bytes",
		"absolute_max_json_body_bytes",
		"default_circuit_failure_threshold",
		// Wave 45 retention still present
		"default_http_max_body_bytes",
		"absolute_max_http_max_body_bytes",
		// Wave 48 Track B absolute ceilings + open duration
		"absolute_max_retries",
		"absolute_max_circuit_failure_threshold",
		"default_circuit_open_duration_seconds",
	} {
		if !detailPositiveIntTools(caps.Details, k) {
			t.Fatalf("Wave 46 operator_caps key %s missing/non-positive: %+v", k, caps.Details[k])
		}
	}
	// Retries default is 2; allow non-negative (0 would mean no auto-retry).
	if !detailNonNegativeIntTools(caps.Details, "default_max_retries") {
		t.Fatalf("default_max_retries missing/negative: %+v", caps.Details["default_max_retries"])
	}
}

// TestWave47_SoftResidual_TrackB_TargetBytesKeys progressive soft residual for
// Wave 47 Track B ResolveTargetBytes soft budget + operator_caps keys.
// If present → assert non-negative/positive as appropriate; if missing → t.Log only.
// Never fails for absence (Track B planned; not claimed Done* by Track D).
func TestWave47_SoftResidual_TrackB_TargetBytesKeys(t *testing.T) {
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
		t.Log("Wave 47 soft residual Track B: operator_caps_snapshot unavailable for optional key probe")
		return
	}

	// Progressive keys Track B may add once ResolveTargetBytes soft budget lands.
	progressivePositive := []string{
		"default_target_bytes",
		"absolute_max_target_bytes",
		"target_bytes_soft_budget",
		"default_soft_target_bytes",
		"absolute_max_soft_target_bytes",
		"resolve_target_bytes",
		"soft_target_bytes",
	}
	// Non-negative (0 may mean unset / unlimited soft budget).
	progressiveNonNeg := []string{
		"target_bytes",
		"soft_budget_target_bytes",
	}

	found := 0
	for _, k := range progressivePositive {
		v, ok := caps.Details[k]
		if !ok {
			continue
		}
		found++
		t.Logf("Wave 47 progressive Track B: operator_caps key %s=%v", k, v)
		if !detailPositiveIntTools(caps.Details, k) {
			t.Fatalf("Wave 47 Track B key %s present but non-positive: %+v", k, v)
		}
	}
	for _, k := range progressiveNonNeg {
		v, ok := caps.Details[k]
		if !ok {
			continue
		}
		found++
		t.Logf("Wave 47 progressive Track B: operator_caps key %s=%v", k, v)
		if !detailNonNegativeIntTools(caps.Details, k) {
			t.Fatalf("Wave 47 Track B key %s present but negative: %+v", k, v)
		}
	}
	if found == 0 {
		t.Log("Wave 47 soft residual Track B: ResolveTargetBytes soft-budget " +
			"operator_caps keys not yet present (Track B planned/in progress; not a failure)")
	}
}

// TestWave47_TargetBytes_Hard hard-asserts Wave 47 Track B soft target resolve
// (absolute lifted Wave 51 Track C to AbsoluteMaxHardMaxBytes).
func TestWave47_TargetBytes_Hard(t *testing.T) {
	t.Parallel()
	if DefaultTargetBytes != 64*1024 {
		t.Fatalf("DefaultTargetBytes=%d", DefaultTargetBytes)
	}
	if AbsoluteMaxTargetBytes != AbsoluteMaxHardMaxBytes {
		t.Fatalf("AbsoluteMaxTargetBytes=%d want AbsoluteMaxHardMaxBytes=%d",
			AbsoluteMaxTargetBytes, AbsoluteMaxHardMaxBytes)
	}
	n, err := ResolveTargetBytes("", "")
	if err != nil || n != DefaultTargetBytes {
		t.Fatalf("default: n=%d err=%v", n, err)
	}
	n, err = ResolveTargetBytes("131072", "65536")
	if err != nil || n != 131072 {
		t.Fatalf("flag wins: n=%d err=%v", n, err)
	}
	if _, err := ResolveTargetBytes("999999999", ""); err == nil {
		t.Fatal("over absolute must fail closed")
	}
	if EnvTargetBytes != "JENKINS_MCP_TARGET_BYTES" {
		t.Fatalf("env name: %q", EnvTargetBytes)
	}
}
