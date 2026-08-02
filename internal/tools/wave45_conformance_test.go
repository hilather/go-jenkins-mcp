package tools

import (
	"context"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/diagnostics"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
)

// Wave 45 / POL-005 + MCP-001 conformance (Track D):
//   - Hard-assert Wave 44 Done* artifact list body-bytes resolve + constants
//   - Soft residual for Wave 45 Track B operator_caps keys (HTTP body +
//     identity reverify TTL) via diagnostics when present — never fail if missing

// TestWave45_ArtifactsListBodyBytes_Hard hard-asserts Wave 44 Done*:
// ResolveArtifactsListBodyBytes default 2 MiB, absolute 8 MiB fail-closed,
// env name, and jenkins body constants still hold after Wave 45 merge work.
func TestWave45_ArtifactsListBodyBytes_Hard(t *testing.T) {
	t.Parallel()

	if jenkins.DefaultArtifactListBodyBytes != 2<<20 {
		t.Fatalf("DefaultArtifactListBodyBytes=%d want 2MiB", jenkins.DefaultArtifactListBodyBytes)
	}
	if jenkins.AbsoluteMaxArtifactListBodyBytes != 8<<20 {
		t.Fatalf("AbsoluteMaxArtifactListBodyBytes=%d want 8MiB", jenkins.AbsoluteMaxArtifactListBodyBytes)
	}
	if jenkins.AbsoluteMaxArtifactListBodyBytes <= jenkins.DefaultArtifactListBodyBytes {
		t.Fatalf("absolute %d must exceed default %d",
			jenkins.AbsoluteMaxArtifactListBodyBytes, jenkins.DefaultArtifactListBodyBytes)
	}

	n, err := ResolveArtifactsListBodyBytes("", "")
	if err != nil || n != jenkins.DefaultArtifactListBodyBytes {
		t.Fatalf("default: n=%d err=%v want %d", n, err, jenkins.DefaultArtifactListBodyBytes)
	}
	n, err = ResolveArtifactsListBodyBytes("", "3145728")
	if err != nil || n != 3145728 {
		t.Fatalf("env: n=%d err=%v", n, err)
	}
	n, err = ResolveArtifactsListBodyBytes("2097152", "4194304")
	if err != nil || n != 2097152 {
		t.Fatalf("flag wins: n=%d err=%v", n, err)
	}
	n, err = ResolveArtifactsListBodyBytes("8388608", "")
	if err != nil || n != jenkins.AbsoluteMaxArtifactListBodyBytes {
		t.Fatalf("absolute max accepted: n=%d err=%v want %d", n, err, jenkins.AbsoluteMaxArtifactListBodyBytes)
	}
	if _, err := ResolveArtifactsListBodyBytes("8388609", ""); err == nil {
		t.Fatal("above AbsoluteMaxArtifactListBodyBytes must fail closed")
	}
	if _, err := ResolveArtifactsListBodyBytes("nope", ""); err == nil {
		t.Fatal("invalid parse must fail closed")
	}
	if EnvArtifactsListBodyBytes != "JENKINS_MCP_ARTIFACTS_LIST_BODY_BYTES" {
		t.Fatalf("env name drift: %q", EnvArtifactsListBodyBytes)
	}
	if jenkins.ArtifactListBodyBytes() <= 0 {
		t.Fatalf("ArtifactListBodyBytes live=%d", jenkins.ArtifactListBodyBytes())
	}
}

// TestWave45_ArtifactsHardCap_StillHard re-asserts Wave 42–44 hard-cap resolve
// still present (regression guard while Wave 45 tracks land elsewhere).
func TestWave45_ArtifactsHardCap_StillHard(t *testing.T) {
	t.Parallel()

	n, err := ResolveArtifactsHardCap("", "")
	if err != nil || n != jenkins.DefaultArtifactsHardCap {
		t.Fatalf("default: n=%d err=%v want %d", n, err, jenkins.DefaultArtifactsHardCap)
	}
	if _, err := ResolveArtifactsHardCap("2001", ""); err == nil {
		t.Fatal("above AbsoluteMaxArtifactsHardCap must fail closed")
	}
	if ArtifactsHardCap() <= 0 {
		t.Fatalf("ArtifactsHardCap=%d", ArtifactsHardCap())
	}
}

// TestWave45_OperatorCapsBodyBytes_Hard re-asserts Wave 44 Track B Done*
// body-bytes keys remain on operator_caps_snapshot (tools → diagnostics canary).
func TestWave45_OperatorCapsBodyBytes_Hard(t *testing.T) {
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
		t.Fatal("operator_caps_snapshot missing (Wave 43/44 Done* hard path)")
	}
	if caps.Status != diagnostics.SelfCheckOK {
		t.Fatalf("operator_caps_snapshot status=%s msg=%s", caps.Status, caps.Message)
	}
	for _, k := range []string{
		"artifacts_list_body_bytes",
		"default_artifacts_list_body_bytes",
		"absolute_max_artifacts_list_body_bytes",
	} {
		if !detailPositiveIntTools(caps.Details, k) {
			t.Fatalf("Wave 44 body-bytes key %s missing/non-positive: %+v", k, caps.Details[k])
		}
	}
}

// TestWave45_SoftResidual_TrackB_OperatorCapsKeys soft-probes Wave 45 Track B
// planned operator_caps keys (HTTP MaxBodyBytes + identity reverify TTL constants).
// Progressive: if present → hard-assert positive/int; if missing → t.Log only.
// Must never fail when Track B has not landed.
func TestWave45_SoftResidual_TrackB_OperatorCapsKeys(t *testing.T) {
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
		t.Log("Wave 45 soft residual Track B: operator_caps_snapshot unavailable for optional key probe")
		return
	}

	// Planned Track B keys (HTTP body + identity reverify TTL + Wave 46 NET-003).
	// Soft only — absence is expected until corresponding Track B merges.
	optionalPositive := []string{
		"http_max_body_bytes",
		"default_http_max_body_bytes",
		"absolute_max_http_max_body_bytes",
		"identity_reverify_ttl_seconds",
		"default_identity_reverify_ttl_seconds",
		"min_identity_reverify_ttl_seconds",
		"max_identity_reverify_ttl_seconds",
		// Alternate spellings some Track B PRs may use:
		"identity_reverify_ttl",
		"default_identity_reverify_ttl",
		// Wave 46 Track B / NET-003 Jenkins resilience constants.
		"default_max_json_body_bytes",
		"absolute_max_json_body_bytes",
		"default_max_retries",
		"default_circuit_failure_threshold",
	}
	found := 0
	for _, k := range optionalPositive {
		if _, ok := caps.Details[k]; !ok {
			continue
		}
		found++
		if !detailPositiveIntTools(caps.Details, k) {
			// Present but non-positive is a real regression once Track B lands.
			t.Fatalf("Wave 45 Track B key %s present but non-positive: %+v", k, caps.Details[k])
		}
		t.Logf("Wave 45 progressive Track B: operator_caps key %s present and positive", k)
	}
	if found == 0 {
		t.Log("Wave 45 soft residual Track B: HTTP body / identity reverify TTL " +
			"operator_caps keys not yet present (Track B planned/in progress; not a failure)")
	}
}

func detailPositiveIntTools(details map[string]any, key string) bool {
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
