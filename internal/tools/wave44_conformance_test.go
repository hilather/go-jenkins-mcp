package tools

import (
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
)

// Wave 44 / POL-005 + MCP-001 conformance:
//   - Hard-assert Wave 43 Done* artifact list body-bytes resolve
//   - Live body-bytes getter still positive after Wave 44 merge
//   - Track A/B (allowlist provenance + operator_caps body keys) hard-asserted
//     in diagnostics; Track C HTTP MaxBodyBytes hard-asserted in mcpserver.

// TestWave44_ArtifactsListBodyBytes_Hard hard-asserts Wave 43 Done*:
// ResolveArtifactsListBodyBytes default 2 MiB, absolute 8 MiB fail-closed,
// env name JENKINS_MCP_ARTIFACTS_LIST_BODY_BYTES, and jenkins constants.
func TestWave44_ArtifactsListBodyBytes_Hard(t *testing.T) {
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

// TestWave44_ArtifactsHardCap_StillHard re-asserts Wave 42/43 Done* hard-cap resolve
// still present (regression guard while Wave 44 tracks land elsewhere).
func TestWave44_ArtifactsHardCap_StillHard(t *testing.T) {
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

// TestWave44_LiveBodyBytes_StillHard re-asserts live ArtifactListBodyBytes after Wave 44 merge.
func TestWave44_LiveBodyBytes_StillHard(t *testing.T) {
	t.Parallel()

	live := jenkins.ArtifactListBodyBytes()
	if live <= 0 {
		t.Fatalf("ArtifactListBodyBytes non-positive %d", live)
	}
	if live != jenkins.DefaultArtifactListBodyBytes && live > jenkins.AbsoluteMaxArtifactListBodyBytes {
		t.Fatalf("live body bytes %d exceeds absolute %d", live, jenkins.AbsoluteMaxArtifactListBodyBytes)
	}
}
