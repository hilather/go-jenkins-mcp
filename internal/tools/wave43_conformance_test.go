package tools

import (
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
)

// Wave 43 / POL-005 conformance:
//   - Hard-assert Wave 42 Done* APIs (must pass on main)
//   - Soft residual for Wave 43 feature tracks not yet present
//     (artifact list body-bytes resolve, operator_caps_snapshot, adapter_framework_residual)

// TestWave43_ArtifactsHardCap_Hard re-asserts Wave 42 Done*:
// ResolveArtifactsHardCap precedence + absolute fail-closed, and live ArtifactsHardCap > 0.
func TestWave43_ArtifactsHardCap_Hard(t *testing.T) {
	t.Parallel()

	n, err := ResolveArtifactsHardCap("", "")
	if err != nil || n != jenkins.DefaultArtifactsHardCap {
		t.Fatalf("default: n=%d err=%v want %d", n, err, jenkins.DefaultArtifactsHardCap)
	}
	n, err = ResolveArtifactsHardCap("", "800")
	if err != nil || n != 800 {
		t.Fatalf("env: n=%d err=%v", n, err)
	}
	n, err = ResolveArtifactsHardCap("900", "800")
	if err != nil || n != 900 {
		t.Fatalf("flag wins: n=%d err=%v", n, err)
	}
	n, err = ResolveArtifactsHardCap("2000", "")
	if err != nil || n != jenkins.AbsoluteMaxArtifactsHardCap {
		t.Fatalf("absolute max accepted: n=%d err=%v want %d", n, err, jenkins.AbsoluteMaxArtifactsHardCap)
	}
	if _, err := ResolveArtifactsHardCap("2001", ""); err == nil {
		t.Fatal("above AbsoluteMaxArtifactsHardCap must fail closed")
	}
	if _, err := ResolveArtifactsHardCap("nope", ""); err == nil {
		t.Fatal("invalid parse must fail closed")
	}
	if EnvArtifactsHardCap != "JENKINS_MCP_ARTIFACTS_HARD_CAP" {
		t.Fatalf("env name drift: %q", EnvArtifactsHardCap)
	}
	if ArtifactsHardCap() <= 0 {
		t.Fatalf("ArtifactsHardCap=%d", ArtifactsHardCap())
	}
	if jenkins.AbsoluteMaxArtifactsHardCap < jenkins.DefaultArtifactsHardCap {
		t.Fatalf("absolute %d < default %d", jenkins.AbsoluteMaxArtifactsHardCap, jenkins.DefaultArtifactsHardCap)
	}
}

// TestWave43_NodesViewsCollectMaxPages_Hard re-asserts Wave 42 Done*:
// ResolveNodesCollectMaxPages / ResolveViewsCollectMaxPages + live process caps.
func TestWave43_NodesViewsCollectMaxPages_Hard(t *testing.T) {
	t.Parallel()

	nn, err := ResolveNodesCollectMaxPages("", "")
	if err != nil || nn != DefaultNodesCollectMaxPages {
		t.Fatalf("nodes default: n=%d err=%v want %d", nn, err, DefaultNodesCollectMaxPages)
	}
	nn, err = ResolveNodesCollectMaxPages("", "70")
	if err != nil || nn != 70 {
		t.Fatalf("nodes env: n=%d err=%v", nn, err)
	}
	nn, err = ResolveNodesCollectMaxPages("90", "70")
	if err != nil || nn != 90 {
		t.Fatalf("nodes flag wins: n=%d err=%v", nn, err)
	}
	nn, err = ResolveNodesCollectMaxPages("200", "")
	if err != nil || nn != AbsoluteMaxNodesCollectMaxPages {
		t.Fatalf("nodes absolute max: n=%d err=%v", nn, err)
	}
	if _, err := ResolveNodesCollectMaxPages("201", ""); err == nil {
		t.Fatal("nodes above absolute must fail closed")
	}
	if EnvNodesCollectMaxPages != "JENKINS_MCP_NODES_COLLECT_MAX_PAGES" {
		t.Fatalf("nodes env name drift: %q", EnvNodesCollectMaxPages)
	}

	nv, err := ResolveViewsCollectMaxPages("", "")
	if err != nil || nv != DefaultViewsCollectMaxPages {
		t.Fatalf("views default: n=%d err=%v want %d", nv, err, DefaultViewsCollectMaxPages)
	}
	nv, err = ResolveViewsCollectMaxPages("80", "70")
	if err != nil || nv != 80 {
		t.Fatalf("views flag wins: n=%d err=%v", nv, err)
	}
	if _, err := ResolveViewsCollectMaxPages("999", ""); err == nil {
		t.Fatal("views above absolute must fail closed")
	}
	if EnvViewsCollectMaxPages != "JENKINS_MCP_VIEWS_COLLECT_MAX_PAGES" {
		t.Fatalf("views env name drift: %q", EnvViewsCollectMaxPages)
	}

	if NodesCollectMaxPages() <= 0 || ViewsCollectMaxPages() <= 0 {
		t.Fatalf("live caps nodes=%d views=%d", NodesCollectMaxPages(), ViewsCollectMaxPages())
	}
}

// TestWave43_ArtifactsListBodyBytes_Hard asserts Wave 43 Done*: body bound resolve.
func TestWave43_ArtifactsListBodyBytes_Hard(t *testing.T) {
	t.Parallel()
	n, err := ResolveArtifactsListBodyBytes("", "")
	if err != nil || n != jenkins.DefaultArtifactListBodyBytes {
		t.Fatalf("default: n=%d err=%v want %d", n, err, jenkins.DefaultArtifactListBodyBytes)
	}
	n, err = ResolveArtifactsListBodyBytes("", "3145728")
	if err != nil || n != 3145728 {
		t.Fatalf("env: n=%d err=%v", n, err)
	}
	if _, err := ResolveArtifactsListBodyBytes("999999999", ""); err == nil {
		t.Fatal("over absolute must fail closed")
	}
	if EnvArtifactsListBodyBytes != "JENKINS_MCP_ARTIFACTS_LIST_BODY_BYTES" {
		t.Fatalf("env name: %q", EnvArtifactsListBodyBytes)
	}
}
