package tools_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
	"github.com/hilather/go-jenkins-mcp/internal/tools"
)

// Wave 40 / POL-005 MCP-layer hard assert for list_artifacts hard-cap fetch
// (Wave 40 Done*). Uses production Register path so the MCP surface matches
// listArtifactsWithPolicyFilter behavior.

const wave40HardCapArtifactsJSON = `{
	"timestamp": 1700000000000,
	"artifacts": [
		{"fileName": "a.txt", "relativePath": "secrets/a.txt"},
		{"fileName": "b.txt", "relativePath": "secrets/b.txt"},
		{"fileName": "ok1.txt", "relativePath": "reports/ok1.txt"},
		{"fileName": "ok2.txt", "relativePath": "reports/ok2.txt"},
		{"fileName": "ok3.txt", "relativePath": "reports/ok3.txt"}
	]
}`

// TestWave40_ListArtifactsHardCap_MCP hard-asserts jenkins_list_artifacts with
// max_artifacts=2 when the first rows are denied returns reports/ok1 + ok2
// (hard-cap fetch-then-filter), not an empty page-level filter result.
func TestWave40_ListArtifactsHardCap_MCP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	f := newArtifactFixture(wave40HardCapArtifactsJSON)
	defer f.close()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:              policy.ModePilot,
		DenyArtifactPaths: []string{"secrets/**"},
	})
	subj := policy.NewSubject("corp", "dev-user", true)

	server := mcp.NewServer(&mcp.Implementation{Name: "wave40-art-hardcap", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: subj,
	})

	cs, ss := connectMCP(t, ctx, server)
	defer ss.Close()
	defer cs.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "jenkins_list_artifacts",
		Arguments: map[string]any{
			"job_name":      "demo",
			"build_number":  7,
			"max_artifacts": 2,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.IsError {
		t.Fatalf("tool error: %#v text=%q", res, toolErrorText(res))
	}

	raw, _ := json.Marshal(res.StructuredContent)
	var out jenkins.ArtifactList
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v raw=%s", err, raw)
	}

	// Never leak denied paths (deny-only always).
	for _, a := range out.Artifacts {
		if strings.HasPrefix(a.Path, "secrets/") {
			t.Fatalf("denied path leaked: %q full=%s", a.Path, raw)
		}
	}
	if strings.Contains(string(raw), "secrets/") {
		t.Fatalf("denied path leaked in response JSON: %s", raw)
	}
	if f.artifactHits.Load() != 0 {
		t.Fatalf("list must not download artifact bodies; hits=%d", f.artifactHits.Load())
	}

	// Wave 40 Done*: hard-cap fetch-then-filter must surface ok1+ok2.
	if len(out.Artifacts) < 2 {
		t.Fatalf("Wave 40 Done* hard-cap: want ≥2 allowed paths (ok1/ok2), got %d raw=%s",
			len(out.Artifacts), raw)
	}
	if out.Artifacts[0].Path != "reports/ok1.txt" || out.Artifacts[1].Path != "reports/ok2.txt" {
		t.Fatalf("hard-cap paths: %+v want reports/ok1 + ok2", out.Artifacts)
	}
	if !out.PolicyFiltered || out.PolicyOmittedCount < 1 {
		t.Fatalf("hard-cap path must set policy flags: filtered=%v omitted=%d raw=%s",
			out.PolicyFiltered, out.PolicyOmittedCount, raw)
	}
	if out.Count != len(out.Artifacts) {
		t.Fatalf("count=%d arts=%d", out.Count, len(out.Artifacts))
	}
	// Re-slice must honor caller max_artifacts (ok3 dropped after filter).
	if len(out.Artifacts) > 2 {
		t.Fatalf("hard-cap re-slice should honor max_artifacts=2, got %d: %+v",
			len(out.Artifacts), out.Artifacts)
	}
}
