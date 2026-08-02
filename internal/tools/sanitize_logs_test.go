package tools_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/redact"
	"github.com/hilather/go-jenkins-mcp/internal/tools"
)

func TestPrepareBuildLogsForModelRedactsAndLabels(t *testing.T) {
	t.Parallel()
	bl := &jenkins.BuildLogs{
		JobName:     "folder/job",
		BuildNumber: 42,
		Offset:      100,
		Length:      50,
		TotalSize:   5000,
		HasMore:     true,
		Logs:        "\x1b[31mpassword=hunter2\x1b[0m build step failed",
	}
	out := tools.PrepareBuildLogsForModel(bl)

	if !out.Untrusted {
		t.Fatal("untrusted")
	}
	if out.ContentKind != redact.ContentKindBuildLog {
		t.Fatal(out.ContentKind)
	}
	// Evidence handles preserved.
	if out.JobName != "folder/job" || out.BuildNumber != 42 || out.Offset != 100 {
		t.Fatalf("evidence handles: %+v", out)
	}
	if out.TotalSize != 5000 || !out.HasMore {
		t.Fatalf("range metadata: %+v", out)
	}
	if strings.Contains(out.Logs, "hunter2") || strings.Contains(out.Logs, "\x1b") {
		t.Fatalf("not sanitized: %q", out.Logs)
	}
	if !strings.Contains(out.Logs, "build step failed") {
		t.Fatalf("lost diagnostic: %q", out.Logs)
	}
	if out.Length != len(out.Logs) {
		t.Fatalf("length=%d len(logs)=%d", out.Length, len(out.Logs))
	}

	// Budget path: serialized payload must not contain canary.
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "hunter2") {
		t.Fatalf("JSON canary: %s", raw)
	}

	// EnforceBudget after prepare (order required by SEC/MCP).
	enforced, _, err := tools.EnforceBudget(out, tools.DefaultBudgets())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(enforced)
	if strings.Contains(string(b), "hunter2") {
		t.Fatalf("budget path canary: %s", b)
	}
}

func TestPrepareBuildLogsForModelNil(t *testing.T) {
	t.Parallel()
	out := tools.PrepareBuildLogsForModel(nil)
	if !out.Untrusted || out.ContentKind == "" {
		t.Fatalf("%+v", out)
	}
}
