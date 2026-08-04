// Package main is not used; this file is a go-test entry for the Python
// task-index validator so `go test ./scripts` exercises the real shipped script.
package scripts_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidateTaskIndex_RepoGraph runs scripts/validate-task-index.py against
// the archived enterprise task index (historical FLC-* reservation). Regression:
// validator must still pass for the archived graph; open work lives in Issues.
func TestValidateTaskIndex_RepoGraph(t *testing.T) {
	root := repoRoot(t)
	script := filepath.Join(root, "scripts", "validate-task-index.py")
	index := filepath.Join(root, "docs", "archive", "jenkins-mcp-enterprise-task-index.json")
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("missing validator: %v", err)
	}
	if _, err := os.Stat(index); err != nil {
		t.Fatalf("missing archived task index: %v", err)
	}
	cmd := exec.Command("python3", script, index)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	body := string(out)
	if err != nil {
		t.Fatalf("validate-task-index failed: %v\n%s", err, body)
	}
	if !strings.Contains(body, "STATUS: OK") {
		t.Fatalf("expected STATUS: OK, got:\n%s", body)
	}
	if !strings.Contains(body, "flc_task_count:") {
		t.Fatalf("expected flc_task_count in output:\n%s", body)
	}
	// Ensure FLC namespace is reserved (Phase 0: 44 tasks from planning pack).
	foundCount := false
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "flc_task_count: ") {
			continue
		}
		foundCount = true
		nStr := strings.TrimSpace(strings.TrimPrefix(line, "flc_task_count: "))
		var n int
		for _, ch := range nStr {
			if ch < '0' || ch > '9' {
				break
			}
			n = n*10 + int(ch-'0')
		}
		if n < 44 {
			t.Fatalf("expected flc_task_count >= 44, got %d (%q)", n, line)
		}
	}
	if !foundCount {
		t.Fatalf("no flc_task_count line:\n%s", body)
	}
	// Must not report runtime false Done claims.
	if strings.Contains(body, "flc_runtime_false_done_claims: ") {
		for _, line := range strings.Split(body, "\n") {
			if strings.HasPrefix(line, "flc_runtime_false_done_claims: ") {
				if !strings.HasSuffix(strings.TrimSpace(line), "0") {
					t.Fatalf("unexpected false Done claims: %s\n%s", line, body)
				}
			}
		}
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// go test CWD is the package dir (scripts/).
	root := filepath.Clean(filepath.Join(wd, ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		// fallback: walk up
		dir := wd
		for i := 0; i < 6; i++ {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				return dir
			}
			dir = filepath.Dir(dir)
		}
		t.Fatalf("go.mod not found from %s", wd)
	}
	return root
}
