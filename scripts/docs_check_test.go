// Package scripts_test exercises scripts/docs-check.sh against the live tree.
package scripts_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestDocsCheck_RepoTree runs the shipped docs-check script.
// Regression: docs CI must stay green when architecture/quick starts/policy land.
func TestDocsCheck_RepoTree(t *testing.T) {
	root := repoRoot(t)
	script := filepath.Join(root, "scripts", "docs-check.sh")
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("missing docs-check: %v", err)
	}
	cmd := exec.Command("bash", script)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	body := string(out)
	if err != nil {
		t.Fatalf("docs-check failed: %v\n%s", err, body)
	}
	if !strings.Contains(body, "docs-check OK") {
		t.Fatalf("expected docs-check OK, got:\n%s", body)
	}
}
