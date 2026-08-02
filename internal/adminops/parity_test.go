package adminops_test

import (
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/adminops"
)

// MCP-OPS-006: every catalog tool has a stable admin_* name; residuals documented.
func TestParityMatrix_CatalogAndResiduals(t *testing.T) {
	t.Parallel()
	for _, name := range adminops.ToolCatalog() {
		if !strings.HasPrefix(name, "admin_") {
			t.Fatalf("tool %q must use admin_ namespace", name)
		}
		if strings.Contains(name, "token") || strings.Contains(name, "password") {
			t.Fatalf("secret-looking tool name %q", name)
		}
	}
	res := adminops.ResidualTools()
	for name, reason := range res {
		if !strings.HasPrefix(name, "admin_") {
			t.Fatalf("residual %q bad namespace", name)
		}
		if strings.TrimSpace(reason) == "" {
			t.Fatalf("residual %q empty reason", name)
		}
	}
}
