package admin

import (
	"net/http"
	"os"

	"github.com/simonfxr/go-jenkins-mcp/internal/diagnostics"
)

// handleGatewayResidualStatus is GET /admin/v1/gateway/residual-status (HOST-007).
//
// Returns the same secret-free unified residual snapshot as
// `jenkins-mcp gateway residual-status` (diagnostics.BuildGatewayResidualStatus).
// Requires console read (viewer/operator/policy_admin). Never tokens, vault
// bytes, Authorization material, or raw subjects.
func (s *server) handleGatewayResidualStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	if !CheckPermission(w, r, PermRead) {
		return
	}
	_ = s
	// Env residual path only (same as CLI). Tests use t.Setenv.
	writeJSON(w, http.StatusOK, diagnostics.BuildGatewayResidualStatus(os.Getenv))
}
