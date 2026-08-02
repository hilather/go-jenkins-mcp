package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/hilather/go-jenkins-mcp/internal/diagnostics"
)

// DoctorArgs are the tool arguments for jenkins_doctor (OPS-001).
// Network is optional; process-bound profile is used (no URL/token args).
type DoctorArgs struct {
	// Offline skips whoAmI network identity check.
	Offline bool `json:"offline,omitempty" jsonschema:"Skip network identity verify (default false)"`
}

// DoctorFunc runs a secret-free doctor report for the process profile.
// Wired from cmd/serve; nil ⇒ jenkins_doctor is not registered.
type DoctorFunc func(ctx context.Context, offline bool) (diagnostics.Report, error)

// registerDoctorTool attaches optional jenkins_doctor when Doctor is configured.
func registerDoctorTool(s *mcp.Server, st regState, doctor DoctorFunc) {
	if doctor == nil {
		return
	}
	addReadTool(s, st, &mcp.Tool{
		Name:        "jenkins_doctor",
		Description: "Run local setup diagnostics (profile, keyring presence, TLS paths, store, policy, read-only). Never returns secrets."},
		func(ctx context.Context, req *mcp.CallToolRequest, args DoctorArgs) (*mcp.CallToolResult, diagnostics.Report, error) {
			rep, err := doctor(ctx, args.Offline)
			if err != nil {
				return nil, diagnostics.Report{}, mapToolErr(err)
			}
			// Defense in depth: re-sanitize every check.
			for i := range rep.Checks {
				rep.Checks[i] = diagnostics.SanitizeCheck(rep.Checks[i])
			}
			rep.Overall = diagnostics.OverallStatus(rep.Checks)
			return structuredResult(rep)
		})
}
