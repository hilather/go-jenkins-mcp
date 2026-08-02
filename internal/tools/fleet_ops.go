package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/hilather/go-jenkins-mcp/internal/fleetmcp"
)

// registerFleetOpsTools attaches fleet_* tools when FleetOps is enabled.
// Tool args never accept peer URLs — membership is roster-only.
func registerFleetOpsTools(s *mcp.Server, st regState, svc *fleetmcp.Service) {
	if svc == nil || !svc.Enabled() {
		return
	}

	registerOne := func(name, desc string, collection fleetmcp.Collection) {
		addReadTool(s, st, &mcp.Tool{
			Name:        name,
			Description: desc,
		}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, fleetmcp.AggregateEnvelope, error) {
			env := svc.Collect(ctx, collection)
			return structuredResult(env)
		})
	}

	addReadTool(s, st, &mcp.Tool{
		Name:        "fleet_list_members",
		Description: "List multi-fleet members from the configured roster and probe reachability (secret-free). Peers cannot be invented via tool args.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, fleetmcp.AggregateEnvelope, error) {
		env := svc.ListMembers(ctx)
		return structuredResult(env)
	})

	registerOne("fleet_health",
		"Fleet-wide process health fan-out (local + roster peers). Incomplete when any peer fails. Not multi-pod HA.",
		fleetmcp.CollectionHealth)
	registerOne("fleet_version",
		"Fleet-wide version/commit matrix (local + peers). Secret-free.",
		fleetmcp.CollectionVersion)
	registerOne("fleet_metrics",
		"Fleet-wide process metrics snapshots plus optional allowlisted counter sums. Process-local counters only; not multi-pod HA.",
		fleetmcp.CollectionMetrics)
	registerOne("fleet_residual_status",
		"Fleet-wide gateway residual-status maps (secret-free bools/counts). Never claims live GO from union.",
		fleetmcp.CollectionResidual)
	registerOne("fleet_doctor",
		"Fleet-wide offline doctor summaries when wired (secret-free). Partial failures set incomplete.",
		fleetmcp.CollectionDoctor)
	registerOne("fleet_cache_status",
		"Fleet-wide cache quota/usage lite (bytes and flags only; no data paths).",
		fleetmcp.CollectionCache)
}
