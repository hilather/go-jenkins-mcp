package tools

import (
	"context"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
)

// Tool names for health / diagnose surfaces (HEALTH-001/002, DIAG-007).
const (
	ToolGetNodes          = "jenkins_get_nodes"
	ToolGetNode           = "jenkins_get_node"
	ToolQueuePressure     = "jenkins_queue_pressure"
	ToolControllerHealth  = "jenkins_controller_health"
	ToolExplainQueueDelay = "jenkins_explain_queue_delay"
)

// registerHealthTools attaches HEALTH-001/002 and DIAG-007 read tools.
func registerHealthTools(s *mcp.Server, client *jenkins.Client, st regState) {
	addReadTool(s, st, &mcp.Tool{
		Name: ToolGetNodes,
		Description: "Get Jenkins node/executor summary (online/offline, busy/idle, labels). Paginated; no environment or system properties. " +
			"Nodes matching MCP deny_node_names are omitted from the response (privacy filter)."},
		func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetNodesToolArgs) (*mcp.CallToolResult, jenkins.GetNodesToolResponse, error) {
			// Wave 36: after successful fetch, drop rows matching deny_node_names
			// (list discovery privacy). Named-target tools still use call-time deny.
			res, err := getNodesWithPolicyFilter(ctx, client, st, args.Offset, args.Limit)
			if err != nil {
				return nil, jenkins.GetNodesToolResponse{}, mapToolErr(err)
			}
			return structuredResult(*res)
		})

	// Wave 36: named-node tool so deny_node_names binds via node_name at call time.
	addReadTool(s, st, &mcp.Tool{
		Name: ToolGetNode,
		Description: "Get a single Jenkins node/executor summary by node_name " +
			"(online/offline, busy/idle, labels). Built-in path is often (master) or built-in. " +
			"No environment or system properties."},
		func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetNodeToolArgs) (*mcp.CallToolResult, jenkins.GetNodeToolResponse, error) {
			if strings.TrimSpace(args.NodeName) == "" {
				return nil, jenkins.GetNodeToolResponse{},
					apperr.New(apperr.CodeInvalidArgument, "node_name is required")
			}
			res, err := client.GetNode(ctx, args.NodeName)
			if err != nil {
				return nil, jenkins.GetNodeToolResponse{}, mapToolErr(err)
			}
			return structuredResult(*res)
		})

	addReadTool(s, st, &mcp.Tool{
		Name:        ToolQueuePressure,
		Description: "Summarize Jenkins queue pressure: depth, stuck count, oldest wait. Distinguishes unauthorized from empty queue."},
		func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetQueuePressureToolArgs) (*mcp.CallToolResult, jenkins.GetQueuePressureToolResponse, error) {
			res, err := client.GetQueuePressure(ctx)
			if err != nil {
				return nil, jenkins.GetQueuePressureToolResponse{}, mapToolErr(err)
			}
			return structuredResult(*res)
		})

	// HEALTH-002: controller version, capabilities, queue/node summary, quiet-down.
	addReadTool(s, st, &mcp.Tool{
		Name: ToolControllerHealth,
		Description: "Controller health summary: Jenkins version, capability/plugin shortlist, " +
			"queue pressure, offline node counts, quiet-down mode. Read-only; no secrets."},
		func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetControllerHealthToolArgs) (*mcp.CallToolResult, jenkins.GetControllerHealthToolResponse, error) {
			res, err := client.GetControllerHealth(ctx, args)
			if err != nil {
				return nil, jenkins.GetControllerHealthToolResponse{}, mapToolErr(err)
			}
			return structuredResult(*res)
		})

	// DIAG-007: explain queue delay from labels/executors/why/quiet-down.
	addReadTool(s, st, &mcp.Tool{
		Name: ToolExplainQueueDelay,
		Description: "Explain why a queue item (or a job's pending queue entry) is delayed: " +
			"why/blocked reasons, required labels, matching nodes/executors, quiet-down. " +
			"ETA is heuristic only. Requires queue_item_id and/or job_name."},
		func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.ExplainQueueDelayToolArgs) (*mcp.CallToolResult, jenkins.ExplainQueueDelayToolResponse, error) {
			if args.QueueItemID <= 0 && strings.TrimSpace(args.JobName) == "" {
				return nil, jenkins.ExplainQueueDelayToolResponse{},
					apperr.New(apperr.CodeInvalidArgument, "queue_item_id or job_name is required")
			}
			if name := strings.TrimSpace(args.JobName); name != "" {
				full, err := jobFullName("job_name", name)
				if err != nil {
					return nil, jenkins.ExplainQueueDelayToolResponse{}, err
				}
				args.JobName = full
			}
			res, err := client.ExplainQueueDelay(ctx, args)
			if err != nil {
				return nil, jenkins.ExplainQueueDelayToolResponse{}, mapToolErr(err)
			}
			return structuredResult(*res)
		})
}
