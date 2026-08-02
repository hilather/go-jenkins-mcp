package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
)

// ToolListViews is the MCP tool name for listing Jenkins views (Wave 38).
const ToolListViews = "jenkins_list_views"

// registerViewsTools attaches jenkins_list_views (discovery + deny_view_names filter).
func registerViewsTools(s *mcp.Server, client *jenkins.Client, st regState) {
	addReadTool(s, st, &mcp.Tool{
		Name: ToolListViews,
		Description: "List Jenkins views (name/description/class only; no job graphs). Paginated. " +
			"Views matching MCP deny_view_names are omitted from the response (privacy filter)."},
		func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.ListViewsToolArgs) (*mcp.CallToolResult, jenkins.ListViewsToolResponse, error) {
			// Wave 38: after successful fetch, drop rows matching deny_view_names
			// (list discovery privacy). Named-view tools still use call-time deny
			// via view_name / seed view on other tools (e.g. jenkins_list_jobs).
			res, err := listViewsWithPolicyFilter(ctx, client, st, args.Offset, args.Limit)
			if err != nil {
				return nil, jenkins.ListViewsToolResponse{}, mapToolErr(err)
			}
			return structuredResult(*res)
		})
}
