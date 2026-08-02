package tools

import (
	"context"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

// Wave 42: configurable get_nodes collect safety page cap when MCP deny_node_names
// forces full-list collect+filter. Each GetNodes page is hard-capped at
// jenkins.MaxNodesPageSize (200).
const (
	// DefaultNodesCollectMaxPages is the default safety page cap for
	// collectAllNodes (~50 × 200 = 10k nodes before incomplete honesty).
	DefaultNodesCollectMaxPages = 50
	// AbsoluteMaxNodesCollectMaxPages is the process absolute fail-closed
	// ceiling for the nodes collect page cap. Operators may raise via env/flag
	// up to this bound; values above fail closed at serve resolve (not clamped).
	AbsoluteMaxNodesCollectMaxPages = 200
	// EnvNodesCollectMaxPages is the serve env for the nodes collect page cap
	// (Wave 42). CLI --nodes-collect-max-pages overrides when set.
	// Empty/0 → DefaultNodesCollectMaxPages. Invalid values and values
	// above AbsoluteMaxNodesCollectMaxPages fail closed at serve start.
	EnvNodesCollectMaxPages = "JENKINS_MCP_NODES_COLLECT_MAX_PAGES"
)

// maxNodesCollectPages is the live process collect page cap (package-level so
// tests can override and serve can set once from ResolveNodesCollectMaxPages).
// Defaults to DefaultNodesCollectMaxPages.
var maxNodesCollectPages = DefaultNodesCollectMaxPages

// SetNodesCollectMaxPages sets the process nodes collect page cap after a
// successful ResolveNodesCollectMaxPages (serve start). Non-positive n uses
// DefaultNodesCollectMaxPages. Oversize values are clamped to absolute max as
// belt-and-suspenders (resolve already fail-closed).
func SetNodesCollectMaxPages(n int) {
	maxNodesCollectPages = clampCollectMaxPages(n, DefaultNodesCollectMaxPages, AbsoluteMaxNodesCollectMaxPages)
}

// NodesCollectMaxPages returns the live nodes collect page cap (diagnostics/tests).
func NodesCollectMaxPages() int {
	return maxNodesCollectPages
}

// ResolveNodesCollectMaxPages resolves the get_nodes policy-collect safety
// page cap (Wave 42). Thin wrapper over ResolveCollectMaxPages.
func ResolveNodesCollectMaxPages(flagVal, envVal string) (int, error) {
	return ResolveCollectMaxPages(flagVal, envVal,
		DefaultNodesCollectMaxPages,
		AbsoluteMaxNodesCollectMaxPages,
		EnvNodesCollectMaxPages,
		"--nodes-collect-max-pages",
		"nodes")
}

// FilterDeniedNodes drops NodeSummary rows whose Name matches any deny_node_names
// pattern (MatchDenyJobPattern). Deny-only: never invents nodes. Empty patterns
// returns a shallow copy of nodes and omitted=0.
//
// Regression: Wave 36 list-row privacy for jenkins_get_nodes.
func FilterDeniedNodes(patterns []string, nodes []jenkins.NodeSummary) (kept []jenkins.NodeSummary, omitted int) {
	if len(patterns) == 0 {
		if nodes == nil {
			return nil, 0
		}
		out := make([]jenkins.NodeSummary, len(nodes))
		copy(out, nodes)
		return out, 0
	}
	kept = make([]jenkins.NodeSummary, 0, len(nodes))
	for _, n := range nodes {
		if policy.NameDeniedByPatterns(patterns, n.Name) {
			omitted++
			continue
		}
		kept = append(kept, n)
	}
	return kept, omitted
}

// summarizeNodeTotals aggregates executor/node totals for the given nodes
// (controller-wide after policy filter, or page-level when filtering a page).
func summarizeNodeTotals(nodes []jenkins.NodeSummary) jenkins.NodeTotals {
	var t jenkins.NodeTotals
	for _, n := range nodes {
		t.TotalNodes++
		if n.Offline {
			t.OfflineNodes++
		} else {
			t.OnlineNodes++
		}
		t.TotalExecutors += n.NumExecutors
		t.BusyExecutors += n.BusyExecutors
		t.IdleExecutors += n.IdleExecutors
	}
	return t
}

// PaginateNodes applies offset/limit like jenkins.Client.GetNodes.
// Exported for filter→paginate composition tests (Wave 37).
func PaginateNodes(all []jenkins.NodeSummary, offset, limit int) (page []jenkins.NodeSummary, truncated bool, nextOffset, off, lim int) {
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 {
		limit = jenkins.DefaultNodesPageSize
	}
	if limit > jenkins.MaxNodesPageSize {
		limit = jenkins.MaxNodesPageSize
	}
	if offset > len(all) {
		offset = len(all)
	}
	end := offset + limit
	truncated = end < len(all)
	page = all[offset:]
	if len(page) > limit {
		page = page[:limit]
	}
	next := 0
	if truncated {
		next = offset + len(page)
	}
	return page, truncated, next, offset, limit
}

// collectAllNodes pages through GetNodes until complete (or safety cap).
// On Unauthorized, returns the unauthorized response and nil nodes.
// incomplete is true when the page safety cap was hit while Jenkins still
// reported more nodes (Wave 36 review: avoid silent under-count).
func collectAllNodes(ctx context.Context, client *jenkins.Client) (all []jenkins.NodeSummary, last *jenkins.GetNodesToolResponse, incomplete bool, err error) {
	offset := 0
	for pageNum := 0; pageNum < maxNodesCollectPages; pageNum++ {
		res, err := client.GetNodes(ctx, offset, jenkins.MaxNodesPageSize)
		if err != nil {
			return nil, nil, false, err
		}
		if res.Unauthorized {
			return nil, res, false, nil
		}
		all = append(all, res.Nodes...)
		last = res
		if !res.Truncated {
			return all, last, false, nil
		}
		if res.NextOffset <= offset {
			// Stuck cursor — return what we have; treat as incomplete.
			return all, last, true, nil
		}
		offset = res.NextOffset
	}
	// Hit safety cap with more pages remaining.
	return all, last, true, nil
}

// getNodesWithPolicyFilter fetches nodes and, when live deny_node_names is
// non-empty, filters the full list then re-paginates and recomputes Summary
// over non-denied nodes. Empty evaluator / empty deny list → unchanged GetNodes.
func getNodesWithPolicyFilter(ctx context.Context, client *jenkins.Client, st regState, offset, limit int) (*jenkins.GetNodesToolResponse, error) {
	patterns := policy.DenyNodeNamesForSubject(st.policy, effectiveSubject(st, ctx))
	if len(patterns) == 0 {
		return client.GetNodes(ctx, offset, limit)
	}

	all, unauthOrLast, incomplete, err := collectAllNodes(ctx, client)
	if err != nil {
		return nil, err
	}
	if unauthOrLast != nil && unauthOrLast.Unauthorized {
		// Preserve Unauthorized path (no filter metadata).
		off := offset
		if off < 0 {
			off = 0
		}
		return &jenkins.GetNodesToolResponse{
			Nodes:        nil,
			Offset:       off,
			Limit:        normalizeNodesLimit(limit),
			Unauthorized: true,
			Message:      unauthOrLast.Message,
		}, nil
	}

	kept, omitted := FilterDeniedNodes(patterns, all)
	summary := summarizeNodeTotals(kept)
	page, truncated, next, off, lim := PaginateNodes(kept, offset, limit)
	// Incomplete collection (safety page cap): force truncated honesty so clients
	// do not treat a partial fleet scan as complete (Wave 36 review).
	if incomplete {
		truncated = true
		if next == 0 {
			next = off + len(page)
		}
	}

	out := &jenkins.GetNodesToolResponse{
		Nodes:      page,
		Summary:    summary,
		Offset:     off,
		Limit:      lim,
		Truncated:  truncated,
		NextOffset: next,
	}
	if omitted > 0 {
		out.PolicyFiltered = true
		out.PolicyOmittedCount = omitted
		// Non-secret operator hint only; do not list denied names or patterns.
		if strings.TrimSpace(out.Message) == "" {
			out.Message = "some nodes omitted by MCP policy"
		}
	}
	if incomplete {
		// Non-secret residual: collection capped; do not claim full fleet coverage.
		if strings.TrimSpace(out.Message) == "" {
			out.Message = "node list collection capped; results may be incomplete"
		} else {
			out.Message = out.Message + "; collection capped (may be incomplete)"
		}
	}
	return out, nil
}

func normalizeNodesLimit(limit int) int {
	if limit <= 0 {
		return jenkins.DefaultNodesPageSize
	}
	if limit > jenkins.MaxNodesPageSize {
		return jenkins.MaxNodesPageSize
	}
	return limit
}
