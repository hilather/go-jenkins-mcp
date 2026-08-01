package tools

import (
	"context"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

// Wave 42: configurable list_views collect safety page cap when MCP deny_view_names
// forces full-list collect+filter. Each ListViews page is hard-capped at
// jenkins.MaxViewsPageSize (200).
const (
	// DefaultViewsCollectMaxPages is the default safety page cap for
	// collectAllViews (~50 × 200 = 10k views before incomplete honesty).
	DefaultViewsCollectMaxPages = 50
	// AbsoluteMaxViewsCollectMaxPages is the process absolute fail-closed
	// ceiling for the views collect page cap. Operators may raise via env/flag
	// up to this bound; values above fail closed at serve resolve (not clamped).
	AbsoluteMaxViewsCollectMaxPages = 200
	// EnvViewsCollectMaxPages is the serve env for the views collect page cap
	// (Wave 42). CLI --views-collect-max-pages overrides when set.
	// Empty/0 → DefaultViewsCollectMaxPages. Invalid values and values
	// above AbsoluteMaxViewsCollectMaxPages fail closed at serve start.
	EnvViewsCollectMaxPages = "JENKINS_MCP_VIEWS_COLLECT_MAX_PAGES"
)

// maxViewsCollectPages is the live process collect page cap (package-level so
// tests can override and serve can set once from ResolveViewsCollectMaxPages).
// Defaults to DefaultViewsCollectMaxPages.
var maxViewsCollectPages = DefaultViewsCollectMaxPages

// SetViewsCollectMaxPages sets the process views collect page cap after a
// successful ResolveViewsCollectMaxPages (serve start). Non-positive n uses
// DefaultViewsCollectMaxPages. Oversize values are clamped to absolute max as
// belt-and-suspenders (resolve already fail-closed).
func SetViewsCollectMaxPages(n int) {
	maxViewsCollectPages = clampCollectMaxPages(n, DefaultViewsCollectMaxPages, AbsoluteMaxViewsCollectMaxPages)
}

// ViewsCollectMaxPages returns the live views collect page cap (diagnostics/tests).
func ViewsCollectMaxPages() int {
	return maxViewsCollectPages
}

// ResolveViewsCollectMaxPages resolves the list_views policy-collect safety
// page cap (Wave 42). Thin wrapper over ResolveCollectMaxPages.
func ResolveViewsCollectMaxPages(flagVal, envVal string) (int, error) {
	return ResolveCollectMaxPages(flagVal, envVal,
		DefaultViewsCollectMaxPages,
		AbsoluteMaxViewsCollectMaxPages,
		EnvViewsCollectMaxPages,
		"--views-collect-max-pages",
		"views")
}

// FilterDeniedViews drops ViewSummary rows whose Name matches any deny_view_names
// pattern (MatchDenyJobPattern). Deny-only: never invents views. Empty patterns
// returns a shallow copy of views and omitted=0.
//
// Regression: Wave 38 list-row privacy for jenkins_list_views.
func FilterDeniedViews(patterns []string, views []jenkins.ViewSummary) (kept []jenkins.ViewSummary, omitted int) {
	if len(patterns) == 0 {
		if views == nil {
			return nil, 0
		}
		out := make([]jenkins.ViewSummary, len(views))
		copy(out, views)
		return out, 0
	}
	kept = make([]jenkins.ViewSummary, 0, len(views))
	for _, v := range views {
		if policy.NameDeniedByPatterns(patterns, v.Name) {
			omitted++
			continue
		}
		kept = append(kept, v)
	}
	return kept, omitted
}

// PaginateViews applies offset/limit like jenkins.Client.ListViews.
// Exported for filter→paginate composition tests (Wave 38).
func PaginateViews(all []jenkins.ViewSummary, offset, limit int) (page []jenkins.ViewSummary, truncated bool, nextOffset, off, lim int) {
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 {
		limit = jenkins.DefaultViewsPageSize
	}
	if limit > jenkins.MaxViewsPageSize {
		limit = jenkins.MaxViewsPageSize
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

// collectAllViews pages through ListViews until complete (or safety cap).
// On Unauthorized, returns the unauthorized response and nil views.
// incomplete is true when the page safety cap was hit while Jenkins still
// reported more views.
func collectAllViews(ctx context.Context, client *jenkins.Client) (all []jenkins.ViewSummary, last *jenkins.ListViewsToolResponse, incomplete bool, err error) {
	offset := 0
	for pageNum := 0; pageNum < maxViewsCollectPages; pageNum++ {
		res, err := client.ListViews(ctx, offset, jenkins.MaxViewsPageSize)
		if err != nil {
			return nil, nil, false, err
		}
		if res.Unauthorized {
			return nil, res, false, nil
		}
		all = append(all, res.Views...)
		last = res
		if !res.Truncated {
			return all, last, false, nil
		}
		if res.NextOffset <= offset {
			return all, last, true, nil
		}
		offset = res.NextOffset
	}
	return all, last, true, nil
}

// listViewsWithPolicyFilter fetches views and, when live deny_view_names is
// non-empty, filters the full list then re-paginates and recomputes Summary
// over non-denied views. Empty evaluator / empty deny list → unchanged ListViews.
func listViewsWithPolicyFilter(ctx context.Context, client *jenkins.Client, st regState, offset, limit int) (*jenkins.ListViewsToolResponse, error) {
	patterns := policy.DenyViewNamesFromEvaluator(st.policy)
	if len(patterns) == 0 {
		return client.ListViews(ctx, offset, limit)
	}

	all, unauthOrLast, incomplete, err := collectAllViews(ctx, client)
	if err != nil {
		return nil, err
	}
	if unauthOrLast != nil && unauthOrLast.Unauthorized {
		off := offset
		if off < 0 {
			off = 0
		}
		return &jenkins.ListViewsToolResponse{
			Views:        nil,
			Offset:       off,
			Limit:        normalizeViewsLimit(limit),
			Unauthorized: true,
			Message:      unauthOrLast.Message,
		}, nil
	}

	kept, omitted := FilterDeniedViews(patterns, all)
	summary := jenkins.ViewTotals{TotalViews: len(kept)}
	page, truncated, next, off, lim := PaginateViews(kept, offset, limit)
	if incomplete {
		truncated = true
		if next == 0 {
			next = off + len(page)
		}
	}

	out := &jenkins.ListViewsToolResponse{
		Views:      page,
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
			out.Message = "some views omitted by MCP policy"
		}
	}
	if incomplete {
		if strings.TrimSpace(out.Message) == "" {
			out.Message = "view list collection capped; results may be incomplete"
		} else {
			out.Message = out.Message + "; collection capped (may be incomplete)"
		}
	}
	return out, nil
}

func normalizeViewsLimit(limit int) int {
	if limit <= 0 {
		return jenkins.DefaultViewsPageSize
	}
	if limit > jenkins.MaxViewsPageSize {
		return jenkins.MaxViewsPageSize
	}
	return limit
}
