package jenkins

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// DefaultViewsPageSize caps view list rows returned in one call (Wave 38).
const DefaultViewsPageSize = 50

// MaxViewsPageSize is the hard upper bound for views pagination limit.
const MaxViewsPageSize = 200

// maxViewsAPIBodyBytes bounds the root views API JSON body.
const maxViewsAPIBodyBytes = 2 << 20 // 2 MiB — views are name/description only

// ListViewsToolArgs are the tool arguments for jenkins_list_views.
type ListViewsToolArgs struct {
	// Offset is the zero-based start index into the views list (pagination).
	Offset int `json:"offset,omitempty" jsonschema:"Zero-based offset into the view list (default 0)"`
	// Limit is the maximum views to return (default 50, max 200).
	Limit int `json:"limit,omitempty" jsonschema:"Maximum views to return (default 50, max 200)"`
}

// ViewSummary is a safe view listing row: name/description/class only.
// No job graphs, credentials, or nested view contents.
type ViewSummary struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Class is the raw Jenkins _class when available (e.g. hudson.model.ListView).
	Class string `json:"class,omitempty"`
}

// ViewTotals aggregates view counts for the controller-wide list (after filter
// when policy applies).
type ViewTotals struct {
	TotalViews int `json:"totalViews"`
}

// ListViewsToolResponse is the result payload for jenkins_list_views.
type ListViewsToolResponse struct {
	Views        []ViewSummary `json:"views"`
	Summary      ViewTotals    `json:"summary"`
	Offset       int           `json:"offset"`
	Limit        int           `json:"limit"`
	Truncated    bool          `json:"truncated,omitempty"`
	NextOffset   int           `json:"nextOffset,omitempty"`
	Unauthorized bool          `json:"unauthorized,omitempty"`
	Message      string        `json:"message,omitempty"`
	// PolicyFiltered is true when MCP deny_view_names omitted at least one row
	// from the response (Wave 38 list-row privacy). Integer-only metadata;
	// denied names are never listed.
	PolicyFiltered bool `json:"policy_filtered,omitempty"`
	// PolicyOmittedCount is how many views were dropped by deny_view_names
	// (controller-wide after filter when patterns apply). Zero when unset.
	PolicyOmittedCount int `json:"policy_omitted_count,omitempty"`
}

// viewsAPITree is the approved list tree: name/description/class only — no jobs.
const viewsAPITree = "views[name,description,_class]"

// rawView is the safe JSON shape for one Jenkins view entry.
type rawView struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Class       string `json:"_class"`
}

// viewSummaryFromRaw maps a raw view JSON object to ViewSummary (sanitized).
func viewSummaryFromRaw(v rawView) ViewSummary {
	return ViewSummary{
		Name:        strings.TrimSpace(v.Name),
		Description: sanitizeNodeText(v.Description),
		Class:       strings.TrimSpace(v.Class),
	}
}

// ListViews fetches view summaries from /api/json?tree=views[name,description,_class].
// On HTTP 403, returns Unauthorized=true without treating empty as success.
// Empty/invalid pagination clamps like GetNodes (default 50, max 200).
func (opts *Client) ListViews(ctx context.Context, offset, limit int) (*ListViewsToolResponse, error) {
	if opts == nil {
		return nil, fmt.Errorf("jenkins client is nil")
	}
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 {
		limit = DefaultViewsPageSize
	}
	if limit > MaxViewsPageSize {
		limit = MaxViewsPageSize
	}

	apiPath := "/api/json?tree=" + url.QueryEscape(viewsAPITree)
	resp, err := opts.CallJenkins(ctx, opts.Client, http.MethodGet, apiPath, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return &ListViewsToolResponse{
			Views:        nil,
			Offset:       offset,
			Limit:        limit,
			Unauthorized: true,
			Message:      "not authorized to list Jenkins views (HTTP 403)",
		}, nil
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("jenkins api returned status 401: unauthorized")
	}

	body, err := readLimited(resp.Body, maxViewsAPIBodyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read views response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var viewsResp struct {
		Views []rawView `json:"views"`
	}
	if err := json.Unmarshal(body, &viewsResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	all := make([]ViewSummary, 0, len(viewsResp.Views))
	for _, v := range viewsResp.Views {
		n := viewSummaryFromRaw(v)
		// Skip empty names (malformed Jenkins payload); deny-only filter also
		// ignores empty names.
		if n.Name == "" {
			continue
		}
		all = append(all, n)
	}

	totals := ViewTotals{TotalViews: len(all)}
	end := offset + limit
	truncated := end < len(all)
	if offset > len(all) {
		offset = len(all)
	}
	page := all[offset:]
	if len(page) > limit {
		page = page[:limit]
	}
	next := 0
	if truncated {
		next = offset + len(page)
	}

	return &ListViewsToolResponse{
		Views:      page,
		Summary:    totals,
		Offset:     offset,
		Limit:      limit,
		Truncated:  truncated,
		NextOffset: next,
	}, nil
}
