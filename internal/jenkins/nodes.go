package jenkins

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// DefaultNodesPageSize caps node list rows returned in one call (HEALTH-001).
const DefaultNodesPageSize = 50

// MaxNodesPageSize is the hard upper bound for pagination limit.
const MaxNodesPageSize = 200

// GetNodesToolArgs are the tool arguments for jenkins_get_nodes.
type GetNodesToolArgs struct {
	// Offset is the zero-based start index into the computer list (pagination).
	Offset int `json:"offset,omitempty" jsonschema:"Zero-based offset into the node list (default 0)"`
	// Limit is the maximum nodes to return (default 50, max 200).
	Limit int `json:"limit,omitempty" jsonschema:"Maximum nodes to return (default 50, max 200)"`
}

// GetNodeToolArgs are the tool arguments for jenkins_get_node (Wave 36).
// NodeName is required; policyTargetFromArgs binds it to Target.NodeName so
// deny_node_names can deny at call time.
type GetNodeToolArgs struct {
	// NodeName is the Jenkins computer path name (e.g. agent-1). Built-in is
	// historically "(master)" or "built-in" — pass the path segment Jenkins uses,
	// not only the display name.
	NodeName string `json:"node_name" jsonschema:"Jenkins node/computer name (required; use (master) or built-in for the controller node)"`
}

// NodeSummary is a safe node/executor summary without environment or system properties.
type NodeSummary struct {
	Name           string   `json:"name"`
	Offline        bool     `json:"offline"`
	TemporarilyOff bool     `json:"temporarilyOffline,omitempty"`
	Idle           bool     `json:"idle"`
	NumExecutors   int      `json:"numExecutors"`
	BusyExecutors  int      `json:"busyExecutors"`
	IdleExecutors  int      `json:"idleExecutors"`
	Labels         []string `json:"labels,omitempty"`
	OfflineCause   string   `json:"offlineCause,omitempty"`
	Description    string   `json:"description,omitempty"`
}

// NodeTotals aggregates executor saturation across the returned page (and
// controller-wide when full list is scanned for summary).
type NodeTotals struct {
	TotalNodes     int `json:"totalNodes"`
	OnlineNodes    int `json:"onlineNodes"`
	OfflineNodes   int `json:"offlineNodes"`
	TotalExecutors int `json:"totalExecutors"`
	BusyExecutors  int `json:"busyExecutors"`
	IdleExecutors  int `json:"idleExecutors"`
}

// GetNodesToolResponse is the result payload for jenkins_get_nodes.
type GetNodesToolResponse struct {
	Nodes        []NodeSummary `json:"nodes"`
	Summary      NodeTotals    `json:"summary"`
	Offset       int           `json:"offset"`
	Limit        int           `json:"limit"`
	Truncated    bool          `json:"truncated,omitempty"`
	NextOffset   int           `json:"nextOffset,omitempty"`
	Unauthorized bool          `json:"unauthorized,omitempty"`
	Message      string        `json:"message,omitempty"`
	// PolicyFiltered is true when MCP deny_node_names omitted at least one row
	// from the response (Wave 36 list-row privacy). Integer-only metadata;
	// denied names are never listed.
	PolicyFiltered bool `json:"policy_filtered,omitempty"`
	// PolicyOmittedCount is how many nodes were dropped by deny_node_names
	// (controller-wide after filter when patterns apply). Zero when unset.
	PolicyOmittedCount int `json:"policy_omitted_count,omitempty"`
}

// GetNodeToolResponse is the result payload for jenkins_get_node (one node).
type GetNodeToolResponse struct {
	Node NodeSummary `json:"node"`
}

// computerAPITree is the approved list tree: no environment / systemProperties.
const computerAPITree = "computer[displayName,description,offline,temporarilyOffline,numExecutors,idle,offlineCauseReason,assignedLabels[name],executors[idle]]"

// singleComputerAPITree is the approved tree for one computer resource (same fields).
const singleComputerAPITree = "displayName,description,offline,temporarilyOffline,numExecutors,idle,offlineCauseReason,assignedLabels[name],executors[idle]"

// rawComputer is the safe JSON shape for one Jenkins computer entry (list or single).
type rawComputer struct {
	DisplayName        string `json:"displayName"`
	Description        string `json:"description"`
	Offline            bool   `json:"offline"`
	TemporarilyOffline bool   `json:"temporarilyOffline"`
	NumExecutors       int    `json:"numExecutors"`
	Idle               bool   `json:"idle"`
	OfflineCauseReason string `json:"offlineCauseReason"`
	AssignedLabels     []struct {
		Name string `json:"name"`
	} `json:"assignedLabels"`
	Executors []struct {
		Idle bool `json:"idle"`
	} `json:"executors"`
}

// nodeSummaryFromRaw maps a raw computer JSON object to NodeSummary (sanitized).
func nodeSummaryFromRaw(c rawComputer) NodeSummary {
	busy := 0
	idleExec := 0
	for _, ex := range c.Executors {
		if ex.Idle {
			idleExec++
		} else {
			busy++
		}
	}
	// Prefer executor counts when present; fall back to numExecutors.
	numExec := c.NumExecutors
	if len(c.Executors) > 0 {
		numExec = len(c.Executors)
	}
	labels := make([]string, 0, len(c.AssignedLabels))
	for _, l := range c.AssignedLabels {
		name := strings.TrimSpace(l.Name)
		if name == "" {
			continue
		}
		labels = append(labels, name)
	}
	return NodeSummary{
		Name:           strings.TrimSpace(c.DisplayName),
		Offline:        c.Offline,
		TemporarilyOff: c.TemporarilyOffline,
		Idle:           c.Idle,
		NumExecutors:   numExec,
		BusyExecutors:  busy,
		IdleExecutors:  idleExec,
		Labels:         labels,
		OfflineCause:   sanitizeNodeText(c.OfflineCauseReason),
		Description:    sanitizeNodeText(c.Description),
	}
}

// GetNodes fetches node/executor summaries from /computer/api/json.
// On HTTP 403, returns Unauthorized=true without treating empty as success.
func (opts *Client) GetNodes(ctx context.Context, offset, limit int) (*GetNodesToolResponse, error) {
	if opts == nil {
		return nil, fmt.Errorf("jenkins client is nil")
	}
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 {
		limit = DefaultNodesPageSize
	}
	if limit > MaxNodesPageSize {
		limit = MaxNodesPageSize
	}

	apiPath := "/computer/api/json?tree=" + computerAPITree
	resp, err := opts.CallJenkins(ctx, opts.Client, http.MethodGet, apiPath, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return &GetNodesToolResponse{
			Nodes:        nil,
			Offset:       offset,
			Limit:        limit,
			Unauthorized: true,
			Message:      "not authorized to list Jenkins nodes (HTTP 403)",
		}, nil
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("jenkins api returned status 401: unauthorized")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, strings.TrimSpace(readLimitedErrBody(resp.Body)))
	}

	var computerResp struct {
		Computer []rawComputer `json:"computer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&computerResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	all := make([]NodeSummary, 0, len(computerResp.Computer))
	var totals NodeTotals
	for _, c := range computerResp.Computer {
		n := nodeSummaryFromRaw(c)
		all = append(all, n)

		totals.TotalNodes++
		if c.Offline {
			totals.OfflineNodes++
		} else {
			totals.OnlineNodes++
		}
		totals.TotalExecutors += n.NumExecutors
		totals.BusyExecutors += n.BusyExecutors
		totals.IdleExecutors += n.IdleExecutors
	}

	totals.TotalNodes = len(all)
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

	return &GetNodesToolResponse{
		Nodes:      page,
		Summary:    totals,
		Offset:     offset,
		Limit:      limit,
		Truncated:  truncated,
		NextOffset: next,
	}, nil
}

// GetNode fetches a single node/executor summary from /computer/<name>/api/json.
// Empty name → invalid_argument; 404 → not_found; 403 → authorization.
// Tree fields match GetNodes (no environment / systemProperties).
//
// nodeName is the Jenkins computer path segment. Built-in historically uses
// "(master)" (URL path /computer/%28master%29/); newer controllers may use
// "built-in". Callers must pass the path name Jenkins expects.
func (opts *Client) GetNode(ctx context.Context, nodeName string) (*GetNodeToolResponse, error) {
	if opts == nil {
		return nil, fmt.Errorf("jenkins client is nil")
	}
	nodeName = strings.TrimSpace(nodeName)
	if nodeName == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "node_name is required")
	}
	// Reject URL-like / traversal values so we never pass secrets-in-query or
	// path escapes through the computer segment.
	if strings.Contains(nodeName, "://") || strings.HasPrefix(nodeName, "/") ||
		strings.Contains(nodeName, "..") || strings.Contains(nodeName, "/") {
		return nil, apperr.New(apperr.CodeInvalidArgument, "node_name must be a single Jenkins computer name, not a URL or path")
	}

	// PathEscape handles spaces, parentheses ((master) → %28master%29), etc.
	apiPath := "/computer/" + url.PathEscape(nodeName) + "/api/json?tree=" + singleComputerAPITree
	resp, err := opts.CallJenkins(ctx, opts.Client, http.MethodGet, apiPath, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// continue
	case http.StatusNotFound:
		return nil, apperr.New(apperr.CodeNotFound, fmt.Sprintf("node %q not found", nodeName))
	case http.StatusUnauthorized:
		return nil, apperr.New(apperr.CodeAuthentication, "not authenticated for Jenkins node")
	case http.StatusForbidden:
		return nil, apperr.New(apperr.CodeAuthorization, "not authorized to read Jenkins node")
	default:
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, strings.TrimSpace(readLimitedErrBody(resp.Body)))
	}

	var raw rawComputer
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	n := nodeSummaryFromRaw(raw)
	// Prefer displayName; if Jenkins omits it, fall back to the requested path name.
	if n.Name == "" {
		n.Name = nodeName
	}
	return &GetNodeToolResponse{Node: n}, nil
}

// sanitizeNodeText strips control sequences and caps length for model-facing fields.
func sanitizeNodeText(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// Drop C0 controls except space-like; keep printable text only.
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 0x20 && r != '\t' {
			continue
		}
		if r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	out := b.String()
	const max = 512
	if len(out) > max {
		// Rune-safe: never split a multi-byte rune at the byte cap.
		out, _ = truncateBytes(out, max)
		out += "…"
	}
	return out
}

// scrubSecretsLike is a lightweight, FND-004-local redaction for jenkins package
// text fields (queue why, probe notes, errors). Full enterprise redaction lives
// in internal/redact at the tools/MCP boundary; this package must not import it.
func scrubSecretsLike(s string) string {
	if s == "" {
		return s
	}
	// Common credential-bearing prefixes/patterns only — conservative replace.
	patterns := []struct {
		prefix string
		repl   string
	}{
		{"Bearer ", "Bearer [REDACTED]"},
		{"bearer ", "bearer [REDACTED]"},
		{"Basic ", "Basic [REDACTED]"},
		{"basic ", "basic [REDACTED]"},
	}
	out := s
	for _, p := range patterns {
		if i := strings.Index(out, p.prefix); i >= 0 {
			// Replace from match through next whitespace/end.
			start := i + len(p.prefix)
			end := start
			for end < len(out) && out[end] != ' ' && out[end] != '\t' && out[end] != '\n' && out[end] != '"' {
				end++
			}
			out = out[:i] + p.repl + out[end:]
		}
	}
	// password=... / token=... / api_key=... style (value until whitespace).
	for _, key := range []string{"password=", "passwd=", "secret=", "token=", "api_key=", "api-token=", "authorization="} {
		lower := strings.ToLower(out)
		idx := strings.Index(lower, key)
		if idx < 0 {
			continue
		}
		start := idx + len(key)
		end := start
		for end < len(out) && out[end] != ' ' && out[end] != '\t' && out[end] != '\n' && out[end] != '"' && out[end] != '&' {
			end++
		}
		out = out[:start] + "[REDACTED]" + out[end:]
	}
	return out
}
