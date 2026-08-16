package jenkins

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Build graph bounds (GRAPH-001).
const (
	defaultGraphMaxDepth = 3
	maxGraphMaxDepth     = 6
	defaultGraphMaxNodes = 32
	maxGraphMaxNodes     = 100
	maxGraphNetworkReqs  = 40
	maxGraphBodyBytes    = 2 << 20
)

// Selective tree for graph node fetch (causes + optional params; no full actions graph).
const graphBuildTree = "number,url,building,result,timestamp,duration,displayName," +
	"actions[_class,causes[_class,upstreamProject,upstreamBuild,shortDescription]," +
	"parameters[name,value]],downstreamBuilds[jobName,projectName,buildNumber,number]," +
	"subBuilds[jobName,buildNumber]"

// Graph direction filters.
const (
	GraphDirectionBoth       = "both"
	GraphDirectionUpstream   = "upstream"
	GraphDirectionDownstream = "downstream"
)

// GetBuildGraphToolArgs are arguments for jenkins_get_build_graph (GRAPH-001).
type GetBuildGraphToolArgs struct {
	JobName     string `json:"job_name" jsonschema:"Name/path of the Jenkins job (supports folders; not an http URL)"`
	BuildNumber int    `json:"build_number" jsonschema:"Build number"`
	// MaxDepth limits traversal depth from the root (default 3, max 6).
	MaxDepth int `json:"max_depth,omitempty" jsonschema:"Maximum traversal depth (default 3, max 6)" default:"3"`
	// MaxNodes caps nodes in the returned graph (default 32, max 100).
	MaxNodes int `json:"max_nodes,omitempty" jsonschema:"Maximum nodes to return (default 32, max 100)" default:"32"`
	// Direction is both | upstream | downstream (default both).
	Direction string `json:"direction,omitempty" jsonschema:"Traversal direction: both, upstream, or downstream (default both)" default:"both"`
}

// BuildGraphNode is one build in a related-builds graph.
type BuildGraphNode struct {
	// ID is a stable node key: "fullName#number".
	ID          string     `json:"id"`
	JobName     string     `json:"jobName"`
	BuildNumber int        `json:"buildNumber"`
	Result      string     `json:"result,omitempty"`
	Building    bool       `json:"building,omitempty"`
	Timestamp   TimeMS     `json:"timestamp,omitempty"`
	Duration    DurationMS `json:"duration,omitempty"`
	// Depth is distance from the root (0 = root).
	Depth int `json:"depth"`
	// Role: root | upstream | downstream.
	Role string `json:"role"`
	// Error is set when the node could not be fully loaded (not found, denied, etc.).
	Error string `json:"error,omitempty"`
}

// BuildGraphEdge links two nodes.
type BuildGraphEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	// Kind: upstream_cause | downstream_ref
	// (CycleDetected is computed over the directed cause→effect relation, so
	// DAG cross-edges and diamond joins no longer report false cycles.)
	Kind string `json:"kind"`
}

// GetBuildGraphToolResponse is a bounded upstream/downstream graph summary.
type GetBuildGraphToolResponse struct {
	Root          string           `json:"root"`
	Nodes         []BuildGraphNode `json:"nodes"`
	Edges         []BuildGraphEdge `json:"edges"`
	NodeCount     int              `json:"nodeCount"`
	EdgeCount     int              `json:"edgeCount"`
	Truncated     bool             `json:"truncated,omitempty"`
	CycleDetected bool             `json:"cycleDetected,omitempty"`
	Requests      int              `json:"requests"`
	// EarliestFailure is the earliest failure timestamp among failing nodes (RFC3339 via TimeMS).
	EarliestFailure *TimeMS `json:"earliestFailure,omitempty"`
	// FirstFailingLeaves are failing nodes with no failing downstream children in the graph.
	FirstFailingLeaves []string `json:"firstFailingLeaves,omitempty"`
	// CapabilityNote explains degrade when cause/relation data is thin.
	CapabilityNote string `json:"capabilityNote,omitempty"`
	Source         string `json:"source"`
}

// GetBuildGraph traverses upstream/downstream relations from a build with
// depth, node, cycle, and network request limits (GRAPH-001).
//
// Relations are taken primarily from Cause$UpstreamCause on build actions.
// Downstream edges are reverse-inferred when a discovered node points upstream
// at a known node, and from optional fixture/API fields when present.
// Missing or permission-denied nodes are represented with Error set rather
// than failing the whole traversal.
func (opts *Client) GetBuildGraph(ctx context.Context, args GetBuildGraphToolArgs) (*GetBuildGraphToolResponse, error) {
	if opts == nil {
		return nil, fmt.Errorf("jenkins client is nil")
	}
	jobName := strings.TrimSpace(args.JobName)
	if jobName == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "job_name is required")
	}
	if strings.Contains(jobName, "://") {
		return nil, apperr.New(apperr.CodeInvalidArgument, "job_name must be a typed path, not a URL")
	}
	if args.BuildNumber <= 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument, "build_number must be positive")
	}

	maxDepth := args.MaxDepth
	if maxDepth <= 0 {
		maxDepth = defaultGraphMaxDepth
	}
	if maxDepth > maxGraphMaxDepth {
		maxDepth = maxGraphMaxDepth
	}
	maxNodes := args.MaxNodes
	if maxNodes <= 0 {
		maxNodes = defaultGraphMaxNodes
	}
	if maxNodes > maxGraphMaxNodes {
		maxNodes = maxGraphMaxNodes
	}
	dir := strings.ToLower(strings.TrimSpace(args.Direction))
	if dir == "" {
		dir = GraphDirectionBoth
	}
	switch dir {
	case GraphDirectionBoth, GraphDirectionUpstream, GraphDirectionDownstream:
	default:
		return nil, apperr.New(apperr.CodeInvalidArgument, "direction must be both, upstream, or downstream")
	}

	rootID := graphNodeID(jobName, args.BuildNumber)
	out := &GetBuildGraphToolResponse{
		Root:   rootID,
		Source: CapabilitySourceLive,
	}

	type pending struct {
		job   string
		num   int
		depth int
		role  string
	}

	seen := make(map[string]bool)   // visited for expansion
	inGraph := make(map[string]int) // id -> index in nodes
	var nodes []BuildGraphNode
	var edges []BuildGraphEdge
	var queue []pending
	reqs := 0
	truncated := false
	cycle := false
	causeEdges := 0

	addNode := func(n BuildGraphNode) {
		if _, ok := inGraph[n.ID]; ok {
			return
		}
		if len(nodes) >= maxNodes {
			truncated = true
			return
		}
		inGraph[n.ID] = len(nodes)
		nodes = append(nodes, n)
	}

	queue = append(queue, pending{job: jobName, num: args.BuildNumber, depth: 0, role: "root"})
	seen[rootID] = true // mark at enqueue: each node is expanded at most once

	for len(queue) > 0 {
		if reqs >= maxGraphNetworkReqs {
			truncated = true
			break
		}
		select {
		case <-ctx.Done():
			return nil, apperr.Wrap(apperr.CodeCancelled, "build graph cancelled", ctx.Err())
		default:
		}

		cur := queue[0]
		queue = queue[1:]
		id := graphNodeID(cur.job, cur.num)

		if len(nodes) >= maxNodes && id != rootID {
			truncated = true
			continue
		}

		node, ups, downs, err := opts.fetchGraphBuild(ctx, cur.job, cur.num)
		reqs++
		node.Depth = cur.depth
		node.Role = cur.role
		if err != nil {
			node.Error = safeGraphErr(err)
		}
		addNode(node)
		if truncated && id != rootID {
			continue
		}

		// Upstream expansion. A relation pointing at an already-seen node is a
		// DAG cross-edge (e.g. the reverse of the edge just traversed, or a
		// diamond join) — not a cycle. Real cycles are detected post-hoc over
		// the collected cause→effect edges below.
		if (dir == GraphDirectionBoth || dir == GraphDirectionUpstream) && cur.depth < maxDepth {
			for _, u := range ups {
				causeEdges++
				uid := graphNodeID(u.job, u.num)
				edges = append(edges, BuildGraphEdge{From: uid, To: id, Kind: "upstream_cause"})
				if seen[uid] {
					continue
				}
				if len(nodes)+len(queue) >= maxNodes {
					truncated = true
					continue
				}
				seen[uid] = true
				queue = append(queue, pending{job: u.job, num: u.num, depth: cur.depth + 1, role: "upstream"})
			}
		}

		// Downstream expansion (explicit refs when API/fixture provides them).
		if (dir == GraphDirectionBoth || dir == GraphDirectionDownstream) && cur.depth < maxDepth {
			for _, d := range downs {
				did := graphNodeID(d.job, d.num)
				edges = append(edges, BuildGraphEdge{From: id, To: did, Kind: "downstream_ref"})
				if seen[did] {
					continue
				}
				if len(nodes)+len(queue) >= maxNodes {
					truncated = true
					continue
				}
				seen[did] = true
				queue = append(queue, pending{job: d.job, num: d.num, depth: cur.depth + 1, role: "downstream"})
			}
		}
	}

	// Deduplicate edges.
	edges = dedupeEdges(edges)

	// Cycle detection over the directed cause→effect relation (both edge kinds
	// point cause→effect after dedupe). Precise: DAG cross-edges and diamond
	// joins do not flag; only a genuine directed cycle does.
	cycle = graphHasDirectedCycle(nodes, edges)

	// Compute earliest failure + first failing leaves.
	var earliest *time.Time
	failing := make(map[string]bool)
	for _, n := range nodes {
		if isFailureResult(n.Result) && n.Error == "" {
			failing[n.ID] = true
			ts := time.Time(n.Timestamp)
			if !ts.IsZero() {
				if earliest == nil || ts.Before(*earliest) {
					t := ts
					earliest = &t
				}
			}
		}
	}
	hasDownFail := make(map[string]bool)
	for _, e := range edges {
		if failing[e.To] && (e.Kind == "downstream_ref" || e.Kind == "upstream_cause") {
			// For upstream_cause edge From=upstream To=current: failing downstream of From is To.
			if e.Kind == "downstream_ref" && failing[e.From] {
				hasDownFail[e.From] = true
			}
			if e.Kind == "upstream_cause" && failing[e.From] {
				// From is upstream of To; if To fails, From has a failing downstream.
				hasDownFail[e.From] = true
			}
		}
	}
	var leaves []string
	for id := range failing {
		if !hasDownFail[id] {
			leaves = append(leaves, id)
		}
	}
	sort.Strings(leaves)

	if earliest != nil {
		tm := TimeMS(*earliest)
		out.EarliestFailure = &tm
	}
	out.FirstFailingLeaves = leaves
	out.Nodes = nodes
	out.Edges = edges
	out.NodeCount = len(nodes)
	out.EdgeCount = len(edges)
	out.Truncated = truncated
	out.CycleDetected = cycle
	out.Requests = reqs
	if causeEdges == 0 && len(nodes) <= 1 {
		out.CapabilityNote = "no upstream/downstream cause links found on this build; graph is root-only"
	}
	return out, nil
}

type graphRef struct {
	job string
	num int
}

func graphNodeID(job string, num int) string {
	return fmt.Sprintf("%s#%d", job, num)
}

// graphHasDirectedCycle reports whether the cause→effect edges contain a
// directed cycle (DFS three-color). Both upstream_cause (From=upstream) and
// downstream_ref (From=current) edges point cause→effect. Bounded by the
// graph node cap, so recursion depth stays shallow.
func graphHasDirectedCycle(nodes []BuildGraphNode, edges []BuildGraphEdge) bool {
	const (
		white = 0 // unvisited
		gray  = 1 // on current DFS path
		black = 2 // fully explored
	)
	adj := make(map[string][]string, len(nodes))
	for _, e := range edges {
		if e.Kind != "upstream_cause" && e.Kind != "downstream_ref" {
			continue
		}
		adj[e.From] = append(adj[e.From], e.To)
	}
	color := make(map[string]int, len(nodes))
	var dfs func(u string) bool
	dfs = func(u string) bool {
		color[u] = gray
		for _, v := range adj[u] {
			if color[v] == gray {
				return true
			}
			if color[v] == white && dfs(v) {
				return true
			}
		}
		color[u] = black
		return false
	}
	for _, n := range nodes {
		if color[n.ID] == white && dfs(n.ID) {
			return true
		}
	}
	return false
}

func (opts *Client) fetchGraphBuild(ctx context.Context, jobName string, buildNumber int) (BuildGraphNode, []graphRef, []graphRef, error) {
	id := graphNodeID(jobName, buildNumber)
	node := BuildGraphNode{
		ID:          id,
		JobName:     jobName,
		BuildNumber: buildNumber,
	}

	jobPath := BuildJobPath(jobName)
	apiPath := fmt.Sprintf("%s/%d/api/json?tree=%s", jobPath, buildNumber, url.QueryEscape(graphBuildTree))
	// Also request optional downstreamProjects-style custom fields used by fixtures:
	// we accept extra JSON keys via a loose decode.
	resp, err := opts.CallJenkins(ctx, opts.Client, http.MethodGet, apiPath, nil, nil)
	if err != nil {
		return node, nil, nil, err
	}
	body, err := readLimited(resp.Body, maxGraphBodyBytes)
	_ = resp.Body.Close()
	if err != nil {
		return node, nil, nil, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
		// continue
	case http.StatusNotFound:
		return node, nil, nil, apperr.New(apperr.CodeNotFound, "build not found")
	case http.StatusForbidden:
		return node, nil, nil, apperr.New(apperr.CodeAuthorization, "not authorized")
	default:
		return node, nil, nil, fmt.Errorf("jenkins api returned status %d", resp.StatusCode)
	}

	var data struct {
		Number    int        `json:"number"`
		Building  bool       `json:"building"`
		Result    string     `json:"result"`
		Timestamp TimeMS     `json:"timestamp"`
		Duration  DurationMS `json:"duration"`
		Actions   []struct {
			Class  string `json:"_class"`
			Causes []struct {
				Class            string `json:"_class"`
				UpstreamProject  string `json:"upstreamProject"`
				UpstreamBuild    int    `json:"upstreamBuild"`
				ShortDescription string `json:"shortDescription"`
			} `json:"causes"`
		} `json:"actions"`
		// Optional fixture/plugin extensions for downstream refs.
		DownstreamBuilds []struct {
			JobName     string `json:"jobName"`
			ProjectName string `json:"projectName"`
			BuildNumber int    `json:"buildNumber"`
			Number      int    `json:"number"`
		} `json:"downstreamBuilds"`
		// SubBuilds used by some multi-job plugins.
		SubBuilds []struct {
			JobName     string `json:"jobName"`
			BuildNumber int    `json:"buildNumber"`
		} `json:"subBuilds"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return node, nil, nil, fmt.Errorf("failed to decode build: %w", err)
	}

	if data.Number > 0 {
		node.BuildNumber = data.Number
		node.ID = graphNodeID(jobName, data.Number)
	}
	node.Building = data.Building
	node.Result = data.Result
	node.Timestamp = data.Timestamp
	node.Duration = data.Duration

	var ups, downs []graphRef
	for _, a := range data.Actions {
		for _, c := range a.Causes {
			if c.UpstreamProject == "" || c.UpstreamBuild <= 0 {
				// Also accept class-based UpstreamCause with empty project via shortDescription parse residual: skip.
				continue
			}
			// Normalize upstream project path (folders use /).
			proj := strings.ReplaceAll(c.UpstreamProject, " » ", "/")
			proj = strings.Trim(proj, "/")
			ups = append(ups, graphRef{job: proj, num: c.UpstreamBuild})
		}
	}
	for _, d := range data.DownstreamBuilds {
		name := d.JobName
		if name == "" {
			name = d.ProjectName
		}
		num := d.BuildNumber
		if num <= 0 {
			num = d.Number
		}
		if name != "" && num > 0 {
			downs = append(downs, graphRef{job: strings.Trim(name, "/"), num: num})
		}
	}
	for _, s := range data.SubBuilds {
		if s.JobName != "" && s.BuildNumber > 0 {
			downs = append(downs, graphRef{job: strings.Trim(s.JobName, "/"), num: s.BuildNumber})
		}
	}
	return node, ups, downs, nil
}

func safeGraphErr(err error) string {
	if err == nil {
		return ""
	}
	code := apperr.CodeOf(err)
	switch code {
	case apperr.CodeNotFound:
		return "not_found"
	case apperr.CodeAuthorization:
		return "permission_denied"
	case apperr.CodeAuthentication:
		return "authentication"
	default:
		// Avoid leaking raw upstream bodies.
		return "unavailable"
	}
}

func isFailureResult(result string) bool {
	switch strings.ToUpper(strings.TrimSpace(result)) {
	case "FAILURE", "UNSTABLE":
		return true
	default:
		return false
	}
}

func dedupeEdges(edges []BuildGraphEdge) []BuildGraphEdge {
	if len(edges) == 0 {
		return edges
	}
	type key struct{ f, t, k string }
	seen := make(map[key]bool, len(edges))
	out := make([]BuildGraphEdge, 0, len(edges))
	for _, e := range edges {
		k := key{e.From, e.To, e.Kind}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, e)
	}
	return out
}
