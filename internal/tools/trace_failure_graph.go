package tools

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/redact"
)

// ToolTraceFailureGraph is the DIAG-005 failure-graph triage tool name.
const ToolTraceFailureGraph = "jenkins_trace_failure_graph"

// Trace-graph budgets (server-enforced).
const (
	// DefaultTraceMaxDiagnoseNodes caps lightweight diagnose fan-out.
	DefaultTraceMaxDiagnoseNodes = 8
	// HardTraceMaxDiagnoseNodes is the absolute diagnose fan-out ceiling.
	HardTraceMaxDiagnoseNodes = 16
	// DefaultTraceLogBytesPerNode is the default log tail per failed node.
	DefaultTraceLogBytesPerNode = 32 << 10 // 32 KiB
	// HardTraceLogBytesPerNode is the per-node log ceiling.
	HardTraceLogBytesPerNode = HardDiagnoseLogBytes
)

// TraceFailureGraphToolArgs is the MCP input for jenkins_trace_failure_graph.
type TraceFailureGraphToolArgs struct {
	JobName     string `json:"job_name" mcp:"Jenkins job full name (folder/job path; not a URL)"`
	BuildNumber int    `json:"build_number" mcp:"root build number"`
	// MaxDepth limits related-build graph depth (default 3, max 6; GRAPH-001).
	MaxDepth int `json:"max_depth,omitempty" mcp:"maximum graph depth (default 3, max 6)"`
	// MaxNodes caps graph nodes (default 32, max 100; GRAPH-001).
	MaxNodes int `json:"max_nodes,omitempty" mcp:"maximum graph nodes (default 32, max 100)"`
	// Direction is both | upstream | downstream (default both).
	Direction string `json:"direction,omitempty" mcp:"both, upstream, or downstream (default both)"`
	// MaxDiagnoseNodes caps how many failed nodes receive log extraction (default 8, max 16).
	MaxDiagnoseNodes int `json:"max_diagnose_nodes,omitempty" mcp:"max failed nodes to diagnose"`
	// MaxLogBytesPerNode caps log tail per diagnosed node (0 ⇒ default).
	MaxLogBytesPerNode int `json:"max_log_bytes_per_node,omitempty" mcp:"max log tail bytes per failed node"`
}

// TraceGraphNode is a compact graph node summary for the MCP response.
type TraceGraphNode struct {
	ID          string `json:"id"`
	JobName     string `json:"job_name"`
	BuildNumber int    `json:"build_number"`
	Result      string `json:"result,omitempty"`
	Building    bool   `json:"building,omitempty"`
	Depth       int    `json:"depth"`
	Role        string `json:"role,omitempty"`
	// Error is set when the node could not be fully loaded (permission/missing).
	Error     string `json:"error,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
}

// TraceFailedNodeDiag is a lightweight diagnose result for one failed graph node.
type TraceFailedNodeDiag struct {
	ID          string `json:"id"`
	JobName     string `json:"job_name"`
	BuildNumber int    `json:"build_number"`
	Result      string `json:"result,omitempty"`
	// IsLeaf is true when the node is among FirstFailingLeaves.
	IsLeaf bool `json:"is_leaf,omitempty"`
	// TopSignature / TopPattern / TopMessage from bounded log extraction.
	TopSignature string  `json:"top_signature,omitempty"`
	TopPattern   string  `json:"top_pattern,omitempty"`
	TopMessage   string  `json:"top_message,omitempty"`
	Confidence   float64 `json:"confidence,omitempty"`
	// EvidenceExcerpt is a short sanitized evidence line.
	EvidenceExcerpt string `json:"evidence_excerpt,omitempty"`
	// LogSource is local_mirror or client_tail when logs were read.
	LogSource string `json:"log_source,omitempty"`
	// SkippedReason when diagnose was not run (budget / non-failure / error).
	SkippedReason string `json:"skipped_reason,omitempty"`
	// LowerConfidence explains permission/missing/incomplete data.
	LowerConfidence string `json:"lower_confidence,omitempty"`
}

// TraceBudgets records graph + diagnose caps and consumption.
type TraceBudgets struct {
	MaxDepth           int `json:"max_depth"`
	MaxNodes           int `json:"max_nodes"`
	MaxDiagnoseNodes   int `json:"max_diagnose_nodes"`
	MaxLogBytesPerNode int `json:"max_log_bytes_per_node"`
	GraphRequests      int `json:"graph_requests"`
	NodesDiagnosed     int `json:"nodes_diagnosed"`
	LogBytesScanned    int `json:"log_bytes_scanned"`
	// UniqueLogsRead is the number of distinct job#build log tails fetched (deduped).
	UniqueLogsRead int `json:"unique_logs_read"`
	// PERF-003 remote ceilings.
	MaxRemoteCalls int   `json:"max_remote_calls,omitempty"`
	MaxRemoteBytes int64 `json:"max_remote_bytes,omitempty"`
	MaxWallMS      int64 `json:"max_wall_ms,omitempty"`
}

// TraceFailureGraphToolResponse is the compact failure-graph triage result.
type TraceFailureGraphToolResponse struct {
	Root string `json:"root"`
	// Graph is a compact related-build summary (nodes/edges/limits).
	Nodes         []TraceGraphNode         `json:"nodes"`
	Edges         []jenkins.BuildGraphEdge `json:"edges,omitempty"`
	NodeCount     int                      `json:"node_count"`
	EdgeCount     int                      `json:"edge_count"`
	Truncated     bool                     `json:"truncated,omitempty"`
	CycleDetected bool                     `json:"cycle_detected,omitempty"`
	// EarliestFailure is the earliest failure timestamp among failing nodes (RFC3339).
	EarliestFailure string `json:"earliest_failure,omitempty"`
	// FirstFailingLeaves are failing nodes with no failing descendants in the graph.
	FirstFailingLeaves []string `json:"first_failing_leaves,omitempty"`
	// FailedNodes are lightweight diagnose results for top failed nodes (budgeted).
	FailedNodes     []TraceFailedNodeDiag `json:"failed_nodes,omitempty"`
	Budgets         TraceBudgets          `json:"budgets"`
	Sources         []string              `json:"sources,omitempty"`
	ConfidenceNotes []string              `json:"confidence_notes,omitempty"`
	Residuals       []string              `json:"residuals,omitempty"`
	Incomplete      bool                  `json:"incomplete,omitempty"`
	Untrusted       bool                  `json:"untrusted"`
	Summary         string                `json:"summary"`
	CapabilityNote  string                `json:"capability_note,omitempty"`
	// Perf is optional request-local cache/remote counters (PERF-003).
	Perf *DiagPerf `json:"perf,omitempty"`
}

// registerTraceFailureGraphTool registers jenkins_trace_failure_graph (DIAG-005).
func registerTraceFailureGraphTool(s *mcp.Server, client *jenkins.Client, st regState) {
	addReadTool(s, st, &mcp.Tool{
		Name: ToolTraceFailureGraph,
		Description: "Trace a bounded related-build failure graph (GRAPH-001) and run lightweight " +
			"diagnose on failed nodes under fan-out/log budgets. Distinguishes earliest failure time " +
			"from first failing leaves; deduplicates shared node log reads; degrades on permission/missing data.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args TraceFailureGraphToolArgs) (*mcp.CallToolResult, TraceFailureGraphToolResponse, error) {
		out, err := runTraceFailureGraph(ctx, client, st, args)
		if err != nil {
			return nil, TraceFailureGraphToolResponse{}, err
		}
		return structuredResult(out)
	})
}

func runTraceFailureGraph(ctx context.Context, client *jenkins.Client, st regState, args TraceFailureGraphToolArgs) (TraceFailureGraphToolResponse, error) {
	bref, err := buildRef("job_name", args.JobName, "build_number", args.BuildNumber)
	if err != nil {
		return TraceFailureGraphToolResponse{}, err
	}
	job := bref.Job.FullName
	build := int(bref.Number)

	maxDiag := args.MaxDiagnoseNodes
	if maxDiag <= 0 {
		maxDiag = DefaultTraceMaxDiagnoseNodes
	}
	if maxDiag > HardTraceMaxDiagnoseNodes {
		maxDiag = HardTraceMaxDiagnoseNodes
	}
	maxLog := args.MaxLogBytesPerNode
	if maxLog <= 0 {
		maxLog = DefaultTraceLogBytesPerNode
	}
	if maxLog > HardTraceLogBytesPerNode {
		maxLog = HardTraceLogBytesPerNode
	}

	budgetCfg := mergeDiagBudget(traceBudgetDefault(), st.diagBudget)
	out := TraceFailureGraphToolResponse{
		Untrusted: true,
		Budgets: TraceBudgets{
			MaxDepth:           args.MaxDepth,
			MaxNodes:           args.MaxNodes,
			MaxDiagnoseNodes:   maxDiag,
			MaxLogBytesPerNode: maxLog,
			MaxRemoteCalls:     budgetCfg.MaxRemoteCalls,
			MaxRemoteBytes:     budgetCfg.MaxRemoteBytes,
		},
		ConfidenceNotes: []string{
			"earliest_failure is the earliest failure timestamp among failed nodes; first_failing_leaves are failed nodes with no failed descendants in the traversed graph",
			"shared nodes are diagnosed at most once; log tails are never re-mirrored twice in one request",
			"PERF-003 process FetchCache dedupes log tails across diagnose/compare/graph tool calls",
		},
	}
	if budgetCfg.MaxWall > 0 {
		out.Budgets.MaxWallMS = budgetCfg.MaxWall.Milliseconds()
	}

	if client == nil {
		return TraceFailureGraphToolResponse{}, apperr.New(apperr.CodeInternal, "jenkins client is nil")
	}

	sess := newDiagSession(st, traceBudgetDefault())
	ctx, cancel := sess.BoundContext(ctx)
	defer cancel()
	ctx = withDiagSession(ctx, sess)

	if sess != nil && !sess.AllowRemote(2048) {
		out.Incomplete = true
		out.ConfidenceNotes = append(out.ConfidenceNotes, "build_graph skipped: "+sess.BudgetNote())
		out.Residuals = append(out.Residuals, sess.BudgetNote())
		perf := sess.PerfSnapshot()
		out.Perf = &perf
		return out, nil
	}
	graph, gerr := client.GetBuildGraph(ctx, jenkins.GetBuildGraphToolArgs{
		JobName:     job,
		BuildNumber: build,
		MaxDepth:    args.MaxDepth,
		MaxNodes:    args.MaxNodes,
		Direction:   args.Direction,
	})
	if gerr != nil {
		return TraceFailureGraphToolResponse{}, mapToolErr(gerr)
	}
	if sess != nil {
		sess.RecordRemote(2048)
	}
	out.Sources = append(out.Sources, "build_graph")
	if graph == nil {
		out.Summary = "empty graph"
		return out, nil
	}

	out.Root = graph.Root
	out.NodeCount = graph.NodeCount
	out.EdgeCount = graph.EdgeCount
	out.Truncated = graph.Truncated
	out.CycleDetected = graph.CycleDetected
	out.FirstFailingLeaves = graph.FirstFailingLeaves
	out.CapabilityNote = graph.CapabilityNote
	out.Budgets.GraphRequests = graph.Requests
	out.Budgets.MaxDepth = args.MaxDepth
	if out.Budgets.MaxDepth <= 0 {
		out.Budgets.MaxDepth = 3
	}
	out.Budgets.MaxNodes = args.MaxNodes
	if out.Budgets.MaxNodes <= 0 {
		out.Budgets.MaxNodes = 32
	}
	if graph.EarliestFailure != nil {
		ts := time.Time(*graph.EarliestFailure)
		if !ts.IsZero() {
			out.EarliestFailure = ts.UTC().Format(time.RFC3339)
		}
	}
	if graph.Truncated {
		out.Incomplete = true
		out.ConfidenceNotes = append(out.ConfidenceNotes, "graph truncated by depth/node/request limits")
	}
	if graph.CycleDetected {
		out.ConfidenceNotes = append(out.ConfidenceNotes, "cycle detected; traversal skipped revisiting nodes")
	}

	// Compact nodes.
	leafSet := make(map[string]bool, len(graph.FirstFailingLeaves))
	for _, id := range graph.FirstFailingLeaves {
		leafSet[id] = true
	}
	nodes := make([]TraceGraphNode, 0, len(graph.Nodes))
	var failed []jenkins.BuildGraphNode
	for _, n := range graph.Nodes {
		tn := TraceGraphNode{
			ID:          n.ID,
			JobName:     n.JobName,
			BuildNumber: n.BuildNumber,
			Result:      n.Result,
			Building:    n.Building,
			Depth:       n.Depth,
			Role:        n.Role,
			Error:       n.Error,
		}
		ts := time.Time(n.Timestamp)
		if !ts.IsZero() {
			tn.Timestamp = ts.UTC().Format(time.RFC3339)
		}
		nodes = append(nodes, tn)
		if n.Error != "" {
			out.ConfidenceNotes = append(out.ConfidenceNotes,
				fmt.Sprintf("node %s lower confidence: %s", n.ID, n.Error))
		}
		if isFailedGraphResult(n.Result) && n.Error == "" {
			failed = append(failed, n)
		} else if isFailedGraphResult(n.Result) && n.Error != "" {
			// Still surface as failed with lower confidence, no log fetch.
			failed = append(failed, n)
		}
	}
	out.Nodes = nodes
	out.Edges = graph.Edges

	// Priority order: first failing leaves, then earlier timestamps, then greater depth (closer to leaf), then id.
	sort.SliceStable(failed, func(i, j int) bool {
		li, lj := leafSet[failed[i].ID], leafSet[failed[j].ID]
		if li != lj {
			return li // leaves first
		}
		ti := time.Time(failed[i].Timestamp)
		tj := time.Time(failed[j].Timestamp)
		if !ti.Equal(tj) {
			if ti.IsZero() {
				return false
			}
			if tj.IsZero() {
				return true
			}
			return ti.Before(tj)
		}
		if failed[i].Depth != failed[j].Depth {
			return failed[i].Depth > failed[j].Depth
		}
		return failed[i].ID < failed[j].ID
	})

	// Deduplicate log reads by job#build (shared nodes / multi-edges).
	type logCacheEntry struct {
		findings   []DiagnoseFinding
		logBytes   int
		source     string
		incomplete bool
		notes      []string
		errNote    string
	}
	logCache := make(map[string]*logCacheEntry)
	logKey := func(jobName string, num int) string {
		return fmt.Sprintf("%s#%d", jobName, num)
	}

	var diags []TraceFailedNodeDiag
	for _, n := range failed {
		select {
		case <-ctx.Done():
			out.Incomplete = true
			out.ConfidenceNotes = append(out.ConfidenceNotes, "diagnose fan-out cancelled: "+safeErrNote(ctx.Err()))
			goto done
		default:
		}
		d := TraceFailedNodeDiag{
			ID:          n.ID,
			JobName:     n.JobName,
			BuildNumber: n.BuildNumber,
			Result:      n.Result,
			IsLeaf:      leafSet[n.ID],
		}
		if n.Error != "" {
			d.LowerConfidence = n.Error
			d.SkippedReason = "node_error_" + n.Error
			diags = append(diags, d)
			continue
		}
		if len(diags) >= maxDiag {
			// Count only diagnose slots for nodes we might still list with skip?
			// Once budget hit, mark remaining as skipped.
			d.SkippedReason = "diagnose_budget"
			diags = append(diags, d)
			// Keep appending skipped-only for remaining failed? Prefer stop after listing budget worth of skipped.
			// Cap total failed_nodes list to maxDiag * 2 to stay compact.
			if len(diags) >= maxDiag*2 {
				out.Incomplete = true
				break
			}
			continue
		}

		key := logKey(n.JobName, n.BuildNumber)
		entry, ok := logCache[key]
		if !ok {
			findings, logBytes, src, incomplete, notes := extractBuildSignatures(
				ctx, client, st, n.JobName, n.BuildNumber, maxLog, 3)
			entry = &logCacheEntry{
				findings:   findings,
				logBytes:   logBytes,
				source:     src,
				incomplete: incomplete,
				notes:      notes,
			}
			logCache[key] = entry
			out.Budgets.UniqueLogsRead++
			out.Budgets.LogBytesScanned += logBytes
			if src != "" {
				out.Sources = append(out.Sources, src)
			}
			out.ConfidenceNotes = append(out.ConfidenceNotes, notes...)
			if incomplete {
				out.Incomplete = true
			}
		}
		out.Budgets.NodesDiagnosed++
		d.LogSource = entry.source
		if entry.errNote != "" {
			d.LowerConfidence = entry.errNote
		}
		if len(entry.findings) > 0 {
			top := entry.findings[0]
			d.TopSignature = top.Signature
			d.TopPattern = top.Pattern
			d.TopMessage = top.Message
			d.Confidence = top.Confidence
			if len(top.Evidence) > 0 {
				d.EvidenceExcerpt = redact.SanitizeForModel(truncateDiagnoseText(top.Evidence[0].Text, MaxEvidenceExcerptBytes))
			} else {
				d.EvidenceExcerpt = top.Message
			}
		} else {
			d.LowerConfidence = joinNonEmpty(d.LowerConfidence, "no_error_markers_in_scanned_window")
		}
		if entry.incomplete {
			d.LowerConfidence = joinNonEmpty(d.LowerConfidence, "incomplete_log_window")
		}
		diags = append(diags, d)
	}
done:
	// If we only appended skipped after budget, trim pure-skipped overflow beyond maxDiag*2 already handled.
	// Prefer returning diagnosed + a few skipped for visibility.
	out.FailedNodes = diags
	if note := sess.BudgetNote(); note != "" {
		out.Incomplete = true
		out.ConfidenceNotes = append(out.ConfidenceNotes, note)
		out.Residuals = append(out.Residuals, note)
	}
	if ctx.Err() != nil {
		out.Incomplete = true
	}
	out.Sources = uniqueStrings(out.Sources)
	out.Summary = buildTraceSummary(out)
	perf := sess.PerfSnapshot()
	out.Perf = &perf
	return out, nil
}

func isFailedGraphResult(result string) bool {
	switch strings.ToUpper(strings.TrimSpace(result)) {
	case "FAILURE", "UNSTABLE":
		return true
	default:
		return false
	}
}

func joinNonEmpty(a, b string) string {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return a + "; " + b
}

func buildTraceSummary(out TraceFailureGraphToolResponse) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("root=%s nodes=%d failed_diagnosed=%d",
		out.Root, out.NodeCount, out.Budgets.NodesDiagnosed))
	if out.EarliestFailure != "" {
		parts = append(parts, "earliest_failure="+out.EarliestFailure)
	}
	if n := len(out.FirstFailingLeaves); n > 0 {
		parts = append(parts, fmt.Sprintf("first_failing_leaves=%d (%s)", n, strings.Join(out.FirstFailingLeaves, ",")))
	}
	if out.CycleDetected {
		parts = append(parts, "cycle_detected")
	}
	if out.Truncated {
		parts = append(parts, "truncated")
	}
	// Top signatures snippet.
	var sigs []string
	for _, d := range out.FailedNodes {
		if d.TopSignature != "" {
			sigs = append(sigs, d.ID+":"+d.TopPattern)
		}
		if len(sigs) >= 3 {
			break
		}
	}
	if len(sigs) > 0 {
		parts = append(parts, "top="+strings.Join(sigs, ","))
	}
	return strings.Join(parts, "; ")
}
