package jenkins

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Delay category codes (stable, model-visible). Differentiated by fixture (DIAG-007).
const (
	DelayCategoryNoExecutor     = "no_executor"
	DelayCategoryOfflineLabel   = "offline_label"
	DelayCategoryThrottling     = "throttling"
	DelayCategoryBlocked        = "blocked"
	DelayCategoryUpstreamWait   = "upstream_wait"
	DelayCategoryQuietingDown   = "quieting_down"
	DelayCategoryAlreadyStarted = "already_started"
	DelayCategoryCancelled      = "cancelled"
	DelayCategoryUnknown        = "unknown"
	DelayCategoryNotInQueue     = "not_in_queue"
)

// ExplainQueueDelayToolArgs are inputs for jenkins_explain_queue_delay (DIAG-007).
// Provide queue_item_id and/or job_name (at least one required).
type ExplainQueueDelayToolArgs struct {
	// QueueItemID is the Jenkins queue item id when known.
	QueueItemID int `json:"queue_item_id,omitempty" jsonschema:"Jenkins queue item ID when known"`
	// JobName is the job full name; used to locate a pending queue item when id is omitted.
	JobName string `json:"job_name,omitempty" jsonschema:"Job full name (folder/job path; not a URL) to find pending queue items"`
	// BuildNumber is optional and only used as a hint in notes (waiting builds rarely have a number yet).
	BuildNumber int `json:"build_number,omitempty" jsonschema:"Optional build number hint (usually unknown while queued)"`
}

// LabelMatchSummary describes how required labels map to nodes.
type LabelMatchSummary struct {
	RequiredLabels        []string `json:"requiredLabels,omitempty"`
	MatchingNodes         int      `json:"matchingNodes"`
	MatchingOnline        int      `json:"matchingOnline"`
	MatchingOffline       int      `json:"matchingOffline"`
	MatchingIdleExecutors int      `json:"matchingIdleExecutors"`
	MatchingBusyExecutors int      `json:"matchingBusyExecutors"`
	// SampleNodeNames is a short list of matching node names (bounded).
	SampleNodeNames []string `json:"sampleNodeNames,omitempty"`
}

// QueueDelayETA is an optional heuristic wait estimate. Never present unsupported
// ETAs as fact — Heuristic is always true when Seconds is set.
type QueueDelayETA struct {
	// Seconds is a rough wait estimate when computable; omit when unsupported.
	Seconds *int64 `json:"seconds,omitempty"`
	// Heuristic is always true when an estimate is provided (never a factual SLA).
	Heuristic bool `json:"heuristic"`
	// Note explains that the estimate is unsupported or how it was derived.
	Note string `json:"note,omitempty"`
}

// ExplainQueueDelayToolResponse is the DIAG-007 triage result.
type ExplainQueueDelayToolResponse struct {
	// PrimaryCategory is the best single delay class (stable code).
	PrimaryCategory string `json:"primaryCategory"`
	// Categories lists all matched delay classes (ordered by confidence).
	Categories []string `json:"categories,omitempty"`
	// Summary is a short human/model blurb (heuristic; not a fabricated root cause).
	Summary string `json:"summary"`
	// Why is the Jenkins queue "why" text (sanitized).
	Why string `json:"why,omitempty"`
	// QueueItemID resolved for this explanation.
	QueueItemID int `json:"queueItemId,omitempty"`
	// JobName of the queued task when known.
	JobName string `json:"jobName,omitempty"`
	// WaitSeconds is how long the item has been in queue (from inQueueSince).
	WaitSeconds int64 `json:"waitSeconds,omitempty"`
	// Stuck / Buildable / Blocked / Cancelled from queue item when known.
	Stuck     bool `json:"stuck,omitempty"`
	Buildable bool `json:"buildable,omitempty"`
	Blocked   bool `json:"blocked,omitempty"`
	Cancelled bool `json:"cancelled,omitempty"`
	// HasExecutable is true when a build was already assigned.
	HasExecutable bool `json:"hasExecutable,omitempty"`
	// AssignedBuildNumber when executable is present.
	AssignedBuildNumber int `json:"assignedBuildNumber,omitempty"`

	// Labels / executor matching.
	LabelMatch *LabelMatchSummary `json:"labelMatch,omitempty"`
	// NodeSummary is controller-wide executor totals from GetNodes (when authorized).
	NodeSummary *NodeTotals `json:"nodeSummary,omitempty"`
	// QueuePressure is a depth/stuck sample when authorized.
	QueuePressure *GetQueuePressureToolResponse `json:"queuePressure,omitempty"`
	// QuietingDown from root mode probe when available.
	QuietingDown bool `json:"quietingDown,omitempty"`
	// Mode is Jenkins mode string when available.
	Mode string `json:"mode,omitempty"`

	// ETA is heuristic-only; unsupported estimates leave Seconds nil.
	ETA QueueDelayETA `json:"eta"`

	// Freshness is when this explanation was assembled (UTC).
	Freshness time.Time `json:"freshness"`
	// EvidenceEndpoints lists Jenkins API paths consulted (no secrets).
	EvidenceEndpoints []string `json:"evidenceEndpoints"`
	// ConfidenceNotes explain limits / unauthorized degradations.
	ConfidenceNotes []string `json:"confidenceNotes,omitempty"`
	// Unauthorized flags partial data due to 403 on secondary endpoints.
	PartialUnauthorized bool `json:"partialUnauthorized,omitempty"`
}

// maxLabelSampleNodes bounds sample node names in LabelMatchSummary.
const maxLabelSampleNodes = 8

// queueItemExplainTree extends GetQueueItem fields with labels/blocked for DIAG-007.
const queueItemExplainTree = "id,task[name,url],why,inQueueSince,stuck,buildable,blocked,cancelled," +
	"assignedLabel[name],executable[number,url,building]"

// ExplainQueueDelay explains why a queue item (or a job's pending queue entry) is delayed (DIAG-007).
// Combines queue item why/blocked, required labels, matching nodes/executors, queue pressure,
// and quiet-down when available without admin-only secrets.
func (opts *Client) ExplainQueueDelay(ctx context.Context, args ExplainQueueDelayToolArgs) (*ExplainQueueDelayToolResponse, error) {
	if opts == nil {
		return nil, fmt.Errorf("jenkins client is nil")
	}
	jobName := strings.TrimSpace(args.JobName)
	if args.QueueItemID <= 0 && jobName == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "queue_item_id or job_name is required")
	}
	if jobName != "" {
		// MCP-002: reject absolute URLs.
		if strings.HasPrefix(strings.ToLower(jobName), "http://") || strings.HasPrefix(strings.ToLower(jobName), "https://") {
			return nil, apperr.New(apperr.CodeInvalidArgument, "job_name must be a Jenkins full name, not an http URL")
		}
	}

	now := time.Now().UTC()
	out := &ExplainQueueDelayToolResponse{
		Freshness:         now,
		EvidenceEndpoints: make([]string, 0, 6),
		ETA: QueueDelayETA{
			Heuristic: true,
			Note:      "ETA is heuristic only and is omitted when unsupported; never treat as SLA",
		},
	}
	if args.BuildNumber > 0 {
		out.ConfidenceNotes = append(out.ConfidenceNotes,
			fmt.Sprintf("build_number=%d is a caller hint only; queue items usually lack a build number until started", args.BuildNumber))
	}

	// 1) Resolve queue item detail.
	item, endpoints, notes, err := opts.resolveQueueItemForExplain(ctx, args.QueueItemID, jobName)
	out.EvidenceEndpoints = append(out.EvidenceEndpoints, endpoints...)
	out.ConfidenceNotes = append(out.ConfidenceNotes, notes...)
	if err != nil {
		return nil, err
	}
	if item == nil {
		out.PrimaryCategory = DelayCategoryNotInQueue
		out.Categories = []string{DelayCategoryNotInQueue}
		out.Summary = "No matching pending queue item found"
		if jobName != "" {
			out.JobName = jobName
			out.Summary = fmt.Sprintf("No pending queue item found for job %q", jobName)
		}
		out.ETA.Note = "No queue wait to estimate (item not in queue)"
		return out, nil
	}

	out.QueueItemID = item.ID
	out.JobName = item.JobName
	out.Why = sanitizeNodeText(scrubSecretsLike(item.Why))
	out.Stuck = item.Stuck
	out.Buildable = item.Buildable
	out.Blocked = item.Blocked
	out.Cancelled = item.Cancelled
	if item.InQueueSince > 0 {
		ms := now.UnixMilli()
		if ms >= item.InQueueSince {
			out.WaitSeconds = (ms - item.InQueueSince) / 1000
		}
	}
	if item.ExecutableNumber > 0 {
		out.HasExecutable = true
		out.AssignedBuildNumber = item.ExecutableNumber
	}

	// 2) Nodes + label match (HEALTH-001 reuse).
	nodesRes, nerr := opts.GetNodes(ctx, 0, MaxNodesPageSize)
	out.EvidenceEndpoints = append(out.EvidenceEndpoints, "/computer/api/json")
	if nerr != nil {
		out.ConfidenceNotes = append(out.ConfidenceNotes, "nodes: "+safeErrNote(nerr))
	} else if nodesRes != nil {
		if nodesRes.Unauthorized {
			out.PartialUnauthorized = true
			out.ConfidenceNotes = append(out.ConfidenceNotes, "nodes: unauthorized (HTTP 403); label matching degraded")
		} else {
			sum := nodesRes.Summary
			out.NodeSummary = &sum
			// For label matching we need the full page; GetNodes already scanned all for summary
			// but returns a page. Re-fetch with large limit when truncated.
			nodes := nodesRes.Nodes
			if nodesRes.Truncated {
				full, ferr := opts.GetNodes(ctx, 0, MaxNodesPageSize)
				if ferr == nil && full != nil && !full.Unauthorized {
					// Walk all pages for matching (bounded by MaxNodesPageSize per call).
					nodes = append([]NodeSummary(nil), full.Nodes...)
					off := full.NextOffset
					for full.Truncated && off > 0 && len(nodes) < MaxNodesPageSize*4 {
						page, perr := opts.GetNodes(ctx, off, MaxNodesPageSize)
						if perr != nil || page == nil || page.Unauthorized {
							break
						}
						nodes = append(nodes, page.Nodes...)
						if !page.Truncated {
							break
						}
						off = page.NextOffset
					}
				}
			}
			lm := matchLabels(item.AssignedLabel, item.Why, nodes)
			out.LabelMatch = &lm
		}
	}

	// 3) Queue pressure.
	qp, qerr := opts.GetQueuePressure(ctx)
	out.EvidenceEndpoints = append(out.EvidenceEndpoints, "/queue/api/json")
	if qerr != nil {
		out.ConfidenceNotes = append(out.ConfidenceNotes, "queue_pressure: "+safeErrNote(qerr))
	} else if qp != nil {
		if qp.Unauthorized {
			out.PartialUnauthorized = true
			out.ConfidenceNotes = append(out.ConfidenceNotes, "queue_pressure: unauthorized (HTTP 403)")
		} else {
			// Strip samples if huge; re-scrub Why (defense in depth for model path).
			slim := *qp
			if len(slim.Samples) > 5 {
				slim.Samples = slim.Samples[:5]
			}
			for i := range slim.Samples {
				slim.Samples[i].Why = sanitizeNodeText(scrubSecretsLike(slim.Samples[i].Why))
				slim.Samples[i].JobName = sanitizeNodeText(slim.Samples[i].JobName)
			}
			out.QueuePressure = &slim
		}
	}

	// 4) Quiet-down / mode (cheap root probe).
	mode, merr := opts.GetControllerMode(ctx)
	out.EvidenceEndpoints = append(out.EvidenceEndpoints, "/api/json?tree="+modeAPITree)
	if merr != nil {
		out.ConfidenceNotes = append(out.ConfidenceNotes, "controller_mode: "+safeErrNote(merr))
	} else if mode != nil {
		if mode.Unauthorized {
			out.PartialUnauthorized = true
			out.ConfidenceNotes = append(out.ConfidenceNotes, "controller_mode: unauthorized (HTTP 403)")
		} else {
			out.QuietingDown = mode.QuietingDown
			out.Mode = mode.Mode
		}
	}

	// 5) Classify delay reasons.
	cats, primary, summary := classifyQueueDelay(out)
	out.Categories = cats
	out.PrimaryCategory = primary
	out.Summary = summary

	// 6) Heuristic ETA only when we have a weak signal; otherwise leave Seconds nil.
	out.ETA = heuristicETA(out)
	out.EvidenceEndpoints = uniqueStrings(out.EvidenceEndpoints)
	return out, nil
}

// queueItemDetail is an internal richer queue item for explain (no params/secrets).
type queueItemDetail struct {
	ID               int
	JobName          string
	Why              string
	InQueueSince     int64
	Stuck            bool
	Buildable        bool
	Blocked          bool
	Cancelled        bool
	AssignedLabel    string
	ExecutableNumber int
}

func (opts *Client) resolveQueueItemForExplain(ctx context.Context, queueID int, jobName string) (*queueItemDetail, []string, []string, error) {
	var endpoints []string
	var notes []string

	if queueID > 0 {
		detail, err := opts.fetchQueueItemDetail(ctx, queueID)
		endpoints = append(endpoints, fmt.Sprintf("/queue/item/%d/api/json", queueID))
		if err != nil {
			// Not found → try job name fallback when provided.
			if jobName != "" && strings.Contains(err.Error(), "not found") {
				notes = append(notes, fmt.Sprintf("queue item #%d not found; searching queue by job_name", queueID))
			} else {
				return nil, endpoints, notes, err
			}
		} else {
			return detail, endpoints, notes, nil
		}
	}

	// Locate by job name via queue list (no params field).
	endpoints = append(endpoints, "/queue/api/json")
	items, err := opts.listQueueItemsForExplain(ctx)
	if err != nil {
		return nil, endpoints, notes, err
	}
	jobName = strings.TrimSpace(jobName)
	var match *queueItemDetail
	for i := range items {
		if jobName == "" || strings.EqualFold(items[i].JobName, jobName) || strings.HasSuffix(items[i].JobName, "/"+jobName) {
			// Prefer exact name; keep first if only one job filter.
			if jobName == "" {
				continue
			}
			if strings.EqualFold(items[i].JobName, jobName) {
				cp := items[i]
				match = &cp
				break
			}
			if match == nil {
				cp := items[i]
				match = &cp
			}
		}
	}
	if match == nil && jobName != "" {
		return nil, endpoints, notes, nil
	}
	if match != nil && match.ID > 0 {
		// Enrich with per-item detail when possible.
		if detail, err := opts.fetchQueueItemDetail(ctx, match.ID); err == nil && detail != nil {
			endpoints = append(endpoints, fmt.Sprintf("/queue/item/%d/api/json", match.ID))
			return detail, endpoints, notes, nil
		}
	}
	return match, endpoints, notes, nil
}

func (opts *Client) fetchQueueItemDetail(ctx context.Context, queueID int) (*queueItemDetail, error) {
	apiPath := fmt.Sprintf("/queue/item/%d/api/json?tree=%s", queueID, queueItemExplainTree)
	resp, err := opts.CallJenkins(ctx, opts.Client, http.MethodGet, apiPath, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch queue item: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("queue item #%d not found", queueID)
	}
	if resp.StatusCode == http.StatusForbidden {
		return nil, apperr.New(apperr.CodeAuthorization, "not authorized to read queue item")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, strings.TrimSpace(readLimitedErrBody(resp.Body)))
	}

	var data struct {
		ID   int `json:"id"`
		Task struct {
			Name string `json:"name"`
		} `json:"task"`
		Why           string `json:"why"`
		InQueueSince  int64  `json:"inQueueSince"`
		Stuck         bool   `json:"stuck"`
		Buildable     bool   `json:"buildable"`
		Blocked       bool   `json:"blocked"`
		Cancelled     bool   `json:"cancelled"`
		AssignedLabel *struct {
			Name string `json:"name"`
		} `json:"assignedLabel"`
		Executable *struct {
			Number int `json:"number"`
		} `json:"executable"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode queue item: %w", err)
	}
	d := &queueItemDetail{
		ID:           data.ID,
		JobName:      strings.TrimSpace(data.Task.Name),
		Why:          data.Why,
		InQueueSince: data.InQueueSince,
		Stuck:        data.Stuck,
		Buildable:    data.Buildable,
		Blocked:      data.Blocked,
		Cancelled:    data.Cancelled,
	}
	if data.AssignedLabel != nil {
		d.AssignedLabel = strings.TrimSpace(data.AssignedLabel.Name)
	}
	if data.Executable != nil {
		d.ExecutableNumber = data.Executable.Number
	}
	return d, nil
}

func (opts *Client) listQueueItemsForExplain(ctx context.Context) ([]queueItemDetail, error) {
	const tree = "items[id,task[name],why,inQueueSince,stuck,buildable,blocked,cancelled,assignedLabel[name]]"
	apiPath := "/queue/api/json?tree=" + tree
	resp, err := opts.CallJenkins(ctx, opts.Client, http.MethodGet, apiPath, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list queue: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		return nil, apperr.New(apperr.CodeAuthorization, "not authorized to read Jenkins queue")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, strings.TrimSpace(readLimitedErrBody(resp.Body)))
	}
	var raw struct {
		Items []struct {
			ID   int `json:"id"`
			Task struct {
				Name string `json:"name"`
			} `json:"task"`
			Why           string `json:"why"`
			InQueueSince  int64  `json:"inQueueSince"`
			Stuck         bool   `json:"stuck"`
			Buildable     bool   `json:"buildable"`
			Blocked       bool   `json:"blocked"`
			Cancelled     bool   `json:"cancelled"`
			AssignedLabel *struct {
				Name string `json:"name"`
			} `json:"assignedLabel"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("failed to decode queue list: %w", err)
	}
	out := make([]queueItemDetail, 0, len(raw.Items))
	for _, it := range raw.Items {
		d := queueItemDetail{
			ID:           it.ID,
			JobName:      strings.TrimSpace(it.Task.Name),
			Why:          it.Why,
			InQueueSince: it.InQueueSince,
			Stuck:        it.Stuck,
			Buildable:    it.Buildable,
			Blocked:      it.Blocked,
			Cancelled:    it.Cancelled,
		}
		if it.AssignedLabel != nil {
			d.AssignedLabel = strings.TrimSpace(it.AssignedLabel.Name)
		}
		out = append(out, d)
	}
	return out, nil
}

func matchLabels(assignedLabel, why string, nodes []NodeSummary) LabelMatchSummary {
	labels := parseRequiredLabels(assignedLabel, why)
	lm := LabelMatchSummary{RequiredLabels: labels}
	if len(nodes) == 0 {
		return lm
	}
	// If no labels required, every node matches (any executor).
	for _, n := range nodes {
		if !nodeMatchesAllLabels(n, labels) {
			continue
		}
		lm.MatchingNodes++
		if n.Offline {
			lm.MatchingOffline++
		} else {
			lm.MatchingOnline++
			lm.MatchingIdleExecutors += n.IdleExecutors
			lm.MatchingBusyExecutors += n.BusyExecutors
		}
		if len(lm.SampleNodeNames) < maxLabelSampleNodes && n.Name != "" {
			lm.SampleNodeNames = append(lm.SampleNodeNames, n.Name)
		}
	}
	return lm
}

// parseRequiredLabels extracts label tokens from assignedLabel expression and why text.
func parseRequiredLabels(assignedLabel, why string) []string {
	var labels []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		// Split simple Jenkins expressions: label && label, label||label.
		for _, part := range strings.FieldsFunc(s, func(r rune) bool {
			return r == '&' || r == '|' || r == '(' || r == ')' || r == ','
		}) {
			part = strings.TrimSpace(part)
			part = strings.Trim(part, "\"'")
			if part == "" || part == "!" {
				continue
			}
			// Skip operator leftovers and very long tokens (not labels).
			if len(part) > 64 {
				continue
			}
			if !containsFold(labels, part) {
				labels = append(labels, part)
			}
		}
	}
	add(assignedLabel)
	// Heuristic from why: "Waiting for next available executor on ‘gpu’" / "label is offline".
	low := strings.ToLower(why)
	if strings.Contains(low, "label") || strings.Contains(low, "there are no nodes") {
		// Pull quoted tokens.
		extractQuoted(&labels, why)
	}
	return labels
}

func extractQuoted(dst *[]string, s string) {
	// Match ‘…’ or '…' or "…"
	repl := strings.NewReplacer("‘", "'", "’", "'", "“", `"`, "”", `"`)
	s = repl.Replace(s)
	for {
		i := strings.IndexAny(s, `'"`)
		if i < 0 || i+1 >= len(s) {
			return
		}
		q := s[i]
		rest := s[i+1:]
		j := strings.IndexByte(rest, q)
		if j < 0 {
			return
		}
		tok := strings.TrimSpace(rest[:j])
		if tok != "" && len(tok) <= 64 && !containsFold(*dst, tok) {
			*dst = append(*dst, tok)
		}
		s = rest[j+1:]
	}
}

func nodeMatchesAllLabels(n NodeSummary, required []string) bool {
	if len(required) == 0 {
		return true
	}
	have := make(map[string]bool, len(n.Labels)+1)
	for _, l := range n.Labels {
		have[strings.ToLower(strings.TrimSpace(l))] = true
	}
	// Jenkins self-label is often the node name.
	if n.Name != "" {
		have[strings.ToLower(n.Name)] = true
	}
	for _, r := range required {
		if !have[strings.ToLower(r)] {
			return false
		}
	}
	return true
}

func classifyQueueDelay(out *ExplainQueueDelayToolResponse) (cats []string, primary, summary string) {
	whyLow := strings.ToLower(out.Why)
	add := func(c string) {
		if !containsFold(cats, c) {
			cats = append(cats, c)
		}
	}

	if out.Cancelled {
		add(DelayCategoryCancelled)
		return cats, DelayCategoryCancelled, "Queue item was cancelled"
	}
	if out.HasExecutable {
		add(DelayCategoryAlreadyStarted)
		return cats, DelayCategoryAlreadyStarted,
			fmt.Sprintf("Queue item already has build #%d assigned", out.AssignedBuildNumber)
	}
	if out.QuietingDown {
		add(DelayCategoryQuietingDown)
	}

	// Upstream / dependency waits from why text.
	if strings.Contains(whyLow, "upstream") ||
		strings.Contains(whyLow, "dependency") ||
		strings.Contains(whyLow, "waiting for the completion") ||
		strings.Contains(whyLow, "blocked by") && strings.Contains(whyLow, "project") {
		add(DelayCategoryUpstreamWait)
	}

	// Throttling plugins / concurrent build limits.
	if strings.Contains(whyLow, "throttl") ||
		strings.Contains(whyLow, "maximum number of concurrent") ||
		strings.Contains(whyLow, "already in progress") ||
		strings.Contains(whyLow, "concurrent build") {
		add(DelayCategoryThrottling)
	}

	// Explicit blocked flag / classic blocked wording (but not only "blocked by offline").
	if out.Blocked || strings.Contains(whyLow, "build is blocked") ||
		(strings.Contains(whyLow, "blocked") && !strings.Contains(whyLow, "offline")) {
		// Avoid double-counting pure offline-label as blocked-only.
		if !strings.Contains(whyLow, "offline") || out.Blocked {
			add(DelayCategoryBlocked)
		}
	}

	// Offline label / no matching online nodes.
	if out.LabelMatch != nil && len(out.LabelMatch.RequiredLabels) > 0 {
		if out.LabelMatch.MatchingOnline == 0 {
			if out.LabelMatch.MatchingOffline > 0 || out.LabelMatch.MatchingNodes > 0 {
				add(DelayCategoryOfflineLabel)
			} else if strings.Contains(whyLow, "offline") || strings.Contains(whyLow, "no nodes") {
				add(DelayCategoryOfflineLabel)
			}
		}
	} else if strings.Contains(whyLow, "offline") && strings.Contains(whyLow, "label") {
		add(DelayCategoryOfflineLabel)
	}

	// No free executor: buildable waiting, or classic why text, or all matching busy.
	if strings.Contains(whyLow, "waiting for next available executor") ||
		strings.Contains(whyLow, "waiting for an available executor") {
		add(DelayCategoryNoExecutor)
	} else if out.LabelMatch != nil && out.LabelMatch.MatchingOnline > 0 &&
		out.LabelMatch.MatchingIdleExecutors == 0 && out.Buildable {
		add(DelayCategoryNoExecutor)
	} else if out.NodeSummary != nil && out.NodeSummary.IdleExecutors == 0 &&
		out.NodeSummary.TotalExecutors > 0 && out.Buildable &&
		(out.LabelMatch == nil || len(out.LabelMatch.RequiredLabels) == 0) {
		add(DelayCategoryNoExecutor)
	}

	if len(cats) == 0 {
		if out.Why != "" {
			add(DelayCategoryUnknown)
			return cats, DelayCategoryUnknown, "Queue delay reason not classified; see why text"
		}
		add(DelayCategoryUnknown)
		return cats, DelayCategoryUnknown, "Queue item present but delay reason is unclear"
	}

	// Primary priority (most actionable first).
	priority := []string{
		DelayCategoryQuietingDown,
		DelayCategoryOfflineLabel,
		DelayCategoryUpstreamWait,
		DelayCategoryThrottling,
		DelayCategoryBlocked,
		DelayCategoryNoExecutor,
		DelayCategoryUnknown,
	}
	primary = cats[0]
	for _, p := range priority {
		if containsFold(cats, p) {
			primary = p
			break
		}
	}
	summary = summaryForCategory(primary, out)
	return cats, primary, summary
}

func summaryForCategory(primary string, out *ExplainQueueDelayToolResponse) string {
	switch primary {
	case DelayCategoryQuietingDown:
		return "Controller is quieting down; new builds are not starting"
	case DelayCategoryOfflineLabel:
		labels := ""
		if out.LabelMatch != nil && len(out.LabelMatch.RequiredLabels) > 0 {
			labels = strings.Join(out.LabelMatch.RequiredLabels, ",")
		}
		if labels != "" {
			return fmt.Sprintf("No online nodes match required label(s) %s", labels)
		}
		return "Required agent label appears offline or has no matching online nodes"
	case DelayCategoryUpstreamWait:
		return "Waiting on upstream/dependency completion"
	case DelayCategoryThrottling:
		return "Delayed by concurrent-build or throttle limits"
	case DelayCategoryBlocked:
		if out.Why != "" {
			return "Queue item is blocked: " + truncateRunes(out.Why, 160)
		}
		return "Queue item is blocked"
	case DelayCategoryNoExecutor:
		if out.LabelMatch != nil && out.LabelMatch.MatchingOnline > 0 {
			return fmt.Sprintf("Waiting for a free executor (%d matching online node(s), 0 idle executors)", out.LabelMatch.MatchingOnline)
		}
		return "Waiting for next available executor"
	default:
		if out.Why != "" {
			return "Queue delay: " + truncateRunes(out.Why, 160)
		}
		return "Queue delay reason unknown"
	}
}

func heuristicETA(out *ExplainQueueDelayToolResponse) QueueDelayETA {
	eta := QueueDelayETA{
		Heuristic: true,
		Note:      "ETA is heuristic only; never treat as factual SLA or supported forecast",
	}
	// Only attempt a rough estimate when pure executor saturation is the primary cause
	// and we have positive wait samples. All other categories leave Seconds nil.
	if out.PrimaryCategory != DelayCategoryNoExecutor {
		eta.Note = "ETA seconds omitted (unsupported for category " + out.PrimaryCategory + "); heuristic note only"
		return eta
	}
	if out.QueuePressure == nil || out.QueuePressure.Depth <= 0 {
		eta.Note = "ETA seconds omitted (no queue pressure sample); heuristic note only"
		return eta
	}
	// Very rough: if oldest wait is known and depth>0, estimate remaining as fraction of oldest.
	// This is intentionally weak and labeled heuristic.
	if out.QueuePressure.OldestWaitSeconds > 0 && out.WaitSeconds >= 0 {
		// Remaining ≈ max(0, oldest - this wait) is not meaningful; use depth * mean wait heuristic.
		// Use oldest wait as a ceiling signal only when depth is small.
		est := out.QueuePressure.OldestWaitSeconds / int64(max(1, out.QueuePressure.Depth))
		if est < 5 {
			est = 5
		}
		if est > 3600 {
			est = 3600
		}
		eta.Seconds = &est
		eta.Note = "Heuristic ETA from queue depth/oldest-wait sample only; not a forecast"
		return eta
	}
	eta.Note = "ETA seconds omitted (insufficient wait samples); heuristic note only"
	return eta
}

func safeErrNote(err error) string {
	if err == nil {
		return ""
	}
	msg := apperr.ModelMessage(err)
	if msg == "" {
		msg = err.Error()
	}
	msg = scrubSecretsLike(msg)
	return truncateRunes(msg, 200)
}

func containsFold(ss []string, want string) bool {
	for _, s := range ss {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
