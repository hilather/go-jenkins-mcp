package tools

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/logmirror"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ToolMirrorLogs is the optional multi-log mirror tool name (LOG-004).
// Registered only when a MultiLogAcquirer is available (Coordinator wired).
const ToolMirrorLogs = "jenkins_mirror_logs"

// Multi-log fan-out caps (server-enforced; callers may only lower via shorter lists).
const (
	// HardMirrorLogsMax is the absolute ceiling of log targets per call (pilot).
	HardMirrorLogsMax = 16
	// DefaultRelatedMax is the default number of extra related builds when
	// include_related is true (Wave 30 / LOG+GRAPH).
	DefaultRelatedMax = 4
	// HardRelatedMax is the absolute ceiling of extra related builds (fail closed).
	HardRelatedMax = 8
	// relatedGraphMaxDepth bounds GetBuildGraph when expanding related logs.
	relatedGraphMaxDepth = 2
)

// Relation labels for collection membership / later pack selection.
const (
	RelationPrimary    = "primary"
	RelationUpstream   = "upstream"
	RelationDownstream = "downstream"
	RelationRelated    = "related"
)

// Per-log status values (status + refs only; never full log bodies).
const (
	MirrorStatusSealed   = "sealed"   // generation sealed locally
	MirrorStatusMirrored = "mirrored" // durable frames present; not sealed yet
	MirrorStatusDenied   = "denied"   // MCP policy / store read deny for this job
	MirrorStatusError    = "error"    // acquire failure
	MirrorStatusSkipped  = "skipped"  // collection budget exhausted before fetch
)

// MultiLogRequest is one log target for multi-log acquisition (tools layer).
type MultiLogRequest struct {
	Job      string
	Build    int64
	Relation string
}

// MultiLogEntry is one per-log outcome (no body text).
type MultiLogEntry struct {
	Job          string
	Build        int64
	Relation     string
	Status       string
	ErrorCode    string
	BytesFetched int64
	Generation   int64
	DurableBytes int64
	Residual     bool
}

// MultiLogCollection is the outcome of a multi-log acquire (status + refs only).
type MultiLogCollection struct {
	CollectionID    string
	Profile         string
	Logs            []MultiLogEntry
	TotalBytes      int64
	TruncatedBudget bool
	Cancelled       bool
}

// MultiLogAcquirer fans out multi-log mirror into local frames (LOG-004).
// *MirrorLogAccess implements this when Coord is non-nil.
//
// Never returns log bodies — only collection membership, status, and byte counts.
type MultiLogAcquirer interface {
	// AcquireMulti streams the requested logs into independent frames under
	// collection budgets. Partial success is reported per log.
	AcquireMulti(ctx context.Context, reqs []MultiLogRequest) (MultiLogCollection, error)
	// ResidualMembers returns unsealed / incomplete members of a prior
	// collection for continue residual (collection_id). Loads durable catalog
	// membership when the in-process session is missing (same profile; restart).
	// NotFound when the collection id is unknown in-process and not in the store.
	ResidualMembers(ctx context.Context, collectionID string) ([]MultiLogRequest, error)
}

// MirrorLogItemArgs is one {job_name, build_number} entry for jenkins_mirror_logs.
type MirrorLogItemArgs struct {
	JobName     string `json:"job_name" mcp:"Jenkins job full name (folder/job path; not a URL)"`
	BuildNumber int    `json:"build_number" mcp:"build number"`
	// Relation is an optional non-secret label (e.g. primary, downstream).
	Relation string `json:"relation,omitempty" mcp:"optional relation label for later pack selection"`
}

// MirrorLogsToolArgs is the MCP input for jenkins_mirror_logs.
//
// Provide logs and/or collection_id (continue residual from a prior session).
// At least one log target is required after residual merge.
// Optional include_related discovers bounded upstream/downstream builds via
// GetBuildGraph (Wave 30); soft-fails on graph errors and still acquires primaries.
type MirrorLogsToolArgs struct {
	// Logs is the list of job/build pairs to mirror (max HardMirrorLogsMax).
	Logs []MirrorLogItemArgs `json:"logs,omitempty" mcp:"list of {job_name, build_number} to mirror (max 16)"`
	// CollectionID continues residual members from a prior collection (durable catalog).
	CollectionID string `json:"collection_id,omitempty" mcp:"optional prior collection id to re-acquire residual (unsealed) members; survives restart when store is open"`
	// IncludeRelated, when true, calls GetBuildGraph from the first primary log
	// and adds up to related_max extra builds (never invents jobs; API edges only).
	IncludeRelated bool `json:"include_related,omitempty" mcp:"discover related builds via build graph and add them to the collection (default false)"`
	// RelatedMax caps extra related builds beyond primaries (default 4, hard max 8).
	// Values above HardRelatedMax fail closed (invalid_argument).
	RelatedMax int `json:"related_max,omitempty" mcp:"max extra related builds when include_related (default 4, hard max 8)"`
	// RelatedDirection is upstream | downstream | both (default both).
	RelatedDirection string `json:"related_direction,omitempty" mcp:"graph direction: upstream, downstream, or both (default both)"`
}

// MirrorLogItemResult is one per-log status row (never includes log body).
type MirrorLogItemResult struct {
	JobName      string `json:"job_name"`
	BuildNumber  int64  `json:"build_number"`
	Relation     string `json:"relation,omitempty"`
	Status       string `json:"status"` // sealed|mirrored|denied|error|skipped
	ErrorCode    string `json:"error_code,omitempty"`
	BytesFetched int64  `json:"bytes_fetched"`
	Generation   int64  `json:"generation,omitempty"`
	DurableBytes int64  `json:"durable_bytes,omitempty"`
	// Residual is true when the generation is not sealed and may need continue.
	Residual bool `json:"residual,omitempty"`
}

// MirrorLogsToolResponse is the structured MCP result (status + refs only).
type MirrorLogsToolResponse struct {
	CollectionID    string                `json:"collection_id"`
	Profile         string                `json:"profile,omitempty"`
	Logs            []MirrorLogItemResult `json:"logs"`
	TotalBytes      int64                 `json:"total_bytes"`
	TruncatedBudget bool                  `json:"truncated_budget,omitempty"`
	Cancelled       bool                  `json:"cancelled,omitempty"`
	// Residuals are short operator/agent notes (no secrets, no log bodies).
	Residuals []string `json:"residuals,omitempty"`
}

// registerMirrorLogsTool registers jenkins_mirror_logs when multi-log acquire is wired.
// client is used for optional include_related GetBuildGraph discovery (may be nil in tests
// that never set include_related).
func registerMirrorLogsTool(s *mcp.Server, client *jenkins.Client, st regState) {
	acq := resolveMultiLogAcquirer(st)
	if acq == nil {
		return
	}
	addReadTool(s, st, &mcp.Tool{
		Name: ToolMirrorLogs,
		Description: "Mirror multiple build logs into the local L1 store under a collection " +
			"(status and refs only; never returns full log bodies). Optional include_related " +
			"discovers bounded upstream/downstream builds. Requires --profile store+mirror.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args MirrorLogsToolArgs) (*mcp.CallToolResult, MirrorLogsToolResponse, error) {
		out, err := runMirrorLogs(ctx, client, st, acq, args)
		if err != nil {
			return nil, MirrorLogsToolResponse{}, err
		}
		return structuredResult(out)
	})
}

// resolveMultiLogAcquirer prefers RegisterOptions.MultiLog, else LogAccess extension.
func resolveMultiLogAcquirer(st regState) MultiLogAcquirer {
	if st.multiLog != nil {
		return st.multiLog
	}
	return asMultiLogAcquirer(st.logs)
}

// asMultiLogAcquirer returns MultiLogAcquirer when Logs implements it with a live coordinator.
func asMultiLogAcquirer(logs LogAccess) MultiLogAcquirer {
	if logs == nil {
		return nil
	}
	if m, ok := logs.(MultiLogAcquirer); ok && m != nil {
		// *MirrorLogAccess with nil Coord still implements the interface methods
		// but must not register the tool — probe with a cheap capability check.
		if cap, ok := m.(interface{ MultiLogAvailable() bool }); ok {
			if !cap.MultiLogAvailable() {
				return nil
			}
		}
		return m
	}
	return nil
}

func runMirrorLogs(ctx context.Context, client *jenkins.Client, st regState, acq MultiLogAcquirer, args MirrorLogsToolArgs) (MirrorLogsToolResponse, error) {
	if acq == nil {
		return MirrorLogsToolResponse{}, apperr.New(apperr.CodeCapabilityMissing,
			"multi-log mirror is not available (configure --profile with local store)")
	}

	relatedMax, relatedDir, err := normalizeRelatedDiscoveryArgs(args)
	if err != nil {
		return MirrorLogsToolResponse{}, err
	}

	// Build request list from args + optional residual continue.
	var reqs []MultiLogRequest
	seen := make(map[string]struct{})
	// Seed candidates for related discovery: user-provided logs only (not residual continue).
	var primarySeeds []MultiLogRequest
	seedSeen := make(map[string]struct{})

	addReq := func(job string, build int64, relation string) error {
		name, err := jobFullName("job_name", job)
		if err != nil {
			return err
		}
		if build <= 0 {
			return invalidArg("build_number must be a positive integer")
		}
		key := name + "|" + strconv.FormatInt(build, 10)
		if _, ok := seen[key]; ok {
			return nil
		}
		seen[key] = struct{}{}
		reqs = append(reqs, MultiLogRequest{
			Job:      name,
			Build:    build,
			Relation: strings.TrimSpace(relation),
		})
		return nil
	}

	collID := strings.TrimSpace(args.CollectionID)
	if collID != "" {
		residuals, err := acq.ResidualMembers(ctx, collID)
		if err != nil {
			return MirrorLogsToolResponse{}, mapToolErr(err)
		}
		for _, r := range residuals {
			if err := addReq(r.Job, r.Build, r.Relation); err != nil {
				return MirrorLogsToolResponse{}, err
			}
		}
	}
	for _, item := range args.Logs {
		// Track seed in caller order (first occurrence only); multi → expand first seed.
		name, jerr := jobFullName("job_name", item.JobName)
		if jerr != nil {
			return MirrorLogsToolResponse{}, jerr
		}
		if item.BuildNumber <= 0 {
			return MirrorLogsToolResponse{}, invalidArg("build_number must be a positive integer")
		}
		rel := strings.TrimSpace(item.Relation)
		if rel == "" {
			rel = RelationPrimary
		}
		seedKey := name + "|" + strconv.Itoa(item.BuildNumber)
		if _, ok := seedSeen[seedKey]; !ok {
			seedSeen[seedKey] = struct{}{}
			primarySeeds = append(primarySeeds, MultiLogRequest{
				Job: name, Build: int64(item.BuildNumber), Relation: rel,
			})
		}
		if err := addReq(item.JobName, int64(item.BuildNumber), rel); err != nil {
			return MirrorLogsToolResponse{}, err
		}
	}
	if len(reqs) == 0 {
		return MirrorLogsToolResponse{}, invalidArg(
			"logs list and/or collection_id with residual members is required")
	}
	if len(reqs) > HardMirrorLogsMax {
		return MirrorLogsToolResponse{}, invalidArg(
			"logs list exceeds maximum of " + strconv.Itoa(HardMirrorLogsMax) + " entries")
	}

	var discoveryNotes []string
	if args.IncludeRelated {
		// Wave 30 review: policy-check the seed **before** GetBuildGraph so
		// denied primaries never trigger Jenkins graph API (metadata side-channel).
		seedOK := true
		if len(primarySeeds) > 0 {
			seed := primarySeeds[0]
			if err := evaluateMirrorLogJobPolicy(ctx, st, seed.Job, seed.Build); err != nil {
				seedOK = false
				discoveryNotes = append(discoveryNotes,
					"related discovery skipped: primary denied by MCP policy")
			} else if err := policy.CheckStoreRead(ctx, st.policy, effectiveSubject(st, ctx), seed.Job); err != nil {
				seedOK = false
				discoveryNotes = append(discoveryNotes,
					"related discovery skipped: primary denied by store policy")
			}
		}
		if seedOK {
			extra, notes := discoverRelatedMirrorRequests(ctx, client, primarySeeds, seen, relatedMax, relatedDir)
			discoveryNotes = append(discoveryNotes, notes...)
			for _, r := range extra {
				// Respect absolute list ceiling; primaries win over related.
				if len(reqs) >= HardMirrorLogsMax {
					discoveryNotes = append(discoveryNotes,
						"related discovery truncated: mirror list hard max of "+strconv.Itoa(HardMirrorLogsMax)+" reached")
					break
				}
				// Validate related job names like primaries (jobFullName).
				name, jerr := jobFullName("job_name", r.Job)
				if jerr != nil {
					discoveryNotes = append(discoveryNotes, "related job skipped: invalid job name from graph")
					continue
				}
				r.Job = name
				key := r.Job + "|" + strconv.FormatInt(r.Build, 10)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				reqs = append(reqs, r)
			}
		}
	}

	// Deterministic order for stable tests and pack selection.
	sort.Slice(reqs, func(i, j int) bool {
		if reqs[i].Job != reqs[j].Job {
			return reqs[i].Job < reqs[j].Job
		}
		return reqs[i].Build < reqs[j].Build
	})

	// Policy: evaluate each job Target for deny_job_prefixes (fail closed per job).
	// Denied jobs are reported in the response; other logs still acquire.
	// Related discoveries are policy-checked the same as primaries (never elevate).
	var allowed []MultiLogRequest
	var denied []MirrorLogItemResult
	for _, r := range reqs {
		if err := evaluateMirrorLogJobPolicy(ctx, st, r.Job, r.Build); err != nil {
			code := string(apperr.CodeOf(err))
			if code == "" {
				code = string(apperr.CodePolicyDenial)
			}
			denied = append(denied, MirrorLogItemResult{
				JobName:     r.Job,
				BuildNumber: r.Build,
				Relation:    r.Relation,
				Status:      MirrorStatusDenied,
				ErrorCode:   code,
			})
			continue
		}
		// POL-004: CheckStoreRead before serving/writing via mirror path.
		if err := policy.CheckStoreRead(ctx, st.policy, effectiveSubject(st, ctx), r.Job); err != nil {
			code := string(apperr.CodeOf(err))
			if code == "" {
				code = string(apperr.CodePolicyDenial)
			}
			denied = append(denied, MirrorLogItemResult{
				JobName:     r.Job,
				BuildNumber: r.Build,
				Relation:    r.Relation,
				Status:      MirrorStatusDenied,
				ErrorCode:   code,
			})
			continue
		}
		allowed = append(allowed, r)
	}

	out := MirrorLogsToolResponse{
		Logs: make([]MirrorLogItemResult, 0, len(reqs)),
	}
	out.Residuals = append(out.Residuals, discoveryNotes...)
	// Preserve denied rows in the response even when nothing is allowed.
	out.Logs = append(out.Logs, denied...)

	if len(allowed) == 0 {
		// All denied — no collection session; still return stable empty id.
		out.Residuals = append(out.Residuals, "all requested logs denied by MCP policy")
		// Sort for determinism.
		sortMirrorLogResults(out.Logs)
		return out, nil
	}

	coll, err := acq.AcquireMulti(ctx, allowed)
	if err != nil {
		return MirrorLogsToolResponse{}, mapToolErr(err)
	}
	out.CollectionID = coll.CollectionID
	out.Profile = coll.Profile
	if out.Profile == "" && st.profileID != "" {
		out.Profile = st.profileID
	}
	out.TotalBytes = coll.TotalBytes
	out.TruncatedBudget = coll.TruncatedBudget
	out.Cancelled = coll.Cancelled

	for _, e := range coll.Logs {
		out.Logs = append(out.Logs, MirrorLogItemResult{
			JobName:      e.Job,
			BuildNumber:  e.Build,
			Relation:     e.Relation,
			Status:       e.Status,
			ErrorCode:    e.ErrorCode,
			BytesFetched: e.BytesFetched,
			Generation:   e.Generation,
			DurableBytes: e.DurableBytes,
			Residual:     e.Residual,
		})
	}
	sortMirrorLogResults(out.Logs)

	// Collection-level residual notes (no bodies).
	if out.TruncatedBudget {
		out.Residuals = append(out.Residuals, "collection total byte budget exhausted; some logs skipped or partial")
	}
	if out.Cancelled {
		out.Residuals = append(out.Residuals, "acquisition cancelled; committed frames remain recoverable")
	}
	var residualCount int
	for _, row := range out.Logs {
		if row.Residual || row.Status == MirrorStatusMirrored || row.Status == MirrorStatusSkipped || row.Status == MirrorStatusError {
			residualCount++
		}
	}
	if residualCount > 0 {
		out.Residuals = append(out.Residuals,
			"re-call jenkins_mirror_logs with collection_id to continue residual members")
	}
	return out, nil
}

// evaluateMirrorLogJobPolicy re-checks deny_job_prefixes for one job target.
// Nil policy ⇒ allow (middleware still gates tool-level denies).
func evaluateMirrorLogJobPolicy(ctx context.Context, st regState, job string, build int64) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "mirror policy check cancelled", err)
	}
	if st.policy == nil {
		return nil
	}
	target := policy.Target{JobName: job}
	if build > 0 {
		target.BuildNumber = build
	}
	d := st.policy.Evaluate(
		effectiveSubject(st, ctx),
		policy.Action{ToolName: ToolMirrorLogs, Class: policy.EffectRead},
		target,
	)
	if err := d.Err(); err != nil {
		return err
	}
	return nil
}

func sortMirrorLogResults(logs []MirrorLogItemResult) {
	sort.Slice(logs, func(i, j int) bool {
		if logs[i].JobName != logs[j].JobName {
			return logs[i].JobName < logs[j].JobName
		}
		return logs[i].BuildNumber < logs[j].BuildNumber
	})
}

// --- MirrorLogAccess MultiLogAcquirer implementation ---

// MultiLogAvailable reports whether Coord is wired for multi-log fan-out.
func (m *MirrorLogAccess) MultiLogAvailable() bool {
	return m != nil && m.Coord != nil && m.Coord.Machine != nil
}

// AcquireMulti implements MultiLogAcquirer via logmirror.Coordinator.
func (m *MirrorLogAccess) AcquireMulti(ctx context.Context, reqs []MultiLogRequest) (MultiLogCollection, error) {
	if !m.MultiLogAvailable() {
		return MultiLogCollection{}, apperr.New(apperr.CodeCapabilityMissing,
			"multi-log mirror coordinator is not configured")
	}
	lr := make([]logmirror.LogRequest, 0, len(reqs))
	for _, r := range reqs {
		lr = append(lr, logmirror.LogRequest{
			Job:      r.Job,
			Build:    r.Build,
			Relation: r.Relation,
		})
	}
	res, err := m.Coord.Acquire(ctx, lr)
	if err != nil {
		return MultiLogCollection{}, err
	}
	out := MultiLogCollection{
		CollectionID:    res.CollectionID,
		Profile:         res.Profile,
		TotalBytes:      res.TotalBytes,
		TruncatedBudget: res.TruncatedBudget,
		Cancelled:       res.Cancelled,
		Logs:            make([]MultiLogEntry, 0, len(res.Results)),
	}
	for _, r := range res.Results {
		out.Logs = append(out.Logs, mapAcquireResult(r))
	}
	return out, nil
}

// ResidualMembers implements MultiLogAcquirer continue residual for collection_id.
// Loads durable catalog membership when the in-process session is missing (restart).
func (m *MirrorLogAccess) ResidualMembers(ctx context.Context, collectionID string) ([]MultiLogRequest, error) {
	if !m.MultiLogAvailable() {
		return nil, apperr.New(apperr.CodeCapabilityMissing,
			"multi-log mirror coordinator is not configured")
	}
	id := strings.TrimSpace(collectionID)
	if id == "" {
		return nil, invalidArg("collection_id is required")
	}
	// LoadSession falls back to Catalog (same profile) after process restart.
	session, err := m.Coord.LoadSession(ctx, id)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, apperr.New(apperr.CodeNotFound, "collection not found")
	}
	var out []MultiLogRequest
	for _, key := range session.Members {
		if err := ctx.Err(); err != nil {
			return nil, apperr.Wrap(apperr.CodeCancelled, "residual membership cancelled", err)
		}
		// Isolation: never leak foreign-profile keys.
		if key.Profile != m.Coord.Profile {
			continue
		}
		st, err := m.Coord.Machine.State(ctx, key)
		if err != nil {
			// Treat state errors as residual (re-acquire).
			rel := ""
			if session.Relations != nil {
				rel = session.Relations[key.String()]
			}
			out = append(out, MultiLogRequest{Job: key.Job, Build: key.Build, Relation: rel})
			continue
		}
		if st.Sealed {
			continue
		}
		rel := ""
		if session.Relations != nil {
			rel = session.Relations[key.String()]
		}
		out = append(out, MultiLogRequest{Job: key.Job, Build: key.Build, Relation: rel})
	}
	return out, nil
}

func mapAcquireResult(r logmirror.LogAcquireResult) MultiLogEntry {
	e := MultiLogEntry{
		Job:          r.Key.Job,
		Build:        r.Key.Build,
		Relation:     r.Relation,
		BytesFetched: r.BytesFetched,
		Generation:   r.State.Generation,
		DurableBytes: r.State.DurableOffset,
	}
	if r.Err != nil {
		code := apperr.CodeOf(r.Err)
		e.ErrorCode = string(code)
		// Budget skip vs other errors.
		if code == apperr.CodeQuota {
			e.Status = MirrorStatusSkipped
			e.Residual = true
		} else {
			e.Status = MirrorStatusError
			e.Residual = true
		}
		// Still surface durable progress when partial frames exist.
		if r.State.Sealed {
			e.Status = MirrorStatusSealed
			e.Residual = false
		} else if r.State.DurableOffset > 0 && e.Status != MirrorStatusSkipped {
			// Partial mirror with error (e.g. timeout mid-poll).
			e.Status = MirrorStatusMirrored
			e.Residual = true
		}
		return e
	}
	if r.State.Sealed {
		e.Status = MirrorStatusSealed
		e.Residual = false
		return e
	}
	e.Status = MirrorStatusMirrored
	e.Residual = true
	return e
}

// Ensure *MirrorLogAccess implements MultiLogAcquirer when Coord is set.
var _ MultiLogAcquirer = (*MirrorLogAccess)(nil)
