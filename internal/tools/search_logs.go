package tools

import (
	"context"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
	"github.com/simonfxr/go-jenkins-mcp/internal/redact"
	"github.com/simonfxr/go-jenkins-mcp/internal/search"
)

// ToolSearchLogs is the optional local log-search tool name (SEARCH-001/002).
// Registered only when RegisterOptions.LogSearch is non-nil.
const ToolSearchLogs = "jenkins_search_logs"

// LogSearcher is the search surface tools may call (SEARCH-001/002).
// *search.Engine implements this.
type LogSearcher interface {
	Search(ctx context.Context, q search.Query) (search.Result, error)
}

// LogScopeResolver resolves a search query to its generation job/build without
// scanning frames. Optional on LogSearch; *search.Engine implements it.
// Used to re-evaluate deny_job_prefixes and CheckStoreRead for generation_id-only
// calls (Wave 19 + Wave 33 store PEP).
type LogScopeResolver interface {
	Resolve(ctx context.Context, q search.Query) (search.Scope, error)
}

// SearchLogsToolArgs is the MCP input for jenkins_search_logs.
// Job full name + build select the mirrored generation; pattern is literal or RE2.
type SearchLogsToolArgs struct {
	// Profile is the connection profile that owns the local cache (optional when
	// generation_id is set; required with job_name/build_number).
	Profile string `json:"profile,omitempty" mcp:"connection profile id for local cache scope"`
	// JobName is the Jenkins job full name (not an http URL). Required unless generation_id is set.
	JobName string `json:"job_name,omitempty" mcp:"Jenkins job full name (folder/job path; not a URL)"`
	// BuildNumber is the build number. Required unless generation_id is set.
	BuildNumber int `json:"build_number,omitempty" mcp:"build number"`
	// GenerationID is the SQLite generation row id when known (optional).
	GenerationID int64 `json:"generation_id,omitempty" mcp:"local log generation id (optional)"`
	// Pattern is the literal substring or RE2 regular expression.
	Pattern string `json:"pattern" mcp:"literal or RE2 pattern to find"`
	// Regex selects RE2 mode when true (default literal).
	Regex bool `json:"regex,omitempty" mcp:"use RE2 regex instead of literal"`
	// CaseSensitive controls matching (default false / zero-value for agent-friendly search).
	CaseSensitive bool `json:"case_sensitive,omitempty" mcp:"case-sensitive match"`
	// Before is context lines before each match.
	Before int `json:"before,omitempty" mcp:"context lines before match"`
	// After is context lines after each match.
	After int `json:"after,omitempty" mcp:"context lines after match"`
	// MaxMatches caps returned matches (server also hard-caps; 0 ⇒ 100).
	MaxMatches int `json:"max_matches,omitempty" mcp:"maximum matches to return"`
}

// SearchLogsToolResponse is the structured MCP result (budget-enforced).
type SearchLogsToolResponse struct {
	Matches         []search.Match `json:"matches"`
	Truncated       bool           `json:"truncated,omitempty"`
	Incomplete      bool           `json:"incomplete,omitempty"`
	FramesOpened    int            `json:"frames_opened"`
	BytesScanned    int64          `json:"bytes_scanned"`
	BytesScannedCap int64          `json:"bytes_scanned_cap"`
	MaxMatches      int            `json:"max_matches"`
	GenerationID    int64          `json:"generation_id"`
	Generation      int64          `json:"generation"`
	Profile         string         `json:"profile,omitempty"`
	Job             string         `json:"job,omitempty"`
	Build           int64          `json:"build,omitempty"`
	Sealed          bool           `json:"sealed,omitempty"`
	// Untrusted marks excerpts as untrusted build output (SEC-003 residual).
	Untrusted bool `json:"untrusted"`
}

func searchQueryFromArgs(args SearchLogsToolArgs) (search.Query, error) {
	pat := strings.TrimSpace(args.Pattern)
	if pat == "" {
		return search.Query{}, invalidArg("pattern is required")
	}
	q := search.Query{
		GenerationID:  args.GenerationID,
		Profile:       strings.TrimSpace(args.Profile),
		Job:           strings.TrimSpace(args.JobName),
		Build:         int64(args.BuildNumber),
		Pattern:       pat,
		CaseSensitive: args.CaseSensitive,
		Before:        args.Before,
		After:         args.After,
		MaxMatches:    args.MaxMatches,
	}
	if args.Regex {
		q.Mode = search.ModeRegex
	} else {
		q.Mode = search.ModeLiteral
	}
	if q.GenerationID <= 0 {
		// MCP-002: validate job full name when resolving by job/build.
		if q.Job == "" || q.Build <= 0 {
			return search.Query{}, invalidArg("generation_id or job_name+build_number is required")
		}
		name, err := jobFullName("job_name", q.Job)
		if err != nil {
			return search.Query{}, err
		}
		q.Job = name
		if q.Profile == "" {
			return search.Query{}, invalidArg("profile is required when searching by job_name")
		}
	}
	return q, nil
}

func searchResultToResponse(r search.Result) SearchLogsToolResponse {
	return SearchLogsToolResponse{
		Matches:         r.Matches,
		Truncated:       r.Truncated,
		Incomplete:      r.Incomplete,
		FramesOpened:    r.FramesOpened,
		BytesScanned:    r.BytesScanned,
		BytesScannedCap: r.BytesScannedCap,
		MaxMatches:      r.MaxMatches,
		GenerationID:    r.GenerationID,
		Generation:      r.Generation,
		Profile:         r.Profile,
		Job:             r.Job,
		Build:           r.Build,
		Sealed:          r.Sealed,
		Untrusted:       true,
	}
}

// registerSearchLogsTool registers jenkins_search_logs when LogSearch is set.
func registerSearchLogsTool(s *mcp.Server, st regState) {
	if st.logSearch == nil {
		return
	}
	addReadTool(s, st, &mcp.Tool{
		Name:        ToolSearchLogs,
		Description: "Search mirrored build logs locally (literal or RE2) without re-downloading from Jenkins",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args SearchLogsToolArgs) (*mcp.CallToolResult, SearchLogsToolResponse, error) {
		if args.JobName != "" {
			if _, err := jobFullName("job_name", args.JobName); err != nil {
				return nil, SearchLogsToolResponse{}, err
			}
		}
		q, err := searchQueryFromArgs(args)
		if err != nil {
			return nil, SearchLogsToolResponse{}, err
		}
		if q.Profile == "" && st.profileID != "" {
			q.Profile = st.profileID
		}
		// Wave 19/33 SEARCH/POL: re-evaluate deny_job_prefixes and CheckStoreRead
		// on the resolved job before scanning L1 frames. Middleware builds Target
		// only from args (job_name); generation_id-only calls leave Target empty.
		// generation_id also wins over job_name in the engine — always resolve
		// when set so a public job_name cannot smuggle a denied generation.
		// Store PEP and tool Evaluate both must allow; disagreement → deny.
		if err := enforceSearchLogsJobPolicy(ctx, st, q); err != nil {
			return nil, SearchLogsToolResponse{}, err
		}
		res, err := st.logSearch.Search(ctx, q)
		if err != nil {
			return nil, SearchLogsToolResponse{}, mapToolErr(err)
		}
		out := searchResultToResponse(res)
		for i := range out.Matches {
			out.Matches[i].LineText = redact.SanitizeForModel(out.Matches[i].LineText)
			for j := range out.Matches[i].Before {
				out.Matches[i].Before[j] = redact.SanitizeForModel(out.Matches[i].Before[j])
			}
			for j := range out.Matches[i].After {
				out.Matches[i].After[j] = redact.SanitizeForModel(out.Matches[i].After[j])
			}
		}
		return structuredResult(out)
	})
}

// enforceSearchLogsJobPolicy fails closed on deny_job_prefixes and the store PEP
// (CheckStoreRead) for the job that will actually be scanned. No-op when Policy
// is nil.
//
// Approach A: resolve generation → job (meta only, no frame open) then:
//  1. Evaluate tool action with Target{JobName} (deny_job_prefixes / deny_tools)
//  2. CheckStoreRead for the same job (store PEP; e.g. store_cached_read deny)
//
// Either deny wins (fail closed). Denied → policy_denial without Search/frame open.
func enforceSearchLogsJobPolicy(ctx context.Context, st regState, q search.Query) error {
	if st.policy == nil {
		return nil
	}
	job := strings.TrimSpace(q.Job)
	build := q.Build

	// generation_id wins in the engine: always resolve so middleware's args-only
	// Target cannot be wrong. Also resolve when job is empty (generation_id-only).
	if q.GenerationID > 0 || job == "" {
		resolver, ok := st.logSearch.(LogScopeResolver)
		if !ok {
			if q.GenerationID > 0 {
				// Active policy + generation_id without offline resolve capability:
				// fail closed — never scan frames without a job target check.
				return searchLogsUnresolvedDeny(ctx, st)
			}
			// job_name path without Resolve: middleware already checked q.Job;
			// still enforce store PEP below when job is present.
		} else {
			scope, err := resolver.Resolve(ctx, q)
			if err != nil {
				return mapToolErr(err)
			}
			job = strings.TrimSpace(scope.Job)
			if scope.Build > 0 {
				build = scope.Build
			}
		}
	}
	if job == "" {
		if q.GenerationID > 0 {
			return searchLogsUnresolvedDeny(ctx, st)
		}
		return nil
	}
	target := policy.Target{JobName: job}
	if build > 0 {
		target.BuildNumber = build
	}
	subj := effectiveSubject(st, ctx)
	d := st.policy.Evaluate(
		subj,
		policy.Action{ToolName: ToolSearchLogs, Class: policy.EffectRead},
		target,
	)
	if err := d.Err(); err != nil {
		reason := d.ReasonCode
		if reason == "" {
			reason = policy.ReasonJobPatternDeny
		}
		emitToolDeny(ctx, st, ToolSearchLogs, string(policy.EffectRead), reason, time.Now())
		return err
	}
	// Wave 33: store PEP before any frame scan. Aligns L1 search with mirrored
	// read/tail (logaccess). Tool Evaluate allow + store deny → still deny.
	if err := policy.CheckStoreRead(ctx, st.policy, subj, job); err != nil {
		if apperr.IsCancelled(err) {
			return err
		}
		reason := policy.ReasonExplicitDeny
		// Re-evaluate store action for a stable audit reason (job pattern vs deny_tools).
		sd := st.policy.Evaluate(
			subj,
			policy.Action{ToolName: policy.StoreReadAction, Class: policy.EffectRead},
			target,
		)
		if sd.Denied() && sd.ReasonCode != "" {
			reason = sd.ReasonCode
		}
		emitToolDeny(ctx, st, ToolSearchLogs, string(policy.EffectRead), reason, time.Now())
		return err
	}
	return nil
}

func searchLogsUnresolvedDeny(ctx context.Context, st regState) error {
	emitToolDeny(ctx, st, ToolSearchLogs, string(policy.EffectRead), policy.ReasonJobPatternDeny, time.Now())
	return apperr.New(apperr.CodePolicyDenial,
		"local log search denied by MCP policy (generation job unresolved)")
}

// Compile-time: production LogSearch implements Search + offline Resolve.
var (
	_ LogSearcher      = (*search.Engine)(nil)
	_ LogScopeResolver = (*search.Engine)(nil)
)
