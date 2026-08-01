package tools

import (
	"context"
	"sort"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

// Wave 41: configurable list_jobs collect safety page cap when MCP deny patterns
// force full-list collect+filter (deny_job_prefixes / deny_branch_names).
// Each ListJobs page is hard-capped at jenkins.MaxListJobsLimit (200).
const (
	// DefaultListJobsCollectMaxPages is the default safety page cap for
	// collectAllJobs (~50 × 200 = 10k jobs before incomplete honesty).
	DefaultListJobsCollectMaxPages = 50
	// AbsoluteMaxListJobsCollectMaxPages is the process absolute fail-closed
	// ceiling for the collect page cap. Operators may raise via env/flag up to
	// this bound; values above fail closed at serve resolve (not clamped).
	AbsoluteMaxListJobsCollectMaxPages = 200
	// EnvListJobsCollectMaxPages is the serve env for the collect page cap
	// (Wave 41). CLI --list-jobs-collect-max-pages overrides when set.
	// Empty/0 → DefaultListJobsCollectMaxPages. Invalid values and values
	// above AbsoluteMaxListJobsCollectMaxPages fail closed at serve start.
	EnvListJobsCollectMaxPages = "JENKINS_MCP_LIST_JOBS_COLLECT_MAX_PAGES"
)

// maxJobsCollectPages is the live process collect page cap (package-level so
// tests can override and serve can set once from ResolveListJobsCollectMaxPages).
// Defaults to DefaultListJobsCollectMaxPages.
var maxJobsCollectPages = DefaultListJobsCollectMaxPages

// SetListJobsCollectMaxPages sets the process collect page cap after a
// successful ResolveListJobsCollectMaxPages (serve start). Non-positive n uses
// DefaultListJobsCollectMaxPages. Does not re-check AbsoluteMax (resolve already
// fail-closed); oversize values are clamped to absolute max as belt-and-suspenders.
func SetListJobsCollectMaxPages(n int) {
	maxJobsCollectPages = clampCollectMaxPages(n, DefaultListJobsCollectMaxPages, AbsoluteMaxListJobsCollectMaxPages)
}

// ListJobsCollectMaxPages returns the live collect page cap (for diagnostics/tests).
func ListJobsCollectMaxPages() int {
	return maxJobsCollectPages
}

// ResolveListJobsCollectMaxPages resolves the list_jobs policy-collect safety
// page cap (Wave 41 residual honesty for large fleets).
// Thin wrapper over ResolveCollectMaxPages (shared with nodes/views Wave 42).
func ResolveListJobsCollectMaxPages(flagVal, envVal string) (int, error) {
	return ResolveCollectMaxPages(flagVal, envVal,
		DefaultListJobsCollectMaxPages,
		AbsoluteMaxListJobsCollectMaxPages,
		EnvListJobsCollectMaxPages,
		"--list-jobs-collect-max-pages",
		"list_jobs")
}

// JobRowKeep reports whether a JobSummary row should remain after policy filters.
// true = keep; false = omit. Composable so deny_branch_names and deny_job_prefixes
// share ApplyJobPolicyFilters without replacing each other (Wave 37).
type JobRowKeep func(j jenkins.JobSummary) bool

// ApplyJobPolicyFilters drops rows rejected by any keep predicate (AND of keeps).
// Deny-only: never invents jobs. Empty filters returns a shallow copy and omitted=0.
func ApplyJobPolicyFilters(jobs []jenkins.JobSummary, keeps ...JobRowKeep) (kept []jenkins.JobSummary, omitted int) {
	if len(keeps) == 0 {
		if jobs == nil {
			return nil, 0
		}
		out := make([]jenkins.JobSummary, len(jobs))
		copy(out, jobs)
		return out, 0
	}
	kept = make([]jenkins.JobSummary, 0, len(jobs))
	for _, j := range jobs {
		drop := false
		for _, keep := range keeps {
			if keep == nil {
				continue
			}
			if !keep(j) {
				drop = true
				break
			}
		}
		if drop {
			omitted++
			continue
		}
		kept = append(kept, j)
	}
	return kept, omitted
}

// KeepUnlessJobPrefixDenied omits rows whose FullName matches deny_job_prefixes.
func KeepUnlessJobPrefixDenied(patterns []string) JobRowKeep {
	if len(patterns) == 0 {
		return nil
	}
	pats := make([]string, len(patterns))
	copy(pats, patterns)
	return func(j jenkins.JobSummary) bool {
		return !policy.NameDeniedByPatterns(pats, j.FullName)
	}
}

// FilterDeniedJobs drops JobSummary rows whose FullName matches any
// deny_job_prefixes pattern. Empty patterns → shallow copy, omitted=0.
func FilterDeniedJobs(patterns []string, jobs []jenkins.JobSummary) (kept []jenkins.JobSummary, omitted int) {
	return ApplyJobPolicyFilters(jobs, KeepUnlessJobPrefixDenied(patterns))
}

// KeepUnlessBranchDenied omits multibranch/matrix branch rows whose leaf Name
// or FullName matches any deny_branch_names pattern. Non-branch kinds are always
// kept so a folder named "main" is not hidden by deny_branch_names:["main"].
//
// Kind scope: branch and matrix_child only (conservative privacy).
func KeepUnlessBranchDenied(patterns []string) JobRowKeep {
	if len(patterns) == 0 {
		return nil
	}
	pats := make([]string, len(patterns))
	copy(pats, patterns)
	return func(j jenkins.JobSummary) bool {
		return !branchJobDeniedByPatterns(pats, j)
	}
}

// FilterDeniedBranchJobs drops JobSummary rows of kind branch/matrix_child that
// match deny_branch_names (Name or FullName). Empty patterns → shallow copy.
func FilterDeniedBranchJobs(patterns []string, jobs []jenkins.JobSummary) (kept []jenkins.JobSummary, omitted int) {
	return ApplyJobPolicyFilters(jobs, KeepUnlessBranchDenied(patterns))
}

// branchJobDeniedByPatterns is true when j is a branch-like kind and any
// BranchDenyCandidates (leaf, intermediate segments, multi-segment suffixes,
// full path) matches a deny pattern — aligned with call-time Evaluate (Wave 39).
func branchJobDeniedByPatterns(patterns []string, j jenkins.JobSummary) bool {
	if len(patterns) == 0 {
		return false
	}
	switch j.Kind {
	case jenkins.JobKindBranch, jenkins.JobKindMatrixChild:
		// ok
	default:
		return false
	}
	// Prefer FullName for candidates; fall back to Name (leaf).
	path := j.FullName
	if path == "" {
		path = j.Name
	}
	if path == "" {
		return false
	}
	if norm, ok := policy.NormalizeJobFullName(path); ok && norm != "" {
		path = norm
	}
	for _, cand := range policy.BranchDenyCandidates(path) {
		if policy.NameDeniedByPatterns(patterns, cand) {
			return true
		}
	}
	// Single-segment branch name (only leaf) still covered by BranchDenyCandidates.
	if j.Name != "" && j.Name != path && policy.NameDeniedByPatterns(patterns, j.Name) {
		return true
	}
	return false
}

// listJobsPolicyKeeps builds keep predicates from live deny_job_prefixes and
// deny_branch_names. Empty when neither pattern set is live.
func listJobsPolicyKeeps(st regState) []JobRowKeep {
	var keeps []JobRowKeep
	if pats := policy.DenyJobPrefixesFromEvaluator(st.policy); len(pats) > 0 {
		if k := KeepUnlessJobPrefixDenied(pats); k != nil {
			keeps = append(keeps, k)
		}
	}
	if pats := policy.DenyBranchNamesFromEvaluator(st.policy); len(pats) > 0 {
		if k := KeepUnlessBranchDenied(pats); k != nil {
			keeps = append(keeps, k)
		}
	}
	return keeps
}

// PolicyFingerprintMaterial returns stable non-secret strings for page-token
// fingerprints when the list_jobs collect path applies live MCP deny patterns
// (Wave 40). Sorted so Document order does not change the fingerprint.
// Job and branch namespaces are labeled separately so patterns cannot collide
// across fields. Empty when neither pattern set is live.
//
// Never includes credentials or raw secrets — only operator-configured deny
// pattern strings (already non-secret policy material).
func PolicyFingerprintMaterial(st regState) []string {
	jobPats := policy.DenyJobPrefixesFromEvaluator(st.policy)
	branchPats := policy.DenyBranchNamesFromEvaluator(st.policy)
	if len(jobPats) == 0 && len(branchPats) == 0 {
		return nil
	}
	var parts []string
	if len(jobPats) > 0 {
		sorted := append([]string(nil), jobPats...)
		sort.Strings(sorted)
		parts = append(parts, "deny_job_prefixes")
		parts = append(parts, sorted...)
	}
	if len(branchPats) > 0 {
		sorted := append([]string(nil), branchPats...)
		sort.Strings(sorted)
		parts = append(parts, "deny_branch_names")
		parts = append(parts, sorted...)
	}
	return parts
}

// listJobsNormalizedFilter returns fingerprint inputs matching Client.ListJobs.
func listJobsNormalizedFilter(args jenkins.ListJobsToolArgs) (folderPrefix, nameContains, view string, maxDepth int) {
	maxDepth = args.MaxDepth
	if maxDepth <= 0 {
		maxDepth = jenkins.DefaultListJobsDepth
	}
	if maxDepth > jenkins.MaxListJobsDepth {
		maxDepth = jenkins.MaxListJobsDepth
	}
	folderPrefix = strings.Trim(strings.TrimSpace(args.FolderPrefix), "/")
	nameContains = strings.ToLower(strings.TrimSpace(args.NameContains))
	view = strings.TrimSpace(args.View)
	return folderPrefix, nameContains, view, maxDepth
}

// listJobsDirectWithSubject is the empty-policy ListJobs path with HOST-004
// subject-bound page_token resolve + next_page_token mint.
//
// Strategy: resolve pagination under the subject-bound fingerprint at the tools
// layer, call Client.ListJobs with offset/limit only (no page_token) so the
// client does not re-check an unbound fingerprint, then rebind next_page_token.
// Empty subjectKey is a pure no-op vs unbound tokens (stdio pilot).
func listJobsDirectWithSubject(ctx context.Context, client *jenkins.Client, st regState, args jenkins.ListJobsToolArgs) (*jenkins.ListJobsToolResponse, error) {
	sk := effectiveSubjectKey(st, ctx)
	folderPrefix, nameContains, view, maxDepth := listJobsNormalizedFilter(args)
	filterFP := jenkins.ListJobsFilterFingerprint(folderPrefix, nameContains, view, maxDepth, args.IncludeFolders)
	off, lim, err := jenkins.ResolveListPaginationWithSubject(
		args.PageToken, args.Offset, args.Limit,
		jenkins.DefaultListJobsLimit, jenkins.MaxListJobsLimit, filterFP, sk,
	)
	if err != nil {
		return nil, err
	}
	call := args
	call.PageToken = ""
	call.Offset = off
	call.Limit = lim
	res, err := client.ListJobs(ctx, call)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, nil
	}
	// Client mints unbound next tokens; rebind so Alice/Bob cannot cross-continue.
	res.NextPageToken = jenkins.NextPageTokenIfMoreWithSubject(
		res.Offset, res.Limit, len(res.Jobs), res.Total, filterFP, sk)
	return res, nil
}

// PaginateJobs applies offset/limit like jenkins.Client.ListJobs page slicing.
// Exported for filter→paginate composition tests (Wave 39).
func PaginateJobs(all []jenkins.JobSummary, offset, limit int) (page []jenkins.JobSummary, off, lim int) {
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 {
		limit = jenkins.DefaultListJobsLimit
	}
	if limit > jenkins.MaxListJobsLimit {
		limit = jenkins.MaxListJobsLimit
	}
	if offset > len(all) {
		offset = len(all)
	}
	page = all[offset:]
	if len(page) > limit {
		page = page[:limit]
	}
	if page == nil {
		page = []jenkins.JobSummary{}
	}
	return page, offset, limit
}

// collectAllJobs pages through ListJobs with user filters until no next page
// token (or safety cap). incomplete is true when the page safety cap was hit
// while more jobs remain (Wave 39: avoid silent under-count after filter).
func collectAllJobs(ctx context.Context, client *jenkins.Client, args jenkins.ListJobsToolArgs) (all []jenkins.JobSummary, last *jenkins.ListJobsToolResponse, incomplete bool, err error) {
	// Preserve user discovery filters; force offset-only pagination with max page size.
	base := args
	base.PageToken = ""
	base.Limit = jenkins.MaxListJobsLimit
	offset := 0
	for pageNum := 0; pageNum < maxJobsCollectPages; pageNum++ {
		base.Offset = offset
		res, err := client.ListJobs(ctx, base)
		if err != nil {
			return nil, nil, false, err
		}
		all = append(all, res.Jobs...)
		last = res
		if res.NextPageToken == "" {
			return all, last, false, nil
		}
		next := offset + len(res.Jobs)
		if next <= offset {
			// Stuck cursor — return what we have; treat as incomplete.
			return all, last, true, nil
		}
		// Prefer Total when known (ListJobs always sets it for the walk).
		if res.Total > 0 && next >= res.Total {
			return all, last, false, nil
		}
		offset = next
	}
	// Hit safety cap with more pages remaining.
	return all, last, true, nil
}

// listJobsWithPolicyFilter runs ListJobs and, when live deny_job_prefixes and/or
// deny_branch_names are non-empty, collects the full filtered list, drops denied
// rows, recomputes Total, and re-applies offset/limit or page_token (Wave 39).
// Empty evaluator / empty patterns → single ListJobs (no extra cost).
//
// Wave 40: page tokens on the collect path bind to live deny pattern material
// (PolicyFingerprintMaterial) so mid-session policy tighten fails closed on
// old tokens instead of silently skewing pages. Empty-patterns single ListJobs
// keeps the Jenkins user-filter-only fingerprint (no policy applied after).
//
// HOST-004: when regState.subjectKey is non-empty, page tokens are subject-bound
// (Alice's next_page_token fails closed for Bob). Empty subjectKey leaves tokens
// unbound (stdio pilot residual).
//
// Deny-only: never invents jobs. Empty after filter → empty jobs, total 0.
func listJobsWithPolicyFilter(ctx context.Context, client *jenkins.Client, st regState, args jenkins.ListJobsToolArgs) (*jenkins.ListJobsToolResponse, error) {
	keeps := listJobsPolicyKeeps(st)
	if len(keeps) == 0 {
		// Empty patterns: single ListJobs; fingerprint stays user-filter only.
		// HOST-004: still subject-bind page tokens when SubjectKey is set.
		return listJobsDirectWithSubject(ctx, client, st, args)
	}

	sk := effectiveSubjectKey(st, ctx)
	folderPrefix, nameContains, view, maxDepth := listJobsNormalizedFilter(args)
	// Collect path: bind page_token to user filters + live deny patterns + subject.
	policyParts := PolicyFingerprintMaterial(st)
	filterFP := jenkins.ListJobsFilterFingerprint(folderPrefix, nameContains, view, maxDepth, args.IncludeFolders, policyParts...)
	userOffset, userLimit, err := jenkins.ResolveListPaginationWithSubject(
		args.PageToken, args.Offset, args.Limit,
		jenkins.DefaultListJobsLimit, jenkins.MaxListJobsLimit, filterFP, sk,
	)
	if err != nil {
		return nil, err
	}

	all, last, incomplete, err := collectAllJobs(ctx, client, args)
	if err != nil {
		return nil, err
	}

	kept, omitted := ApplyJobPolicyFilters(all, keeps...)
	if kept == nil {
		kept = []jenkins.JobSummary{}
	}
	total := len(kept)
	page, off, lim := PaginateJobs(kept, userOffset, userLimit)
	nextTok := jenkins.NextPageTokenIfMoreWithSubject(off, lim, len(page), total, filterFP, sk)

	// Truncated honesty: preserve Jenkins scan/depth truncation and force true
	// when collection hit the safety page cap (may have missed jobs).
	truncated := false
	scanned := 0
	source := "root"
	if last != nil {
		truncated = last.Truncated
		scanned = last.Scanned
		if last.Source != "" {
			source = last.Source
		}
	}
	if incomplete {
		truncated = true
	}

	out := &jenkins.ListJobsToolResponse{
		Jobs:          page,
		Offset:        off,
		Limit:         lim,
		Total:         total,
		Scanned:       scanned,
		Truncated:     truncated,
		Source:        source,
		NextPageToken: nextTok,
	}
	if omitted > 0 {
		out.PolicyFiltered = true
		out.PolicyOmittedCount = omitted
	}
	if incomplete {
		// Non-secret residual (mirror nodes/views incomplete messaging).
		// Do not list denied names or patterns; do not overwrite a prior message
		// (e.g. unauthorized) if one were ever set on this path.
		if strings.TrimSpace(out.Message) == "" {
			out.Message = "job list collection capped; results may be incomplete"
		} else {
			out.Message = out.Message + "; collection capped (may be incomplete)"
		}
	}
	return out, nil
}

// applyListJobsPolicyFilters composes job-prefix + branch keep predicates on an
// already-fetched page/list (unit-test helper; production path uses collect).
func applyListJobsPolicyFilters(res *jenkins.ListJobsToolResponse, st regState) *jenkins.ListJobsToolResponse {
	if res == nil {
		return res
	}
	keeps := listJobsPolicyKeeps(st)
	if len(keeps) == 0 {
		return res
	}
	kept, omitted := ApplyJobPolicyFilters(res.Jobs, keeps...)
	res.Jobs = kept
	if omitted == 0 {
		return res
	}
	res.PolicyFiltered = true
	res.PolicyOmittedCount = omitted
	// Recompute Total for full-list callers; page-only callers may under-count
	// (production uses collectAllJobs instead).
	if res.Total >= omitted {
		res.Total -= omitted
	} else {
		n := res.Offset + len(kept)
		if n < 0 {
			n = 0
		}
		res.Total = n
	}
	if res.Jobs == nil {
		res.Jobs = []jenkins.JobSummary{}
	}
	return res
}
