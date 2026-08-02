package tools

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/diagnostics"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
	"github.com/simonfxr/go-jenkins-mcp/internal/redact"
)

// ToolCompareBuilds is the DIAG-003 build comparison tool name.
const ToolCompareBuilds = "jenkins_compare_builds"

// Compare budgets (server-enforced; callers may only lower).
const (
	// DefaultCompareMaxTestDiffs caps failed-test name diffs returned.
	DefaultCompareMaxTestDiffs = 20
	// HardCompareMaxTestDiffs is the absolute test-diff ceiling.
	HardCompareMaxTestDiffs = 50
	// DefaultCompareMaxArtifactDiffs caps artifact path diffs.
	DefaultCompareMaxArtifactDiffs = 50
	// HardCompareMaxArtifactDiffs is the absolute artifact-diff ceiling.
	HardCompareMaxArtifactDiffs = 100
	// DefaultCompareMaxStageDiffs caps stage summary diffs.
	DefaultCompareMaxStageDiffs = 30
	// HardCompareMaxStageDiffs is the absolute stage-diff ceiling.
	HardCompareMaxStageDiffs = 50
	// DefaultCompareMaxSCMCommits caps redacted commit messages in the SCM summary.
	DefaultCompareMaxSCMCommits = 10
	// HardCompareMaxSCMCommits is the absolute commit list ceiling for compare.
	HardCompareMaxSCMCommits = 20
	// MaxCompareSCMScanBuilds caps baseline-range scan when comparing A vs B.
	// When |build_a−build_b| exceeds this, per-build summaries are used instead.
	MaxCompareSCMScanBuilds = 5
)

// CompareBuildsToolArgs is the MCP input for jenkins_compare_builds.
type CompareBuildsToolArgs struct {
	JobName string `json:"job_name" mcp:"Jenkins job full name (folder/job path; not a URL)"`
	// BuildA is typically the failing/candidate build.
	BuildA int `json:"build_a" mcp:"first build number (often failing)"`
	// BuildB is typically the baseline/green build.
	BuildB int `json:"build_b" mcp:"second build number (often baseline)"`
	// MaxFindings caps error signature findings compared per build (0 ⇒ default).
	MaxFindings int `json:"max_findings,omitempty" mcp:"maximum error signatures per build"`
	// MaxLogBytes caps the log tail scanned per build (0 ⇒ default; hard-capped).
	MaxLogBytes int `json:"max_log_bytes,omitempty" mcp:"max log tail bytes to scan per build"`
	// MaxTestDiffs caps returned failed-test name diffs (0 ⇒ default).
	MaxTestDiffs int `json:"max_test_diffs,omitempty" mcp:"maximum failed-test diffs to return"`
}

// CompareResultDiff is a result/building difference.
type CompareResultDiff struct {
	BuildAResult   string `json:"build_a_result,omitempty"`
	BuildBResult   string `json:"build_b_result,omitempty"`
	BuildABuilding bool   `json:"build_a_building,omitempty"`
	BuildBBuilding bool   `json:"build_b_building,omitempty"`
}

// CompareDurationDiff is a timing difference.
type CompareDurationDiff struct {
	BuildADuration string `json:"build_a_duration,omitempty"`
	BuildBDuration string `json:"build_b_duration,omitempty"`
	DeltaMs        int64  `json:"delta_ms,omitempty"`
}

// CompareParamDiff is a non-secret parameter difference.
type CompareParamDiff struct {
	Name   string `json:"name"`
	BuildA string `json:"build_a,omitempty"`
	BuildB string `json:"build_b,omitempty"`
	// Change is added | removed | changed.
	Change string `json:"change"`
}

// CompareStageDiff is a compact stage status/duration difference.
type CompareStageDiff struct {
	Name           string `json:"name"`
	BuildAStatus   string `json:"build_a_status,omitempty"`
	BuildBStatus   string `json:"build_b_status,omitempty"`
	BuildADuration string `json:"build_a_duration,omitempty"`
	BuildBDuration string `json:"build_b_duration,omitempty"`
	// Change is added | removed | status_changed | duration_changed.
	Change string `json:"change"`
}

// CompareTestSummaryDiff is high-level JUnit count differences.
type CompareTestSummaryDiff struct {
	BuildAPass  int  `json:"build_a_pass"`
	BuildBPass  int  `json:"build_b_pass"`
	BuildAFail  int  `json:"build_a_fail"`
	BuildBFail  int  `json:"build_b_fail"`
	BuildASkip  int  `json:"build_a_skip"`
	BuildBSkip  int  `json:"build_b_skip"`
	BuildATotal int  `json:"build_a_total"`
	BuildBTotal int  `json:"build_b_total"`
	AvailableA  bool `json:"available_a"`
	AvailableB  bool `json:"available_b"`
}

// CompareTestCaseDiff is a failed-test name present on only one side.
type CompareTestCaseDiff struct {
	Key string `json:"key"`
	// Side is only_a | only_b.
	Side   string `json:"side"`
	Status string `json:"status,omitempty"`
}

// CompareSignatureDiff is an error signature present on only one side (or both with count delta).
type CompareSignatureDiff struct {
	Signature string `json:"signature"`
	Pattern   string `json:"pattern,omitempty"`
	Message   string `json:"message,omitempty"`
	// Side is only_a | only_b | both_count_diff.
	Side       string  `json:"side"`
	CountA     int     `json:"count_a,omitempty"`
	CountB     int     `json:"count_b,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
}

// CompareArtifactDiff is an artifact path present on only one side.
type CompareArtifactDiff struct {
	Path string `json:"path"`
	// Side is only_a | only_b.
	Side string `json:"side"`
}

// CompareSCMCommit is a bounded, redacted commit summary for compare (SCM-001).
type CompareSCMCommit struct {
	ID      string `json:"id,omitempty"`
	Message string `json:"message,omitempty"`
	Author  string `json:"author,omitempty"`
	// BuildNumber is the build that reported this commit (range aggregate).
	BuildNumber int `json:"build_number,omitempty"`
	// Side is only_a | only_b | both when known from per-build mode; empty in range mode.
	Side string `json:"side,omitempty"`
}

// CompareRevisionDiff is a BuildData branch/SHA tip difference between A and B.
type CompareRevisionDiff struct {
	Branch string `json:"branch,omitempty"`
	Kind   string `json:"kind,omitempty"`
	SHAA   string `json:"sha_a,omitempty"`
	SHAB   string `json:"sha_b,omitempty"`
	// Change is only_a | only_b | changed.
	Change string `json:"change"`
}

// CompareSCMDiff is the bounded SCM comparison attached to jenkins_compare_builds.
// Prefer range mode (changes after the older build through the newer) when the
// span is within MaxCompareSCMScanBuilds; otherwise per-build summaries.
type CompareSCMDiff struct {
	// Mode is "range" (baseline→target aggregate) or "per_build".
	Mode string `json:"mode"`
	// BaselineBuild / TargetBuild describe the aggregation window (range mode).
	// Baseline is the older of build_a/build_b; target is the newer.
	BaselineBuild int `json:"baseline_build,omitempty"`
	TargetBuild   int `json:"target_build,omitempty"`
	// CommitsTotal is commits seen in the comparison window (pre-truncation).
	CommitsTotal int `json:"commits_total"`
	// Commits are redacted/bounded commit messages.
	Commits []CompareSCMCommit `json:"commits,omitempty"`
	// RevisionDiffs lists BuildData tips that differ between A and B (when available).
	RevisionDiffs []CompareRevisionDiff `json:"revision_diffs,omitempty"`
	// CommitCountA / CommitCountB are per-build totals (per_build mode or side stats).
	CommitCountA int  `json:"commit_count_a,omitempty"`
	CommitCountB int  `json:"commit_count_b,omitempty"`
	MultiSCM     bool `json:"multi_scm,omitempty"`
	Truncated    bool `json:"truncated,omitempty"`
	// Message is a short status when no commits (never invents changes).
	Message string `json:"message,omitempty"`
}

// CompareBudgets records caps consumed for the comparison.
type CompareBudgets struct {
	MaxFindings     int   `json:"max_findings"`
	MaxLogBytes     int   `json:"max_log_bytes_per_build"`
	MaxTestDiffs    int   `json:"max_test_diffs"`
	LogBytesScanned int   `json:"log_bytes_scanned"`
	MaxRemoteCalls  int   `json:"max_remote_calls,omitempty"`
	MaxRemoteBytes  int64 `json:"max_remote_bytes,omitempty"`
	MaxWallMS       int64 `json:"max_wall_ms,omitempty"`
}

// CompareBuildsToolResponse is the bounded differences-only comparison result.
type CompareBuildsToolResponse struct {
	Job                string                  `json:"job"`
	BuildA             int                     `json:"build_a"`
	BuildB             int                     `json:"build_b"`
	MaterialDifference bool                    `json:"material_difference"`
	Summary            string                  `json:"summary"`
	ResultDiff         *CompareResultDiff      `json:"result_diff,omitempty"`
	DurationDiff       *CompareDurationDiff    `json:"duration_diff,omitempty"`
	ParameterDiffs     []CompareParamDiff      `json:"parameter_diffs,omitempty"`
	StageDiffs         []CompareStageDiff      `json:"stage_diffs,omitempty"`
	TestSummaryDiff    *CompareTestSummaryDiff `json:"test_summary_diff,omitempty"`
	TestCaseDiffs      []CompareTestCaseDiff   `json:"test_case_diffs,omitempty"`
	SignatureDiffs     []CompareSignatureDiff  `json:"signature_diffs,omitempty"`
	ArtifactPathDiffs  []CompareArtifactDiff   `json:"artifact_path_diffs,omitempty"`
	// ArtifactsPolicyFiltered is true when ≥1 artifact path diff was omitted by
	// live deny_artifact_paths (Wave 39 deny-only privacy). Integer-only metadata;
	// denied paths are never listed.
	ArtifactsPolicyFiltered bool `json:"artifacts_policy_filtered,omitempty"`
	// ArtifactsPolicyOmittedCount is how many artifact path diffs were dropped by MCP policy.
	ArtifactsPolicyOmittedCount int `json:"artifacts_policy_omitted_count,omitempty"`
	// SCMDiff is bounded SCM changes/revisions between the two builds (SCM-001 wire-up).
	SCMDiff         *CompareSCMDiff `json:"scm_diff,omitempty"`
	Residuals       []string        `json:"residuals,omitempty"`
	Sources         []string        `json:"sources,omitempty"`
	ConfidenceNotes []string        `json:"confidence_notes,omitempty"`
	Incomplete      bool            `json:"incomplete,omitempty"`
	// Untrusted marks log/test-derived text as untrusted build output.
	Untrusted bool           `json:"untrusted"`
	Budgets   CompareBudgets `json:"budgets"`
	// Perf is optional request-local cache/remote counters (PERF-003).
	Perf *DiagPerf `json:"perf,omitempty"`
}

// registerCompareBuildsTool registers jenkins_compare_builds (DIAG-003).
func registerCompareBuildsTool(s *mcp.Server, client *jenkins.Client, st regState) {
	addReadTool(s, st, &mcp.Tool{
		Name: ToolCompareBuilds,
		Description: "Compare two builds of the same job (result, timing, stages, non-secret " +
			"parameters, tests, error signatures, artifact paths, SCM changes/revisions). " +
			"Returns only differences by default; identical → compact no-material-difference. " +
			"Never dumps full logs or downloads artifacts.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args CompareBuildsToolArgs) (*mcp.CallToolResult, CompareBuildsToolResponse, error) {
		out, err := runCompareBuilds(ctx, client, st, args)
		if err != nil {
			return nil, CompareBuildsToolResponse{}, err
		}
		return structuredResult(out)
	})
}

func runCompareBuilds(ctx context.Context, client *jenkins.Client, st regState, args CompareBuildsToolArgs) (CompareBuildsToolResponse, error) {
	name, err := jobFullName("job_name", args.JobName)
	if err != nil {
		return CompareBuildsToolResponse{}, err
	}
	if args.BuildA <= 0 {
		return CompareBuildsToolResponse{}, invalidArg("build_a must be positive")
	}
	if args.BuildB <= 0 {
		return CompareBuildsToolResponse{}, invalidArg("build_b must be positive")
	}

	maxFindings := args.MaxFindings
	if maxFindings <= 0 {
		maxFindings = DefaultDiagnoseMaxFindings
	}
	if maxFindings > HardDiagnoseMaxFindings {
		maxFindings = HardDiagnoseMaxFindings
	}
	maxLog := args.MaxLogBytes
	if maxLog <= 0 {
		maxLog = DefaultDiagnoseLogBytes
	}
	if maxLog > HardDiagnoseLogBytes {
		maxLog = HardDiagnoseLogBytes
	}
	maxTestDiffs := args.MaxTestDiffs
	if maxTestDiffs <= 0 {
		maxTestDiffs = DefaultCompareMaxTestDiffs
	}
	if maxTestDiffs > HardCompareMaxTestDiffs {
		maxTestDiffs = HardCompareMaxTestDiffs
	}

	budgetCfg := mergeDiagBudget(compareBudgetDefault(), st.diagBudget)
	out := CompareBuildsToolResponse{
		Job:       name,
		BuildA:    args.BuildA,
		BuildB:    args.BuildB,
		Untrusted: true,
		Budgets: CompareBudgets{
			MaxFindings:    maxFindings,
			MaxLogBytes:    maxLog,
			MaxTestDiffs:   maxTestDiffs,
			MaxRemoteCalls: budgetCfg.MaxRemoteCalls,
			MaxRemoteBytes: budgetCfg.MaxRemoteBytes,
		},
	}
	if budgetCfg.MaxWall > 0 {
		out.Budgets.MaxWallMS = budgetCfg.MaxWall.Milliseconds()
	}

	if client == nil {
		return CompareBuildsToolResponse{}, apperr.New(apperr.CodeInternal, "jenkins client is nil")
	}

	sess := newDiagSession(st, compareBudgetDefault())
	ctx, cancel := sess.BoundContext(ctx)
	defer cancel()
	ctx = withDiagSession(ctx, sess)

	// Build metadata (required for a meaningful compare); PERF-003 cache.
	ba, errA := getCachedBuildDetails(ctx, st, client, name, args.BuildA)
	if errA != nil {
		if isDiagBudgetErr(errA) {
			out.Incomplete = true
			out.ConfidenceNotes = append(out.ConfidenceNotes, sess.BudgetNote())
			out.Residuals = append(out.Residuals, sess.BudgetNote())
			perf := sess.PerfSnapshot()
			out.Perf = &perf
			out.Summary = "incomplete: remote budget exhausted before build metadata"
			return out, nil
		}
		return CompareBuildsToolResponse{}, mapToolErr(errA)
	}
	bb, errB := getCachedBuildDetails(ctx, st, client, name, args.BuildB)
	if errB != nil {
		if isDiagBudgetErr(errB) {
			out.Incomplete = true
			out.ConfidenceNotes = append(out.ConfidenceNotes, sess.BudgetNote())
			out.Residuals = append(out.Residuals, sess.BudgetNote())
			perf := sess.PerfSnapshot()
			out.Perf = &perf
			out.Summary = "incomplete: remote budget exhausted before build metadata"
			return out, nil
		}
		return CompareBuildsToolResponse{}, mapToolErr(errB)
	}
	if ba == nil || bb == nil {
		return CompareBuildsToolResponse{}, apperr.New(apperr.CodeNotFound, "build metadata unavailable")
	}
	out.Sources = append(out.Sources, "build_api")

	// Result / building.
	if ba.Result != bb.Result || ba.Building != bb.Building {
		out.ResultDiff = &CompareResultDiff{
			BuildAResult:   ba.Result,
			BuildBResult:   bb.Result,
			BuildABuilding: ba.Building,
			BuildBBuilding: bb.Building,
		}
	}

	// Duration.
	durA := time.Duration(ba.Duration)
	durB := time.Duration(bb.Duration)
	if durA != durB {
		delta := (durA - durB).Milliseconds()
		out.DurationDiff = &CompareDurationDiff{
			BuildADuration: durA.String(),
			BuildBDuration: durB.String(),
			DeltaMs:        delta,
		}
	}

	// Non-secret parameters only.
	paramsA := safeParamsForCompare(ba.Parameters)
	paramsB := safeParamsForCompare(bb.Parameters)
	out.ParameterDiffs = diffParams(paramsA, paramsB)
	if len(out.ParameterDiffs) > 0 {
		out.Sources = append(out.Sources, "parameters")
	}

	// Pipeline stages (PIPE-001) — degrade on capability/missing; PERF-003 cache.
	stagesA, stagesB, stageNote, stageSrc := fetchStageSummaries(ctx, st, client, name, args.BuildA, args.BuildB)
	if stageNote != "" {
		out.ConfidenceNotes = append(out.ConfidenceNotes, stageNote)
	}
	if stageSrc != "" {
		out.Sources = append(out.Sources, stageSrc)
	}
	out.StageDiffs = diffStages(stagesA, stagesB)

	// Test summaries + failed case keys (TEST-001).
	tsDiff, caseDiffs, testNote, testSrc := compareTests(ctx, st, client, name, args.BuildA, args.BuildB, maxTestDiffs)
	if testNote != "" {
		out.ConfidenceNotes = append(out.ConfidenceNotes, testNote)
	}
	if testSrc != "" {
		out.Sources = append(out.Sources, testSrc)
	}
	if tsDiff != nil {
		// Only attach when counts differ or availability differs.
		if tsDiff.AvailableA != tsDiff.AvailableB ||
			tsDiff.BuildAPass != tsDiff.BuildBPass ||
			tsDiff.BuildAFail != tsDiff.BuildBFail ||
			tsDiff.BuildASkip != tsDiff.BuildBSkip ||
			tsDiff.BuildATotal != tsDiff.BuildBTotal {
			out.TestSummaryDiff = tsDiff
		}
	}
	out.TestCaseDiffs = caseDiffs

	// Error signatures via bounded log tails (prefer logmirror; shared FetchCache).
	sigDiffs, logBytes, logNotes, logSrcs, logIncomplete := compareSignatures(
		ctx, client, st, name, args.BuildA, args.BuildB, maxLog, maxFindings)
	out.SignatureDiffs = sigDiffs
	out.Budgets.LogBytesScanned = logBytes
	out.ConfidenceNotes = append(out.ConfidenceNotes, logNotes...)
	out.Sources = append(out.Sources, logSrcs...)
	if logIncomplete {
		out.Incomplete = true
	}

	// Artifact path lists only (ART-001 list; no download).
	// Wave 39: omit diffs matching live deny_artifact_paths (deny-only privacy).
	artDiffs, artNote, artSrc, artOmitted := compareArtifactPaths(ctx, st, client, name, args.BuildA, args.BuildB)
	if artNote != "" {
		out.ConfidenceNotes = append(out.ConfidenceNotes, artNote)
	}
	if artSrc != "" {
		out.Sources = append(out.Sources, artSrc)
	}
	out.ArtifactPathDiffs = artDiffs
	if artOmitted > 0 {
		out.ArtifactsPolicyFiltered = true
		out.ArtifactsPolicyOmittedCount = artOmitted
	}

	// SCM changes/revisions (SCM-001 wire-up): degrade on budget/missing; never fail compare.
	scmDiff, scmResidual, scmNote, scmSrc := compareSCM(ctx, st, client, name, args.BuildA, args.BuildB)
	if scmDiff != nil {
		out.SCMDiff = scmDiff
	}
	if scmResidual != "" {
		out.Residuals = append(out.Residuals, scmResidual)
	}
	if scmNote != "" {
		out.ConfidenceNotes = append(out.ConfidenceNotes, scmNote)
	}
	if scmSrc != "" {
		out.Sources = append(out.Sources, scmSrc)
	}

	if note := sess.BudgetNote(); note != "" {
		out.Incomplete = true
		out.ConfidenceNotes = append(out.ConfidenceNotes, note)
		out.Residuals = append(out.Residuals, note)
	}
	if ctx.Err() != nil {
		out.Incomplete = true
		out.ConfidenceNotes = append(out.ConfidenceNotes, "operation cancelled: "+safeErrNote(ctx.Err()))
	}

	out.MaterialDifference = hasMaterialDiff(out)
	out.Summary = buildCompareSummary(out)
	out.ConfidenceNotes = append(out.ConfidenceNotes,
		"comparison is heuristic over bounded windows; not a proven root-cause analysis")
	out.Sources = uniqueStrings(out.Sources)
	perf := sess.PerfSnapshot()
	out.Perf = &perf
	return out, nil
}

func safeParamsForCompare(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if redact.IsSensitiveFieldName(k) {
			// Exclude secrets entirely (not even redacted placeholders as diffs).
			continue
		}
		out[k] = redact.RedactText(v)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func diffParams(a, b map[string]string) []CompareParamDiff {
	keys := make(map[string]struct{})
	for k := range a {
		keys[k] = struct{}{}
	}
	for k := range b {
		keys[k] = struct{}{}
	}
	if len(keys) == 0 {
		return nil
	}
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)
	var diffs []CompareParamDiff
	for _, k := range names {
		va, oka := a[k]
		vb, okb := b[k]
		if oka && okb && va == vb {
			continue
		}
		d := CompareParamDiff{Name: k}
		if oka {
			d.BuildA = va
		}
		if okb {
			d.BuildB = vb
		}
		switch {
		case oka && !okb:
			d.Change = "removed"
		case !oka && okb:
			d.Change = "added"
		default:
			d.Change = "changed"
		}
		diffs = append(diffs, d)
	}
	return diffs
}

type stageSummary struct {
	Name     string
	Status   string
	Duration string
}

func fetchStageSummaries(ctx context.Context, st regState, client *jenkins.Client, job string, a, b int) (sa, sb []stageSummary, note, src string) {
	psA, errA := getCachedPipelineStages(ctx, st, client, job, a)
	psB, errB := getCachedPipelineStages(ctx, st, client, job, b)
	if errA != nil && errB != nil {
		if isDiagBudgetErr(errA) || isDiagBudgetErr(errB) {
			return nil, nil, "pipeline stages skipped: remote budget exhausted", ""
		}
		code := apperr.CodeOf(errA)
		if code == apperr.CodeCapabilityMissing {
			return nil, nil, "pipeline stages unavailable: capability_missing (PIPE-001 residual)", ""
		}
		return nil, nil, "pipeline stages unavailable: " + safeErrNote(errA), ""
	}
	if errA != nil {
		if isDiagBudgetErr(errA) {
			note = "pipeline stages for build_a skipped: remote budget exhausted"
		} else {
			note = "pipeline stages for build_a unavailable: " + safeErrNote(errA)
		}
	}
	if errB != nil {
		if note != "" {
			note += "; "
		}
		if isDiagBudgetErr(errB) {
			note += "pipeline stages for build_b skipped: remote budget exhausted"
		} else {
			note += "pipeline stages for build_b unavailable: " + safeErrNote(errB)
		}
	}
	if psA != nil {
		sa = flattenStageSummaries(psA.Stages)
		src = "pipeline_stages"
	}
	if psB != nil {
		sb = flattenStageSummaries(psB.Stages)
		src = "pipeline_stages"
	}
	return sa, sb, note, src
}

func flattenStageSummaries(nodes []jenkins.StageNode) []stageSummary {
	var out []stageSummary
	var walk func([]jenkins.StageNode)
	walk = func(ns []jenkins.StageNode) {
		for _, n := range ns {
			name := strings.TrimSpace(n.Name)
			if name != "" {
				out = append(out, stageSummary{
					Name:     name,
					Status:   n.Status,
					Duration: time.Duration(n.Duration).String(),
				})
			}
			if len(n.Children) > 0 {
				walk(n.Children)
			}
			if len(out) >= HardCompareMaxStageDiffs*2 {
				return
			}
		}
	}
	walk(nodes)
	return out
}

func diffStages(a, b []stageSummary) []CompareStageDiff {
	mapA := make(map[string]stageSummary, len(a))
	mapB := make(map[string]stageSummary, len(b))
	// Last occurrence wins on name collisions (parallel branches share parent names rarely).
	for _, s := range a {
		mapA[s.Name] = s
	}
	for _, s := range b {
		mapB[s.Name] = s
	}
	keys := make(map[string]struct{})
	for k := range mapA {
		keys[k] = struct{}{}
	}
	for k := range mapB {
		keys[k] = struct{}{}
	}
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)
	var diffs []CompareStageDiff
	for _, name := range names {
		sa, oka := mapA[name]
		sb, okb := mapB[name]
		if oka && okb && sa.Status == sb.Status && sa.Duration == sb.Duration {
			continue
		}
		d := CompareStageDiff{Name: name}
		if oka {
			d.BuildAStatus = sa.Status
			d.BuildADuration = sa.Duration
		}
		if okb {
			d.BuildBStatus = sb.Status
			d.BuildBDuration = sb.Duration
		}
		switch {
		case oka && !okb:
			d.Change = "removed"
		case !oka && okb:
			d.Change = "added"
		case sa.Status != sb.Status:
			d.Change = "status_changed"
		default:
			d.Change = "duration_changed"
		}
		diffs = append(diffs, d)
		if len(diffs) >= HardCompareMaxStageDiffs {
			break
		}
	}
	if len(diffs) > DefaultCompareMaxStageDiffs {
		diffs = diffs[:DefaultCompareMaxStageDiffs]
	}
	return diffs
}

func compareTests(ctx context.Context, st regState, client *jenkins.Client, job string, a, b, maxDiffs int) (*CompareTestSummaryDiff, []CompareTestCaseDiff, string, string) {
	ra, errA := getCachedTestReport(ctx, st, client, job, a, maxDiffs)
	rb, errB := getCachedTestReport(ctx, st, client, job, b, maxDiffs)
	if errA != nil && errB != nil {
		if isDiagBudgetErr(errA) || isDiagBudgetErr(errB) {
			return nil, nil, "test reports skipped: remote budget exhausted", ""
		}
		code := apperr.CodeOf(errA)
		if code == apperr.CodeCapabilityMissing {
			return nil, nil, "test reports unavailable: capability_missing (TEST-001 residual)", ""
		}
		return nil, nil, "test reports unavailable: " + safeErrNote(errA), ""
	}
	var note string
	if errA != nil {
		if isDiagBudgetErr(errA) {
			note = "test report for build_a skipped: remote budget exhausted"
		} else {
			note = "test report for build_a unavailable: " + safeErrNote(errA)
		}
	}
	if errB != nil {
		if note != "" {
			note += "; "
		}
		if isDiagBudgetErr(errB) {
			note += "test report for build_b skipped: remote budget exhausted"
		} else {
			note += "test report for build_b unavailable: " + safeErrNote(errB)
		}
	}
	// Normalize nil reports.
	if ra == nil {
		ra = &jenkins.TestReport{}
	}
	if rb == nil {
		rb = &jenkins.TestReport{}
	}
	ts := &CompareTestSummaryDiff{
		BuildAPass:  ra.PassCount,
		BuildBPass:  rb.PassCount,
		BuildAFail:  ra.FailCount,
		BuildBFail:  rb.FailCount,
		BuildASkip:  ra.SkipCount,
		BuildBSkip:  rb.SkipCount,
		BuildATotal: ra.TotalCount,
		BuildBTotal: rb.TotalCount,
		AvailableA:  ra.Available,
		AvailableB:  rb.Available,
	}
	setA := failedTestKeys(ra.FailedTests)
	setB := failedTestKeys(rb.FailedTests)
	var diffs []CompareTestCaseDiff
	// only_a
	for k, st := range setA {
		if _, ok := setB[k]; !ok {
			diffs = append(diffs, CompareTestCaseDiff{
				Key:    redact.SanitizeForModel(truncateDiagnoseText(k, 256)),
				Side:   "only_a",
				Status: redact.SanitizeForModel(truncateDiagnoseText(st, 64)),
			})
		}
	}
	// only_b
	for k, st := range setB {
		if _, ok := setA[k]; !ok {
			diffs = append(diffs, CompareTestCaseDiff{
				Key:    redact.SanitizeForModel(truncateDiagnoseText(k, 256)),
				Side:   "only_b",
				Status: redact.SanitizeForModel(truncateDiagnoseText(st, 64)),
			})
		}
	}
	sort.Slice(diffs, func(i, j int) bool {
		if diffs[i].Side != diffs[j].Side {
			return diffs[i].Side < diffs[j].Side
		}
		return diffs[i].Key < diffs[j].Key
	})
	if len(diffs) > maxDiffs {
		diffs = diffs[:maxDiffs]
	}
	return ts, diffs, note, "tests"
}

func failedTestKeys(tests []jenkins.FailedTest) map[string]string {
	out := make(map[string]string, len(tests))
	for _, t := range tests {
		key := t.ClassName
		if key != "" && t.Name != "" {
			key = key + "#" + t.Name
		} else if t.Name != "" {
			key = t.Name
		} else {
			continue
		}
		out[key] = t.Status
	}
	return out
}

func compareSignatures(
	ctx context.Context,
	client *jenkins.Client,
	st regState,
	job string,
	a, b, maxLog, maxFindings int,
) (diffs []CompareSignatureDiff, logBytes int, notes []string, srcs []string, incomplete bool) {
	findA, bytesA, srcA, incA, notesA := extractBuildSignatures(ctx, client, st, job, a, maxLog, maxFindings)
	findB, bytesB, srcB, incB, notesB := extractBuildSignatures(ctx, client, st, job, b, maxLog, maxFindings)
	logBytes = bytesA + bytesB
	incomplete = incA || incB
	notes = append(notes, notesA...)
	notes = append(notes, notesB...)
	if srcA != "" {
		srcs = append(srcs, srcA)
	}
	if srcB != "" {
		srcs = append(srcs, srcB)
	}

	type sigInfo struct {
		pattern    string
		message    string
		confidence float64
		countA     int
		countB     int
	}
	merged := make(map[string]*sigInfo)
	for _, f := range findA {
		si := merged[f.Signature]
		if si == nil {
			si = &sigInfo{pattern: f.Pattern, message: f.Message, confidence: f.Confidence}
			merged[f.Signature] = si
		}
		si.countA += f.Count
		if f.Count == 0 {
			si.countA++
		}
	}
	for _, f := range findB {
		si := merged[f.Signature]
		if si == nil {
			si = &sigInfo{pattern: f.Pattern, message: f.Message, confidence: f.Confidence}
			merged[f.Signature] = si
		}
		si.countB += f.Count
		if f.Count == 0 {
			si.countB++
		}
	}
	sigs := make([]string, 0, len(merged))
	for s := range merged {
		sigs = append(sigs, s)
	}
	sort.Strings(sigs)
	for _, s := range sigs {
		si := merged[s]
		if si.countA == si.countB && si.countA > 0 {
			continue // identical presence/count — not a difference
		}
		d := CompareSignatureDiff{
			Signature:  s,
			Pattern:    si.pattern,
			Message:    redact.SanitizeForModel(truncateDiagnoseText(si.message, MaxEvidenceExcerptBytes)),
			Confidence: si.confidence,
			CountA:     si.countA,
			CountB:     si.countB,
		}
		switch {
		case si.countA > 0 && si.countB == 0:
			d.Side = "only_a"
		case si.countA == 0 && si.countB > 0:
			d.Side = "only_b"
		default:
			d.Side = "both_count_diff"
		}
		diffs = append(diffs, d)
		if len(diffs) >= maxFindings {
			break
		}
	}
	return diffs, logBytes, notes, uniqueStrings(srcs), incomplete
}

// extractBuildSignatures returns sanitized findings for one build under log budget.
func extractBuildSignatures(
	ctx context.Context,
	client *jenkins.Client,
	st regState,
	job string,
	build, maxLog, maxFindings int,
) (findings []DiagnoseFinding, logBytes int, source string, incomplete bool, notes []string) {
	select {
	case <-ctx.Done():
		return nil, 0, "", true, []string{"log extraction cancelled: " + safeErrNote(ctx.Err())}
	default:
	}
	text, meta, src, inc, err := acquireDiagnoseLog(ctx, st, client, job, build, maxLog)
	if err != nil {
		return nil, 0, "", true, []string{fmt.Sprintf("log for #%d unavailable: %s", build, safeErrNote(err))}
	}
	logBytes = meta.Length
	if logBytes == 0 && text != "" {
		logBytes = len(text)
	}
	source = src
	incomplete = inc
	if text == "" {
		notes = append(notes, fmt.Sprintf("no log text for build #%d", build))
		return nil, logBytes, source, incomplete, notes
	}
	if meta.TotalSize > 0 && meta.Length < meta.TotalSize {
		incomplete = true
		notes = append(notes, fmt.Sprintf("build #%d scanned log tail only (%d of %d bytes)", build, meta.Length, meta.TotalSize))
	}
	ext := diagnostics.ExtractCandidates(text, diagnostics.Options{
		MaxFindings:      maxFindings,
		MaxEvidenceLines: diagnostics.DefaultMaxEvidenceLines,
	})
	return sanitizeFindings(ext.Findings), logBytes, source, incomplete, notes
}

// compareArtifactPaths returns path-only diffs between two builds' artifact lists.
// Wave 41: getCachedArtifactList already applies deny_artifact_paths (fingerprint
// key + post-filter), so denied paths never enter path sets. Wave 39 residual:
// re-filter diffs with live patterns (defense in depth) and surface integer-only
// omit metadata from list-level PolicyOmittedCount plus any residual diff drops.
// Does not mutate cached artifact lists.
func compareArtifactPaths(ctx context.Context, st regState, client *jenkins.Client, job string, a, b int) (diffs []CompareArtifactDiff, note, source string, omitted int) {
	la, errA := getCachedArtifactList(ctx, st, client, job, a, DefaultCompareMaxArtifactDiffs)
	lb, errB := getCachedArtifactList(ctx, st, client, job, b, DefaultCompareMaxArtifactDiffs)
	if errA != nil && errB != nil {
		if isDiagBudgetErr(errA) || isDiagBudgetErr(errB) {
			return nil, "artifact lists skipped: remote budget exhausted", "", 0
		}
		return nil, "artifact lists unavailable: " + safeErrNote(errA), "", 0
	}
	if errA != nil {
		if isDiagBudgetErr(errA) {
			note = "artifact list for build_a skipped: remote budget exhausted"
		} else {
			note = "artifact list for build_a unavailable: " + safeErrNote(errA)
		}
	}
	if errB != nil {
		if note != "" {
			note += "; "
		}
		if isDiagBudgetErr(errB) {
			note += "artifact list for build_b skipped: remote budget exhausted"
		} else {
			note += "artifact list for build_b unavailable: " + safeErrNote(errB)
		}
	}
	// Wave 41: list-level omit counts (paths never enter diffs when cache filter ran).
	listOmitted := 0
	if la != nil && la.PolicyOmittedCount > 0 {
		listOmitted += la.PolicyOmittedCount
	}
	if lb != nil && lb.PolicyOmittedCount > 0 {
		listOmitted += lb.PolicyOmittedCount
	}
	setA := artifactPathSet(la)
	setB := artifactPathSet(lb)
	for p := range setA {
		if !setB[p] {
			diffs = append(diffs, CompareArtifactDiff{Path: p, Side: "only_a"})
		}
	}
	for p := range setB {
		if !setA[p] {
			diffs = append(diffs, CompareArtifactDiff{Path: p, Side: "only_b"})
		}
	}
	sort.Slice(diffs, func(i, j int) bool {
		if diffs[i].Side != diffs[j].Side {
			return diffs[i].Side < diffs[j].Side
		}
		return diffs[i].Path < diffs[j].Path
	})

	// Wave 39 + Wave 41: drop any residual diffs matching live deny_artifact_paths
	// (defense if a cache entry predated filter). Empty patterns → unchanged.
	// Job deny remains call-time separate.
	// Process-bound subject (compare path); multi-user uses st.subject from bind.
	patterns := policy.DenyArtifactPathsForSubject(st.policy, st.subject)
	diffOmitted := 0
	if len(patterns) > 0 {
		var kept []CompareArtifactDiff
		kept, diffOmitted = FilterDeniedArtifactDiffs(patterns, diffs)
		diffs = kept
	}
	omitted = listOmitted + diffOmitted
	if omitted > 0 {
		// Integer-only note — never echo denied path strings (canary).
		omitNote := fmt.Sprintf("artifact path diffs omit %d path(s) matching deny_artifact_paths", omitted)
		if note != "" {
			note += "; "
		}
		note += omitNote
	}

	if len(diffs) > HardCompareMaxArtifactDiffs {
		diffs = diffs[:HardCompareMaxArtifactDiffs]
	}

	if len(diffs) == 0 && note == "" {
		return nil, "", "artifacts", 0
	}
	return diffs, note, "artifacts", omitted
}

func artifactPathSet(list *jenkins.ArtifactList) map[string]bool {
	out := make(map[string]bool)
	if list == nil {
		return out
	}
	for _, a := range list.Artifacts {
		p := strings.TrimSpace(a.Path)
		if p != "" {
			out[p] = true
		}
	}
	return out
}

func hasMaterialDiff(out CompareBuildsToolResponse) bool {
	if out.ResultDiff != nil || out.DurationDiff != nil {
		return true
	}
	if len(out.ParameterDiffs) > 0 || len(out.StageDiffs) > 0 {
		return true
	}
	if out.TestSummaryDiff != nil || len(out.TestCaseDiffs) > 0 {
		return true
	}
	if len(out.SignatureDiffs) > 0 || len(out.ArtifactPathDiffs) > 0 {
		return true
	}
	if scmHasMaterialDiff(out.SCMDiff) {
		return true
	}
	return false
}

// scmHasMaterialDiff reports whether SCM data indicates a meaningful difference.
func scmHasMaterialDiff(d *CompareSCMDiff) bool {
	if d == nil {
		return false
	}
	if d.CommitsTotal > 0 || len(d.Commits) > 0 {
		return true
	}
	if len(d.RevisionDiffs) > 0 {
		return true
	}
	// Per-build commit counts differing is material even when both are empty of messages.
	if d.CommitCountA != d.CommitCountB {
		return true
	}
	return false
}

func buildCompareSummary(out CompareBuildsToolResponse) string {
	if !out.MaterialDifference {
		return fmt.Sprintf("%s #%d vs #%d: no material difference under compare budgets",
			out.Job, out.BuildA, out.BuildB)
	}
	var parts []string
	parts = append(parts, fmt.Sprintf("%s #%d vs #%d material differences", out.Job, out.BuildA, out.BuildB))
	if out.ResultDiff != nil {
		parts = append(parts, fmt.Sprintf("result %q→%q", out.ResultDiff.BuildAResult, out.ResultDiff.BuildBResult))
	}
	if out.DurationDiff != nil {
		parts = append(parts, fmt.Sprintf("duration %s vs %s", out.DurationDiff.BuildADuration, out.DurationDiff.BuildBDuration))
	}
	if n := len(out.SignatureDiffs); n > 0 {
		parts = append(parts, fmt.Sprintf("%d signature diff(s)", n))
	}
	if n := len(out.TestCaseDiffs); n > 0 {
		parts = append(parts, fmt.Sprintf("%d test case diff(s)", n))
	}
	if n := len(out.ParameterDiffs); n > 0 {
		parts = append(parts, fmt.Sprintf("%d parameter diff(s)", n))
	}
	if n := len(out.StageDiffs); n > 0 {
		parts = append(parts, fmt.Sprintf("%d stage diff(s)", n))
	}
	if n := len(out.ArtifactPathDiffs); n > 0 {
		parts = append(parts, fmt.Sprintf("%d artifact path diff(s)", n))
	}
	if out.SCMDiff != nil {
		if n := out.SCMDiff.CommitsTotal; n > 0 {
			parts = append(parts, fmt.Sprintf("%d SCM commit(s) in window", n))
		} else if n := len(out.SCMDiff.RevisionDiffs); n > 0 {
			parts = append(parts, fmt.Sprintf("%d SCM revision diff(s)", n))
		}
	}
	return strings.Join(parts, "; ")
}

// compareSCM wires bounded SCM comparison via GetBuildChanges (SCM-001 residual removal).
// On capability/budget/missing data: residual note only — never fails the whole compare.
// Prefers baseline-range aggregation when |a−b| ≤ MaxCompareSCMScanBuilds.
func compareSCM(
	ctx context.Context,
	st regState,
	client *jenkins.Client,
	job string,
	a, b int,
) (diff *CompareSCMDiff, residual, note, src string) {
	if client == nil {
		return nil, "SCM changes: use jenkins_get_build_changes (no client)", "", ""
	}
	if a == b {
		// Same build number: nothing to compare.
		return &CompareSCMDiff{
			Mode:    "range",
			Message: "build_a and build_b are the same number; no SCM window",
		}, "", "", ""
	}
	if err := ctx.Err(); err != nil {
		return nil, "SCM compare skipped (cancelled)", "SCM: " + safeErrNote(err), ""
	}

	older, newer := a, b
	if b < a {
		older, newer = b, a
	}
	span := newer - older

	// Prefer range mode when the span is cheap (changes after older through newer).
	// Single GetBuildChanges with baseline — no extra tip fetches (PERF: ≤ MaxCompareSCMScanBuilds).
	if span <= MaxCompareSCMScanBuilds {
		ch, err := getCachedBuildChanges(ctx, st, client, job, newer, older, DefaultCompareMaxSCMCommits, MaxCompareSCMScanBuilds)
		if err != nil {
			if isDiagBudgetErr(err) {
				return nil, "SCM compare skipped (remote budget; use jenkins_get_build_changes)",
					"SCM changes skipped: remote budget exhausted", ""
			}
			// Soft-fail: residual, do not fail compare.
			return nil, "SCM changes: use jenkins_get_build_changes",
				"SCM changes unavailable: " + safeErrNote(err), ""
		}
		diff = buildSCMDiffFromRange(ch, a, b, older, newer)
		if ch != nil && (len(ch.ChangeSets) > 0 || ch.CommitsTotal > 0) {
			src = "scm"
		}
		// Missing change data residual (nothing invented) — same spirit as diagnose.
		// Only when Jenkins reported neither change sets nor commits in the window.
		if ch == nil || (ch.CommitsTotal == 0 && len(ch.ChangeSets) == 0) {
			residual = "SCM: no changeSet/changeSets/BuildData between builds (nothing invented); use jenkins_get_build_changes for details"
		}
		if ch != nil {
			for i, r := range ch.Residuals {
				if i >= 2 {
					break
				}
				note = appendSCMNote(note, r)
			}
		}
		return diff, residual, note, src
	}

	// Span too large for range scan: per-build summaries only.
	note = fmt.Sprintf("SCM range span %d exceeds max_scan_builds=%d; per-build summaries only",
		span, MaxCompareSCMScanBuilds)
	chA, errA := getCachedBuildChanges(ctx, st, client, job, a, 0, DefaultCompareMaxSCMCommits, MaxCompareSCMScanBuilds)
	chB, errB := getCachedBuildChanges(ctx, st, client, job, b, 0, DefaultCompareMaxSCMCommits, MaxCompareSCMScanBuilds)
	if errA != nil && errB != nil {
		if isDiagBudgetErr(errA) || isDiagBudgetErr(errB) {
			return nil, "SCM compare skipped (remote budget; use jenkins_get_build_changes)",
				"SCM changes skipped: remote budget exhausted", ""
		}
		return nil, "SCM changes: use jenkins_get_build_changes",
			"SCM changes unavailable: " + safeErrNote(errA), ""
	}
	if errA != nil {
		if isDiagBudgetErr(errA) {
			note = appendSCMNote(note, "build_a SCM skipped: remote budget exhausted")
		} else {
			note = appendSCMNote(note, "build_a SCM unavailable: "+safeErrNote(errA))
		}
	}
	if errB != nil {
		if isDiagBudgetErr(errB) {
			note = appendSCMNote(note, "build_b SCM skipped: remote budget exhausted")
		} else {
			note = appendSCMNote(note, "build_b SCM unavailable: "+safeErrNote(errB))
		}
	}
	diff = buildSCMDiffPerBuild(chA, chB, a, b)
	if (chA != nil && (len(chA.ChangeSets) > 0 || chA.CommitsTotal > 0)) ||
		(chB != nil && (len(chB.ChangeSets) > 0 || chB.CommitsTotal > 0)) ||
		(diff != nil && len(diff.RevisionDiffs) > 0) {
		src = "scm"
	}
	if diff != nil && diff.CommitsTotal == 0 && len(diff.RevisionDiffs) == 0 &&
		diff.CommitCountA == 0 && diff.CommitCountB == 0 {
		residual = "SCM: no changeSet/changeSets/BuildData for either build (nothing invented); use jenkins_get_build_changes for details"
	}
	return diff, residual, note, src
}

func appendSCMNote(existing, add string) string {
	add = strings.TrimSpace(add)
	if add == "" {
		return existing
	}
	add = "SCM: " + redact.SanitizeForModel(truncateDiagnoseText(add, 160))
	if existing == "" {
		return add
	}
	return existing + "; " + add
}

func flattenRevisions(ch *jenkins.BuildChanges) []jenkins.SCMRevision {
	if ch == nil {
		return nil
	}
	var out []jenkins.SCMRevision
	seen := make(map[string]struct{})
	for _, cs := range ch.ChangeSets {
		for _, r := range cs.Revisions {
			key := r.Branch + "|" + r.SHA
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, r)
		}
	}
	return out
}

func buildSCMDiffFromRange(
	ch *jenkins.BuildChanges,
	buildA, buildB, older, newer int,
) *CompareSCMDiff {
	diff := &CompareSCMDiff{
		Mode:          "range",
		BaselineBuild: older,
		TargetBuild:   newer,
	}
	if ch == nil {
		diff.Message = "no SCM change data"
		return diff
	}
	diff.CommitsTotal = ch.CommitsTotal
	diff.MultiSCM = len(ch.ChangeSets) > 1
	diff.Truncated = ch.Truncated || ch.CommitsReturned < ch.CommitsTotal
	if ch.Message != "" {
		diff.Message = redact.SanitizeForModel(truncateDiagnoseText(ch.Message, 200))
	}
	diff.Commits = flattenCompareCommits(ch, DefaultCompareMaxSCMCommits, "")
	if len(diff.Commits) >= DefaultCompareMaxSCMCommits && ch.CommitsTotal > len(diff.Commits) {
		diff.Truncated = true
	}
	// Side stats: commits reported on each build number when available.
	for _, c := range flattenAllCommits(ch) {
		if c.BuildNumber == buildA {
			diff.CommitCountA++
		}
		if c.BuildNumber == buildB {
			diff.CommitCountB++
		}
	}
	// If BuildNumber is unset on commits, attribute whole page to target (range only scans after baseline).
	if diff.CommitCountA == 0 && diff.CommitCountB == 0 && ch.CommitsTotal > 0 {
		if newer == buildA {
			diff.CommitCountA = ch.CommitsTotal
		} else {
			diff.CommitCountB = ch.CommitsTotal
		}
	}
	// Range responses merge BuildData tips across scanned builds; surface identity-only
	// tips as confidence when present, but skip synthetic A/B revision diffs (no clean split).
	// Per-build mode fills RevisionDiffs via two single-build fetches.
	if tips := flattenRevisions(ch); len(tips) > 0 && ch.CommitsTotal == 0 {
		// Identity-only: still mark source-worthy via MultiSCM / message, no invent.
		if diff.Message == "" {
			diff.Message = "SCM identity present but no commits in range"
		}
	}
	return diff
}

func buildSCMDiffPerBuild(chA, chB *jenkins.BuildChanges, buildA, buildB int) *CompareSCMDiff {
	_ = buildA
	_ = buildB
	diff := &CompareSCMDiff{Mode: "per_build"}
	var commits []CompareSCMCommit
	if chA != nil {
		diff.CommitCountA = chA.CommitsTotal
		diff.MultiSCM = diff.MultiSCM || len(chA.ChangeSets) > 1
		diff.Truncated = diff.Truncated || chA.Truncated || chA.CommitsReturned < chA.CommitsTotal
		for _, c := range flattenCompareCommits(chA, DefaultCompareMaxSCMCommits/2+1, "only_a") {
			commits = append(commits, c)
		}
	}
	if chB != nil {
		diff.CommitCountB = chB.CommitsTotal
		diff.MultiSCM = diff.MultiSCM || len(chB.ChangeSets) > 1
		diff.Truncated = diff.Truncated || chB.Truncated || chB.CommitsReturned < chB.CommitsTotal
		for _, c := range flattenCompareCommits(chB, DefaultCompareMaxSCMCommits/2+1, "only_b") {
			commits = append(commits, c)
		}
	}
	if len(commits) > DefaultCompareMaxSCMCommits {
		commits = commits[:DefaultCompareMaxSCMCommits]
		diff.Truncated = true
	}
	diff.Commits = commits
	diff.CommitsTotal = diff.CommitCountA + diff.CommitCountB
	diff.RevisionDiffs = diffRevisions(flattenRevisions(chA), flattenRevisions(chB))
	if diff.CommitsTotal == 0 && len(diff.RevisionDiffs) == 0 {
		diff.Message = "no SCM change data reported by Jenkins for either build"
	}
	return diff
}

func flattenAllCommits(ch *jenkins.BuildChanges) []jenkins.SCMCommit {
	if ch == nil {
		return nil
	}
	var out []jenkins.SCMCommit
	for _, cs := range ch.ChangeSets {
		out = append(out, cs.Commits...)
	}
	return out
}

func flattenCompareCommits(ch *jenkins.BuildChanges, max int, side string) []CompareSCMCommit {
	if ch == nil || max <= 0 {
		return nil
	}
	if max > HardCompareMaxSCMCommits {
		max = HardCompareMaxSCMCommits
	}
	var out []CompareSCMCommit
	for _, cs := range ch.ChangeSets {
		for _, c := range cs.Commits {
			if len(out) >= max {
				return out
			}
			// Redact commit messages (canaries / secrets); same path spirit as PrepareBuildChangesForModel.
			msg := redact.SanitizeForModel(truncateDiagnoseText(c.Message, 256))
			out = append(out, CompareSCMCommit{
				ID:          redact.SanitizeForModel(truncateDiagnoseText(c.ID, 64)),
				Message:     msg,
				Author:      redact.SanitizeForModel(truncateDiagnoseText(c.Author, 128)),
				BuildNumber: c.BuildNumber,
				Side:        side,
			})
		}
	}
	return out
}

func diffRevisions(a, b []jenkins.SCMRevision) []CompareRevisionDiff {
	// Index by branch (empty branch → sha-only key).
	type tip struct {
		branch string
		sha    string
	}
	mapA := make(map[string]tip)
	mapB := make(map[string]tip)
	for _, r := range a {
		key := strings.TrimSpace(r.Branch)
		if key == "" {
			key = "sha:" + r.SHA
		}
		mapA[key] = tip{branch: r.Branch, sha: r.SHA}
	}
	for _, r := range b {
		key := strings.TrimSpace(r.Branch)
		if key == "" {
			key = "sha:" + r.SHA
		}
		mapB[key] = tip{branch: r.Branch, sha: r.SHA}
	}
	keys := make(map[string]struct{})
	for k := range mapA {
		keys[k] = struct{}{}
	}
	for k := range mapB {
		keys[k] = struct{}{}
	}
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)
	var diffs []CompareRevisionDiff
	for _, k := range names {
		ta, oka := mapA[k]
		tb, okb := mapB[k]
		if oka && okb && ta.sha == tb.sha {
			continue
		}
		d := CompareRevisionDiff{}
		if oka {
			d.Branch = ta.branch
			d.SHAA = ta.sha
		}
		if okb {
			if d.Branch == "" {
				d.Branch = tb.branch
			}
			d.SHAB = tb.sha
		}
		switch {
		case oka && !okb:
			d.Change = "only_a"
		case !oka && okb:
			d.Change = "only_b"
		default:
			d.Change = "changed"
		}
		diffs = append(diffs, d)
		if len(diffs) >= 10 {
			break
		}
	}
	return diffs
}

func uniqueStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
