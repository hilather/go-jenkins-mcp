package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/diagnostics"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/otelx"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
	"github.com/hilather/go-jenkins-mcp/internal/redact"
	"github.com/hilather/go-jenkins-mcp/internal/search"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ToolDiagnoseBuild is the minimal DIAG-002 triage tool name.
const ToolDiagnoseBuild = "jenkins_diagnose_build"

// Diagnose log/read budgets (server-enforced; callers may only lower).
const (
	// DefaultDiagnoseLogBytes is the max log tail scanned for extraction.
	DefaultDiagnoseLogBytes = 128 << 10 // 128 KiB
	// HardDiagnoseLogBytes is the absolute scan ceiling for diagnose.
	HardDiagnoseLogBytes = 512 << 10 // 512 KiB
	// DefaultDiagnoseMaxFindings caps returned findings (0 ⇒ this).
	DefaultDiagnoseMaxFindings = 10
	// HardDiagnoseMaxFindings is the absolute findings ceiling for the tool.
	HardDiagnoseMaxFindings = 25
	// MaxEvidenceExcerptBytes truncates each evidence line in the MCP response.
	MaxEvidenceExcerptBytes = 512

	// Enrichment budgets (DIAG-002 auto-wire of SCM/TEST/PIPE/GRAPH residuals).
	// MaxDiagnoseExtraRemoteCalls caps additional Jenkins API work beyond build
	// metadata + one log tail (already acquired). Soft budget; remaining surfaces
	// become residuals when exhausted.
	// Sized for: tests(1) + scm(1) + baseline resolve(1) + scm scan extras(≤2) + pipe(1) + graph(1).
	MaxDiagnoseExtraRemoteCalls = 8
	// DefaultDiagnoseMaxSCMCommits caps commit messages in the diagnose SCM summary.
	DefaultDiagnoseMaxSCMCommits = 5
	// HardDiagnoseMaxSCMCommits is the absolute commit list ceiling for diagnose.
	HardDiagnoseMaxSCMCommits = 10
	// DefaultDiagnoseMaxTests caps auto-wired failed tests (when no Tests helper).
	DefaultDiagnoseMaxTests = 10
	// HardDiagnoseMaxTests is the absolute auto-wire test list ceiling.
	HardDiagnoseMaxTests = 20
	// MaxDiagnoseSCMScanBuilds caps baseline-range scan when last_successful is cheap.
	MaxDiagnoseSCMScanBuilds = 3
	// MaxDiagnoseUpstreamHints caps one-hop upstream cause entries.
	MaxDiagnoseUpstreamHints = 5
)

// TestFailure is a minimal failed-test summary (TEST-002 residual surface).
type TestFailure struct {
	Name    string `json:"name"`
	Class   string `json:"class,omitempty"`
	Message string `json:"message,omitempty"`
	// Status is typically "FAILED" / "REGRESSION" / "SKIPPED" when known.
	Status string `json:"status,omitempty"`
}

// TestFailureSource is an optional TEST-002 adapter. When non-nil, diagnose uses
// it instead of auto-wiring client.GetTestReport. Nil ⇒ auto-wire from client
// when JUnit capability is present; otherwise a residual note (never fabricates).
type TestFailureSource interface {
	ListFailedTests(ctx context.Context, job string, build int64) ([]TestFailure, error)
}

// DiagnoseHelpers groups optional diagnose-time adapters (DIAG-002).
// Zero value is valid: built-in extraction + client auto-wire for SCM/TEST/PIPE/GRAPH.
type DiagnoseHelpers struct {
	// Tests overrides client.GetTestReport auto-wire when non-nil.
	Tests TestFailureSource
}

// DiagnoseBuildToolArgs is the MCP input for jenkins_diagnose_build.
type DiagnoseBuildToolArgs struct {
	JobName     string `json:"job_name" mcp:"Jenkins job full name (folder/job path; not a URL)"`
	BuildNumber int    `json:"build_number" mcp:"build number"`
	// MaxFindings caps top findings (0 ⇒ DefaultDiagnoseMaxFindings; hard-capped).
	MaxFindings int `json:"max_findings,omitempty" mcp:"maximum findings to return"`
	// MaxLogBytes caps the log tail scanned for extraction (0 ⇒ default; hard-capped).
	MaxLogBytes int `json:"max_log_bytes,omitempty" mcp:"max log tail bytes to scan"`
}

// DiagnoseFinding is a model-facing finding (sanitized evidence).
type DiagnoseFinding struct {
	Signature  string                     `json:"signature"`
	Pattern    string                     `json:"pattern"`
	Message    string                     `json:"message"`
	Confidence float64                    `json:"confidence"`
	LineStart  int64                      `json:"line_start"`
	LineEnd    int64                      `json:"line_end"`
	Count      int                        `json:"count"`
	Evidence   []diagnostics.EvidenceLine `json:"evidence,omitempty"`
}

// DiagnoseSCMCommit is a bounded, sanitized commit summary for diagnose.
type DiagnoseSCMCommit struct {
	ID      string `json:"id,omitempty"`
	Message string `json:"message,omitempty"`
	Author  string `json:"author,omitempty"`
}

// DiagnoseSCMCulprit is a Jenkins-reported culprit (correlation, not proof).
type DiagnoseSCMCulprit struct {
	FullName string `json:"full_name,omitempty"`
	// Note always labels culprits as correlation-only.
	Note string `json:"note,omitempty"`
}

// DiagnoseSCMSummary is a bounded change summary attached to diagnose (SCM-001 wire-up).
type DiagnoseSCMSummary struct {
	// CommitCount is commits seen for the diagnosed (optionally baseline-ranged) build.
	CommitCount int `json:"commit_count"`
	// MultiSCM is true when more than one change set/repo contributed.
	MultiSCM bool `json:"multi_scm,omitempty"`
	// BaselineBuild is last_successful (or other) when resolved cheaply; 0 if unused.
	BaselineBuild int `json:"baseline_build,omitempty"`
	// Commits are the first N commit messages (redacted/truncated).
	Commits []DiagnoseSCMCommit `json:"commits,omitempty"`
	// Culprits are Jenkins correlation labels only (not proof of cause).
	Culprits []DiagnoseSCMCulprit `json:"culprits,omitempty"`
	// Truncated when more commits exist than returned.
	Truncated bool `json:"truncated,omitempty"`
	// Message is a short status when no commits (never invents changes).
	Message string `json:"message,omitempty"`
}

// DiagnoseFailedStage is the top failed Pipeline stage hint (PIPE residual).
type DiagnoseFailedStage struct {
	ID     string `json:"id,omitempty"`
	Name   string `json:"name,omitempty"`
	Status string `json:"status,omitempty"`
	// Type is STAGE/PARALLEL/etc when known.
	Type string `json:"type,omitempty"`
}

// DiagnoseUpstreamHint is one one-hop upstream cause (GRAPH lightweight).
type DiagnoseUpstreamHint struct {
	JobName     string `json:"job_name"`
	BuildNumber int    `json:"build_number"`
	// Description is the short Jenkins cause description when present (sanitized).
	Description string `json:"description,omitempty"`
}

// DiagnoseRelatedBuilds is a lightweight related-build hint (not a full graph walk).
type DiagnoseRelatedBuilds struct {
	// Upstream are one-hop UpstreamCause entries from the diagnosed build's actions.
	Upstream []DiagnoseUpstreamHint `json:"upstream,omitempty"`
	// Note directs multi-hop work to dedicated graph tools.
	Note string `json:"note,omitempty"`
}

// DiagnoseBuildToolResponse is the bounded structured triage result.
// Never includes a full log dump.
type DiagnoseBuildToolResponse struct {
	Job         string `json:"job"`
	Build       int    `json:"build"`
	Result      string `json:"result,omitempty"`
	Building    bool   `json:"building,omitempty"`
	DisplayName string `json:"display_name,omitempty"`

	// Summary is a short heuristic triage blurb (not a fabricated root cause).
	Summary string `json:"summary"`
	// Findings are top deterministic error candidates (max N).
	Findings []DiagnoseFinding `json:"findings"`
	// TestFailures is present when Tests helper is wired or JUnit auto-wire succeeds.
	TestFailures []TestFailure `json:"test_failures,omitempty"`
	// SCM is a bounded change summary when SCM auto-wire succeeds (SCM-001).
	SCM *DiagnoseSCMSummary `json:"scm,omitempty"`
	// FailedStage is the top failed Pipeline stage when PIPE REST is available.
	FailedStage *DiagnoseFailedStage `json:"failed_stage,omitempty"`
	// RelatedBuilds holds one-hop upstream causes when present (GRAPH lightweight).
	RelatedBuilds *DiagnoseRelatedBuilds `json:"related_builds,omitempty"`
	// TraceRefs is present when EnableTraceRefs (INT-002) and build parameters
	// contain recognized correlation identifiers. Labeled build-metadata only.
	TraceRefs []otelx.TraceRef `json:"trace_refs,omitempty"`
	// ConfidenceNotes explain heuristic limits and missing evidence.
	ConfidenceNotes []string `json:"confidence_notes,omitempty"`
	// Sources lists data paths used (local_mirror, client_tail, search, build_api, tests, scm, pipeline, upstream_cause, trace_refs).
	Sources []string `json:"sources,omitempty"`
	// Residuals lists surfaces that could not be auto-wired (capability missing, budget, no data).
	Residuals []string `json:"residuals,omitempty"`

	LogOffset    int  `json:"log_offset,omitempty"`
	LogLength    int  `json:"log_length,omitempty"`
	LogTotalSize int  `json:"log_total_size,omitempty"`
	LogSealed    bool `json:"log_sealed,omitempty"`
	Incomplete   bool `json:"incomplete,omitempty"`
	FindingsCap  int  `json:"findings_cap"`
	// Untrusted marks log-derived text as untrusted build output.
	Untrusted bool `json:"untrusted"`
	// EnrichmentCalls is how many extra remote API units were spent (budget accounting).
	EnrichmentCalls int `json:"enrichment_calls,omitempty"`
	// Budgets records result + remote ceilings (PERF-003).
	Budgets DiagnoseBudgets `json:"budgets"`
	// Perf is optional request-local cache/remote counters (PERF-003).
	Perf *DiagPerf `json:"perf,omitempty"`
}

type DiagnoseBudgets struct {
	MaxFindings    int   `json:"max_findings"`
	MaxLogBytes    int   `json:"max_log_bytes"`
	MaxRemoteCalls int   `json:"max_remote_calls"`
	MaxRemoteBytes int64 `json:"max_remote_bytes"`
	// MaxWallMS is the wall-clock ceiling in milliseconds (0 = none).
	MaxWallMS int64 `json:"max_wall_ms,omitempty"`
}

// registerDiagnoseBuildTool registers jenkins_diagnose_build (always; client fallback).
func registerDiagnoseBuildTool(s *mcp.Server, client *jenkins.Client, st regState) {
	addReadTool(s, st, &mcp.Tool{
		Name: ToolDiagnoseBuild,
		Description: "Diagnose a Jenkins build with bounded deterministic error extraction " +
			"(summary + top findings + sanitized evidence; never dumps the full log)",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args DiagnoseBuildToolArgs) (*mcp.CallToolResult, DiagnoseBuildToolResponse, error) {
		out, err := runDiagnoseBuild(ctx, client, st, args)
		if err != nil {
			return nil, DiagnoseBuildToolResponse{}, err
		}
		return structuredResult(out)
	})
}

func runDiagnoseBuild(ctx context.Context, client *jenkins.Client, st regState, args DiagnoseBuildToolArgs) (DiagnoseBuildToolResponse, error) {
	bref, err := buildRef("job_name", args.JobName, "build_number", args.BuildNumber)
	if err != nil {
		return DiagnoseBuildToolResponse{}, err
	}
	job := bref.Job.FullName
	build := int(bref.Number)

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

	sess := newDiagSession(st, diagnoseBudgetDefault())
	ctx, cancel := sess.BoundContext(ctx)
	defer cancel()
	ctx = withDiagSession(ctx, sess)

	budgetCfg := mergeDiagBudget(diagnoseBudgetDefault(), st.diagBudget)
	out := DiagnoseBuildToolResponse{
		Job:         job,
		Build:       build,
		FindingsCap: maxFindings,
		Untrusted:   true,
		Budgets: DiagnoseBudgets{
			MaxFindings:    maxFindings,
			MaxLogBytes:    maxLog,
			MaxRemoteCalls: budgetCfg.MaxRemoteCalls,
			MaxRemoteBytes: budgetCfg.MaxRemoteBytes,
		},
	}
	if budgetCfg.MaxWall > 0 {
		out.Budgets.MaxWallMS = budgetCfg.MaxWall.Milliseconds()
	}

	// Build API metadata (result / building) — degrade if unavailable.
	// PERF-003: getCachedBuildDetails is the single GetBuildDetailsByJob path for
	// this invocation (process cache + single-flight); enrichment must not re-fetch.
	if client != nil {
		if b, berr := getCachedBuildDetails(ctx, st, client, job, build); berr == nil && b != nil {
			out.Result = b.Result
			out.Building = b.Building
			out.DisplayName = b.DisplayName
			out.Sources = append(out.Sources, "build_api")
			// INT-002: optional correlation from parameters already on the build
			// (no extra remote call; no log text; no OTLP).
			if st.enableTraceRefs {
				ext := extractTraceRefsFromBuildParams(b.Parameters, 0)
				if len(ext.Refs) > 0 {
					out.TraceRefs = ext.Refs
					out.Sources = append(out.Sources, "trace_refs")
					if ext.Truncated {
						out.ConfidenceNotes = append(out.ConfidenceNotes,
							fmt.Sprintf("trace_refs truncated to %d", ext.MaxRefs))
					}
				}
				out.Residuals = append(out.Residuals, residualOTLPBackend)
			}
		} else if berr != nil {
			if isDiagBudgetErr(berr) {
				out.Incomplete = true
				out.ConfidenceNotes = append(out.ConfidenceNotes, "build metadata skipped: "+sess.BudgetNote())
			} else if ctx.Err() != nil {
				out.Incomplete = true
				out.ConfidenceNotes = append(out.ConfidenceNotes, "build metadata cancelled: "+safeErrNote(ctx.Err()))
			} else {
				out.ConfidenceNotes = append(out.ConfidenceNotes,
					"build metadata unavailable: "+safeErrNote(berr))
			}
		}
	}

	// Acquire bounded log text (local mirror preferred; PERF-003 session cache).
	// Enrichment never re-downloads the log (SCM/TEST/PIPE/GRAPH use other APIs only).
	logText, logMeta, logSrc, logIncomplete, logErr := acquireDiagnoseLog(ctx, st, client, job, build, maxLog)
	if logErr != nil {
		return DiagnoseBuildToolResponse{}, logErr
	}
	if logSrc != "" {
		out.Sources = append(out.Sources, logSrc)
	}
	out.LogOffset = logMeta.Offset
	out.LogLength = logMeta.Length
	out.LogTotalSize = logMeta.TotalSize
	out.LogSealed = logMeta.Sealed
	if logIncomplete {
		out.Incomplete = true
	}

	// Deterministic extraction (DIAG-001).
	ext := diagnostics.ExtractCandidates(logText, diagnostics.Options{
		MaxFindings:      maxFindings,
		MaxEvidenceLines: diagnostics.DefaultMaxEvidenceLines,
	})

	// Optional SEARCH for ERROR/FAILED when mirror search is available and
	// extraction is thin (degrades silently if search fails).
	if st.logSearch != nil && len(ext.Findings) < maxFindings {
		merged := mergeSearchFindings(ctx, st, job, build, maxFindings, ext)
		if merged.used {
			out.Sources = append(out.Sources, "search")
			ext = merged.result
		}
	}

	out.Findings = sanitizeFindings(ext.Findings)
	if ext.Truncated {
		out.Incomplete = true
		out.ConfidenceNotes = append(out.ConfidenceNotes,
			fmt.Sprintf("findings truncated to %d signatures", maxFindings))
	}
	if logText == "" {
		out.ConfidenceNotes = append(out.ConfidenceNotes, "no log text available for extraction")
	} else if logMeta.TotalSize > 0 && logMeta.Length < logMeta.TotalSize {
		out.ConfidenceNotes = append(out.ConfidenceNotes,
			fmt.Sprintf("scanned log tail only (%d of %d bytes); earlier failures may be missed",
				logMeta.Length, logMeta.TotalSize))
		out.Incomplete = true
	}
	if logMeta.Offset > 0 {
		// ExtractCandidates numbers lines within the scanned window (1-based),
		// not absolute full-log line indices when only a tail was read.
		out.ConfidenceNotes = append(out.ConfidenceNotes,
			fmt.Sprintf("finding line_start/line_end are relative to scanned window (log_offset=%d), not absolute full-log lines",
				logMeta.Offset))
	}

	// Auto-wire SCM / TEST / PIPE / GRAPH under a shared remote budget.
	enrichDiagnose(ctx, client, st, &out, job, build)

	if note := sess.BudgetNote(); note != "" {
		out.Incomplete = true
		out.ConfidenceNotes = append(out.ConfidenceNotes, note)
		out.Residuals = append(out.Residuals, note)
	}
	if ctx.Err() != nil {
		out.Incomplete = true
		out.ConfidenceNotes = append(out.ConfidenceNotes, "operation cancelled: "+safeErrNote(ctx.Err()))
	}

	out.Summary = buildDiagnoseSummary(out)
	out.ConfidenceNotes = append(out.ConfidenceNotes,
		"conclusions are heuristic candidates with evidence; not a proven root cause")
	if len(out.Findings) > 1 {
		out.ConfidenceNotes = append(out.ConfidenceNotes,
			"multiple candidates returned; treat as ambiguous until verified")
	}
	if len(out.Findings) == 0 && !out.Building && strings.EqualFold(out.Result, "SUCCESS") {
		out.ConfidenceNotes = append(out.ConfidenceNotes, "build result is SUCCESS and no error markers found in scanned log")
	}
	if len(out.Findings) == 0 && (out.Result == "" || strings.EqualFold(out.Result, "FAILURE") || strings.EqualFold(out.Result, "UNSTABLE")) {
		out.ConfidenceNotes = append(out.ConfidenceNotes,
			"no deterministic error markers in scanned window; try jenkins_search_logs or a larger max_log_bytes")
	}

	perfSnap := sess.PerfSnapshot()
	out.Perf = &perfSnap
	return out, nil
}

// enrichDiagnose attaches SCM/TEST/PIPE/GRAPH surfaces under MaxDiagnoseExtraRemoteCalls.
// Never panics; missing capability or data becomes residuals/confidence notes.
// Log is never re-fetched here.
// Build metadata always comes from getCachedBuildDetails (PERF-003 single-flight);
// enrichment does not re-call GetBuildDetailsByJob for the same job+build.
func enrichDiagnose(ctx context.Context, client *jenkins.Client, st regState, out *DiagnoseBuildToolResponse, job string, build int) {
	if out == nil {
		return
	}
	// PERF-003: honor DiagSession remote budget in addition to enrichment soft cap.
	// When MaxRemoteCalls is exhausted (e.g. only log allowed), skip remaining surfaces.
	sess := diagSessionFrom(ctx)
	budget := MaxDiagnoseExtraRemoteCalls
	spent := 0
	// take charges enrichment soft cap and session remote units (paths that do not
	// go through getCached* themselves).
	take := func(n int) bool {
		if n <= 0 {
			return true
		}
		if spent+n > budget {
			return false
		}
		// PERF-003 session: all n units must fit before charging.
		if sess != nil {
			for i := 0; i < n; i++ {
				if !sess.AllowRemote(256) {
					return false
				}
			}
			for i := 0; i < n; i++ {
				sess.RecordRemote(256)
			}
		}
		spent += n
		return true
	}
	// takeSoft reserves enrichment soft-cap only; getCached* owns session accounting.
	takeSoft := func(n int) bool {
		if n <= 0 {
			return true
		}
		if spent+n > budget {
			return false
		}
		if sess != nil {
			for i := 0; i < n; i++ {
				if !sess.AllowRemote(256) {
					return false
				}
			}
		}
		spent += n
		return true
	}

	// --- TEST: helper override or client GetTestReport auto-wire (shared FetchCache) ---
	if st.diagnose.Tests != nil {
		// Helper does not consume Jenkins budget (may be local/fake).
		tests, terr := st.diagnose.Tests.ListFailedTests(ctx, job, int64(build))
		if terr != nil {
			out.ConfidenceNotes = append(out.ConfidenceNotes,
				"test failures unavailable: "+safeErrNote(terr))
			out.Residuals = append(out.Residuals, "TEST failures helper error (TEST-002 residual)")
		} else {
			out.TestFailures = sanitizeTestFailures(tests)
			out.Sources = append(out.Sources, "tests")
		}
	} else if client == nil {
		out.Residuals = append(out.Residuals, "TEST failures not wired (no client; TEST-002 residual)")
	} else if !takeSoft(1) {
		out.Residuals = append(out.Residuals, "TEST auto-wire skipped (enrichment budget; use jenkins_get_test_report)")
	} else {
		enrichDiagnoseTests(ctx, client, st, out, job, build)
	}

	// --- SCM: GetBuildChanges (+ optional cheap last_successful baseline) ---
	if client == nil {
		out.Residuals = append(out.Residuals, "SCM changes not wired (no client; use jenkins_get_build_changes)")
	} else if !take(1) {
		out.Residuals = append(out.Residuals, "SCM auto-wire skipped (enrichment budget; use jenkins_get_build_changes)")
	} else {
		// Optional baseline: one ResolveBaseline call when build looks failed and budget allows.
		baseline := 0
		if isDiagnoseFailureResult(out.Result) && take(1) {
			if br, berr := client.ResolveBaseline(ctx, job, jenkins.BaselineLastSuccessful); berr == nil && br != nil && br.Found && br.BuildNumber > 0 && br.BuildNumber < build {
				// Only use baseline when range is cheap (≤ MaxDiagnoseSCMScanBuilds).
				if build-br.BuildNumber <= MaxDiagnoseSCMScanBuilds {
					baseline = br.BuildNumber
				} else {
					// Record resolved green for correlation only; do not scan a large range.
					out.ConfidenceNotes = append(out.ConfidenceNotes,
						fmt.Sprintf("last_successful=#%d is more than %d builds before this failure; SCM summary is for this build only",
							br.BuildNumber, MaxDiagnoseSCMScanBuilds))
				}
			}
		}
		// GetBuildChanges may scan multiple builds; charge remaining scan units if baseline set.
		if baseline > 0 {
			scan := build - baseline // builds after baseline through target (inclusive of target already charged as 1)
			if scan > 1 {
				// We already charged 1 for the target; charge extras if budget allows, else drop baseline.
				extra := scan - 1
				if !take(extra) {
					baseline = 0
					out.ConfidenceNotes = append(out.ConfidenceNotes,
						"SCM baseline range skipped (enrichment budget); single-build changes only")
				}
			}
		}
		enrichDiagnoseSCM(ctx, client, out, job, build, baseline)
	}

	// --- PIPE: top failed stage (shared FetchCache + single-flight) ---
	if client == nil {
		out.Residuals = append(out.Residuals, "PIPE failed stage not wired (no client; use jenkins_get_pipeline_stages)")
	} else if !takeSoft(1) {
		out.Residuals = append(out.Residuals, "PIPE auto-wire skipped (enrichment budget; use jenkins_get_pipeline_stages)")
	} else {
		enrichDiagnosePipeline(ctx, client, st, out, job, build)
	}

	// --- GRAPH: one-hop upstream causes only ---
	if client == nil {
		out.Residuals = append(out.Residuals, "GRAPH related builds: use jenkins_get_build_graph / jenkins_trace_failure_graph")
	} else if !take(1) {
		out.Residuals = append(out.Residuals, "GRAPH auto-wire skipped (enrichment budget; use jenkins_get_build_graph / jenkins_trace_failure_graph)")
	} else {
		enrichDiagnoseUpstream(ctx, client, out, job, build)
	}

	out.EnrichmentCalls = spent
	out.Residuals = uniqueDiagnoseStrings(out.Residuals)
}

func enrichDiagnoseTests(ctx context.Context, client *jenkins.Client, st regState, out *DiagnoseBuildToolResponse, job string, build int) {
	// PERF-003: shared getCachedTestReport (TTL + single-flight). Does not re-fetch
	// GetBuildDetailsByJob for this job+build.
	rep, err := getCachedTestReport(ctx, st, client, job, build, DefaultDiagnoseMaxTests)
	if err != nil {
		if isDiagBudgetErr(err) {
			out.Residuals = append(out.Residuals, "TEST auto-wire skipped (remote budget; use jenkins_get_test_report)")
			return
		}
		if apperr.CodeOf(err) == apperr.CodeCapabilityMissing {
			out.Residuals = append(out.Residuals,
				"TEST failures unavailable: JUnit capability missing (use jenkins_get_test_report when plugin present)")
			return
		}
		out.ConfidenceNotes = append(out.ConfidenceNotes, "test report unavailable: "+safeErrNote(err))
		out.Residuals = append(out.Residuals, "TEST failures not attached (TEST-001 residual)")
		return
	}
	if rep == nil || !rep.Available {
		msg := "no test report for this build"
		if rep != nil && rep.Message != "" {
			msg = rep.Message
		}
		out.ConfidenceNotes = append(out.ConfidenceNotes, "tests: "+msg)
		// Not a residual capability gap — report simply absent; no invented failures.
		return
	}
	out.Sources = append(out.Sources, "tests")
	if len(rep.FailedTests) == 0 {
		if rep.FailCount > 0 {
			out.ConfidenceNotes = append(out.ConfidenceNotes,
				fmt.Sprintf("tests: failCount=%d but case details unavailable", rep.FailCount))
		}
		return
	}
	failures := make([]TestFailure, 0, len(rep.FailedTests))
	for _, ft := range rep.FailedTests {
		failures = append(failures, TestFailure{
			Name:    ft.Name,
			Class:   ft.ClassName,
			Message: ft.ErrorDetails,
			Status:  ft.Status,
		})
	}
	out.TestFailures = sanitizeTestFailures(failures)
	if rep.FailedTestsTruncated || rep.FailCount > len(rep.FailedTests) {
		out.ConfidenceNotes = append(out.ConfidenceNotes,
			fmt.Sprintf("test failures truncated (showing %d of failCount=%d); use jenkins_get_test_report / jenkins_analyze_tests",
				len(out.TestFailures), rep.FailCount))
		out.Incomplete = true
	}
}

func enrichDiagnoseSCM(ctx context.Context, client *jenkins.Client, out *DiagnoseBuildToolResponse, job string, build, baseline int) {
	args := jenkins.GetBuildChangesToolArgs{
		JobName:         job,
		BuildNumber:     build,
		BaselineBuild:   baseline,
		MaxCommits:      DefaultDiagnoseMaxSCMCommits,
		MaxFiles:        0, // default inside client
		MaxMessageBytes: 256,
		MaxScanBuilds:   MaxDiagnoseSCMScanBuilds,
	}
	ch, err := client.GetBuildChanges(ctx, args)
	if err != nil {
		out.ConfidenceNotes = append(out.ConfidenceNotes, "SCM changes unavailable: "+safeErrNote(err))
		out.Residuals = append(out.Residuals, "SCM changes: use jenkins_get_build_changes")
		return
	}
	if ch == nil {
		out.Residuals = append(out.Residuals, "SCM changes: empty response; use jenkins_get_build_changes")
		return
	}
	out.Sources = append(out.Sources, "scm")
	sum := &DiagnoseSCMSummary{
		CommitCount:   ch.CommitsTotal,
		BaselineBuild: ch.BaselineBuild,
		MultiSCM:      len(ch.ChangeSets) > 1,
		Truncated:     ch.Truncated || ch.CommitsReturned < ch.CommitsTotal,
	}
	if ch.Message != "" {
		sum.Message = redact.SanitizeForModel(truncateDiagnoseText(ch.Message, 200))
	}
	// Flatten first N commits across change sets (already page-limited by client).
	var commits []DiagnoseSCMCommit
	for _, cs := range ch.ChangeSets {
		for _, c := range cs.Commits {
			if len(commits) >= DefaultDiagnoseMaxSCMCommits {
				sum.Truncated = true
				break
			}
			commits = append(commits, DiagnoseSCMCommit{
				ID:      redact.SanitizeForModel(truncateDiagnoseText(c.ID, 64)),
				Message: redact.SanitizeForModel(truncateDiagnoseText(c.Message, 256)),
				Author:  redact.SanitizeForModel(truncateDiagnoseText(c.Author, 128)),
			})
		}
		if len(commits) >= DefaultDiagnoseMaxSCMCommits {
			sum.Truncated = true
			break
		}
	}
	sum.Commits = commits
	for _, c := range ch.Culprits {
		name := strings.TrimSpace(c.FullName)
		if name == "" {
			continue
		}
		note := c.Note
		if note == "" {
			note = "Jenkins-reported correlation, not proof of cause"
		}
		sum.Culprits = append(sum.Culprits, DiagnoseSCMCulprit{
			FullName: redact.SanitizeForModel(truncateDiagnoseText(name, 128)),
			Note:     note,
		})
	}
	// Missing change data: residual note, never invent commits.
	if sum.CommitCount == 0 && len(ch.ChangeSets) == 0 {
		out.Residuals = append(out.Residuals,
			"SCM: no changeSet/changeSets/BuildData for this build (nothing invented); use jenkins_get_build_changes for details")
		if sum.Message == "" {
			sum.Message = "no SCM change data reported by Jenkins for this build"
		}
	}
	// Propagate client residuals as confidence notes (bounded).
	for i, r := range ch.Residuals {
		if i >= 3 {
			break
		}
		out.ConfidenceNotes = append(out.ConfidenceNotes, "SCM: "+redact.SanitizeForModel(truncateDiagnoseText(r, 160)))
	}
	out.SCM = sum
}

func enrichDiagnosePipeline(ctx context.Context, client *jenkins.Client, st regState, out *DiagnoseBuildToolResponse, job string, build int) {
	// PERF-003: shared getCachedPipelineStages (TTL + single-flight).
	ps, err := getCachedPipelineStages(ctx, st, client, job, build)
	if err != nil {
		if isDiagBudgetErr(err) {
			out.Residuals = append(out.Residuals, "PIPE auto-wire skipped (remote budget; use jenkins_get_pipeline_stages)")
			return
		}
		if apperr.CodeOf(err) == apperr.CodeCapabilityMissing {
			out.Residuals = append(out.Residuals,
				"PIPE failed stage unavailable: Pipeline REST capability missing (use jenkins_get_pipeline_stages when plugin present)")
			return
		}
		if apperr.CodeOf(err) == apperr.CodeNotFound {
			// Not a Pipeline job or missing build — residual, not invented stage.
			out.Residuals = append(out.Residuals,
				"PIPE stages not found for this build (missing build or not a Pipeline job)")
			return
		}
		out.ConfidenceNotes = append(out.ConfidenceNotes, "pipeline stages unavailable: "+safeErrNote(err))
		out.Residuals = append(out.Residuals, "PIPE failed stage: use jenkins_get_pipeline_stages")
		return
	}
	if ps == nil || len(ps.Stages) == 0 {
		out.Residuals = append(out.Residuals, "PIPE: no stages returned for this build")
		return
	}
	out.Sources = append(out.Sources, "pipeline")
	if stage := findTopFailedStage(ps.Stages); stage != nil {
		out.FailedStage = &DiagnoseFailedStage{
			ID:     redact.SanitizeForModel(truncateDiagnoseText(stage.ID, 64)),
			Name:   redact.SanitizeForModel(truncateDiagnoseText(stage.Name, 256)),
			Status: redact.SanitizeForModel(truncateDiagnoseText(stage.Status, 64)),
			Type:   redact.SanitizeForModel(truncateDiagnoseText(stage.Type, 64)),
		}
	} else {
		out.ConfidenceNotes = append(out.ConfidenceNotes,
			fmt.Sprintf("pipeline status=%s with %d stage(s); no failed stage status found",
				ps.Status, ps.StageCount))
	}
}

func enrichDiagnoseUpstream(ctx context.Context, client *jenkins.Client, out *DiagnoseBuildToolResponse, job string, build int) {
	// One-hop only: load root with upstream expansion depth 1, no deep traversal.
	g, err := client.GetBuildGraph(ctx, jenkins.GetBuildGraphToolArgs{
		JobName:     job,
		BuildNumber: build,
		MaxDepth:    1,
		MaxNodes:    MaxDiagnoseUpstreamHints + 1, // root + ups
		Direction:   jenkins.GraphDirectionUpstream,
	})
	if err != nil {
		out.ConfidenceNotes = append(out.ConfidenceNotes, "related builds unavailable: "+safeErrNote(err))
		out.Residuals = append(out.Residuals,
			"GRAPH related builds: use jenkins_get_build_graph / jenkins_trace_failure_graph")
		return
	}
	if g == nil {
		out.Residuals = append(out.Residuals,
			"GRAPH related builds: use jenkins_get_build_graph / jenkins_trace_failure_graph")
		return
	}
	var ups []DiagnoseUpstreamHint
	// Prefer edges of kind upstream_cause; fall back to nodes with role=upstream.
	seen := make(map[string]struct{})
	for _, e := range g.Edges {
		if e.Kind != "upstream_cause" {
			continue
		}
		// Edge From=upstream To=current
		for _, n := range g.Nodes {
			if n.ID != e.From {
				continue
			}
			if _, ok := seen[n.ID]; ok {
				break
			}
			seen[n.ID] = struct{}{}
			ups = append(ups, DiagnoseUpstreamHint{
				JobName:     redact.SanitizeForModel(truncateDiagnoseText(n.JobName, 256)),
				BuildNumber: n.BuildNumber,
			})
			break
		}
		if len(ups) >= MaxDiagnoseUpstreamHints {
			break
		}
	}
	if len(ups) == 0 {
		for _, n := range g.Nodes {
			if n.Role != "upstream" {
				continue
			}
			if _, ok := seen[n.ID]; ok {
				continue
			}
			seen[n.ID] = struct{}{}
			ups = append(ups, DiagnoseUpstreamHint{
				JobName:     redact.SanitizeForModel(truncateDiagnoseText(n.JobName, 256)),
				BuildNumber: n.BuildNumber,
			})
			if len(ups) >= MaxDiagnoseUpstreamHints {
				break
			}
		}
	}
	if len(ups) == 0 {
		// No one-hop causes — residual pointing at dedicated tools (not a panic path).
		out.Residuals = append(out.Residuals,
			"GRAPH related builds: no one-hop upstream causes; use jenkins_get_build_graph / jenkins_trace_failure_graph")
		if g.CapabilityNote != "" {
			out.ConfidenceNotes = append(out.ConfidenceNotes,
				"GRAPH: "+redact.SanitizeForModel(truncateDiagnoseText(g.CapabilityNote, 200)))
		}
		return
	}
	out.Sources = append(out.Sources, "upstream_cause")
	out.RelatedBuilds = &DiagnoseRelatedBuilds{
		Upstream: ups,
		Note:     "one-hop upstream causes only (correlation); multi-hop: jenkins_get_build_graph / jenkins_trace_failure_graph",
	}
}

// findTopFailedStage returns the first failed stage in depth-first order (parent then children).
func findTopFailedStage(stages []jenkins.StageNode) *jenkins.StageNode {
	var walk func([]jenkins.StageNode) *jenkins.StageNode
	walk = func(list []jenkins.StageNode) *jenkins.StageNode {
		for i := range list {
			s := &list[i]
			if isFailedStageStatus(s.Status) {
				// Prefer a failed leaf/child if present under this node.
				if len(s.Children) > 0 {
					if child := walk(s.Children); child != nil {
						return child
					}
				}
				return s
			}
			if len(s.Children) > 0 {
				if child := walk(s.Children); child != nil {
					return child
				}
			}
		}
		return nil
	}
	return walk(stages)
}

func isFailedStageStatus(status string) bool {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "FAILED", "FAILURE", "UNSTABLE", "ABORTED", "FAILED_WITH_CONTINUE":
		return true
	default:
		return false
	}
}

func isDiagnoseFailureResult(result string) bool {
	switch strings.ToUpper(strings.TrimSpace(result)) {
	case "FAILURE", "UNSTABLE":
		return true
	default:
		return false
	}
}

func uniqueDiagnoseStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
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

type logMeta struct {
	Offset    int
	Length    int
	TotalSize int
	Sealed    bool
}

// acquireDiagnoseLog prefers session cache, then local mirror tail, then client log tail.
// Hard policy denials are returned as errors; soft mirror failures fall back.
// PERF-003: repeated diagnose/compare/graph calls hit FetchCache for the same
// job|build logtail window (TTL + max entries on regState.fetchCache).
func acquireDiagnoseLog(ctx context.Context, st regState, client *jenkins.Client, job string, build, maxLog int) (text string, meta logMeta, source string, incomplete bool, err error) {
	if err := ctx.Err(); err != nil {
		return "", logMeta{}, "", true, nil
	}
	sess := diagSessionFrom(ctx)

	// Shared process/session cache (PERF-003).
	// POL-004: still CheckStoreRead before serving cached log text.
	if st.fetchCache != nil {
		if t, m, src, inc, ok := st.fetchCache.GetLogTail(job, build, maxLog); ok {
			if st.policy != nil {
				if perr := policy.CheckStoreRead(ctx, st.policy, effectiveSubject(st, ctx), job); perr != nil {
					return "", logMeta{}, "", false, perr
				}
			}
			if sess != nil {
				sess.NoteHit()
			}
			return t, m, src, inc, nil
		}
		if sess != nil {
			sess.NoteMiss()
		}
	}

	// Per-operation remote budget (counts mirror+client as remote work for MVP).
	if sess != nil && !sess.AllowRemote(int64(maxLog)) {
		return "", logMeta{}, "", true, nil
	}

	var (
		outText string
		outMeta logMeta
		outSrc  string
		outInc  bool
	)

	if st.logs != nil {
		// POL-004 before cache read.
		if perr := policy.CheckStoreRead(ctx, st.policy, effectiveSubject(st, ctx), job); perr != nil {
			return "", logMeta{}, "", false, perr
		}
		if err := st.logs.EnsureMirrored(ctx, job, int64(build)); err != nil {
			// Continue — may still have partial frames.
			if ctx.Err() != nil {
				return "", logMeta{}, "", true, nil
			}
			_ = err
		}
		if err := ctx.Err(); err != nil {
			return "", logMeta{}, "", true, nil
		}
		logs, lm, rerr := st.logs.Tail(ctx, job, int64(build), int64(maxLog))
		if rerr == nil && (lm.TotalSize > 0 || logs != "") {
			inc := lm.HasMore || (lm.TotalSize > 0 && lm.Length < lm.TotalSize)
			outText = logs
			outMeta = logMeta{
				Offset:    lm.Offset,
				Length:    lm.Length,
				TotalSize: lm.TotalSize,
				Sealed:    lm.Sealed,
			}
			outSrc = "local_mirror"
			outInc = inc
		}
	}

	if outSrc == "" {
		if client == nil {
			return "", logMeta{}, "", true, nil
		}
		if err := ctx.Err(); err != nil {
			return "", logMeta{}, "", true, nil
		}
		bl, cerr := client.GetBuildLogTail(ctx, job, build, maxLog)
		if cerr != nil {
			if ctx.Err() != nil {
				return "", logMeta{}, "", true, nil
			}
			return "", logMeta{}, "", false, mapToolErr(cerr)
		}
		if bl == nil {
			return "", logMeta{}, "client_tail", true, nil
		}
		inc := bl.HasMore || (bl.TotalSize > 0 && bl.Length < bl.TotalSize)
		outText = bl.Logs
		outMeta = logMeta{
			Offset:    bl.Offset,
			Length:    bl.Length,
			TotalSize: bl.TotalSize,
		}
		outSrc = "client_tail"
		outInc = inc
	}

	remoteBytes := int64(outMeta.Length)
	if remoteBytes == 0 && outText != "" {
		remoteBytes = int64(len(outText))
	}
	if sess != nil {
		sess.RecordRemote(remoteBytes)
	}
	if st.fetchCache != nil && outSrc != "" {
		st.fetchCache.PutLogTail(job, build, maxLog, outText, outMeta, outSrc, outInc)
	}
	return outText, outMeta, outSrc, outInc, nil
}

type searchMerge struct {
	used   bool
	result diagnostics.Result
}

func mergeSearchFindings(ctx context.Context, st regState, job string, build, maxFindings int, base diagnostics.Result) searchMerge {
	if st.logSearch == nil {
		return searchMerge{result: base}
	}
	profile := st.profileID
	if profile == "" {
		return searchMerge{result: base}
	}
	// Bounded dual literal searches; ignore errors (degrade).
	patterns := []string{"ERROR", "FAILED"}
	var hits []diagnostics.SearchHit
	for _, pat := range patterns {
		q := search.Query{
			Profile:       profile,
			Job:           job,
			Build:         int64(build),
			Pattern:       pat,
			Mode:          search.ModeLiteral,
			CaseSensitive: false,
			MaxMatches:    maxFindings * 2,
			// Keep scan modest for diagnose.
			MaxBytesScanned: int64(HardDiagnoseLogBytes),
		}
		res, err := st.logSearch.Search(ctx, q)
		if err != nil {
			continue
		}
		for _, m := range res.Matches {
			// search.Match.Line is 0-based absolute → 1-based for diagnostics.
			hits = append(hits, diagnostics.SearchHit{
				Line: m.Line + 1,
				Text: m.LineText,
			})
		}
	}
	if len(hits) == 0 {
		return searchMerge{result: base}
	}
	fromHits := diagnostics.ExtractFromHits(hits, diagnostics.Options{
		MaxFindings:      maxFindings,
		MaxEvidenceLines: diagnostics.DefaultMaxEvidenceLines,
	})
	// Prefer higher-confidence union: re-rank by concatenating and re-extracting
	// is complex; simple approach: if base empty use hits; else keep base and
	// append hit-only signatures until cap.
	if len(base.Findings) == 0 {
		return searchMerge{used: true, result: fromHits}
	}
	seen := make(map[string]struct{}, len(base.Findings))
	for _, f := range base.Findings {
		seen[f.Signature] = struct{}{}
	}
	merged := base
	for _, f := range fromHits.Findings {
		if _, ok := seen[f.Signature]; ok {
			continue
		}
		if len(merged.Findings) >= maxFindings {
			merged.Truncated = true
			break
		}
		merged.Findings = append(merged.Findings, f)
		seen[f.Signature] = struct{}{}
	}
	return searchMerge{used: true, result: merged}
}

func sanitizeFindings(in []diagnostics.Finding) []DiagnoseFinding {
	if len(in) == 0 {
		return nil
	}
	out := make([]DiagnoseFinding, 0, len(in))
	for _, f := range in {
		df := DiagnoseFinding{
			Signature:  f.Signature,
			Pattern:    f.Pattern,
			Message:    redact.SanitizeForModel(truncateDiagnoseText(f.Message, MaxEvidenceExcerptBytes)),
			Confidence: f.Confidence,
			LineStart:  f.LineStart,
			LineEnd:    f.LineEnd,
			Count:      f.Count,
		}
		if len(f.Evidence) > 0 {
			ev := make([]diagnostics.EvidenceLine, 0, len(f.Evidence))
			for _, e := range f.Evidence {
				ev = append(ev, diagnostics.EvidenceLine{
					Line: e.Line,
					Text: redact.SanitizeForModel(truncateDiagnoseText(e.Text, MaxEvidenceExcerptBytes)),
				})
			}
			df.Evidence = ev
		}
		out = append(out, df)
	}
	return out
}

func sanitizeTestFailures(in []TestFailure) []TestFailure {
	if len(in) == 0 {
		return nil
	}
	// Cap test failures in response.
	const maxTests = 20
	if len(in) > maxTests {
		in = in[:maxTests]
	}
	out := make([]TestFailure, len(in))
	for i, t := range in {
		out[i] = TestFailure{
			Name:    redact.SanitizeForModel(truncateDiagnoseText(t.Name, 256)),
			Class:   redact.SanitizeForModel(truncateDiagnoseText(t.Class, 256)),
			Message: redact.SanitizeForModel(truncateDiagnoseText(t.Message, MaxEvidenceExcerptBytes)),
			Status:  redact.SanitizeForModel(truncateDiagnoseText(t.Status, 64)),
		}
	}
	return out
}

func buildDiagnoseSummary(out DiagnoseBuildToolResponse) string {
	var parts []string
	status := out.Result
	if out.Building {
		status = "BUILDING"
	}
	if status == "" {
		status = "UNKNOWN"
	}
	parts = append(parts, fmt.Sprintf("%s #%d result=%s", out.Job, out.Build, status))
	if out.FailedStage != nil && out.FailedStage.Name != "" {
		parts = append(parts, fmt.Sprintf("failed_stage=%s status=%s",
			compactOneLine(out.FailedStage.Name), out.FailedStage.Status))
	}
	if len(out.Findings) == 0 {
		parts = append(parts, "no deterministic error markers in scanned log window")
	} else {
		top := out.Findings[0]
		parts = append(parts, fmt.Sprintf("top finding [%s] conf=%.2f sig=%s: %s",
			top.Pattern, top.Confidence, top.Signature, compactOneLine(top.Message)))
		if len(out.Findings) > 1 {
			parts = append(parts, fmt.Sprintf("(+%d more candidate signatures)", len(out.Findings)-1))
		}
	}
	if n := len(out.TestFailures); n > 0 {
		parts = append(parts, fmt.Sprintf("%d failed test(s) attached", n))
	}
	if out.SCM != nil && out.SCM.CommitCount > 0 {
		parts = append(parts, fmt.Sprintf("%d SCM commit(s)", out.SCM.CommitCount))
	}
	if out.RelatedBuilds != nil && len(out.RelatedBuilds.Upstream) > 0 {
		parts = append(parts, fmt.Sprintf("%d upstream cause(s)", len(out.RelatedBuilds.Upstream)))
	}
	return strings.Join(parts, "; ")
}

func compactOneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.Join(strings.Fields(s), " ")
	return truncateDiagnoseText(s, 160)
}

func truncateDiagnoseText(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	// Byte truncate with ellipsis (UTF-8 safe-enough for logs).
	cut := max - len("…")
	for cut > 0 && cut < len(s) && s[cut]&0xc0 == 0x80 {
		cut--
	}
	if cut <= 0 {
		return "…"
	}
	return s[:cut] + "…"
}

// safeErrNote returns a short secret-free error note for confidence_notes.
func safeErrNote(err error) string {
	if err == nil {
		return ""
	}
	// Prefer coded apperr messages when present (already model-safe).
	msg := err.Error()
	msg = redact.SanitizeForModel(msg)
	return truncateDiagnoseText(msg, 160)
}
