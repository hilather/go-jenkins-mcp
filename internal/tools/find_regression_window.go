package tools

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/redact"
)

// ToolFindRegressionWindow is the DIAG-004 regression-window tool name.
const ToolFindRegressionWindow = "jenkins_find_regression_window"

// Regression-window budgets (server-enforced).
const (
	// DefaultRegressionMaxBuilds is the default max builds scanned.
	DefaultRegressionMaxBuilds = 30
	// HardRegressionMaxBuilds is the absolute build-scan ceiling.
	HardRegressionMaxBuilds = 50
	// DefaultRegressionLogBytesPerBuild is the default log tail per candidate.
	DefaultRegressionLogBytesPerBuild = 64 << 10 // 64 KiB
	// HardRegressionLogBytesPerBuild is the per-build log ceiling.
	HardRegressionLogBytesPerBuild = HardDiagnoseLogBytes
	// DefaultRegressionMaxLogBytesTotal is the default total log bytes across candidates.
	DefaultRegressionMaxLogBytesTotal = 1 << 20 // 1 MiB
	// HardRegressionMaxLogBytesTotal is the absolute total log-byte ceiling.
	HardRegressionMaxLogBytesTotal = 2 << 20 // 2 MiB
)

// FindRegressionWindowToolArgs is the MCP input for jenkins_find_regression_window.
type FindRegressionWindowToolArgs struct {
	JobName string `json:"job_name" mcp:"Jenkins job full name (folder/job path; not a URL)"`
	// Signature matches a diagnostics signature hex exactly (optional when pattern/message/test set).
	Signature string `json:"signature,omitempty" mcp:"exact error signature hex to match"`
	// Pattern matches a diagnostics rule id (e.g. error_prefix, build_failure).
	Pattern string `json:"pattern,omitempty" mcp:"error pattern id to match (e.g. build_failure)"`
	// MessageContains is a case-insensitive substring match on finding message.
	MessageContains string `json:"message_contains,omitempty" mcp:"substring to match in error message"`
	// TestCaseKey matches a failed JUnit case as class#name or bare name.
	TestCaseKey string `json:"test_case_key,omitempty" mcp:"failed test key (class#name or name)"`
	// MaxBuilds caps how many history builds are considered (default 30, max 50).
	MaxBuilds int `json:"max_builds,omitempty" mcp:"maximum builds to scan (default 30, max 50)"`
	// MaxLogBytesPerBuild caps log tail per candidate (0 ⇒ default).
	MaxLogBytesPerBuild int `json:"max_log_bytes_per_build,omitempty" mcp:"max log tail bytes per build"`
	// MaxLogBytesTotal caps total log bytes scanned across candidates (0 ⇒ default).
	MaxLogBytesTotal int `json:"max_log_bytes_total,omitempty" mcp:"max total log bytes across scan"`
	// AssumeMonotonic when true may binary-search; default false does a full reverse-chronological scan.
	// Monotonicity is never assumed silently — algorithm is always reported.
	AssumeMonotonic bool `json:"assume_monotonic,omitempty" mcp:"if true, binary-search under monotonic assumption; default full scan"`
	// EndBuild when >0 starts the lookback at this build number (inclusive upper bound).
	EndBuild int `json:"end_build,omitempty" mcp:"optional newest build number to start from"`
}

// RegressionBuildEvidence cites a boundary build and matching evidence.
type RegressionBuildEvidence struct {
	BuildNumber int    `json:"build_number"`
	Result      string `json:"result,omitempty"`
	// Match describes how the candidate matched (signature / pattern / message / test).
	Match string `json:"match,omitempty"`
	// Signature is the matched error signature when applicable.
	Signature string `json:"signature,omitempty"`
	Pattern   string `json:"pattern,omitempty"`
	Message   string `json:"message,omitempty"`
	// EvidenceExcerpt is a short sanitized evidence line when available.
	EvidenceExcerpt string `json:"evidence_excerpt,omitempty"`
}

// UncertainInterval describes a gap where builds are missing, unscanned, or inconclusive.
type UncertainInterval struct {
	// FromBuild / ToBuild are inclusive build numbers when known (0 = open).
	FromBuild int    `json:"from_build,omitempty"`
	ToBuild   int    `json:"to_build,omitempty"`
	Reason    string `json:"reason"`
}

// RegressionBudgets records scan caps and consumption.
type RegressionBudgets struct {
	MaxBuilds           int   `json:"max_builds"`
	MaxLogBytesPerBuild int   `json:"max_log_bytes_per_build"`
	MaxLogBytesTotal    int   `json:"max_log_bytes_total"`
	BuildsScanned       int   `json:"builds_scanned"`
	LogBytesScanned     int   `json:"log_bytes_scanned"`
	BudgetExhausted     bool  `json:"budget_exhausted,omitempty"`
	MaxRemoteCalls      int   `json:"max_remote_calls,omitempty"`
	MaxRemoteBytes      int64 `json:"max_remote_bytes,omitempty"`
	MaxWallMS           int64 `json:"max_wall_ms,omitempty"`
}

// FindRegressionWindowToolResponse is the bounded regression-window result.
type FindRegressionWindowToolResponse struct {
	Job string `json:"job"`
	// Algorithm is reverse_chronological_scan (default) or binary_search_monotonic.
	Algorithm string `json:"algorithm"`
	// FirstKnownGood is the newest scanned build older than FirstKnownBad that does not match.
	FirstKnownGood *RegressionBuildEvidence `json:"first_known_good,omitempty"`
	// FirstKnownBad is the oldest scanned build that matches the target signature/test.
	FirstKnownBad      *RegressionBuildEvidence `json:"first_known_bad,omitempty"`
	UncertainIntervals []UncertainInterval      `json:"uncertain_intervals,omitempty"`
	// ScannedBuilds lists build numbers examined (newest→oldest), for auditability.
	ScannedBuilds   []int             `json:"scanned_builds,omitempty"`
	MissingBuilds   []int             `json:"missing_builds,omitempty"`
	Budgets         RegressionBudgets `json:"budgets"`
	Sources         []string          `json:"sources,omitempty"`
	ConfidenceNotes []string          `json:"confidence_notes,omitempty"`
	Residuals       []string          `json:"residuals,omitempty"`
	Incomplete      bool              `json:"incomplete,omitempty"`
	Untrusted       bool              `json:"untrusted"`
	Summary         string            `json:"summary"`
	// Perf is optional request-local cache/remote counters (PERF-003).
	Perf *DiagPerf `json:"perf,omitempty"`
}

// registerFindRegressionWindowTool registers jenkins_find_regression_window (DIAG-004).
func registerFindRegressionWindowTool(s *mcp.Server, client *jenkins.Client, st regState) {
	addReadTool(s, st, &mcp.Tool{
		Name: ToolFindRegressionWindow,
		Description: "Find the first build exhibiting an error signature (or optional test case key) " +
			"within a bounded lookback. Default algorithm is reverse-chronological full scan; " +
			"binary search only when assume_monotonic=true (never assumed silently). " +
			"Returns first_known_good, first_known_bad, uncertain intervals, and evidence citations.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args FindRegressionWindowToolArgs) (*mcp.CallToolResult, FindRegressionWindowToolResponse, error) {
		out, err := runFindRegressionWindow(ctx, client, st, args)
		if err != nil {
			return nil, FindRegressionWindowToolResponse{}, err
		}
		return structuredResult(out)
	})
}

func runFindRegressionWindow(ctx context.Context, client *jenkins.Client, st regState, args FindRegressionWindowToolArgs) (FindRegressionWindowToolResponse, error) {
	name, err := jobFullName("job_name", args.JobName)
	if err != nil {
		return FindRegressionWindowToolResponse{}, err
	}
	sig := strings.TrimSpace(args.Signature)
	pattern := strings.TrimSpace(args.Pattern)
	msgSub := strings.TrimSpace(args.MessageContains)
	testKey := strings.TrimSpace(args.TestCaseKey)
	if sig == "" && pattern == "" && msgSub == "" && testKey == "" {
		return FindRegressionWindowToolResponse{}, invalidArg(
			"at least one of signature, pattern, message_contains, or test_case_key is required")
	}

	maxBuilds := args.MaxBuilds
	if maxBuilds <= 0 {
		maxBuilds = DefaultRegressionMaxBuilds
	}
	if maxBuilds > HardRegressionMaxBuilds {
		maxBuilds = HardRegressionMaxBuilds
	}
	maxLogPer := args.MaxLogBytesPerBuild
	if maxLogPer <= 0 {
		maxLogPer = DefaultRegressionLogBytesPerBuild
	}
	if maxLogPer > HardRegressionLogBytesPerBuild {
		maxLogPer = HardRegressionLogBytesPerBuild
	}
	maxLogTotal := args.MaxLogBytesTotal
	if maxLogTotal <= 0 {
		maxLogTotal = DefaultRegressionMaxLogBytesTotal
	}
	if maxLogTotal > HardRegressionMaxLogBytesTotal {
		maxLogTotal = HardRegressionMaxLogBytesTotal
	}

	budgetCfg := mergeDiagBudget(regressionBudgetDefault(), st.diagBudget)
	out := FindRegressionWindowToolResponse{
		Job:       name,
		Untrusted: true,
		Budgets: RegressionBudgets{
			MaxBuilds:           maxBuilds,
			MaxLogBytesPerBuild: maxLogPer,
			MaxLogBytesTotal:    maxLogTotal,
			MaxRemoteCalls:      budgetCfg.MaxRemoteCalls,
			MaxRemoteBytes:      budgetCfg.MaxRemoteBytes,
		},
		ConfidenceNotes: []string{
			"algorithm never assumes monotonicity silently; see algorithm field",
			"missing/evicted builds create uncertain intervals",
		},
	}
	if budgetCfg.MaxWall > 0 {
		out.Budgets.MaxWallMS = budgetCfg.MaxWall.Milliseconds()
	}
	if testKey != "" {
		out.Residuals = append(out.Residuals, "test-case lookback uses live JUnit reports per build (TEST-001); no cached test index")
	}

	if client == nil {
		return FindRegressionWindowToolResponse{}, apperr.New(apperr.CodeInternal, "jenkins client is nil")
	}

	sess := newDiagSession(st, regressionBudgetDefault())
	ctx, cancel := sess.BoundContext(ctx)
	defer cancel()
	ctx = withDiagSession(ctx, sess)

	// Load bounded build history (JEN-003), newest first.
	if sess != nil && !sess.AllowRemote(1024) {
		out.Incomplete = true
		out.ConfidenceNotes = append(out.ConfidenceNotes, "list_builds skipped: "+sess.BudgetNote())
		out.Residuals = append(out.Residuals, sess.BudgetNote())
		perf := sess.PerfSnapshot()
		out.Perf = &perf
		return out, nil
	}
	listArgs := jenkins.ListBuildsToolArgs{
		JobName:     name,
		Limit:       maxBuilds,
		MaxLookback: maxBuilds,
	}
	if args.EndBuild > 0 {
		listArgs.SinceBuild = args.EndBuild
	}
	hist, herr := client.ListBuilds(ctx, listArgs)
	if herr != nil {
		return FindRegressionWindowToolResponse{}, mapToolErr(herr)
	}
	if sess != nil {
		sess.RecordRemote(1024)
	}
	out.Sources = append(out.Sources, "list_builds")
	if hist == nil || len(hist.Builds) == 0 {
		out.Summary = fmt.Sprintf("%s: no builds in lookback", name)
		out.ConfidenceNotes = append(out.ConfidenceNotes, "empty build history in lookback window")
		perf := sess.PerfSnapshot()
		out.Perf = &perf
		return out, nil
	}

	// Detect number gaps as uncertain intervals (evicted/missing builds).
	numbers := make([]int, 0, len(hist.Builds))
	byNum := make(map[int]jenkins.Build, len(hist.Builds))
	for _, b := range hist.Builds {
		numbers = append(numbers, b.Number)
		byNum[b.Number] = b
	}
	// ListBuilds returns newest first; keep that order for reverse chrono.
	missing := detectMissingBuildNumbers(numbers)
	out.MissingBuilds = missing
	for _, m := range missing {
		out.UncertainIntervals = append(out.UncertainIntervals, UncertainInterval{
			FromBuild: m,
			ToBuild:   m,
			Reason:    "build number present in range but absent from Jenkins history (evicted or never existed)",
		})
	}
	if hist.Truncated {
		out.Incomplete = true
		out.UncertainIntervals = append(out.UncertainIntervals, UncertainInterval{
			Reason: "list_builds truncated by lookback; older builds not examined",
		})
	}

	matchCfg := regressionMatchConfig{
		Signature:       sig,
		Pattern:         pattern,
		MessageContains: msgSub,
		TestCaseKey:     testKey,
	}

	if args.AssumeMonotonic {
		out.Algorithm = "binary_search_monotonic"
		out.ConfidenceNotes = append(out.ConfidenceNotes,
			"assume_monotonic=true: binary search used; non-monotonic history may misplace the window — verify boundary evidence")
		runRegressionBinarySearch(ctx, client, st, &out, hist.Builds, byNum, matchCfg, maxLogPer, maxLogTotal)
	} else {
		out.Algorithm = "reverse_chronological_scan"
		runRegressionFullScan(ctx, client, st, &out, hist.Builds, matchCfg, maxLogPer, maxLogTotal)
	}

	if note := sess.BudgetNote(); note != "" {
		out.Incomplete = true
		out.Budgets.BudgetExhausted = true
		out.ConfidenceNotes = append(out.ConfidenceNotes, note)
		out.Residuals = append(out.Residuals, note)
	}
	if ctx.Err() != nil {
		out.Incomplete = true
	}

	out.Summary = buildRegressionSummary(out)
	out.Sources = uniqueStrings(out.Sources)
	perf := sess.PerfSnapshot()
	out.Perf = &perf
	return out, nil
}

type regressionMatchConfig struct {
	Signature       string
	Pattern         string
	MessageContains string
	TestCaseKey     string
}

type candidateVerdict struct {
	matched bool
	// inconclusive means we could not decide (log/test error).
	inconclusive bool
	evidence     RegressionBuildEvidence
	logBytes     int
	source       string
	notes        []string
}

func runRegressionFullScan(
	ctx context.Context,
	client *jenkins.Client,
	st regState,
	out *FindRegressionWindowToolResponse,
	builds []jenkins.Build, // newest first
	cfg regressionMatchConfig,
	maxLogPer, maxLogTotal int,
) {
	// Evaluate all candidates newest→oldest under budgets.
	// first_known_bad = oldest matching build number.
	// first_known_good = newest non-matching build older than first_known_bad.
	type row struct {
		build   jenkins.Build
		verdict candidateVerdict
	}
	var rows []row
	logTotal := 0
	budgetHit := false

	for _, b := range builds {
		select {
		case <-ctx.Done():
			out.Incomplete = true
			out.UncertainIntervals = append(out.UncertainIntervals, UncertainInterval{
				Reason: "scan cancelled: " + safeErrNote(ctx.Err()),
			})
			budgetHit = true
			break
		default:
		}
		if logTotal >= maxLogTotal {
			budgetHit = true
			out.Incomplete = true
			out.UncertainIntervals = append(out.UncertainIntervals, UncertainInterval{
				FromBuild: 0,
				ToBuild:   b.Number,
				Reason:    "max_log_bytes_total exhausted; remaining older builds not scanned",
			})
			break
		}
		remain := maxLogTotal - logTotal
		per := maxLogPer
		if per > remain {
			per = remain
		}
		v := evaluateCandidate(ctx, client, st, out.Job, b, cfg, per)
		logTotal += v.logBytes
		if v.source != "" {
			out.Sources = append(out.Sources, v.source)
		}
		out.ConfidenceNotes = append(out.ConfidenceNotes, v.notes...)
		out.ScannedBuilds = append(out.ScannedBuilds, b.Number)
		out.Budgets.BuildsScanned++
		out.Budgets.LogBytesScanned = logTotal
		rows = append(rows, row{build: b, verdict: v})
		if v.inconclusive {
			out.UncertainIntervals = append(out.UncertainIntervals, UncertainInterval{
				FromBuild: b.Number,
				ToBuild:   b.Number,
				Reason:    "inconclusive (log/test unavailable or empty)",
			})
		}
	}
	out.Budgets.BudgetExhausted = budgetHit
	out.Budgets.LogBytesScanned = logTotal

	// Derive boundaries from complete scanned set (non-monotonic safe).
	var oldestBad *row
	for i := len(rows) - 1; i >= 0; i-- { // oldest first within scanned
		if rows[i].verdict.matched {
			oldestBad = &rows[i]
			break
		}
	}
	if oldestBad == nil {
		// No match in scanned window — report newest conclusive good if any.
		for _, r := range rows {
			if !r.verdict.matched && !r.verdict.inconclusive {
				ev := r.verdict.evidence
				ev.BuildNumber = r.build.Number
				ev.Result = r.build.Result
				if ev.Match == "" {
					ev.Match = "no_match"
				}
				out.FirstKnownGood = &ev
				break
			}
		}
		out.ConfidenceNotes = append(out.ConfidenceNotes, "no matching failure found in scanned lookback")
		return
	}

	badEv := oldestBad.verdict.evidence
	badEv.BuildNumber = oldestBad.build.Number
	badEv.Result = oldestBad.build.Result
	out.FirstKnownBad = &badEv

	// Newest good strictly older than first_known_bad.
	var bestGood *RegressionBuildEvidence
	bestGoodNum := 0
	for _, r := range rows {
		if r.build.Number >= oldestBad.build.Number {
			continue
		}
		if r.verdict.matched || r.verdict.inconclusive {
			continue
		}
		if r.build.Number > bestGoodNum {
			ev := r.verdict.evidence
			ev.BuildNumber = r.build.Number
			ev.Result = r.build.Result
			if ev.Match == "" {
				ev.Match = "no_match"
			}
			bestGood = &ev
			bestGoodNum = r.build.Number
		}
	}
	out.FirstKnownGood = bestGood

	if out.FirstKnownGood == nil {
		out.UncertainIntervals = append(out.UncertainIntervals, UncertainInterval{
			ToBuild: oldestBad.build.Number,
			Reason:  "no conclusive good build older than first_known_bad within scanned window",
		})
	}
}

func runRegressionBinarySearch(
	ctx context.Context,
	client *jenkins.Client,
	st regState,
	out *FindRegressionWindowToolResponse,
	builds []jenkins.Build, // newest first
	byNum map[int]jenkins.Build,
	cfg regressionMatchConfig,
	maxLogPer, maxLogTotal int,
) {
	// Work on ascending build numbers for classic binary search.
	asc := make([]jenkins.Build, len(builds))
	copy(asc, builds)
	sort.Slice(asc, func(i, j int) bool { return asc[i].Number < asc[j].Number })

	logTotal := 0
	type evalCache map[int]candidateVerdict
	cache := make(evalCache)

	eval := func(b jenkins.Build) candidateVerdict {
		if v, ok := cache[b.Number]; ok {
			return v
		}
		if logTotal >= maxLogTotal {
			v := candidateVerdict{inconclusive: true, notes: []string{"log budget exhausted before evaluation"}}
			cache[b.Number] = v
			return v
		}
		remain := maxLogTotal - logTotal
		per := maxLogPer
		if per > remain {
			per = remain
		}
		v := evaluateCandidate(ctx, client, st, out.Job, b, cfg, per)
		logTotal += v.logBytes
		out.Budgets.LogBytesScanned = logTotal
		out.Budgets.BuildsScanned++
		out.ScannedBuilds = append(out.ScannedBuilds, b.Number)
		if v.source != "" {
			out.Sources = append(out.Sources, v.source)
		}
		out.ConfidenceNotes = append(out.ConfidenceNotes, v.notes...)
		cache[b.Number] = v
		return v
	}

	// Evaluate endpoints first.
	if len(asc) == 0 {
		return
	}
	lo, hi := 0, len(asc)-1
	vLo := eval(asc[lo])
	vHi := eval(asc[hi])

	// If newest does not match, no regression in window under monotonic assumption.
	if !vHi.matched {
		if !vHi.inconclusive {
			ev := vHi.evidence
			ev.BuildNumber = asc[hi].Number
			ev.Result = asc[hi].Result
			if ev.Match == "" {
				ev.Match = "no_match"
			}
			out.FirstKnownGood = &ev
		}
		out.ConfidenceNotes = append(out.ConfidenceNotes, "newest scanned build does not match; no first_known_bad under monotonic assumption")
		if logTotal >= maxLogTotal {
			out.Budgets.BudgetExhausted = true
			out.Incomplete = true
		}
		return
	}

	// If oldest matches, first_known_bad may be at or before window start.
	if vLo.matched {
		ev := vLo.evidence
		ev.BuildNumber = asc[lo].Number
		ev.Result = asc[lo].Result
		out.FirstKnownBad = &ev
		out.UncertainIntervals = append(out.UncertainIntervals, UncertainInterval{
			ToBuild: asc[lo].Number,
			Reason:  "oldest scanned build already matches; first_known_good may lie outside lookback (uncertain)",
		})
	}

	// Binary search for first (oldest) match under monotonic assumption:
	// find lowest index where matched=true.
	left, right := lo, hi
	firstBadIdx := hi
	for left <= right {
		select {
		case <-ctx.Done():
			out.Incomplete = true
			out.UncertainIntervals = append(out.UncertainIntervals, UncertainInterval{
				Reason: "binary search cancelled: " + safeErrNote(ctx.Err()),
			})
			out.Budgets.BudgetExhausted = true
			return
		default:
		}
		if logTotal >= maxLogTotal {
			out.Budgets.BudgetExhausted = true
			out.Incomplete = true
			out.UncertainIntervals = append(out.UncertainIntervals, UncertainInterval{
				Reason: "max_log_bytes_total exhausted during binary search; window may be incomplete",
			})
			break
		}
		mid := (left + right) / 2
		v := eval(asc[mid])
		if v.inconclusive {
			// Skip mid into uncertain; search both sides conservatively by expanding linear neighbors.
			out.UncertainIntervals = append(out.UncertainIntervals, UncertainInterval{
				FromBuild: asc[mid].Number,
				ToBuild:   asc[mid].Number,
				Reason:    "inconclusive during binary search (missing data)",
			})
			// Fall back: treat inconclusive as "unknown" — search right for a known bad, left for good.
			// Move leftward to try to find an older conclusive match boundary.
			right = mid - 1
			continue
		}
		if v.matched {
			firstBadIdx = mid
			right = mid - 1
		} else {
			left = mid + 1
		}
	}

	bad := asc[firstBadIdx]
	vBad := eval(bad)
	if vBad.matched {
		ev := vBad.evidence
		ev.BuildNumber = bad.Number
		ev.Result = bad.Result
		out.FirstKnownBad = &ev
	}

	// first_known_good: highest number < first_known_bad that does not match.
	if out.FirstKnownBad != nil {
		for i := firstBadIdx - 1; i >= 0; i-- {
			v := eval(asc[i])
			if v.inconclusive {
				out.UncertainIntervals = append(out.UncertainIntervals, UncertainInterval{
					FromBuild: asc[i].Number,
					ToBuild:   asc[i].Number,
					Reason:    "inconclusive candidate between good/bad boundary",
				})
				continue
			}
			if !v.matched {
				ev := v.evidence
				ev.BuildNumber = asc[i].Number
				ev.Result = asc[i].Result
				if ev.Match == "" {
					ev.Match = "no_match"
				}
				out.FirstKnownGood = &ev
				break
			}
		}
		if out.FirstKnownGood == nil {
			out.UncertainIntervals = append(out.UncertainIntervals, UncertainInterval{
				ToBuild: out.FirstKnownBad.BuildNumber,
				Reason:  "no conclusive good build older than first_known_bad within scanned window",
			})
		}
		// Uncertain gaps between good and bad when numbers are non-contiguous.
		if out.FirstKnownGood != nil && out.FirstKnownBad.BuildNumber-out.FirstKnownGood.BuildNumber > 1 {
			// Check if any numbers in (good, bad) are missing from history.
			for n := out.FirstKnownGood.BuildNumber + 1; n < out.FirstKnownBad.BuildNumber; n++ {
				if _, ok := byNum[n]; !ok {
					out.UncertainIntervals = append(out.UncertainIntervals, UncertainInterval{
						FromBuild: n,
						ToBuild:   n,
						Reason:    "build gap between first_known_good and first_known_bad (monotonic assumption uncertain)",
					})
				}
			}
		}
	}
	out.Budgets.LogBytesScanned = logTotal
	_ = byNum
}

func evaluateCandidate(
	ctx context.Context,
	client *jenkins.Client,
	st regState,
	job string,
	b jenkins.Build,
	cfg regressionMatchConfig,
	maxLog int,
) candidateVerdict {
	ev := RegressionBuildEvidence{BuildNumber: b.Number, Result: b.Result}

	// Optional test-case path first (no log bytes when only test_case_key and no log filters).
	needLog := cfg.Signature != "" || cfg.Pattern != "" || cfg.MessageContains != ""
	if cfg.TestCaseKey != "" {
		matched, excerpt, note, src, err := matchTestCaseKey(ctx, client, job, b.Number, cfg.TestCaseKey)
		if err != nil {
			// capability missing or other — inconclusive for test path; may still try logs
			if !needLog {
				return candidateVerdict{
					inconclusive: true,
					evidence:     ev,
					notes:        []string{fmt.Sprintf("#%d test match unavailable: %s", b.Number, safeErrNote(err))},
				}
			}
		} else if matched {
			ev.Match = "test_case"
			ev.EvidenceExcerpt = excerpt
			return candidateVerdict{matched: true, evidence: ev, source: src}
		} else if !needLog {
			ev.Match = "no_match"
			return candidateVerdict{matched: false, evidence: ev, source: src, notes: noteSlice(note)}
		}
		// If not matched on test but log criteria present, continue to log path.
	}

	if !needLog {
		ev.Match = "no_match"
		return candidateVerdict{matched: false, evidence: ev}
	}

	findings, logBytes, src, incomplete, notes := extractBuildSignatures(ctx, client, st, job, b.Number, maxLog, DefaultDiagnoseMaxFindings)
	// Incomplete log with no matching findings is inconclusive: a truncated/partial
	// tail must not become first_known_good (Regression: non-empty incomplete tail).
	if incomplete && len(findings) == 0 {
		return candidateVerdict{
			inconclusive: true,
			evidence:     ev,
			logBytes:     logBytes,
			source:       src,
			notes:        append(notes, fmt.Sprintf("#%d log incomplete/partial; no conclusive match", b.Number)),
		}
	}
	for _, f := range findings {
		if matchFinding(f, cfg) {
			ev.Match = matchKind(f, cfg)
			ev.Signature = f.Signature
			ev.Pattern = f.Pattern
			ev.Message = f.Message
			if len(f.Evidence) > 0 {
				ev.EvidenceExcerpt = redact.SanitizeForModel(truncateDiagnoseText(f.Evidence[0].Text, MaxEvidenceExcerptBytes))
			} else {
				ev.EvidenceExcerpt = f.Message
			}
			return candidateVerdict{matched: true, evidence: ev, logBytes: logBytes, source: src, notes: notes}
		}
	}
	ev.Match = "no_match"
	return candidateVerdict{matched: false, evidence: ev, logBytes: logBytes, source: src, notes: notes}
}

func matchFinding(f DiagnoseFinding, cfg regressionMatchConfig) bool {
	if cfg.Signature != "" && !strings.EqualFold(f.Signature, cfg.Signature) {
		// Signature is exclusive when set: must match.
		// But if other filters also set, require all set filters (AND).
	}
	ok := true
	any := false
	if cfg.Signature != "" {
		any = true
		if !strings.EqualFold(f.Signature, cfg.Signature) {
			ok = false
		}
	}
	if cfg.Pattern != "" {
		any = true
		if !strings.EqualFold(f.Pattern, cfg.Pattern) {
			ok = false
		}
	}
	if cfg.MessageContains != "" {
		any = true
		if !strings.Contains(strings.ToLower(f.Message), strings.ToLower(cfg.MessageContains)) {
			ok = false
		}
	}
	return any && ok
}

func matchKind(f DiagnoseFinding, cfg regressionMatchConfig) string {
	var parts []string
	if cfg.Signature != "" {
		parts = append(parts, "signature")
	}
	if cfg.Pattern != "" {
		parts = append(parts, "pattern")
	}
	if cfg.MessageContains != "" {
		parts = append(parts, "message")
	}
	if len(parts) == 0 {
		return f.Pattern
	}
	return strings.Join(parts, "+")
}

func matchTestCaseKey(ctx context.Context, client *jenkins.Client, job string, build int, key string) (matched bool, excerpt, note, src string, err error) {
	rep, err := client.GetTestReport(ctx, job, build, DefaultCompareMaxTestDiffs)
	if err != nil {
		return false, "", "", "", err
	}
	if rep == nil || !rep.Available {
		return false, "", "no test report", "tests", nil
	}
	key = strings.TrimSpace(key)
	for _, t := range rep.FailedTests {
		full := t.ClassName
		if full != "" && t.Name != "" {
			full = full + "#" + t.Name
		} else {
			full = t.Name
		}
		if strings.EqualFold(full, key) || strings.EqualFold(t.Name, key) {
			ex := redact.SanitizeForModel(truncateDiagnoseText(t.ErrorDetails, MaxEvidenceExcerptBytes))
			if ex == "" {
				ex = redact.SanitizeForModel(truncateDiagnoseText(full, 256))
			}
			return true, ex, "", "tests", nil
		}
	}
	return false, "", "", "tests", nil
}

func detectMissingBuildNumbers(numbers []int) []int {
	if len(numbers) < 2 {
		return nil
	}
	// numbers may be newest-first or mixed; sort copy ascending.
	cp := append([]int(nil), numbers...)
	sort.Ints(cp)
	var missing []int
	for i := 1; i < len(cp); i++ {
		for n := cp[i-1] + 1; n < cp[i]; n++ {
			missing = append(missing, n)
			// Cap missing list size.
			if len(missing) >= HardRegressionMaxBuilds {
				return missing
			}
		}
	}
	return missing
}

func noteSlice(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

func buildRegressionSummary(out FindRegressionWindowToolResponse) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("%s algorithm=%s scanned=%d", out.Job, out.Algorithm, out.Budgets.BuildsScanned))
	if out.FirstKnownBad != nil {
		parts = append(parts, fmt.Sprintf("first_known_bad=#%d", out.FirstKnownBad.BuildNumber))
	} else {
		parts = append(parts, "first_known_bad=none")
	}
	if out.FirstKnownGood != nil {
		parts = append(parts, fmt.Sprintf("first_known_good=#%d", out.FirstKnownGood.BuildNumber))
	} else {
		parts = append(parts, "first_known_good=none")
	}
	if n := len(out.UncertainIntervals); n > 0 {
		parts = append(parts, fmt.Sprintf("uncertain_intervals=%d", n))
	}
	return strings.Join(parts, "; ")
}
