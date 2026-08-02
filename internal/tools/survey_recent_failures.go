package tools

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/diagnostics"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/redact"
	"github.com/hilather/go-jenkins-mcp/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ToolSurveyRecentFailures is the DIAG-006 multi-build failure survey tool name.
const ToolSurveyRecentFailures = "jenkins_survey_recent_failures"

// NormalizationMethodDiag001 documents the signature preimage rules (DIAG-001).
const NormalizationMethodDiag001 = "diag001_normalize_line"

// Survey budgets (server-enforced; callers may only lower).
const (
	// DefaultSurveyMaxJobs is the default max jobs in scope.
	DefaultSurveyMaxJobs = 10
	// HardSurveyMaxJobs is the absolute job-scope ceiling.
	HardSurveyMaxJobs = 25
	// DefaultSurveyMaxBuildsPerJob is the default failed builds per job.
	DefaultSurveyMaxBuildsPerJob = 10
	// HardSurveyMaxBuildsPerJob is the absolute per-job build ceiling.
	HardSurveyMaxBuildsPerJob = 30
	// DefaultSurveyMaxTotalBuilds is the default total failed builds surveyed.
	DefaultSurveyMaxTotalBuilds = 30
	// HardSurveyMaxTotalBuilds is the absolute total-build ceiling.
	HardSurveyMaxTotalBuilds = 100
	// DefaultSurveyMaxLogBytesPerBuild is the default log tail per candidate.
	DefaultSurveyMaxLogBytesPerBuild = 64 << 10 // 64 KiB
	// HardSurveyMaxLogBytesPerBuild is the per-build log ceiling.
	HardSurveyMaxLogBytesPerBuild = HardDiagnoseLogBytes
	// DefaultSurveyMaxLogBytesTotal is the default total log bytes across candidates.
	DefaultSurveyMaxLogBytesTotal = 1 << 20 // 1 MiB
	// HardSurveyMaxLogBytesTotal is the absolute total log-byte ceiling.
	HardSurveyMaxLogBytesTotal = 4 << 20 // 4 MiB
	// DefaultSurveyMaxClusters caps returned signature clusters.
	DefaultSurveyMaxClusters = 20
	// HardSurveyMaxClusters is the absolute cluster ceiling.
	HardSurveyMaxClusters = 50
	// DefaultSurveyMaxFindingsPerBuild caps extract findings per build.
	DefaultSurveyMaxFindingsPerBuild = 5
	// HardSurveyMaxFindingsPerBuild is the absolute per-build findings ceiling.
	HardSurveyMaxFindingsPerBuild = 15
	// DefaultSurveyMaxExamplesPerCluster caps example job#build rows per cluster.
	DefaultSurveyMaxExamplesPerCluster = 5
	// DefaultSurveyMaxWallSeconds is the default wall-time budget (0 in args ⇒ this).
	DefaultSurveyMaxWallSeconds = 30
	// HardSurveyMaxWallSeconds is the absolute wall-time ceiling.
	HardSurveyMaxWallSeconds = 120
)

// SurveyRecentFailuresToolArgs is the MCP input for jenkins_survey_recent_failures.
//
// Scope selection (at least one required):
//   - job_names: explicit typed full names (folder/job path; not URLs)
//   - job_prefix: single folder/job path prefix; matches jobs where full name equals
//     the prefix or starts with prefix+"/" (same semantics as list_jobs folder_prefix)
//
// Cross-job survey is disabled by default: when the resolved scope has more than
// one job, allow_cross_job must be true (policy-friendly explicit enablement).
type SurveyRecentFailuresToolArgs struct {
	// JobNames are explicit Jenkins job full names to include.
	JobNames []string `json:"job_names,omitempty" mcp:"explicit job full names (folder/job path; not URLs)"`
	// JobPrefix is a single folder/job path prefix filter (optional).
	JobPrefix string `json:"job_prefix,omitempty" mcp:"folder/job path prefix; matches exact or under prefix/"`
	// AllowCrossJob enables multi-job survey (default false).
	AllowCrossJob bool `json:"allow_cross_job,omitempty" mcp:"required true when scope resolves to more than one job"`
	// MaxJobs caps jobs after scope resolution (0 ⇒ default).
	MaxJobs int `json:"max_jobs,omitempty" mcp:"max jobs in survey scope"`
	// MaxBuildsPerJob caps failed/unstable builds considered per job (0 ⇒ default).
	MaxBuildsPerJob int `json:"max_builds_per_job,omitempty" mcp:"max failed builds per job"`
	// MaxTotalBuilds caps total failed builds surveyed across jobs (0 ⇒ default).
	MaxTotalBuilds int `json:"max_total_builds,omitempty" mcp:"max total failed builds across jobs"`
	// MaxLogBytesPerBuild caps log tail per candidate (0 ⇒ default).
	MaxLogBytesPerBuild int `json:"max_log_bytes_per_build,omitempty" mcp:"max log tail bytes per build"`
	// MaxLogBytesTotal caps total log bytes across candidates (0 ⇒ default).
	MaxLogBytesTotal int `json:"max_log_bytes_total,omitempty" mcp:"max total log bytes across survey"`
	// MaxClusters caps returned clusters (0 ⇒ default).
	MaxClusters int `json:"max_clusters,omitempty" mcp:"max signature clusters to return"`
	// MaxWallSeconds caps wall time via a child context (0 ⇒ default; hard-capped).
	MaxWallSeconds int `json:"max_wall_seconds,omitempty" mcp:"max wall time seconds for the survey"`
}

// SurveyExampleBuild cites one job#build that contributed to a cluster.
type SurveyExampleBuild struct {
	Job    string `json:"job"`
	Build  int    `json:"build"`
	Result string `json:"result,omitempty"`
}

// SurveyFailureCluster is one recurring failure signature group.
type SurveyFailureCluster struct {
	// Signature is the DIAG-001 normalized signature (sha256 of NormalizeLine preimage, 16 hex).
	Signature string `json:"signature"`
	// Normalized is a truncated normalized preimage when available.
	Normalized string `json:"normalized,omitempty"`
	// NormalizationMethod documents the volatile-token rules applied.
	NormalizationMethod string `json:"normalization_method"`
	// Pattern is the primary extract rule id (e.g. build_failure).
	Pattern string `json:"pattern,omitempty"`
	// Count is the number of (job, build) occurrences contributing this signature.
	Count int `json:"count"`
	// ExactVariantCount is how many distinct light-exact signatures rolled up here.
	ExactVariantCount int `json:"exact_variant_count,omitempty"`
	// Message is a representative sanitized message.
	Message string `json:"message,omitempty"`
	// EvidenceExcerpt is a short sanitized evidence line.
	EvidenceExcerpt string `json:"evidence_excerpt,omitempty"`
	// Examples lists sample job#build citations (bounded).
	Examples []SurveyExampleBuild `json:"examples,omitempty"`
	// Jobs lists distinct job names that hit this cluster (bounded).
	Jobs []string `json:"jobs,omitempty"`
	// Confidence is the highest confidence among contributing findings.
	Confidence float64 `json:"confidence,omitempty"`
}

// SurveyBudgets records survey caps and consumption.
type SurveyBudgets struct {
	MaxJobs             int  `json:"max_jobs"`
	MaxBuildsPerJob     int  `json:"max_builds_per_job"`
	MaxTotalBuilds      int  `json:"max_total_builds"`
	MaxLogBytesPerBuild int  `json:"max_log_bytes_per_build"`
	MaxLogBytesTotal    int  `json:"max_log_bytes_total"`
	MaxClusters         int  `json:"max_clusters"`
	MaxWallSeconds      int  `json:"max_wall_seconds"`
	JobsInScope         int  `json:"jobs_in_scope"`
	JobsSurveyed        int  `json:"jobs_surveyed"`
	BuildsListed        int  `json:"builds_listed"`
	BuildsExtracted     int  `json:"builds_extracted"`
	LogBytesScanned     int  `json:"log_bytes_scanned"`
	CacheHits           int  `json:"cache_hits"`
	CacheMisses         int  `json:"cache_misses"`
	BudgetExhausted     bool `json:"budget_exhausted,omitempty"`
}

// SurveyRecentFailuresToolResponse is the bounded survey result.
type SurveyRecentFailuresToolResponse struct {
	// ScopeJobs is the resolved ordered job list actually considered.
	ScopeJobs []string `json:"scope_jobs"`
	// JobPrefix is the prefix used when set.
	JobPrefix string `json:"job_prefix,omitempty"`
	// AllowCrossJob echoes whether multi-job was enabled.
	AllowCrossJob bool `json:"allow_cross_job"`
	// Clusters are normalized-signature groups sorted by count desc, then signature.
	Clusters []SurveyFailureCluster `json:"clusters"`
	// BuildsWithoutSignature are failed/unstable builds that yielded no extract hits.
	BuildsWithoutSignature []SurveyExampleBuild `json:"builds_without_signature,omitempty"`
	Budgets                SurveyBudgets        `json:"budgets"`
	Sources                []string             `json:"sources,omitempty"`
	ConfidenceNotes        []string             `json:"confidence_notes,omitempty"`
	Residuals              []string             `json:"residuals,omitempty"`
	Incomplete             bool                 `json:"incomplete,omitempty"`
	Untrusted              bool                 `json:"untrusted"`
	Summary                string               `json:"summary"`
}

// registerSurveyRecentFailuresTool registers jenkins_survey_recent_failures (DIAG-006).
func registerSurveyRecentFailuresTool(s *mcp.Server, client *jenkins.Client, st regState) {
	addReadTool(s, st, &mcp.Tool{
		Name: ToolSurveyRecentFailures,
		Description: "Summarize recurring failure signatures across an approved job scope " +
			"(bounded lookback; failed/unstable only; clusters by exact then normalized signature). " +
			"Cross-job survey requires allow_cross_job=true. Prefer local logmirror when configured. " +
			"Never dumps full logs.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args SurveyRecentFailuresToolArgs) (*mcp.CallToolResult, SurveyRecentFailuresToolResponse, error) {
		out, err := runSurveyRecentFailures(ctx, client, st, args)
		if err != nil {
			return nil, SurveyRecentFailuresToolResponse{}, err
		}
		return structuredResult(out)
	})
}

func runSurveyRecentFailures(ctx context.Context, client *jenkins.Client, st regState, args SurveyRecentFailuresToolArgs) (SurveyRecentFailuresToolResponse, error) {
	if client == nil {
		return SurveyRecentFailuresToolResponse{}, apperr.New(apperr.CodeInternal, "jenkins client is nil")
	}

	maxJobs, maxPerJob, maxTotal, maxLogPer, maxLogTotal, maxClusters, maxWall := clampSurveyBudgets(args)

	// Wall-time budget via child context.
	var cancel context.CancelFunc
	if deadline, ok := ctx.Deadline(); ok {
		// Respect parent deadline; only tighten if maxWall is shorter remaining.
		remain := time.Until(deadline)
		if remain > 0 && time.Duration(maxWall)*time.Second < remain {
			ctx, cancel = context.WithTimeout(ctx, time.Duration(maxWall)*time.Second)
			defer cancel()
		}
	} else {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(maxWall)*time.Second)
		defer cancel()
	}

	out := SurveyRecentFailuresToolResponse{
		JobPrefix:     strings.Trim(strings.TrimSpace(args.JobPrefix), "/"),
		AllowCrossJob: args.AllowCrossJob,
		Untrusted:     true,
		Budgets: SurveyBudgets{
			MaxJobs:             maxJobs,
			MaxBuildsPerJob:     maxPerJob,
			MaxTotalBuilds:      maxTotal,
			MaxLogBytesPerBuild: maxLogPer,
			MaxLogBytesTotal:    maxLogTotal,
			MaxClusters:         maxClusters,
			MaxWallSeconds:      maxWall,
		},
		ConfidenceNotes: []string{
			"clusters are heuristic signature groups from bounded log tails; not a proven root cause",
			"only FAILURE/UNSTABLE completed builds are considered",
			"cross-job survey is disabled by default (set allow_cross_job=true)",
		},
		Residuals: surveyCacheResiduals(st),
	}

	jobs, scopeNotes, sources, err := resolveSurveyScope(ctx, client, args, maxJobs)
	if err != nil {
		return SurveyRecentFailuresToolResponse{}, err
	}
	out.ConfidenceNotes = append(out.ConfidenceNotes, scopeNotes...)
	out.Sources = append(out.Sources, sources...)
	out.ScopeJobs = jobs
	out.Budgets.JobsInScope = len(jobs)

	if len(jobs) == 0 {
		out.Summary = "no jobs in survey scope"
		out.ConfidenceNotes = append(out.ConfidenceNotes, "empty scope after job_names/job_prefix resolution")
		return out, nil
	}
	if len(jobs) > 1 && !args.AllowCrossJob {
		return SurveyRecentFailuresToolResponse{}, invalidArg(
			"cross-job survey is disabled by default; set allow_cross_job=true when surveying more than one job " +
				fmt.Sprintf("(resolved %d jobs)", len(jobs)))
	}

	// Occurrence collectors for clustering (exact then normalized).
	var occurrences []surveyOcc
	var noSig []SurveyExampleBuild
	logTotal := 0
	budgetHit := false
	buildsExtracted := 0
	buildsListed := 0
	cacheHits := 0
	cacheMisses := 0
	jobsSurveyed := 0

	cache := surveyCache()
	profile := st.profileID

outer:
	for _, job := range jobs {
		select {
		case <-ctx.Done():
			budgetHit = true
			out.Incomplete = true
			out.ConfidenceNotes = append(out.ConfidenceNotes, "survey cancelled: "+safeErrNote(ctx.Err()))
			break outer
		default:
		}
		if buildsExtracted >= maxTotal || logTotal >= maxLogTotal {
			budgetHit = true
			out.Incomplete = true
			break outer
		}

		// Compact history first (JEN-003); filter failed/unstable client-side.
		lookback := maxPerJob * 3
		if lookback < maxPerJob {
			lookback = maxPerJob
		}
		if lookback > 100 {
			lookback = 100
		}
		hist, herr := client.ListBuilds(ctx, jenkins.ListBuildsToolArgs{
			JobName:     job,
			Limit:       lookback,
			MaxLookback: lookback,
		})
		if herr != nil {
			out.ConfidenceNotes = append(out.ConfidenceNotes,
				fmt.Sprintf("list_builds for %s failed: %s", job, safeErrNote(herr)))
			out.Incomplete = true
			continue
		}
		out.Sources = append(out.Sources, "list_builds")
		jobsSurveyed++

		var candidates []jenkins.Build
		if hist != nil {
			for _, b := range hist.Builds {
				if b.Building {
					continue
				}
				if !isSurveyFailureResult(b.Result) {
					continue
				}
				candidates = append(candidates, b)
				if len(candidates) >= maxPerJob {
					break
				}
			}
			if hist.Truncated {
				out.Incomplete = true
				out.ConfidenceNotes = append(out.ConfidenceNotes,
					fmt.Sprintf("%s: build history truncated by lookback", job))
			}
		}
		buildsListed += len(candidates)

		for _, b := range candidates {
			select {
			case <-ctx.Done():
				budgetHit = true
				out.Incomplete = true
				out.ConfidenceNotes = append(out.ConfidenceNotes, "survey cancelled: "+safeErrNote(ctx.Err()))
				break outer
			default:
			}
			if buildsExtracted >= maxTotal {
				budgetHit = true
				out.Incomplete = true
				out.ConfidenceNotes = append(out.ConfidenceNotes, "max_total_builds exhausted")
				break outer
			}
			if logTotal >= maxLogTotal {
				budgetHit = true
				out.Incomplete = true
				out.ConfidenceNotes = append(out.ConfidenceNotes, "max_log_bytes_total exhausted")
				break outer
			}

			remain := maxLogTotal - logTotal
			per := maxLogPer
			if per > remain {
				per = remain
			}

			summary, hit, notes, src := loadSurveyBuildSummary(ctx, client, st, cache, profile, job, b, per)
			if hit {
				cacheHits++
			} else {
				cacheMisses++
			}
			if src != "" {
				out.Sources = append(out.Sources, src)
			}
			out.ConfidenceNotes = append(out.ConfidenceNotes, notes...)
			logTotal += summary.LogBytes
			buildsExtracted++
			if summary.Incomplete {
				out.Incomplete = true
			}
			if len(summary.Findings) == 0 {
				noSig = append(noSig, SurveyExampleBuild{Job: job, Build: b.Number, Result: b.Result})
				continue
			}
			for _, f := range summary.Findings {
				occurrences = append(occurrences, surveyOcc{
					job:        job,
					build:      b.Number,
					result:     b.Result,
					pattern:    f.Pattern,
					message:    f.Message,
					normalized: f.Normalized,
					exactSig:   f.ExactSignature,
					normSig:    f.Signature,
					excerpt:    f.EvidenceExcerpt,
					confidence: f.Confidence,
				})
			}
		}
	}

	out.Budgets.JobsSurveyed = jobsSurveyed
	out.Budgets.BuildsListed = buildsListed
	out.Budgets.BuildsExtracted = buildsExtracted
	out.Budgets.LogBytesScanned = logTotal
	out.Budgets.CacheHits = cacheHits
	out.Budgets.CacheMisses = cacheMisses
	out.Budgets.BudgetExhausted = budgetHit

	// Cluster: exact signature first (variant tracking), then roll up by normalized signature.
	out.Clusters = clusterSurveyOccurrences(occurrences, maxClusters)
	if len(noSig) > DefaultSurveyMaxExamplesPerCluster*2 {
		noSig = noSig[:DefaultSurveyMaxExamplesPerCluster*2]
	}
	out.BuildsWithoutSignature = noSig
	out.Sources = uniqueStrings(out.Sources)
	out.ConfidenceNotes = uniqueStrings(out.ConfidenceNotes)
	out.Summary = buildSurveySummary(out)
	return out, nil
}

func clampSurveyBudgets(args SurveyRecentFailuresToolArgs) (maxJobs, maxPerJob, maxTotal, maxLogPer, maxLogTotal, maxClusters, maxWall int) {
	maxJobs = args.MaxJobs
	if maxJobs <= 0 {
		maxJobs = DefaultSurveyMaxJobs
	}
	if maxJobs > HardSurveyMaxJobs {
		maxJobs = HardSurveyMaxJobs
	}
	maxPerJob = args.MaxBuildsPerJob
	if maxPerJob <= 0 {
		maxPerJob = DefaultSurveyMaxBuildsPerJob
	}
	if maxPerJob > HardSurveyMaxBuildsPerJob {
		maxPerJob = HardSurveyMaxBuildsPerJob
	}
	maxTotal = args.MaxTotalBuilds
	if maxTotal <= 0 {
		maxTotal = DefaultSurveyMaxTotalBuilds
	}
	if maxTotal > HardSurveyMaxTotalBuilds {
		maxTotal = HardSurveyMaxTotalBuilds
	}
	maxLogPer = args.MaxLogBytesPerBuild
	if maxLogPer <= 0 {
		maxLogPer = DefaultSurveyMaxLogBytesPerBuild
	}
	if maxLogPer > HardSurveyMaxLogBytesPerBuild {
		maxLogPer = HardSurveyMaxLogBytesPerBuild
	}
	maxLogTotal = args.MaxLogBytesTotal
	if maxLogTotal <= 0 {
		maxLogTotal = DefaultSurveyMaxLogBytesTotal
	}
	if maxLogTotal > HardSurveyMaxLogBytesTotal {
		maxLogTotal = HardSurveyMaxLogBytesTotal
	}
	maxClusters = args.MaxClusters
	if maxClusters <= 0 {
		maxClusters = DefaultSurveyMaxClusters
	}
	if maxClusters > HardSurveyMaxClusters {
		maxClusters = HardSurveyMaxClusters
	}
	maxWall = args.MaxWallSeconds
	if maxWall <= 0 {
		maxWall = DefaultSurveyMaxWallSeconds
	}
	if maxWall > HardSurveyMaxWallSeconds {
		maxWall = HardSurveyMaxWallSeconds
	}
	return
}

// resolveSurveyScope returns ordered unique job full names within maxJobs.
//
// Matching rules:
//   - job_names: each entry is validated as a typed full name (not a URL)
//   - job_prefix: ListJobs with FolderPrefix; full name equals prefix or has prefix+"/" path prefix
//   - union when both provided; stable sorted order for determinism
func resolveSurveyScope(ctx context.Context, client *jenkins.Client, args SurveyRecentFailuresToolArgs, maxJobs int) (jobs []string, notes []string, sources []string, err error) {
	prefix := strings.Trim(strings.TrimSpace(args.JobPrefix), "/")
	seen := make(map[string]struct{})
	var ordered []string

	add := func(name string) error {
		name = strings.TrimSpace(name)
		if name == "" {
			return nil
		}
		n, jerr := jobFullName("job_names", name)
		if jerr != nil {
			// Reuse jobFullName validation but attribute to the right field when prefix.
			return jerr
		}
		if _, ok := seen[n]; ok {
			return nil
		}
		seen[n] = struct{}{}
		ordered = append(ordered, n)
		return nil
	}

	if len(args.JobNames) == 0 && prefix == "" {
		return nil, nil, nil, invalidArg("at least one of job_names or job_prefix is required")
	}

	for _, n := range args.JobNames {
		if err := add(n); err != nil {
			return nil, nil, nil, err
		}
	}

	if prefix != "" {
		if strings.Contains(prefix, "://") {
			return nil, nil, nil, invalidArg("job_prefix must be a typed path, not a URL")
		}
		// Also include the prefix itself when it is a concrete job (not only children).
		_ = add(prefix)
		lj, lerr := client.ListJobs(ctx, jenkins.ListJobsToolArgs{
			FolderPrefix: prefix,
			Limit:        maxJobs,
			MaxDepth:     4,
		})
		if lerr != nil {
			// Prefix alone may still be a valid single job if ListJobs fails (e.g. leaf job path).
			notes = append(notes, "list_jobs for job_prefix failed: "+safeErrNote(lerr)+"; using explicit/prefix names only")
		} else {
			sources = append(sources, "list_jobs")
			if lj != nil {
				for _, j := range lj.Jobs {
					if j.FullName == "" {
						continue
					}
					if !jobMatchesPrefix(j.FullName, prefix) {
						continue
					}
					// Skip pure containers if kind is folder-like with no builds — still allow;
					// survey will no-op on missing history.
					if err := add(j.FullName); err != nil {
						return nil, nil, nil, err
					}
					if len(ordered) >= maxJobs {
						break
					}
				}
				if lj.Truncated {
					notes = append(notes, "list_jobs truncated; job scope may be incomplete")
				}
			}
		}
	}

	if len(ordered) > maxJobs {
		notes = append(notes, fmt.Sprintf("job scope truncated to max_jobs=%d", maxJobs))
		ordered = ordered[:maxJobs]
	}
	// Stable order for deterministic clustering examples.
	sort.Strings(ordered)
	return ordered, notes, sources, nil
}

// jobMatchesPrefix reports whether fullName equals prefix or is under prefix/.
func jobMatchesPrefix(fullName, prefix string) bool {
	fullName = strings.Trim(strings.TrimSpace(fullName), "/")
	prefix = strings.Trim(strings.TrimSpace(prefix), "/")
	if prefix == "" {
		return true
	}
	return fullName == prefix || strings.HasPrefix(fullName, prefix+"/")
}

func isSurveyFailureResult(result string) bool {
	switch strings.ToUpper(strings.TrimSpace(result)) {
	case "FAILURE", "UNSTABLE":
		return true
	default:
		return false
	}
}

func surveyCacheResiduals(st regState) []string {
	if st.meta != nil {
		return []string{
			"durable compact survey summary cache active (profile Meta schema v7; hashes + short redacted text only; never log bodies)",
			"cross-process durable cache only when profile store is open; cold start without Meta still process-scoped TTL only",
		}
	}
	return []string{
		"no profile Meta/data dir for survey; process-scoped TTL cache only (durable compact cache residual when store closed)",
	}
}

func loadSurveyBuildSummary(
	ctx context.Context,
	client *jenkins.Client,
	st regState,
	cache *surveySigCache,
	profile, job string,
	b jenkins.Build,
	maxLog int,
) (summary surveyBuildSummary, cacheHit bool, notes []string, source string) {
	key := surveyCacheKey(profile, job, b.Number, maxLog)
	if cache != nil {
		if cached, ok := cache.get(key); ok {
			// Refresh result from listing when present.
			if b.Result != "" {
				cached.Result = b.Result
			}
			return cached, true, nil, "survey_cache"
		}
	}

	// Durable L2: profile Meta survey_summary_cache (schema v7).
	if st.meta != nil {
		if dur, ok := loadDurableSurveySummary(ctx, st.meta, profile, job, b.Number, maxLog); ok {
			if b.Result != "" {
				dur.Result = b.Result
			}
			if cache != nil {
				cache.put(key, dur)
			}
			return dur, true, nil, "survey_cache_durable"
		}
	}

	findings, logBytes, src, incomplete, nts := extractBuildSignatures(ctx, client, st, job, b.Number, maxLog, DefaultSurveyMaxFindingsPerBuild)
	// extractBuildSignatures already sanitizes Message/Evidence via redact.
	compact := make([]surveyFindingCompact, 0, len(findings))
	for _, f := range findings {
		// Re-extract normalized preimage for cluster reporting (from sanitized message).
		norm := diagnostics.NormalizeLine(f.Message)
		if norm == "" {
			norm = f.Message
		}
		exactPre := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(f.Message, "\r", "")))
		exactSig := diagnostics.Signature(exactPre)
		excerpt := f.Message
		if len(f.Evidence) > 0 {
			excerpt = f.Evidence[0].Text
		}
		// Compact + re-redact before any cache write (process or durable).
		compact = append(compact, surveyFindingCompact{
			Signature:       f.Signature,
			Pattern:         f.Pattern,
			Message:         redact.SanitizeForModel(truncateDiagnoseText(f.Message, store.SurveyCacheMaxTextField)),
			Normalized:      redact.SanitizeForModel(truncateDiagnoseText(norm, store.SurveyCacheMaxTextField)),
			ExactSignature:  exactSig,
			EvidenceExcerpt: redact.SanitizeForModel(truncateDiagnoseText(excerpt, store.SurveyCacheMaxTextField)),
			Confidence:      f.Confidence,
			Count:           f.Count,
		})
	}
	summary = surveyBuildSummary{
		Job:        job,
		Build:      b.Number,
		Result:     b.Result,
		Findings:   compact,
		Source:     src,
		LogBytes:   logBytes,
		Incomplete: incomplete,
	}
	// Do not sticky-cache incomplete extracts (budget/cancel/partial tail) for
	// the full TTL — that under-clusters real failures until expiry (Wave 28 review).
	if !incomplete {
		if cache != nil {
			cache.put(key, summary)
		}
		if st.meta != nil {
			putDurableSurveySummary(ctx, st.meta, profile, summary, maxLog)
		}
	}
	return summary, false, nts, src
}

func loadDurableSurveySummary(
	ctx context.Context,
	meta *store.Meta,
	profile, job string,
	build, maxLog int,
) (surveyBuildSummary, bool) {
	if meta == nil {
		return surveyBuildSummary{}, false
	}
	if err := ctx.Err(); err != nil {
		return surveyBuildSummary{}, false
	}
	if profile == "" {
		profile = "_"
	}
	entry, err := meta.GetSurveySummary(ctx, store.SurveyCacheKey{
		Profile: profile, Job: job, Build: int64(build), MaxLogBytes: maxLog,
	})
	if err != nil || entry == nil {
		// Fail closed: treat errors as miss (re-fetch).
		return surveyBuildSummary{}, false
	}
	findings := make([]surveyFindingCompact, 0, len(entry.Findings))
	for _, f := range entry.Findings {
		// Defense in depth: re-sanitize on read.
		findings = append(findings, surveyFindingCompact{
			Signature:       f.Signature,
			Pattern:         f.Pattern,
			Message:         redact.SanitizeForModel(f.Message),
			Normalized:      redact.SanitizeForModel(f.Normalized),
			ExactSignature:  f.ExactSignature,
			EvidenceExcerpt: redact.SanitizeForModel(f.EvidenceExcerpt),
			Confidence:      f.Confidence,
			Count:           f.Count,
		})
	}
	return surveyBuildSummary{
		Job:        job,
		Build:      build,
		Result:     entry.Result,
		Findings:   findings,
		Source:     entry.Source,
		LogBytes:   entry.LogBytes,
		Incomplete: entry.Incomplete,
	}, true
}

func putDurableSurveySummary(ctx context.Context, meta *store.Meta, profile string, summary surveyBuildSummary, maxLog int) {
	if meta == nil || maxLog <= 0 || summary.Build <= 0 {
		return
	}
	if err := ctx.Err(); err != nil {
		return
	}
	if profile == "" {
		profile = "_"
	}
	findings := make([]store.SurveyCacheFinding, 0, len(summary.Findings))
	for _, f := range summary.Findings {
		findings = append(findings, store.SurveyCacheFinding{
			Signature:       f.Signature,
			Pattern:         f.Pattern,
			Message:         redact.SanitizeForModel(truncateDiagnoseText(f.Message, store.SurveyCacheMaxTextField)),
			Normalized:      redact.SanitizeForModel(truncateDiagnoseText(f.Normalized, store.SurveyCacheMaxTextField)),
			ExactSignature:  f.ExactSignature,
			EvidenceExcerpt: redact.SanitizeForModel(truncateDiagnoseText(f.EvidenceExcerpt, store.SurveyCacheMaxTextField)),
			Confidence:      f.Confidence,
			Count:           f.Count,
		})
	}
	_ = meta.PutSurveySummary(ctx, &store.SurveyCacheEntry{
		Key: store.SurveyCacheKey{
			Profile: profile, Job: summary.Job, Build: int64(summary.Build), MaxLogBytes: maxLog,
		},
		Result:     summary.Result,
		Source:     summary.Source,
		LogBytes:   summary.LogBytes,
		Incomplete: summary.Incomplete,
		Findings:   findings,
	}, DefaultSurveyCacheTTL, DefaultSurveyCacheMaxEntries)
}

type surveyOcc struct {
	job, result, pattern, message, normalized, exactSig, normSig, excerpt string
	build                                                                 int
	confidence                                                            float64
}

func clusterSurveyOccurrences(occurrences []surveyOcc, maxClusters int) []SurveyFailureCluster {
	type agg struct {
		normSig, pattern, message, normalized, excerpt string
		count                                          int
		confidence                                     float64
		exactSet                                       map[string]struct{}
		examples                                       []SurveyExampleBuild
		jobs                                           map[string]struct{}
		// seen (job,build) so one build with multi findings of same sig counts once per sig
		seenBuilds map[string]struct{}
	}
	byNorm := make(map[string]*agg)
	order := make([]string, 0)

	for _, o := range occurrences {
		if o.normSig == "" {
			continue
		}
		a, ok := byNorm[o.normSig]
		if !ok {
			a = &agg{
				normSig:    o.normSig,
				pattern:    o.pattern,
				message:    o.message,
				normalized: o.normalized,
				excerpt:    o.excerpt,
				confidence: o.confidence,
				exactSet:   make(map[string]struct{}),
				jobs:       make(map[string]struct{}),
				seenBuilds: make(map[string]struct{}),
			}
			byNorm[o.normSig] = a
			order = append(order, o.normSig)
		}
		bk := o.job + "#" + strconv.Itoa(o.build)
		if _, seen := a.seenBuilds[bk]; !seen {
			a.seenBuilds[bk] = struct{}{}
			a.count++
			if len(a.examples) < DefaultSurveyMaxExamplesPerCluster {
				a.examples = append(a.examples, SurveyExampleBuild{
					Job: o.job, Build: o.build, Result: o.result,
				})
			}
			a.jobs[o.job] = struct{}{}
		}
		if o.exactSig != "" {
			a.exactSet[o.exactSig] = struct{}{}
		}
		if o.confidence > a.confidence {
			a.confidence = o.confidence
		}
		// Prefer higher-confidence message as representative.
		if o.confidence >= a.confidence && o.message != "" {
			a.message = o.message
			if o.excerpt != "" {
				a.excerpt = o.excerpt
			}
			if o.pattern != "" {
				a.pattern = o.pattern
			}
			if o.normalized != "" {
				a.normalized = o.normalized
			}
		}
	}

	// Sort by count desc, then signature asc.
	sort.SliceStable(order, func(i, j int) bool {
		ai, aj := byNorm[order[i]], byNorm[order[j]]
		if ai.count != aj.count {
			return ai.count > aj.count
		}
		return order[i] < order[j]
	})
	if maxClusters > 0 && len(order) > maxClusters {
		order = order[:maxClusters]
	}

	out := make([]SurveyFailureCluster, 0, len(order))
	for _, sig := range order {
		a := byNorm[sig]
		jobs := make([]string, 0, len(a.jobs))
		for j := range a.jobs {
			jobs = append(jobs, j)
		}
		sort.Strings(jobs)
		// Bound jobs list size.
		if len(jobs) > DefaultSurveyMaxExamplesPerCluster {
			jobs = jobs[:DefaultSurveyMaxExamplesPerCluster]
		}
		out = append(out, SurveyFailureCluster{
			Signature:           a.normSig,
			Normalized:          a.normalized,
			NormalizationMethod: NormalizationMethodDiag001,
			Pattern:             a.pattern,
			Count:               a.count,
			ExactVariantCount:   len(a.exactSet),
			Message:             a.message,
			EvidenceExcerpt:     a.excerpt,
			Examples:            a.examples,
			Jobs:                jobs,
			Confidence:          a.confidence,
		})
	}
	return out
}

func buildSurveySummary(out SurveyRecentFailuresToolResponse) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("jobs=%d builds_extracted=%d clusters=%d",
		out.Budgets.JobsInScope, out.Budgets.BuildsExtracted, len(out.Clusters)))
	if out.Budgets.CacheHits > 0 {
		parts = append(parts, fmt.Sprintf("cache_hits=%d", out.Budgets.CacheHits))
	}
	if len(out.Clusters) > 0 {
		top := out.Clusters[0]
		parts = append(parts, fmt.Sprintf("top_sig=%s count=%d pattern=%s",
			top.Signature, top.Count, top.Pattern))
	} else {
		parts = append(parts, "no failure signatures clustered")
	}
	if out.Budgets.BudgetExhausted {
		parts = append(parts, "budget_exhausted")
	}
	return strings.Join(parts, "; ")
}
