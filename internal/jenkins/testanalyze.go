package jenkins

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// Bounds for flaky/new-failure analysis (TEST-002).
const (
	DefaultTestLookback       = 10
	MaxTestLookback           = 50
	DefaultMaxClassifications = 50
	MaxClassificationsHardCap = 100
	maxCompactCasesPerBuild   = 500
	// DurationRegressionFactor flags cases whose duration exceeds factor × baseline median.
	DurationRegressionFactor = 2.0
	// MinDurationBaselineSec avoids noise on sub-second cases.
	MinDurationBaselineSec = 0.5
)

// TestIdentity matching rules (TEST-002):
//
//   - Primary key is ClassName + "/" + Name (exact string match).
//   - When ClassName is empty, Name alone is the key.
//   - Parameterized tests (JUnit name with [params]) match only when the full
//     case name string is identical across builds — renames are treated as
//     distinct tests (documented; no fuzzy rename matching).
func TestCaseKey(className, name string) string {
	className = strings.TrimSpace(className)
	name = strings.TrimSpace(name)
	if className == "" {
		return name
	}
	return className + "/" + name
}

// CompactCaseOutcome is one case status without stack traces (history cache unit).
type CompactCaseOutcome struct {
	Key       string `json:"key"`
	Name      string `json:"name"`
	ClassName string `json:"className,omitempty"`
	Status    string `json:"status"`
	// DurationSec is the case duration in seconds (Jenkins JUnit unit).
	DurationSec float64 `json:"durationSec,omitempty"`
	Failed      bool    `json:"failed"`
}

// CompactBuildTests is a bounded per-build case outcome set for history lookback.
type CompactBuildTests struct {
	BuildNumber int                  `json:"buildNumber"`
	Available   bool                 `json:"available"`
	Cases       []CompactCaseOutcome `json:"cases,omitempty"`
	// Truncated is true when more cases existed than maxCompactCasesPerBuild.
	Truncated bool `json:"truncated,omitempty"`
}

// TestClassificationKind is a stable classification label.
type TestClassificationKind string

const (
	ClassNewFailure         TestClassificationKind = "new_failure"
	ClassFlaky              TestClassificationKind = "flaky"
	ClassKnownFailure       TestClassificationKind = "known_failure"
	ClassDurationRegression TestClassificationKind = "duration_regression"
)

// Confidence is a coarse sample-size based confidence (not binary certainty).
type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// TestClassification is one classified failure (or duration regression) case.
type TestClassification struct {
	Name        string                 `json:"name"`
	ClassName   string                 `json:"className,omitempty"`
	Key         string                 `json:"key"`
	Kind        TestClassificationKind `json:"kind"`
	Confidence  Confidence             `json:"confidence"`
	SampleSize  int                    `json:"sampleSize"` // history builds that had this case
	FailCount   int                    `json:"failCount"`  // fails in lookback (excluding current)
	PassCount   int                    `json:"passCount"`  // passes in lookback
	CurrentAge  int                    `json:"currentAge,omitempty"`
	DurationSec float64                `json:"durationSec,omitempty"`
	BaselineSec float64                `json:"baselineSec,omitempty"` // median of historical pass durations
	Message     string                 `json:"message,omitempty"`
}

// TestAnalysis is the bounded result of jenkins_analyze_tests (TEST-002).
type TestAnalysis struct {
	JobName          string               `json:"jobName"`
	BuildNumber      int                  `json:"buildNumber"`
	Lookback         int                  `json:"lookback"`
	SampleSize       int                  `json:"sampleSize"` // history builds successfully consulted
	CurrentAvailable bool                 `json:"currentAvailable"`
	CurrentFailCount int                  `json:"currentFailCount"`
	Classifications  []TestClassification `json:"classifications,omitempty"`
	// Truncated when more classifications existed than returned.
	Truncated bool   `json:"truncated,omitempty"`
	Message   string `json:"message,omitempty"`
	// HistoryTruncated when some lookback builds could not be fetched.
	HistoryTruncated bool `json:"historyTruncated,omitempty"`
}

// AnalyzeTestsToolArgs are tool arguments for jenkins_analyze_tests.
type AnalyzeTestsToolArgs struct {
	JobName     string `json:"job_name" jsonschema:"Name/path of the Jenkins job (supports folders)"`
	BuildNumber int    `json:"build_number" jsonschema:"Build number to analyze"`
	// Lookback is how many prior builds to consult (default 10, max 50).
	Lookback int `json:"lookback,omitempty" jsonschema:"Prior builds to consult for history (default: 10, max: 50)" default:"10"`
	// MaxResults caps classifications returned (default 50, max 100).
	MaxResults int `json:"max_results,omitempty" jsonschema:"Maximum classifications to return (default: 50, max: 100)" default:"50"`
}

// AnalyzeTestsToolResponse is returned by jenkins_analyze_tests.
type AnalyzeTestsToolResponse = TestAnalysis

// AnalyzeTests fetches the current report + compact prior history and classifies
// failures (TEST-002). Lookback and result counts are hard-capped; full history
// is never dumped.
func (opts *Client) AnalyzeTests(ctx context.Context, jobName string, buildNumber, lookback, maxResults int) (*TestAnalysis, error) {
	if opts == nil {
		return nil, fmt.Errorf("jenkins client is nil")
	}
	if strings.TrimSpace(jobName) == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "job_name is required")
	}
	if buildNumber <= 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument, "build_number must be positive")
	}
	lookback, maxResults = normalizeAnalyzeBounds(lookback, maxResults)

	// Current full report (failures with details for age).
	current, err := opts.GetTestReport(ctx, jobName, buildNumber, MaxFailedTestsHardCap)
	if err != nil {
		return nil, err
	}

	history, histTrunc, err := opts.fetchCompactHistory(ctx, jobName, buildNumber, lookback)
	if err != nil {
		return nil, err
	}

	out := AnalyzeTestFailures(jobName, buildNumber, lookback, current, history, maxResults)
	out.HistoryTruncated = histTrunc
	return out, nil
}

func normalizeAnalyzeBounds(lookback, maxResults int) (int, int) {
	if lookback <= 0 {
		lookback = DefaultTestLookback
	}
	if lookback > MaxTestLookback {
		lookback = MaxTestLookback
	}
	if maxResults <= 0 {
		maxResults = DefaultMaxClassifications
	}
	if maxResults > MaxClassificationsHardCap {
		maxResults = MaxClassificationsHardCap
	}
	return lookback, maxResults
}

// fetchCompactHistory loads compact case outcomes for builds (buildNumber-1 .. buildNumber-lookback).
func (opts *Client) fetchCompactHistory(ctx context.Context, jobName string, buildNumber, lookback int) ([]CompactBuildTests, bool, error) {
	out := make([]CompactBuildTests, 0, lookback)
	truncated := false
	for i := 1; i <= lookback; i++ {
		bn := buildNumber - i
		if bn <= 0 {
			break
		}
		if err := ctx.Err(); err != nil {
			return out, true, err
		}
		c, err := opts.GetCompactTestOutcomes(ctx, jobName, bn)
		if err != nil {
			// Capability missing should fail the whole analysis (consistent with current).
			if apperr.IsCode(err, apperr.CodeCapabilityMissing) ||
				apperr.IsCode(err, apperr.CodeAuthentication) ||
				apperr.IsCode(err, apperr.CodeAuthorization) {
				return nil, false, err
			}
			// Transient / not-found builds: skip and note truncation.
			truncated = true
			continue
		}
		out = append(out, *c)
	}
	return out, truncated, nil
}

// GetCompactTestOutcomes fetches case statuses for history without error stacks.
// Missing reports return Available=false (not an error).
func (opts *Client) GetCompactTestOutcomes(ctx context.Context, jobName string, buildNumber int) (*CompactBuildTests, error) {
	if opts == nil {
		return nil, fmt.Errorf("jenkins client is nil")
	}
	if strings.TrimSpace(jobName) == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "job_name is required")
	}
	if buildNumber <= 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument, "build_number must be positive")
	}

	caps, err := opts.Capabilities(ctx)
	if err != nil {
		return nil, err
	}
	if !caps.HasJUnit {
		return nil, apperr.New(apperr.CodeCapabilityMissing,
			"JUnit test results are not available on this Jenkins controller")
	}

	jobPath := BuildJobPath(jobName)
	// Compact tree: status + duration only (no error text).
	tree := "failCount,passCount,skipCount," +
		"suites[cases[name,className,status,duration,skipped]]"
	apiPath := fmt.Sprintf("%s/%d/testReport/api/json?tree=%s", jobPath, buildNumber, tree)

	resp, err := opts.CallJenkins(ctx, opts.Client, http.MethodGet, apiPath, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch compact test report: %w", err)
	}
	defer resp.Body.Close()

	body, err := readLimited(resp.Body, maxTestReportBodyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read compact test report: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		// continue
	case http.StatusNotFound:
		return &CompactBuildTests{BuildNumber: buildNumber, Available: false}, nil
	case http.StatusUnauthorized:
		return nil, apperr.New(apperr.CodeAuthentication, "not authenticated for test report")
	case http.StatusForbidden:
		return nil, apperr.New(apperr.CodeAuthorization, "not authorized to read test report")
	default:
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, truncateForErr(string(body)))
	}

	var raw junitCompactJSON
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, apperr.Wrap(apperr.CodeUpstreamProtocol, "invalid compact test report JSON", err)
	}

	out := &CompactBuildTests{BuildNumber: buildNumber, Available: true}
	cases := make([]CompactCaseOutcome, 0, 64)
	truncated := false
	for _, suite := range raw.Suites {
		for _, c := range suite.Cases {
			if len(cases) >= maxCompactCasesPerBuild {
				truncated = true
				break
			}
			st := strings.ToUpper(strings.TrimSpace(c.Status))
			if c.Skipped {
				st = "SKIPPED"
			}
			failed := isFailedStatus(st, c.Skipped)
			key := TestCaseKey(c.ClassName, c.Name)
			if key == "" {
				continue
			}
			cases = append(cases, CompactCaseOutcome{
				Key:         key,
				Name:        c.Name,
				ClassName:   c.ClassName,
				Status:      st,
				DurationSec: c.Duration,
				Failed:      failed,
			})
		}
		if truncated {
			break
		}
	}
	out.Cases = cases
	out.Truncated = truncated
	return out, nil
}

type junitCompactJSON struct {
	FailCount int `json:"failCount"`
	PassCount int `json:"passCount"`
	SkipCount int `json:"skipCount"`
	Suites    []struct {
		Cases []struct {
			Name      string  `json:"name"`
			ClassName string  `json:"className"`
			Status    string  `json:"status"`
			Duration  float64 `json:"duration"`
			Skipped   bool    `json:"skipped"`
		} `json:"cases"`
	} `json:"suites"`
}

func isFailedStatus(st string, skipped bool) bool {
	if skipped {
		return false
	}
	switch st {
	case "FAILED", "REGRESSION":
		return true
	case "PASSED", "SKIPPED", "SUCCESS", "FIXED":
		return false
	}
	return false
}

// AnalyzeTestFailures classifies current failures against compact history (pure; TEST-002).
// history is ordered newest-prior first (build-1, build-2, ...) but order is not required.
func AnalyzeTestFailures(
	jobName string,
	buildNumber int,
	lookback int,
	current *TestReport,
	history []CompactBuildTests,
	maxResults int,
) *TestAnalysis {
	lookback, maxResults = normalizeAnalyzeBounds(lookback, maxResults)
	out := &TestAnalysis{
		JobName:     jobName,
		BuildNumber: buildNumber,
		Lookback:    lookback,
	}
	if current == nil || !current.Available {
		out.CurrentAvailable = false
		out.Message = "no test report for this build"
		if current != nil && current.Message != "" {
			out.Message = current.Message
		}
		return out
	}
	out.CurrentAvailable = true
	out.CurrentFailCount = current.FailCount

	// Index history by test key.
	type histAgg struct {
		sample   int
		fails    int
		passes   int
		passDurs []float64
	}
	agg := make(map[string]*histAgg)
	sampleBuilds := 0
	for _, b := range history {
		if !b.Available {
			continue
		}
		sampleBuilds++
		seen := make(map[string]struct{})
		for _, c := range b.Cases {
			if c.Key == "" {
				continue
			}
			if _, ok := seen[c.Key]; ok {
				continue
			}
			seen[c.Key] = struct{}{}
			a := agg[c.Key]
			if a == nil {
				a = &histAgg{}
				agg[c.Key] = a
			}
			a.sample++
			if c.Failed {
				a.fails++
			} else if isPassStatus(c.Status) {
				a.passes++
				if c.DurationSec > 0 {
					a.passDurs = append(a.passDurs, c.DurationSec)
				}
			}
		}
	}
	out.SampleSize = sampleBuilds

	classifications := make([]TestClassification, 0, len(current.FailedTests))
	for _, ft := range current.FailedTests {
		key := TestCaseKey(ft.ClassName, ft.Name)
		if key == "" {
			continue
		}
		a := agg[key]
		sample, fails, passes := 0, 0, 0
		var passDurs []float64
		if a != nil {
			sample, fails, passes = a.sample, a.fails, a.passes
			passDurs = a.passDurs
		}
		kind, msg := classifyFailure(sample, fails, passes)
		classifications = append(classifications, TestClassification{
			Name:        ft.Name,
			ClassName:   ft.ClassName,
			Key:         key,
			Kind:        kind,
			Confidence:  confidenceFor(sample),
			SampleSize:  sample,
			FailCount:   fails,
			PassCount:   passes,
			CurrentAge:  ft.Age,
			DurationSec: durationMSToSec(ft.Duration),
			Message:     msg,
		})

		// Optional duration regression (separate row when threshold exceeded).
		if baseline, ok := medianFloat(passDurs); ok && baseline >= MinDurationBaselineSec {
			cur := durationMSToSec(ft.Duration)
			if cur > baseline*DurationRegressionFactor {
				classifications = append(classifications, TestClassification{
					Name:        ft.Name,
					ClassName:   ft.ClassName,
					Key:         key,
					Kind:        ClassDurationRegression,
					Confidence:  confidenceFor(len(passDurs)),
					SampleSize:  len(passDurs),
					FailCount:   fails,
					PassCount:   passes,
					DurationSec: cur,
					BaselineSec: baseline,
					Message: fmt.Sprintf("duration %.2fs exceeds %.1fx baseline median %.2fs",
						cur, DurationRegressionFactor, baseline),
				})
			}
		}
	}

	// Deterministic order: kind priority then key.
	sort.SliceStable(classifications, func(i, j int) bool {
		pi, pj := kindPriority(classifications[i].Kind), kindPriority(classifications[j].Kind)
		if pi != pj {
			return pi < pj
		}
		return classifications[i].Key < classifications[j].Key
	})

	if len(classifications) > maxResults {
		out.Truncated = true
		classifications = classifications[:maxResults]
	}
	out.Classifications = classifications
	if len(classifications) == 0 && current.FailCount == 0 {
		out.Message = "no failed tests to classify"
	}
	return out
}

func classifyFailure(sample, fails, passes int) (TestClassificationKind, string) {
	if sample == 0 {
		return ClassNewFailure, "no prior samples in lookback (treat as new)"
	}
	if fails == 0 {
		return ClassNewFailure, "did not fail in lookback history"
	}
	if fails > 0 && passes > 0 {
		return ClassFlaky, "failed and passed within lookback"
	}
	// fails > 0 && passes == 0
	return ClassKnownFailure, "failed in all observed lookback samples"
}

func confidenceFor(sample int) Confidence {
	// sample is history builds (or pass-duration count for duration_regression).
	switch {
	case sample >= 8:
		return ConfidenceHigh
	case sample >= 3:
		return ConfidenceMedium
	default:
		return ConfidenceLow
	}
}

func kindPriority(k TestClassificationKind) int {
	switch k {
	case ClassNewFailure:
		return 0
	case ClassFlaky:
		return 1
	case ClassKnownFailure:
		return 2
	case ClassDurationRegression:
		return 3
	default:
		return 9
	}
}

func isPassStatus(st string) bool {
	switch strings.ToUpper(strings.TrimSpace(st)) {
	case "PASSED", "SUCCESS", "FIXED":
		return true
	default:
		return false
	}
}

func durationMSToSec(d DurationMS) float64 {
	return time.Duration(d).Seconds()
}

func medianFloat(vals []float64) (float64, bool) {
	if len(vals) == 0 {
		return 0, false
	}
	cp := append([]float64(nil), vals...)
	sort.Float64s(cp)
	n := len(cp)
	if n%2 == 1 {
		return cp[n/2], true
	}
	return (cp[n/2-1] + cp[n/2]) / 2, true
}
