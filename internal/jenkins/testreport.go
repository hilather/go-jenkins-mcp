package jenkins

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Bounds for JUnit test report retrieval (TEST-001).
const (
	DefaultMaxFailedTests    = 25
	MaxFailedTestsHardCap    = 100
	maxTestErrorMessageRunes = 2048
	maxTestReportBodyBytes   = 4 << 20 // 4 MiB
)

// FailedTest is a single failed (or regression) case with bounded error text.
type FailedTest struct {
	Name         string     `json:"name"`
	ClassName    string     `json:"className,omitempty"`
	Status       string     `json:"status,omitempty"`
	Duration     DurationMS `json:"duration"`
	Age          int        `json:"age,omitempty"`
	ErrorDetails string     `json:"errorDetails,omitempty"`
	// ErrorStackTrace is truncated; tool layer may further redact.
	ErrorStackTrace string `json:"errorStackTrace,omitempty"`
}

// TestReport is a bounded JUnit summary for a build (TEST-001).
type TestReport struct {
	JobName     string `json:"jobName"`
	BuildNumber int    `json:"buildNumber"`
	// Available is false when the build has no test report (not an invented success).
	Available   bool         `json:"available"`
	PassCount   int          `json:"passCount"`
	FailCount   int          `json:"failCount"`
	SkipCount   int          `json:"skipCount"`
	TotalCount  int          `json:"totalCount"`
	Duration    DurationMS   `json:"duration"`
	FailedTests []FailedTest `json:"failedTests,omitempty"`
	// FailedTestsTruncated is true when more failures exist than returned.
	FailedTestsTruncated bool   `json:"failedTestsTruncated,omitempty"`
	Message              string `json:"message,omitempty"`
}

// GetTestReportToolArgs are tool arguments for jenkins_get_test_report.
type GetTestReportToolArgs struct {
	JobName     string `json:"job_name" jsonschema:"Name/path of the Jenkins job (supports folders)"`
	BuildNumber int    `json:"build_number" jsonschema:"Build number"`
	// MaxFailed caps the failed-test list (default 25, hard max 100).
	MaxFailed int `json:"max_failed,omitempty" jsonschema:"Maximum failed tests to return (default: 25, max: 100)" default:"25"`
}

// GetTestReportToolResponse is the test report returned by jenkins_get_test_report.
type GetTestReportToolResponse = TestReport

// GetTestReport fetches and bounds the JUnit testReport API for a build (TEST-001).
// Missing reports return Available=false with a clear message (not invented success).
// When the JUnit capability is absent, returns CodeCapabilityMissing.
func (opts *Client) GetTestReport(ctx context.Context, jobName string, buildNumber, maxFailed int) (*TestReport, error) {
	if opts == nil {
		return nil, fmt.Errorf("jenkins client is nil")
	}
	if strings.TrimSpace(jobName) == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "job_name is required")
	}
	if buildNumber <= 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument, "build_number must be positive")
	}
	if maxFailed <= 0 {
		maxFailed = DefaultMaxFailedTests
	}
	if maxFailed > MaxFailedTestsHardCap {
		maxFailed = MaxFailedTestsHardCap
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
	// Tree selector: summary counts + case fields needed for failures only.
	// Suites may still be large; body is hard-capped and we filter client-side.
	tree := "failCount,passCount,skipCount,totalCount,duration," +
		"suites[name,cases[name,className,status,duration,errorDetails,errorStackTrace,age,skipped]]"
	apiPath := fmt.Sprintf("%s/%d/testReport/api/json?tree=%s", jobPath, buildNumber, tree)

	resp, err := opts.CallJenkins(ctx, opts.Client, http.MethodGet, apiPath, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch test report: %w", err)
	}
	defer resp.Body.Close()

	body, err := readLimited(resp.Body, maxTestReportBodyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read test report response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		// continue
	case http.StatusNotFound:
		// No test report for this build (or not a test-bearing job).
		return &TestReport{
			JobName:     jobName,
			BuildNumber: buildNumber,
			Available:   false,
			Message:     "no test report for this build",
		}, nil
	case http.StatusUnauthorized:
		return nil, apperr.New(apperr.CodeAuthentication, "not authenticated for test report")
	case http.StatusForbidden:
		return nil, apperr.New(apperr.CodeAuthorization, "not authorized to read test report")
	default:
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, truncateForErr(string(body)))
	}

	var raw junitReportJSON
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, apperr.Wrap(apperr.CodeUpstreamProtocol, "invalid test report JSON", err)
	}

	out := &TestReport{
		JobName:     jobName,
		BuildNumber: buildNumber,
		Available:   true,
		PassCount:   raw.PassCount,
		FailCount:   raw.FailCount,
		SkipCount:   raw.SkipCount,
		TotalCount:  raw.TotalCount,
		Duration:    DurationMS(time.Duration(raw.Duration * float64(time.Second))),
	}
	// Prefer server total when present; otherwise derive.
	if out.TotalCount == 0 && (out.PassCount+out.FailCount+out.SkipCount) > 0 {
		out.TotalCount = out.PassCount + out.FailCount + out.SkipCount
	}

	failed := make([]FailedTest, 0, maxFailed)
	truncated := false
	for _, suite := range raw.Suites {
		for _, c := range suite.Cases {
			if !isFailedCase(c) {
				continue
			}
			if len(failed) >= maxFailed {
				truncated = true
				break
			}
			failed = append(failed, FailedTest{
				Name:            c.Name,
				ClassName:       c.ClassName,
				Status:          c.Status,
				Duration:        DurationMS(time.Duration(c.Duration * float64(time.Second))),
				Age:             c.Age,
				ErrorDetails:    truncateRunes(c.ErrorDetails, maxTestErrorMessageRunes),
				ErrorStackTrace: truncateRunes(c.ErrorStackTrace, maxTestErrorMessageRunes),
			})
		}
		if truncated {
			break
		}
	}
	// If summary says failures exist but suite walk found none (tree clipped), note it.
	if out.FailCount > 0 && len(failed) == 0 {
		out.Message = "failure count present but case details unavailable in response"
	}
	if out.FailCount > len(failed) {
		truncated = true
	}
	out.FailedTests = failed
	out.FailedTestsTruncated = truncated
	return out, nil
}

type junitReportJSON struct {
	FailCount  int     `json:"failCount"`
	PassCount  int     `json:"passCount"`
	SkipCount  int     `json:"skipCount"`
	TotalCount int     `json:"totalCount"`
	Duration   float64 `json:"duration"`
	Suites     []struct {
		Name  string `json:"name"`
		Cases []struct {
			Name            string  `json:"name"`
			ClassName       string  `json:"className"`
			Status          string  `json:"status"`
			Duration        float64 `json:"duration"`
			ErrorDetails    string  `json:"errorDetails"`
			ErrorStackTrace string  `json:"errorStackTrace"`
			Age             int     `json:"age"`
			Skipped         bool    `json:"skipped"`
		} `json:"cases"`
	} `json:"suites"`
}

func isFailedCase(c struct {
	Name            string  `json:"name"`
	ClassName       string  `json:"className"`
	Status          string  `json:"status"`
	Duration        float64 `json:"duration"`
	ErrorDetails    string  `json:"errorDetails"`
	ErrorStackTrace string  `json:"errorStackTrace"`
	Age             int     `json:"age"`
	Skipped         bool    `json:"skipped"`
}) bool {
	if c.Skipped {
		return false
	}
	st := strings.ToUpper(strings.TrimSpace(c.Status))
	switch st {
	case "FAILED", "REGRESSION":
		return true
	case "PASSED", "SKIPPED", "SUCCESS", "FIXED":
		return false
	}
	// Some Jenkins versions use empty status with errorDetails for failures.
	return c.ErrorDetails != "" || c.ErrorStackTrace != ""
}

func truncateRunes(s string, max int) string {
	if max <= 0 || s == "" {
		return s
	}
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	var b strings.Builder
	b.Grow(max * 2)
	n := 0
	for _, r := range s {
		if n >= max {
			break
		}
		b.WriteRune(r)
		n++
	}
	b.WriteString("…")
	return b.String()
}
