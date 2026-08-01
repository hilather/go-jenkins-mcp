package jenkins

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// Build history bounds (JEN-003).
const (
	// DefaultListBuildsLimit is the default page size for jenkins_list_builds.
	DefaultListBuildsLimit = 20
	// MaxListBuildsLimit is the hard upper bound for list_builds pagination limit.
	MaxListBuildsLimit = 100
	// DefaultListBuildsLookback is the default build history scan window.
	DefaultListBuildsLookback = 100
	// MaxListBuildsLookback is the hard upper bound for list_builds lookback.
	MaxListBuildsLookback = 500

	// Unexported aliases kept for package-local call sites / tests.
	defaultListBuildsLimit    = DefaultListBuildsLimit
	maxListBuildsLimit        = MaxListBuildsLimit
	defaultListBuildsLookback = DefaultListBuildsLookback
	maxListBuildsLookback     = MaxListBuildsLookback
	maxListBuildsBodyBytes    = 4 << 20
)

// BaselineKind selects a deterministic baseline build number (JEN-003).
type BaselineKind string

const (
	BaselineLastSuccessful BaselineKind = "last_successful"
	BaselineLastFailed     BaselineKind = "last_failed"
	BaselineLastUnstable   BaselineKind = "last_unstable"
	BaselineLastCompleted  BaselineKind = "last_completed"
	BaselineLastBuild      BaselineKind = "last_build"
)

// ListBuildsToolArgs are arguments for jenkins_list_builds (JEN-003).
type ListBuildsToolArgs struct {
	JobName string `json:"job_name" jsonschema:"Name/path of the Jenkins job (supports folders; not an http URL)"`
	// Limit caps returned builds after filters (default 20, max 100).
	// When page_token is set, the token's limit is used (still hard-capped at 100).
	Limit int `json:"limit,omitempty" jsonschema:"Maximum builds to return after filters (default 20, max 100; page_token wins when set)" default:"20"`
	// Offset is the zero-based index into the filtered match list.
	// Prefer page_token for continuation; when both are set, page_token wins.
	Offset int `json:"offset,omitempty" jsonschema:"Zero-based offset into the filtered match list (default 0; ignored when page_token is set)" default:"0"`
	// PageToken is an opaque continuation from a prior next_page_token (MCP-001).
	// Invalid/tampered/non-matching-filter tokens fail closed as invalid_argument.
	PageToken string `json:"page_token,omitempty" jsonschema:"Opaque page token from a prior next_page_token; wins over offset/limit when set"`
	// SinceBuild when >0 keeps only builds with number <= since_build (inclusive upper bound).
	SinceBuild int `json:"since_build,omitempty" jsonschema:"When set, only include builds with number less than or equal to this (scan older history)"`
	// Result filters by Jenkins result (SUCCESS, FAILURE, UNSTABLE, ABORTED). Empty = any completed/running.
	Result string `json:"result,omitempty" jsonschema:"Filter by result: SUCCESS, FAILURE, UNSTABLE, ABORTED (empty = no filter)"`
	// MaxLookback is the maximum number of builds to fetch from Jenkins (default 100, max 500).
	MaxLookback int `json:"max_lookback,omitempty" jsonschema:"Maximum builds to scan from Jenkins (default 100, max 500)" default:"100"`
	// IncludeParameters when true includes non-secret build parameters (secrets always redacted/stripped).
	IncludeParameters bool `json:"include_parameters,omitempty" jsonschema:"Include non-secret build parameters (secrets never returned)"`
}

// ListBuildsToolResponse is paginated build history for a job.
type ListBuildsToolResponse struct {
	JobName       string  `json:"jobName"`
	Builds        []Build `json:"builds"`
	Offset        int     `json:"offset"`
	Limit         int     `json:"limit"`
	Scanned       int     `json:"scanned"`
	Matched       int     `json:"matched"`                   // filtered matches within lookback (before pagination)
	Truncated     bool    `json:"truncated,omitempty"`       // hit lookback before exhausting matches
	NextPageToken string  `json:"next_page_token,omitempty"` // opaque; pass as page_token for next page
	// Source is always "live" for this path (cache residual reserved).
	Source string `json:"source"`
	// Cached is false for live Jenkins fetches (JEN-003 freshness distinction).
	Cached bool `json:"cached"`
}

// ResolveBaselineToolArgs are arguments for resolving a baseline build number.
type ResolveBaselineToolArgs struct {
	JobName string `json:"job_name" jsonschema:"Name/path of the Jenkins job (supports folders)"`
	// Baseline is one of last_successful, last_failed, last_unstable, last_completed, last_build.
	Baseline string `json:"baseline" jsonschema:"Baseline kind: last_successful, last_failed, last_unstable, last_completed, last_build"`
}

// ResolveBaselineToolResponse is the resolved baseline build reference.
type ResolveBaselineToolResponse struct {
	JobName     string `json:"jobName"`
	Baseline    string `json:"baseline"`
	BuildNumber int    `json:"buildNumber,omitempty"`
	Result      string `json:"result,omitempty"`
	Building    bool   `json:"building,omitempty"`
	Found       bool   `json:"found"`
	Source      string `json:"source"`
	Cached      bool   `json:"cached"`
	Message     string `json:"message,omitempty"`
}

// ListBuilds returns filtered, bounded build history for a job (JEN-003).
// Secret parameter values are never returned (stripped by name heuristics).
func (opts *Client) ListBuilds(ctx context.Context, args ListBuildsToolArgs) (*ListBuildsToolResponse, error) {
	if opts == nil {
		return nil, fmt.Errorf("jenkins client is nil")
	}
	jobName := strings.TrimSpace(args.JobName)
	if jobName == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "job_name is required")
	}
	if strings.Contains(jobName, "://") {
		return nil, apperr.New(apperr.CodeInvalidArgument, "job_name must be a typed path, not a URL")
	}

	lookback := args.MaxLookback
	if lookback <= 0 {
		lookback = defaultListBuildsLookback
	}
	if lookback > maxListBuildsLookback {
		lookback = maxListBuildsLookback
	}
	resultFilter := strings.ToUpper(strings.TrimSpace(args.Result))

	filterFP := FilterFingerprint(
		"list_builds",
		jobName,
		FormatFilterInt(args.SinceBuild),
		resultFilter,
		FormatFilterInt(lookback),
		FormatFilterBool(args.IncludeParameters),
	)
	offset, limit, err := ResolveListPagination(
		args.PageToken, args.Offset, args.Limit,
		defaultListBuildsLimit, maxListBuildsLimit, filterFP,
	)
	if err != nil {
		return nil, err
	}

	jobPath := BuildJobPath(jobName)
	tree := fmt.Sprintf(
		"builds[number,url,building,result,timestamp,duration,estimatedDuration,displayName,actions[_class,parameters[name,value]]]{0,%d}",
		lookback,
	)
	apiPath := jobPath + "/api/json?tree=" + url.QueryEscape(tree)

	resp, err := opts.CallJenkins(ctx, opts.Client, http.MethodGet, apiPath, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list builds: %w", err)
	}
	body, err := readLimited(resp.Body, maxListBuildsBodyBytes)
	_ = resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to read builds response: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, apperr.New(apperr.CodeNotFound, fmt.Sprintf("job %q not found", jobName))
	}
	if resp.StatusCode == http.StatusForbidden {
		return nil, apperr.New(apperr.CodeAuthorization, "not authorized to list builds")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var data struct {
		Builds []struct {
			Build
			Actions []buildAction `json:"actions"`
		} `json:"builds"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("failed to decode builds response: %w", err)
	}

	// Newest first.
	sort.SliceStable(data.Builds, func(i, j int) bool {
		return data.Builds[i].Number > data.Builds[j].Number
	})

	// Collect all matches within the lookback window, then page (offset/limit or page_token).
	matched := make([]Build, 0, limit)
	for _, b := range data.Builds {
		if args.SinceBuild > 0 && b.Number > args.SinceBuild {
			continue
		}
		if resultFilter != "" {
			if b.Building || !strings.EqualFold(b.Result, resultFilter) {
				continue
			}
		}
		build := b.Build
		build.URL = "" // typed surface: no absolute URLs required
		if args.IncludeParameters {
			params := extractBuildParams(b.Actions)
			build.Parameters = stripSecretParams(params)
		} else {
			build.Parameters = nil
		}
		matched = append(matched, build)
	}

	totalMatched := len(matched)
	if offset > totalMatched {
		offset = totalMatched
	}
	end := offset + limit
	if end > totalMatched {
		end = totalMatched
	}
	page := matched[offset:end]
	if page == nil {
		page = []Build{}
	}

	// Truncated when lookback may have cut off older history on Jenkins.
	truncated := len(data.Builds) >= lookback
	// Also surface truncated when the lookback window was full and we still
	// could not fill the requested page from matches.
	if len(data.Builds) >= lookback && len(page) < limit {
		truncated = true
	}

	return &ListBuildsToolResponse{
		JobName:       jobName,
		Builds:        page,
		Offset:        offset,
		Limit:         limit,
		Scanned:       len(data.Builds),
		Matched:       totalMatched,
		Truncated:     truncated,
		NextPageToken: NextPageTokenIfMore(offset, limit, len(page), totalMatched, filterFP),
		Source:        CapabilitySourceLive,
		Cached:        false,
	}, nil
}

// ResolveBaseline returns a deterministic baseline build number for a job (JEN-003).
// Running builds are never selected for completed baselines; aborted/running
// fixtures resolve stably via Jenkins last*Build fields when present, else scan.
func (opts *Client) ResolveBaseline(ctx context.Context, jobName string, kind BaselineKind) (*ResolveBaselineToolResponse, error) {
	if opts == nil {
		return nil, fmt.Errorf("jenkins client is nil")
	}
	jobName = strings.TrimSpace(jobName)
	if jobName == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "job_name is required")
	}
	kind = BaselineKind(strings.ToLower(strings.TrimSpace(string(kind))))
	field, ok := baselineTreeField(kind)
	if !ok {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			"baseline must be one of last_successful, last_failed, last_unstable, last_completed, last_build")
	}

	jobPath := BuildJobPath(jobName)
	// Selective fields only for the chosen baseline pointer.
	tree := field + "[number,building,result,timestamp,duration,displayName]"
	// Also pull lastBuild for deterministic fallback when pointer is null.
	tree += ",lastBuild[number,building,result],builds[number,building,result]{0,50}"
	apiPath := jobPath + "/api/json?tree=" + url.QueryEscape(tree)

	resp, err := opts.CallJenkins(ctx, opts.Client, http.MethodGet, apiPath, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve baseline: %w", err)
	}
	body, err := readLimited(resp.Body, maxListBuildsBodyBytes)
	_ = resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to read baseline response: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, apperr.New(apperr.CodeNotFound, fmt.Sprintf("job %q not found", jobName))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var data map[string]json.RawMessage
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("failed to decode baseline response: %w", err)
	}

	out := &ResolveBaselineToolResponse{
		JobName:  jobName,
		Baseline: string(kind),
		Source:   CapabilitySourceLive,
		Cached:   false,
	}

	// Prefer Jenkins pointer field when present and valid for the kind.
	if raw, ok := data[field]; ok && string(raw) != "null" && len(raw) > 0 {
		var b struct {
			Number   int    `json:"number"`
			Building bool   `json:"building"`
			Result   string `json:"result"`
		}
		if err := json.Unmarshal(raw, &b); err == nil && b.Number > 0 {
			if baselineAccept(kind, b.Building, b.Result) {
				out.Found = true
				out.BuildNumber = b.Number
				out.Result = b.Result
				out.Building = b.Building
				return out, nil
			}
		}
	}

	// Deterministic scan fallback (newest first): skip building for completed kinds.
	var builds []struct {
		Number   int    `json:"number"`
		Building bool   `json:"building"`
		Result   string `json:"result"`
	}
	if raw, ok := data["builds"]; ok {
		_ = json.Unmarshal(raw, &builds)
	}
	sort.SliceStable(builds, func(i, j int) bool { return builds[i].Number > builds[j].Number })
	for _, b := range builds {
		if baselineAccept(kind, b.Building, b.Result) {
			out.Found = true
			out.BuildNumber = b.Number
			out.Result = b.Result
			out.Building = b.Building
			return out, nil
		}
	}

	out.Message = "no matching baseline build"
	return out, nil
}

func baselineTreeField(kind BaselineKind) (string, bool) {
	switch kind {
	case BaselineLastSuccessful:
		return "lastSuccessfulBuild", true
	case BaselineLastFailed:
		return "lastFailedBuild", true
	case BaselineLastUnstable:
		return "lastUnstableBuild", true
	case BaselineLastCompleted:
		return "lastCompletedBuild", true
	case BaselineLastBuild:
		return "lastBuild", true
	default:
		return "", false
	}
}

func baselineAccept(kind BaselineKind, building bool, result string) bool {
	result = strings.ToUpper(strings.TrimSpace(result))
	switch kind {
	case BaselineLastBuild:
		return true
	case BaselineLastSuccessful:
		return !building && result == "SUCCESS"
	case BaselineLastFailed:
		return !building && result == "FAILURE"
	case BaselineLastUnstable:
		return !building && result == "UNSTABLE"
	case BaselineLastCompleted:
		return !building && result != ""
	default:
		return false
	}
}

// stripSecretParams omits sensitive build parameters by key name (JEN-003).
// Lives in jenkins (not tools/redact) to respect FND-004 package boundaries;
// the tools layer also redacts values before MCP serialization.
func stripSecretParams(params map[string]string) map[string]string {
	if len(params) == 0 {
		return nil
	}
	out := make(map[string]string, len(params))
	for k, v := range params {
		if isSensitiveParamName(k) {
			// Never return secret parameter values.
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// isSensitiveParamName is a local heuristic for Jenkins parameter keys.
// Kept intentionally conservative and independent of internal/redact (FND-004).
func isSensitiveParamName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(name)
	n = strings.ReplaceAll(n, "-", "_")
	switch n {
	case "password", "passwd", "secret", "token", "api_key", "apikey",
		"private_key", "access_key", "client_secret", "authorization",
		"cookie", "credentials", "credential", "auth", "auth_token",
		"access_token", "refresh_token", "api_token":
		return true
	}
	for _, frag := range []string{
		"password", "passwd", "secret", "token", "api_key", "apikey",
		"private_key", "access_key", "client_secret", "credential",
	} {
		if strings.Contains(n, frag) {
			return true
		}
	}
	return false
}

// ParseBaselineKind converts a tool string to BaselineKind.
func ParseBaselineKind(s string) (BaselineKind, error) {
	k := BaselineKind(strings.ToLower(strings.TrimSpace(s)))
	if _, ok := baselineTreeField(k); !ok {
		return "", apperr.New(apperr.CodeInvalidArgument,
			"baseline must be one of last_successful, last_failed, last_unstable, last_completed, last_build")
	}
	return k, nil
}
