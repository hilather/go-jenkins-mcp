package jenkins

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

func BuildJobPath(jobName string) string {
	segs := strings.Split(jobName, "/")
	var b strings.Builder
	for _, s := range segs {
		if s == "" {
			continue
		}
		b.WriteString("/job/")
		b.WriteString(url.PathEscape(s))
	}
	return b.String()
}

// FullNameFromJobURL derives a Jenkins job full name from a job or queue-task URL.
// Examples:
//
//	http://jenkins/job/demo/          → "demo"
//	http://jenkins/job/folder/job/demo/ → "folder/demo"
//	/job/a/job/b/job/c/                 → "a/b/c"
//
// Returns empty string when the path has no /job/ segments (ambiguous / unusable).
// Segment values are path-unescaped. Does not include build numbers or trailing
// actions (stop, api, etc.): only successive /job/{name} path pairs.
func FullNameFromJobURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// Prefer path component if absolute URL.
	p := raw
	if i := strings.Index(p, "://"); i >= 0 {
		rest := p[i+3:]
		if j := strings.Index(rest, "/"); j >= 0 {
			p = rest[j:]
		} else {
			return ""
		}
	}
	if k := strings.IndexAny(p, "?#"); k >= 0 {
		p = p[:k]
	}
	// Normalize and walk segments.
	parts := strings.Split(strings.Trim(p, "/"), "/")
	var segs []string
	for i := 0; i < len(parts); i++ {
		if parts[i] != "job" {
			continue
		}
		if i+1 >= len(parts) {
			break
		}
		name := parts[i+1]
		// Stop at build-number-looking trailing path if we already have segments
		// and next is numeric only — but build URLs look like /job/x/1/ so after
		// collecting job names we stop when segment is not after "job".
		if unesc, err := url.PathUnescape(name); err == nil {
			name = unesc
		}
		name = strings.TrimSpace(name)
		if name == "" || name == "." || name == ".." {
			continue
		}
		segs = append(segs, name)
		i++ // skip name segment
	}
	if len(segs) == 0 {
		return ""
	}
	return strings.Join(segs, "/")
}

// buildAction represents a Jenkins build action (used to extract parameters).
type buildAction struct {
	Class      string `json:"_class"`
	Parameters []struct {
		Name  string `json:"name"`
		Value any    `json:"value"`
	} `json:"parameters"`
}

// extractBuildParams extracts build parameters from Jenkins actions.
func extractBuildParams(actions []buildAction) map[string]string {
	for _, a := range actions {
		if a.Class != "hudson.model.ParametersAction" || len(a.Parameters) == 0 {
			continue
		}
		params := make(map[string]string, len(a.Parameters))
		for _, p := range a.Parameters {
			params[p.Name] = fmt.Sprint(p.Value)
		}
		return params
	}
	return nil
}

// parameterDefinitionsTree is the selective tree fragment for job parameter
// definitions (MUT-002). Includes _class as a fallback when type is absent.
const parameterDefinitionsTree = "property[parameterDefinitions[name,type,_class,description,defaultParameterValue[value],choices]]"

// rawParamDef is the Jenkins JSON shape for a single parameter definition.
type rawParamDef struct {
	Name                  string `json:"name"`
	Type                  string `json:"type"`
	Class                 string `json:"_class"`
	Description           string `json:"description"`
	DefaultParameterValue *struct {
		Value any `json:"value"`
	} `json:"defaultParameterValue"`
	Choices flexibleChoices `json:"choices"`
}

// flexibleChoices accepts Jenkins choices as a string array or newline-separated string.
type flexibleChoices []string

func (c *flexibleChoices) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		*c = nil
		return nil
	}
	var arr []string
	if err := json.Unmarshal(b, &arr); err == nil {
		*c = arr
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		if s == "" {
			*c = nil
			return nil
		}
		parts := strings.Split(s, "\n")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
		*c = out
		return nil
	}
	// Unknown shape: ignore rather than fail the whole job fetch.
	*c = nil
	return nil
}

// parseParameterDefinitions converts Jenkins property.parameterDefinitions into
// BuildParameter values. Secret/password-type defaults are scrubbed (never returned).
func parseParameterDefinitions(defs []rawParamDef) []BuildParameter {
	if len(defs) == 0 {
		return []BuildParameter{}
	}
	out := make([]BuildParameter, 0, len(defs))
	for _, paramDef := range defs {
		name := strings.TrimSpace(paramDef.Name)
		if name == "" {
			continue
		}
		typ := normalizeParameterType(paramDef.Type, paramDef.Class)
		param := BuildParameter{
			Name:        name,
			Type:        typ,
			Description: paramDef.Description,
			Choices:     []string(paramDef.Choices),
		}
		if paramDef.DefaultParameterValue != nil && !isSecretParameterType(typ) {
			param.DefaultValue = paramDef.DefaultParameterValue.Value
		}
		// Secret-type definitions: omit default entirely (architecture: no secret defaults).
		out = append(out, param)
	}
	return out
}

// normalizeParameterType prefers the short type field; falls back to the last
// segment of _class (e.g. hudson.model.StringParameterDefinition).
func normalizeParameterType(typeField, classField string) string {
	t := strings.TrimSpace(typeField)
	if t != "" {
		return t
	}
	c := strings.TrimSpace(classField)
	if c == "" {
		return ""
	}
	if i := strings.LastIndex(c, "."); i >= 0 && i+1 < len(c) {
		return c[i+1:]
	}
	return c
}

// isSecretParameterType reports Jenkins parameter definition types that must
// never accept model-supplied values (Password, Credentials, Secret, …).
func isSecretParameterType(typ string) bool {
	s := strings.ToLower(strings.TrimSpace(typ))
	if s == "" {
		return false
	}
	// Drop package path if present.
	if i := strings.LastIndex(s, "."); i >= 0 {
		s = s[i+1:]
	}
	return strings.Contains(s, "password") ||
		strings.Contains(s, "passwd") ||
		strings.Contains(s, "credentials") ||
		strings.Contains(s, "secret")
}

// extractParamDefsFromProperty walks property[] and collects parameterDefinitions.
func extractParamDefsFromProperty(property []struct {
	ParameterDefinitions []rawParamDef `json:"parameterDefinitions"`
}) []BuildParameter {
	var all []rawParamDef
	for _, p := range property {
		all = append(all, p.ParameterDefinitions...)
	}
	return parseParameterDefinitions(all)
}

// GetJobParameterDefinitions fetches only parameter definitions for a job (MUT-002).
// Lighter than GetJenkinsJob: no builds, no queue scan. Used by start_job validation.
func (opts *Client) GetJobParameterDefinitions(ctx context.Context, jobName string) ([]BuildParameter, error) {
	if opts == nil {
		return nil, fmt.Errorf("jenkins client is nil")
	}
	jobPath := BuildJobPath(jobName)
	apiPath := jobPath + "/api/json?tree=" + url.QueryEscape("name,"+parameterDefinitionsTree)
	resp, err := opts.CallJenkins(ctx, opts.Client, http.MethodGet, apiPath, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch job parameter definitions: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("job '%s' not found", jobName)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, readLimitedErrBody(resp.Body))
	}
	var data struct {
		Name     string `json:"name"`
		Property []struct {
			ParameterDefinitions []rawParamDef `json:"parameterDefinitions"`
		} `json:"property"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode parameter definitions: %w", err)
	}
	return extractParamDefsFromProperty(data.Property), nil
}

// getJenkinsJob fetches a specific job from jenkins api by name
func (opts *Client) GetJenkinsJob(ctx context.Context, jobName string, maxBuilds int) (*Job, error) {
	client := opts.Client

	// Build Jenkins job path for nested jobs/folders
	jobPath := BuildJobPath(jobName)

	// Build the API URL for the specific job with expanded parameter information
	apiPath := jobPath + "/api/json?tree=" +
		"name,url,color,buildable,description," +
		"lastBuild[" +
		"number,url,building,result,timestamp,duration,estimatedDuration,displayName," +
		"actions[_class,parameters[name,value]]" +
		"]," +
		"builds[" +
		"number,url,building,result,timestamp,duration,estimatedDuration,displayName," +
		"actions[_class,parameters[name,value]]" +
		"]{0," + strconv.Itoa(maxBuilds) + "}," +
		parameterDefinitionsTree
	resp, err := opts.CallJenkins(ctx, client, http.MethodGet, apiPath, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("job '%s' not found", jobName)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, readLimitedErrBody(resp.Body))
	}

	// Parse response
	var jobData struct {
		Name        string `json:"name"`
		URL         string `json:"url"`
		Color       string `json:"color"`
		Buildable   bool   `json:"buildable"`
		Description string `json:"description"`
		LastBuild   *struct {
			Build
			Actions []buildAction `json:"actions"`
		} `json:"lastBuild"`
		Builds []struct {
			Build
			Actions []buildAction `json:"actions"`
		} `json:"builds"`
		Property []struct {
			ParameterDefinitions []rawParamDef `json:"parameterDefinitions"`
		} `json:"property"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&jobData); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Convert builds to our format
	recentBuilds := make([]Build, len(jobData.Builds))
	for i, b := range jobData.Builds {
		recentBuilds[i] = b.Build
		recentBuilds[i].Parameters = extractBuildParams(b.Actions)
	}

	// Convert to our format
	var lastBuild *Build
	if jobData.LastBuild != nil {
		lb := jobData.LastBuild.Build
		lb.Parameters = extractBuildParams(jobData.LastBuild.Actions)
		lastBuild = &lb
	}
	jenkinsJob := &Job{
		Name:         jobData.Name,
		URL:          jobData.URL,
		Color:        jobData.Color,
		Buildable:    jobData.Buildable,
		Description:  jobData.Description,
		LastBuild:    lastBuild,
		RecentBuilds: recentBuilds,
		// MUT-002: surface parameter definitions (not discarded).
		Parameters: extractParamDefsFromProperty(jobData.Property),
	}

	// Sort recentBuilds by build number (descending - most recent first)
	sort.Slice(recentBuilds, func(i, j int) bool {
		return recentBuilds[i].Number > recentBuilds[j].Number
	})

	// Include queued builds that match this job (by URL prefix)
	if queuedAll, err := opts.GetQueuedBuilds(ctx); err == nil {
		for _, qb := range queuedAll {
			if strings.HasPrefix(qb.URL, jenkinsJob.URL) {
				jenkinsJob.QueuedBuilds = append(jenkinsJob.QueuedBuilds, qb)
			}
		}
	}

	return jenkinsJob, nil
}

// searchBuilds fetches builds from Jenkins and filters by result and parameters.
func (opts *Client) SearchBuilds(ctx context.Context, args SearchBuildsToolArgs) (*SearchBuildsToolResponse, error) {
	jobPath := BuildJobPath(args.JobName)

	apiPath := jobPath + "/api/json?tree=" +
		"builds[" +
		"number,url,building,result,timestamp,duration,estimatedDuration,displayName," +
		"actions[_class,parameters[name,value]]" +
		"]{0," + strconv.Itoa(args.MaxLookback) + "}"

	resp, err := opts.CallJenkins(ctx, opts.Client, http.MethodGet, apiPath, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("job '%s' not found", args.JobName)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, readLimitedErrBody(resp.Body))
	}

	var data struct {
		Builds []struct {
			Build
			Actions []buildAction `json:"actions"`
		} `json:"builds"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Parse param filters
	type paramFilter struct {
		key   string
		value string
	}
	var filters []paramFilter
	for _, p := range args.Params {
		k, v, _ := strings.Cut(p, "=")
		filters = append(filters, paramFilter{k, v})
	}

	var matched []Build
	for _, b := range data.Builds {
		if args.Result != "" && b.Result != args.Result {
			continue
		}
		params := extractBuildParams(b.Actions)
		skip := false
		for _, f := range filters {
			got := params[f.key]
			if got != f.value {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		build := b.Build
		build.Parameters = params
		matched = append(matched, build)
		if len(matched) >= args.Limit {
			break
		}
	}

	return &SearchBuildsToolResponse{
		Builds:  matched,
		Scanned: len(data.Builds),
	}, nil
}

// GetJenkinsJobs fetches the root job list from Jenkins (legacy seed path).
// Prefer ListJobs for folder-aware discovery. Pagination is applied by
// GetJobs (MCP-001 opaque page tokens).
func (opts *Client) GetJenkinsJobs(ctx context.Context) ([]Job, error) {
	client := opts.Client

	// Build the API URL
	resp, err := opts.CallJenkins(ctx, client, http.MethodGet, "/api/json?tree="+
		"jobs["+
		"name,url,color,buildable,description,"+
		"lastBuild[number,url,building,result,timestamp,duration,estimatedDuration,displayName]"+
		"]", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, readLimitedErrBody(resp.Body))
	}

	// Parse response
	var apiResp struct {
		Jobs []Job `json:"jobs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return apiResp.Jobs, nil
}

// GetJobs returns a paginated root job list for jenkins_get_jobs (MCP-001).
// Empty args use default limit (50, max 200). page_token wins over offset/limit.
func (opts *Client) GetJobs(ctx context.Context, args GetJobsToolArgs) (*GetJobsToolResponse, error) {
	if opts == nil {
		return nil, fmt.Errorf("jenkins client is nil")
	}
	filterFP := FilterFingerprint("get_jobs")
	offset, limit, err := ResolveListPagination(
		args.PageToken, args.Offset, args.Limit,
		defaultGetJobsLimit, maxGetJobsLimit, filterFP,
	)
	if err != nil {
		return nil, err
	}
	jobs, err := opts.GetJenkinsJobs(ctx)
	if err != nil {
		return nil, err
	}
	total := len(jobs)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	page := jobs[offset:end]
	if page == nil {
		page = []Job{}
	}
	return &GetJobsToolResponse{
		JobList:       page,
		Offset:        offset,
		Limit:         limit,
		Total:         total,
		NextPageToken: NextPageTokenIfMore(offset, limit, len(page), total, filterFP),
	}, nil
}
