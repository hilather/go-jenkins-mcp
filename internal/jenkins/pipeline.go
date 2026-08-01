package jenkins

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// Bounds for Pipeline stage graph retrieval (PIPE-001 / MCP budgets).
const (
	maxPipelineStages     = 200
	maxPipelineDepth      = 4
	maxPipelineChildFetch = 32
	maxPipelineBodyBytes  = 2 << 20 // 2 MiB
)

// StageNode is one node in a Pipeline stage graph (PIPE-001).
// Children hold parallel branches or nested stages without flattening ambiguity.
type StageNode struct {
	ID        string      `json:"id,omitempty"`
	Name      string      `json:"name"`
	Status    string      `json:"status,omitempty"`
	Duration  DurationMS  `json:"duration"`
	StartTime TimeMS      `json:"startTime,omitempty"`
	Type      string      `json:"type,omitempty"` // STAGE, PARALLEL, etc. when known
	Children  []StageNode `json:"children,omitempty"`
}

// PipelineStages is the stage graph for a single Pipeline build.
type PipelineStages struct {
	JobName     string      `json:"jobName"`
	BuildNumber int         `json:"buildNumber"`
	Name        string      `json:"name,omitempty"`
	Status      string      `json:"status,omitempty"`
	Duration    DurationMS  `json:"duration"`
	StartTime   TimeMS      `json:"startTime,omitempty"`
	Stages      []StageNode `json:"stages"`
	Truncated   bool        `json:"truncated,omitempty"`
	StageCount  int         `json:"stageCount"`
}

// GetPipelineStagesToolArgs are tool arguments for jenkins_get_pipeline_stages.
type GetPipelineStagesToolArgs struct {
	JobName     string `json:"job_name" jsonschema:"Name/path of the Jenkins job (supports folders)"`
	BuildNumber int    `json:"build_number" jsonschema:"Build number"`
}

// GetPipelineStagesToolResponse is the stage graph returned by jenkins_get_pipeline_stages.
type GetPipelineStagesToolResponse = PipelineStages

// GetPipelineStages fetches the Pipeline REST stage graph for a build (PIPE-001).
// When the Pipeline REST API capability is missing, returns CodeCapabilityMissing.
// When the build/job is missing, returns a not-found style error.
func (opts *Client) GetPipelineStages(ctx context.Context, jobName string, buildNumber int) (*PipelineStages, error) {
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
	if !caps.HasPipelineREST {
		return nil, apperr.New(apperr.CodeCapabilityMissing,
			"Pipeline REST API is not available on this Jenkins controller")
	}

	jobPath := BuildJobPath(jobName)
	apiPath := fmt.Sprintf("%s/%d/wfapi/describe", jobPath, buildNumber)
	resp, err := opts.CallJenkins(ctx, opts.Client, http.MethodGet, apiPath, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch pipeline stages: %w", err)
	}
	defer resp.Body.Close()

	body, err := readLimited(resp.Body, maxPipelineBodyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read pipeline stages response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		// continue
	case http.StatusNotFound:
		// Distinguish missing build vs missing wfapi on this object.
		// If capability said REST is present, 404 is usually job/build not found
		// or not a Pipeline job.
		return nil, apperr.New(apperr.CodeNotFound,
			fmt.Sprintf("pipeline stages not found for job %q build #%d (missing build or not a Pipeline job)", jobName, buildNumber))
	case http.StatusUnauthorized:
		return nil, apperr.New(apperr.CodeAuthentication, "not authenticated for pipeline stages")
	case http.StatusForbidden:
		return nil, apperr.New(apperr.CodeAuthorization, "not authorized to read pipeline stages")
	default:
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, truncateForErr(string(body)))
	}

	var raw wfapiRun
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, apperr.Wrap(apperr.CodeUpstreamProtocol, "invalid pipeline stages JSON", err)
	}

	out := &PipelineStages{
		JobName:     jobName,
		BuildNumber: buildNumber,
		Name:        raw.Name,
		Status:      raw.Status,
		Duration:    DurationMS(time.Duration(raw.DurationMillis) * time.Millisecond),
		StartTime:   timeMSFromMillis(raw.StartTimeMillis),
	}

	truncated := false
	stages := make([]StageNode, 0, len(raw.Stages))
	childFetches := 0
	for i, s := range raw.Stages {
		if i >= maxPipelineStages {
			truncated = true
			break
		}
		node := stageFromWFAPI(s)
		// Optionally expand parallel/composite nodes (bounded).
		if childFetches < maxPipelineChildFetch && s.ID != "" && looksExpandable(s) {
			children, didFetch, childTrunc := opts.fetchStageChildren(ctx, jobPath, buildNumber, s.ID, 1)
			if didFetch {
				childFetches++
			}
			if len(children) > 0 {
				node.Children = children
			}
			if childTrunc {
				truncated = true
			}
		}
		stages = append(stages, node)
	}
	out.Stages = stages
	out.StageCount = countStageNodes(stages)
	out.Truncated = truncated
	return out, nil
}

// wfapiRun matches pipeline-rest-api RunExt / describe payload (fields we use).
type wfapiRun struct {
	Name            string       `json:"name"`
	Status          string       `json:"status"`
	StartTimeMillis int64        `json:"startTimeMillis"`
	DurationMillis  int64        `json:"durationMillis"`
	Stages          []wfapiStage `json:"stages"`
}

type wfapiStage struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Status          string `json:"status"`
	StartTimeMillis int64  `json:"startTimeMillis"`
	DurationMillis  int64  `json:"durationMillis"`
	Type            string `json:"type"`
	// Some Jenkins versions embed branch nodes here.
	StageFlowNodes []wfapiStage `json:"stageFlowNodes"`
}

func stageFromWFAPI(s wfapiStage) StageNode {
	n := StageNode{
		ID:        s.ID,
		Name:      s.Name,
		Status:    s.Status,
		Duration:  DurationMS(time.Duration(s.DurationMillis) * time.Millisecond),
		StartTime: timeMSFromMillis(s.StartTimeMillis),
		Type:      s.Type,
	}
	if len(s.StageFlowNodes) > 0 {
		children := make([]StageNode, 0, len(s.StageFlowNodes))
		for i, c := range s.StageFlowNodes {
			if i >= maxPipelineStages {
				break
			}
			children = append(children, stageFromWFAPI(c))
		}
		n.Children = children
	}
	return n
}

func looksExpandable(s wfapiStage) bool {
	if len(s.StageFlowNodes) > 0 {
		return false // already expanded in payload
	}
	t := strings.ToUpper(s.Type)
	if t == "PARALLEL" || t == "PARALLEL_BRANCH" {
		return true
	}
	// Heuristic: names used by Declarative parallel blocks.
	name := strings.ToLower(s.Name)
	return strings.Contains(name, "parallel")
}

func (opts *Client) fetchStageChildren(
	ctx context.Context,
	jobPath string,
	buildNumber int,
	stageID string,
	depth int,
) (children []StageNode, fetched bool, truncated bool) {
	if depth > maxPipelineDepth || stageID == "" {
		return nil, false, false
	}
	apiPath := fmt.Sprintf("%s/%d/execution/node/%s/wfapi/describe", jobPath, buildNumber, urlPathEscapeSegment(stageID))
	resp, err := opts.CallJenkins(ctx, opts.Client, http.MethodGet, apiPath, nil, nil)
	if err != nil {
		return nil, false, false
	}
	defer resp.Body.Close()
	body, err := readLimited(resp.Body, maxPipelineBodyBytes)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, true, false
	}
	var raw wfapiStage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, true, false
	}
	// Prefer stageFlowNodes (Pipeline REST node describe).
	nodes := raw.StageFlowNodes
	if len(nodes) == 0 {
		return nil, true, false
	}
	out := make([]StageNode, 0, len(nodes))
	for i, n := range nodes {
		if i >= maxPipelineStages {
			truncated = true
			break
		}
		child := stageFromWFAPI(n)
		out = append(out, child)
	}
	return out, true, truncated
}

func countStageNodes(stages []StageNode) int {
	n := 0
	var walk func([]StageNode)
	walk = func(list []StageNode) {
		for _, s := range list {
			n++
			if len(s.Children) > 0 {
				walk(s.Children)
			}
		}
	}
	walk(stages)
	return n
}

func timeMSFromMillis(ms int64) TimeMS {
	if ms <= 0 {
		return TimeMS{}
	}
	sec := ms / 1000
	nsec := (ms % 1000) * int64(time.Millisecond)
	return TimeMS(time.Unix(sec, nsec))
}

func urlPathEscapeSegment(s string) string {
	// Stage IDs are numeric in practice; still escape for safety.
	return url.PathEscape(s)
}

func truncateForErr(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 256 {
		return s[:256]
	}
	return s
}
