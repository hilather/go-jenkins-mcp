package jenkins

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// Bounds for stage/node log retrieval (PIPE-002 / MCP budgets).
const (
	DefaultStageLogLength = 8192
	MaxStageLogLength     = 256 << 10 // 256 KiB hard cap per tool call
	maxStageLogBodyBytes  = 512 << 10 // allow header/JSON overhead over max text
)

// StageLog is a bounded stage/node log excerpt (PIPE-002).
type StageLog struct {
	JobName     string `json:"jobName"`
	BuildNumber int    `json:"buildNumber"`
	StageID     string `json:"stageId"`
	StageName   string `json:"stageName,omitempty"`
	// SourceAPI identifies the Jenkins endpoint used (evidence for PIPE-002).
	SourceAPI string `json:"sourceApi"`
	// NodeStatus is the Pipeline node status when reported by wfapi/log.
	NodeStatus string `json:"nodeStatus,omitempty"`
	// Offset is always 0 for the wfapi/log JSON text field (not progressive).
	Offset int `json:"offset"`
	// Length is the returned text length in bytes.
	Length int `json:"length"`
	// TotalSize is the reported full log length when known.
	TotalSize int `json:"totalSize"`
	// HasMore is true when Jenkins reports more text than returned (or we truncated).
	HasMore bool   `json:"hasMore"`
	Logs    string `json:"logs"`
	// LogKeyJob is the job field to use when mirroring under a distinct store key
	// (console job name is never used — avoids corrupting console generations).
	LogKeyJob string `json:"logKeyJob,omitempty"`
	// Mirrored is set by the tools layer when optional local mirror succeeded.
	Mirrored bool `json:"mirrored,omitempty"`
}

// GetStageLogToolArgs are tool arguments for jenkins_get_stage_log.
type GetStageLogToolArgs struct {
	JobName     string `json:"job_name" jsonschema:"Name/path of the Jenkins job (supports folders)"`
	BuildNumber int    `json:"build_number" jsonschema:"Build number"`
	// StageID is the Pipeline node id (preferred when known).
	StageID string `json:"stage_id,omitempty" jsonschema:"Pipeline stage/node id (preferred)"`
	// StageName resolves the first stage with this exact name when stage_id is empty.
	StageName string `json:"stage_name,omitempty" jsonschema:"Stage name (used when stage_id is empty)"`
	// MaxLength caps returned text bytes (default 8192, hard max 256KiB).
	MaxLength int `json:"max_length,omitempty" jsonschema:"Maximum bytes of stage log text (default: 8192, max: 262144)" default:"8192"`
	// Mirror, when true, requests that the tools layer append the fetched text
	// under a distinct logmirror key (job#stage:id). No-op without log access.
	Mirror bool `json:"mirror,omitempty" jsonschema:"Optionally mirror into local log store under a distinct stage key"`
}

// GetStageLogToolResponse is the stage log returned by jenkins_get_stage_log.
type GetStageLogToolResponse = StageLog

// StageLogKeyJob returns the LogKey.Job value for stage-specific storage.
// Distinct from the console job name so missing/partial stage logs never
// corrupt the console generation (PIPE-002 acceptance).
func StageLogKeyJob(jobName, stageID string) string {
	return strings.TrimSpace(jobName) + "#stage:" + strings.TrimSpace(stageID)
}

// GetStageLog fetches bounded stage/node log text via Pipeline REST wfapi/log (PIPE-002).
// stageID or stageName (exact match) is required. Missing Pipeline REST → capability_missing;
// unknown stage or missing log → not_found.
func (opts *Client) GetStageLog(ctx context.Context, jobName string, buildNumber int, stageID, stageName string, maxLength int) (*StageLog, error) {
	if opts == nil {
		return nil, fmt.Errorf("jenkins client is nil")
	}
	if strings.TrimSpace(jobName) == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "job_name is required")
	}
	if buildNumber <= 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument, "build_number must be positive")
	}
	stageID = strings.TrimSpace(stageID)
	stageName = strings.TrimSpace(stageName)
	if stageID == "" && stageName == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "stage_id or stage_name is required")
	}
	if maxLength <= 0 {
		maxLength = DefaultStageLogLength
	}
	if maxLength > MaxStageLogLength {
		maxLength = MaxStageLogLength
	}

	caps, err := opts.Capabilities(ctx)
	if err != nil {
		return nil, err
	}
	if !caps.HasPipelineREST {
		return nil, apperr.New(apperr.CodeCapabilityMissing,
			"Pipeline REST API is not available on this Jenkins controller")
	}

	resolvedID := stageID
	resolvedName := stageName
	if resolvedID == "" {
		id, name, err := opts.resolveStageIDByName(ctx, jobName, buildNumber, stageName)
		if err != nil {
			return nil, err
		}
		resolvedID = id
		resolvedName = name
	} else if resolvedName == "" {
		// Best-effort name lookup; ignore graph errors (id is authoritative).
		if n, ok := opts.lookupStageName(ctx, jobName, buildNumber, resolvedID); ok {
			resolvedName = n
		}
	}

	jobPath := BuildJobPath(jobName)
	apiPath := fmt.Sprintf("%s/%d/execution/node/%s/wfapi/log",
		jobPath, buildNumber, urlPathEscapeSegment(resolvedID))
	const sourceAPI = "pipeline-rest-api:wfapi/log"

	resp, err := opts.CallJenkins(ctx, opts.Client, http.MethodGet, apiPath, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch stage log: %w", err)
	}
	defer resp.Body.Close()

	body, err := readLimited(resp.Body, maxStageLogBodyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read stage log response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		// continue
	case http.StatusNotFound:
		return nil, apperr.New(apperr.CodeNotFound,
			fmt.Sprintf("stage log not found for job %q build #%d stage %q", jobName, buildNumber, resolvedID))
	case http.StatusUnauthorized:
		return nil, apperr.New(apperr.CodeAuthentication, "not authenticated for stage log")
	case http.StatusForbidden:
		return nil, apperr.New(apperr.CodeAuthorization, "not authorized to read stage log")
	default:
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, truncateForErr(string(body)))
	}

	var raw wfapiNodeLog
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, apperr.Wrap(apperr.CodeUpstreamProtocol, "invalid stage log JSON", err)
	}

	text := raw.Text
	totalSize := raw.Length
	if totalSize <= 0 {
		totalSize = len(text)
	}
	hasMore := raw.HasMore
	if len(text) > maxLength {
		text = text[:maxLength]
		hasMore = true
	}
	// Truncate to maxLength even when Jenkins length field says otherwise.
	if totalSize > maxLength && len(text) >= maxLength {
		hasMore = true
	}

	return &StageLog{
		JobName:     jobName,
		BuildNumber: buildNumber,
		StageID:     resolvedID,
		StageName:   firstNonEmpty(resolvedName, raw.NodeID),
		SourceAPI:   sourceAPI,
		NodeStatus:  raw.NodeStatus,
		Offset:      0,
		Length:      len(text),
		TotalSize:   totalSize,
		HasMore:     hasMore,
		Logs:        text,
		LogKeyJob:   StageLogKeyJob(jobName, resolvedID),
	}, nil
}

// wfapiNodeLog matches pipeline-rest-api FlowNodeLogExt (fields we use).
type wfapiNodeLog struct {
	NodeID     string `json:"nodeId"`
	NodeStatus string `json:"nodeStatus"`
	Length     int    `json:"length"`
	HasMore    bool   `json:"hasMore"`
	Text       string `json:"text"`
}

func (opts *Client) resolveStageIDByName(ctx context.Context, jobName string, buildNumber int, name string) (id, resolvedName string, err error) {
	ps, err := opts.GetPipelineStages(ctx, jobName, buildNumber)
	if err != nil {
		return "", "", err
	}
	id, resolvedName, ok := findStageByName(ps.Stages, name)
	if !ok {
		return "", "", apperr.New(apperr.CodeNotFound,
			fmt.Sprintf("stage named %q not found for job %q build #%d", name, jobName, buildNumber))
	}
	if id == "" {
		return "", "", apperr.New(apperr.CodeNotFound,
			fmt.Sprintf("stage named %q has no node id (cannot fetch log)", name))
	}
	return id, resolvedName, nil
}

func (opts *Client) lookupStageName(ctx context.Context, jobName string, buildNumber int, id string) (string, bool) {
	ps, err := opts.GetPipelineStages(ctx, jobName, buildNumber)
	if err != nil {
		return "", false
	}
	return findStageNameByID(ps.Stages, id)
}

func findStageByName(stages []StageNode, name string) (id, resolved string, ok bool) {
	var walk func([]StageNode) bool
	walk = func(list []StageNode) bool {
		for _, s := range list {
			if s.Name == name {
				id = s.ID
				resolved = s.Name
				return true
			}
			if len(s.Children) > 0 && walk(s.Children) {
				return true
			}
		}
		return false
	}
	ok = walk(stages)
	return id, resolved, ok
}

func findStageNameByID(stages []StageNode, id string) (string, bool) {
	var walk func([]StageNode) (string, bool)
	walk = func(list []StageNode) (string, bool) {
		for _, s := range list {
			if s.ID == id {
				return s.Name, true
			}
			if len(s.Children) > 0 {
				if n, ok := walk(s.Children); ok {
					return n, true
				}
			}
		}
		return "", false
	}
	return walk(stages)
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
