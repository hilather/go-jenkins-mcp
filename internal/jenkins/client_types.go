package jenkins

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// DurationMS is a JSON-friendly duration that unmarshals from milliseconds (number)
// and marshals to a human-readable string (e.g., "5m10s").
type DurationMS time.Duration

// UnmarshalJSON parses a duration from milliseconds or string into DurationMS.
func (d *DurationMS) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*d = 0
		return nil
	}
	var ms int64
	if err := json.Unmarshal(b, &ms); err == nil {
		*d = DurationMS(time.Duration(ms) * time.Millisecond)
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		if dur, err := time.ParseDuration(s); err == nil {
			*d = DurationMS(dur)
			return nil
		}
		if v, err := strconv.ParseInt(s, 10, 64); err == nil {
			*d = DurationMS(time.Duration(v) * time.Millisecond)
			return nil
		}
	}
	return fmt.Errorf("invalid duration value: %s", string(b))
}

// MarshalJSON encodes DurationMS as a human-readable string (e.g., "5m10s").
func (d DurationMS) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// TimeMS is a JSON-friendly time that unmarshals from milliseconds-since-epoch (number)
// and marshals to an RFC3339 timestamp string (UTC).
type TimeMS time.Time

// UnmarshalJSON parses a timestamp from milliseconds or RFC3339 string into TimeMS.
func (t *TimeMS) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*t = TimeMS(time.Time{})
		return nil
	}
	// Try numeric milliseconds
	var ms int64
	if err := json.Unmarshal(b, &ms); err == nil {
		sec := ms / 1000
		nsec := (ms % 1000) * int64(time.Millisecond)
		*t = TimeMS(time.Unix(sec, nsec))
		return nil
	}
	// Try string timestamp
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		if s == "" {
			*t = TimeMS(time.Time{})
			return nil
		}
		if parsed, err := time.Parse(time.RFC3339Nano, s); err == nil {
			*t = TimeMS(parsed)
			return nil
		}
		if parsed, err := time.Parse(time.RFC3339, s); err == nil {
			*t = TimeMS(parsed)
			return nil
		}
		if ms, err := strconv.ParseInt(s, 10, 64); err == nil {
			sec := ms / 1000
			nsec := (ms % 1000) * int64(time.Millisecond)
			*t = TimeMS(time.Unix(sec, nsec))
			return nil
		}
	}
	return fmt.Errorf("invalid timestamp value: %s", string(b))
}

// MarshalJSON encodes TimeMS as an RFC3339 UTC timestamp string.
func (t TimeMS) MarshalJSON() ([]byte, error) {
	tt := time.Time(t)
	if tt.IsZero() {
		return []byte("null"), nil
	}
	return json.Marshal(tt.UTC().Format(time.RFC3339))
}

// GetJobs bounds (legacy flat list; prefer jenkins_list_jobs for discovery).
const (
	defaultGetJobsLimit = 50
	maxGetJobsLimit     = 200
)

// GetJobsToolArgs are the tool arguments for jenkins_get_jobs.
// Offset/limit and opaque page_token (MCP-001) keep the seed tool bounded.
// Prefer jenkins_list_jobs for folder-aware discovery.
type GetJobsToolArgs struct {
	// Offset is the zero-based pagination offset into the root job list.
	// Prefer page_token for continuation; when both are set, page_token wins.
	Offset int `json:"offset,omitempty" jsonschema:"Zero-based offset into the root job list (default 0; ignored when page_token is set)" default:"0"`
	// Limit is the maximum jobs to return (default 50, max 200).
	// When page_token is set, the token's limit is used (still hard-capped at 200).
	Limit int `json:"limit,omitempty" jsonschema:"Maximum jobs to return (default 50, max 200; page_token wins when set)" default:"50"`
	// PageToken is an opaque continuation from a prior next_page_token (MCP-001).
	// Invalid/tampered tokens fail closed as invalid_argument.
	PageToken string `json:"page_token,omitempty" jsonschema:"Opaque page token from a prior next_page_token; wins over offset/limit when set"`
}

// GetJobsToolResponse is the result payload for jenkins_get_jobs.
type GetJobsToolResponse struct {
	JobList       []Job  `json:"JobList"`
	Offset        int    `json:"offset,omitempty"`
	Limit         int    `json:"limit,omitempty"`
	Total         int    `json:"total,omitempty"`
	NextPageToken string `json:"next_page_token,omitempty"`
}

// GetJobToolArgs are the tool arguments for jenkins_get_job.
// Seed clients send JSON "name"; "job_name" is an optional alias (preferred when both set).
type GetJobToolArgs struct {
	// Name is the seed/canonical JSON field for the job full name.
	Name string `json:"name,omitempty" jsonschema:"Name of the Jenkins job to retrieve (folder/job path; not a URL)"`
	// JobName is an optional alias for Name (json:"job_name"); handler and policy prefer it when non-empty.
	JobName   string `json:"job_name,omitempty" jsonschema:"Alias for name; preferred when both name and job_name are set"`
	MaxBuilds int    `json:"max_builds,omitempty" jsonschema:"Maximum number of recent builds to return (default: 20)" default:"20"`
}

// GetJobToolResponse is the detailed job information returned by jenkins_get_job.
type GetJobToolResponse = Job

// GetRunningBuildsToolArgs are the tool arguments for jenkins_get_running_builds.
type GetRunningBuildsToolArgs struct {
	// No arguments
}

// GetRunningBuildsToolResponse contains the list of currently running builds.
type GetRunningBuildsToolResponse struct {
	Builds []RunningBuild `json:"builds"`
	Queued []QueuedBuild  `json:"queuedBuilds,omitempty"`
}

// GetBuildLogsToolArgs are the tool arguments for jenkins_get_build_logs.
type GetBuildLogsToolArgs struct {
	Name        string `json:"job_name" jsonschema:"Name of the Jenkins job"`
	BuildNumber int    `json:"build_number" jsonschema:"Build number"`
	Offset      int    `json:"offset,omitempty" jsonschema:"Starting byte offset in the log file (default: 0)" default:"0"`
	Length      int    `json:"length,omitempty" jsonschema:"Maximum number of bytes to retrieve (default: 8192)" default:"8192"`
}

// GetBuildLogsToolResponse is the build log payload returned by jenkins_get_build_logs.
type GetBuildLogsToolResponse = BuildLogs

// GetBuildToolArgs are the tool arguments for jenkins_get_build.
type GetBuildToolArgs struct {
	JobName     string `json:"job_name" jsonschema:"Name/path of the Jenkins job (supports folders)"`
	BuildNumber int    `json:"build_number" jsonschema:"Build number"`
}

// GetBuildToolResponse is the build payload returned by jenkins_get_build.
type GetBuildToolResponse = Build

// GetBuildLogTailToolArgs are the tool arguments for jenkins_get_build_log_tail.
type GetBuildLogTailToolArgs struct {
	JobName     string `json:"job_name" jsonschema:"Name of the Jenkins job"`
	BuildNumber int    `json:"build_number" jsonschema:"Build number"`
	MaxLength   int    `json:"max_length,omitempty" jsonschema:"Maximum bytes from end of log to retrieve (default: 8192)" default:"8192"`
}

// GetBuildLogTailToolResponse is the tailed build log payload returned by jenkins_get_build_log_tail.
type GetBuildLogTailToolResponse = BuildLogs

// StartJobToolArgs are the tool arguments for jenkins_start_job.
type StartJobToolArgs struct {
	JobName           string         `json:"job_name" jsonschema:"Name/path of the Jenkins job (supports folders)"`
	Parameters        map[string]any `json:"parameters,omitempty" jsonschema:"Optional key/value map of build parameters"`
	ConfirmationToken string         `json:"confirmation_token,omitempty" jsonschema:"MUT-002: token from prior preview to execute once"`
}

// StartJobToolResponse represents the response from jenkins_start_job
type StartJobToolResponse struct {
	JobName     string `json:"jobName"`
	QueueURL    string `json:"queueUrl,omitempty"`
	QueueID     int    `json:"queueId,omitempty"`
	BuildURL    string `json:"buildUrl,omitempty"`
	BuildNumber int    `json:"buildNumber,omitempty"`
}

// GetQueueItemToolArgs are the tool arguments for jenkins_get_queue_item.
type GetQueueItemToolArgs struct {
	QueueID int    `json:"queue_id" jsonschema:"Jenkins queue item ID"`
	Profile string `json:"profile,omitempty" jsonschema:"Optional connection profile id (not an http URL)"`
}

// QueueItem represents a Jenkins queue item.
type QueueItem struct {
	QueueID     int    `json:"queueId"`
	JobName     string `json:"jobName,omitempty"`
	URL         string `json:"url,omitempty"`
	Why         string `json:"why,omitempty"`
	QueuedSince TimeMS `json:"queuedSince"`
	Stuck       bool   `json:"stuck,omitempty"`
	Buildable   bool   `json:"buildable,omitempty"`
	Parameters  string `json:"parameters,omitempty"`
	Cancelled   bool   `json:"cancelled,omitempty"`
	Executable  *Build `json:"executable,omitempty"`
}

// WaitForQueueItemToolArgs are the tool arguments for jenkins_wait_for_queue_item.
type WaitForQueueItemToolArgs struct {
	QueueID         int    `json:"queue_id" jsonschema:"Jenkins queue item ID"`
	Profile         string `json:"profile,omitempty" jsonschema:"Optional connection profile id (not an http URL)"`
	TimeoutSeconds  int    `json:"timeout_seconds,omitempty" jsonschema:"Maximum time to wait in seconds (default: 30)" default:"30"`
	PollIntervalSec int    `json:"poll_interval_seconds,omitempty" jsonschema:"Polling interval in seconds (default: 2)" default:"2"`
}

// WaitForQueueItemToolResponse represents the response from jenkins_wait_for_queue_item.
type WaitForQueueItemToolResponse struct {
	QueueItem *QueueItem `json:"queueItem,omitempty"`
	Build     *Build     `json:"build,omitempty"`
	WaitTime  DurationMS `json:"waitTime"`
	TimedOut  bool       `json:"timedOut"`
	Status    string     `json:"status"`
	PollCount int        `json:"pollCount,omitempty"`
}

// WaitForRunningBuildToolArgs are the tool arguments for jenkins_wait_for_running_build.
type WaitForRunningBuildToolArgs struct {
	JobName        string `json:"job_name" jsonschema:"Name of the Jenkins job"`
	BuildNumber    int    `json:"build_number" jsonschema:"Build number"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" jsonschema:"Maximum time to wait in seconds (default: 600)" default:"600"`
}

// WaitForRunningBuildToolResponse represents the response from jenkins_wait_for_running_build
type WaitForRunningBuildToolResponse struct {
	JobName     string     `json:"jobName"`
	BuildNumber int        `json:"buildNumber"`
	Status      string     `json:"status"`   // "success", "failure", "unstable", "aborted", "timeout"
	Result      string     `json:"result"`   // Jenkins result string (SUCCESS, FAILURE, UNSTABLE, ABORTED, or empty if timeout)
	Duration    DurationMS `json:"duration"` // Total build duration (human-readable)
	WaitTime    DurationMS `json:"waitTime"` // Time spent waiting (human-readable)
	TimedOut    bool       `json:"timedOut"` // Whether the wait operation timed out
	PollCount   int        `json:"pollCount,omitempty"`
}

// StopBuildToolArgs are the tool arguments for jenkins_stop_build.
type StopBuildToolArgs struct {
	JobName           string `json:"job_name" jsonschema:"Name/path of the Jenkins job (supports folders)"`
	BuildNumber       int    `json:"build_number" jsonschema:"Build number to stop"`
	ConfirmationToken string `json:"confirmation_token,omitempty" jsonschema:"MUT-003: token from prior preview to execute once"`
}

// SearchBuildsToolArgs are the tool arguments for jenkins_search_builds.
type SearchBuildsToolArgs struct {
	JobName     string   `json:"job_name" jsonschema:"Name of the Jenkins job"`
	Result      string   `json:"result,omitempty" jsonschema:"Filter by build result: SUCCESS, FAILURE, ABORTED"`
	Params      []string `json:"params,omitempty" jsonschema:"Filter by build parameters as key=value pairs. Empty value (key=) matches empty/unset parameter."`
	Limit       int      `json:"limit,omitempty" jsonschema:"Maximum number of matching results to return (default: 5)" default:"5"`
	MaxLookback int      `json:"max_lookback,omitempty" jsonschema:"Maximum number of builds to scan (default: 100)" default:"100"`
}

// SearchBuildsToolResponse is the result payload for jenkins_search_builds.
type SearchBuildsToolResponse struct {
	Builds  []Build `json:"builds"`
	Scanned int     `json:"scanned"` // how many builds were scanned
}

// StopBuildToolResponse represents the response from jenkins_stop_build.
type StopBuildToolResponse struct {
	JobName     string `json:"jobName"`
	BuildNumber int    `json:"buildNumber"`
	Stopped     bool   `json:"stopped"`
}

// CancelQueueItemToolArgs are the tool arguments for jenkins_cancel_queue_item.
type CancelQueueItemToolArgs struct {
	QueueID           int    `json:"queue_id" jsonschema:"Jenkins queue item ID to cancel"`
	ConfirmationToken string `json:"confirmation_token,omitempty" jsonschema:"MUT-003: token from prior preview to execute once"`
}

// CancelQueueItemToolResponse represents the response from jenkins_cancel_queue_item
// after a confirmed execute (preview returns mutation.PreviewResult instead).
type CancelQueueItemToolResponse struct {
	Status  string `json:"status"`  // "cancelled" on successful cancel POST
	QueueID int    `json:"queueId"` // cancelled queue item id
	Message string `json:"message"`
	JobName string `json:"jobName,omitempty"` // task name when known from prior lookup
}

// BuildLogs describes a slice of a Jenkins build log and related metadata.
type BuildLogs struct {
	JobName     string `json:"jobName"`
	BuildNumber int    `json:"buildNumber"`
	Offset      int    `json:"offset"`
	Length      int    `json:"length"`
	TotalSize   int    `json:"totalSize"`
	HasMore     bool   `json:"hasMore"`
	Logs        string `json:"logs"`
}

// RunningBuild represents a currently running Jenkins build
type RunningBuild struct {
	JobName     string     `json:"jobName"`
	BuildNumber int        `json:"buildNumber"`
	URL         string     `json:"url"`
	StartTime   TimeMS     `json:"startTime"`          // RFC3339 timestamp
	Duration    DurationMS `json:"duration"`           // Current duration (human-readable)
	Progress    *int       `json:"progress,omitempty"` // Progress percentage (if available)
}

// Job represents a Jenkins job with its current status
type Job struct {
	Name         string  `json:"name"`
	URL          string  `json:"url"`
	Color        string  `json:"color"`                  // Jenkins color coding (blue, red, yellow, etc.)
	Buildable    bool    `json:"buildable"`              // Whether the job can be built
	Description  string  `json:"description"`            // Job description
	LastBuild    *Build  `json:"lastBuild,omitempty"`    // Most recent build info
	RecentBuilds []Build `json:"recentBuilds,omitempty"` // Last 10 builds
	// Parameters are job-level parameter definitions (MUT-002), not last-build values.
	// Password/Credentials/Secret definition defaults are scrubbed.
	Parameters   []BuildParameter `json:"parameters"`
	QueuedBuilds []QueuedBuild    `json:"queuedBuilds,omitempty"` // Queued builds for this job
}

// JobParameterDefinition is an alias for job-level parameter definitions (MUT-002).
type JobParameterDefinition = BuildParameter

// BuildParameter represents a Jenkins job parameter definition (or legacy name for it).
type BuildParameter struct {
	Name         string   `json:"name"`
	Type         string   `json:"type"` // e.g. StringParameterDefinition, ChoiceParameterDefinition
	Description  string   `json:"description"`
	DefaultValue any      `json:"defaultValue,omitempty"`
	Choices      []string `json:"choices,omitempty"` // For choice parameters
}

// Build represents a Jenkins build
type Build struct {
	Number            int               `json:"number"`
	URL               string            `json:"url"`
	Building          bool              `json:"building"`
	Result            string            `json:"result"`            // SUCCESS, FAILURE, UNSTABLE, ABORTED, null if building
	Timestamp         TimeMS            `json:"timestamp"`         // RFC3339 timestamp
	Duration          DurationMS        `json:"duration"`          // Human-readable in output, parses from ms
	EstimatedDuration DurationMS        `json:"estimatedDuration"` // Human-readable in output, parses from ms
	DisplayName       string            `json:"displayName"`
	Parameters        map[string]string `json:"parameters,omitempty"` // Build parameters (name -> value)
}

// QueuedBuild represents a queued Jenkins build item
type QueuedBuild struct {
	JobName     string `json:"jobName"`
	URL         string `json:"url"`
	QueueID     int    `json:"queueId"`
	Why         string `json:"why"`
	QueuedSince TimeMS `json:"queuedSince"`
	Stuck       bool   `json:"stuck"`
	Buildable   bool   `json:"buildable"`
	Parameters  string `json:"parameters,omitempty"`
}
