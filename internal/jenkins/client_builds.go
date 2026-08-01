package jenkins

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// getBuildDetails fetches detailed information about a specific build URL.
func (opts *Client) GetBuildDetails(ctx context.Context, buildURL string) (*Build, error) {
	apiURL := strings.TrimRight(buildURL, "/") + "/api/json?tree=number,url,building,result,timestamp,duration,estimatedDuration,displayName,actions[_class,parameters[name,value]]"
	resp, err := opts.CallJenkins(ctx, opts.Client, http.MethodGet, apiURL, nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("build not found")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, strings.TrimSpace(readLimitedErrBody(resp.Body)))
	}

	var buildData struct {
		Build
		Actions []buildAction `json:"actions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&buildData); err != nil {
		return nil, err
	}
	build := buildData.Build
	build.Parameters = extractBuildParams(buildData.Actions)
	return &build, nil
}

// getBuildDetailsByJob fetches detailed information about a specific build by job path and build number.
func (opts *Client) GetBuildDetailsByJob(ctx context.Context, jobName string, buildNumber int) (*Build, error) {
	jobPath := BuildJobPath(jobName)
	apiPath := fmt.Sprintf("%s/%d/api/json?tree=number,url,building,result,timestamp,duration,estimatedDuration,displayName,actions[_class,parameters[name,value]]", jobPath, buildNumber)
	resp, err := opts.CallJenkins(ctx, opts.Client, http.MethodGet, apiPath, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("job '%s' build #%d not found", jobName, buildNumber)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, strings.TrimSpace(readLimitedErrBody(resp.Body)))
	}

	var buildData struct {
		Build
		Actions []buildAction `json:"actions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&buildData); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	build := buildData.Build
	build.Parameters = extractBuildParams(buildData.Actions)
	return &build, nil
}

// getRunningBuilds fetches currently running builds from jenkins api
func (opts *Client) GetRunningBuilds(ctx context.Context) ([]RunningBuild, error) {
	client := opts.Client

	// Build the API URL for computer information (includes executors)
	resp, err := opts.CallJenkins(ctx, client, http.MethodGet, "/computer/api/json?tree=computer[displayName,executors[currentExecutable[url,fullDisplayName,timestamp],idle,likelyStuck,progress]]", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, readLimitedErrBody(resp.Body))
	}

	// Parse response
	var computerResp struct {
		Computer []struct {
			DisplayName string `json:"displayName"`
			Executors   []struct {
				CurrentExecutable *struct {
					URL             string `json:"url"`
					FullDisplayName string `json:"fullDisplayName"`
					Timestamp       int64  `json:"timestamp"`
				} `json:"currentExecutable"`
				Idle        bool `json:"idle"`
				LikelyStuck bool `json:"likelyStuck"`
				Progress    *int `json:"progress,omitempty"`
			} `json:"executors"`
		} `json:"computer"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&computerResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var runningBuilds []RunningBuild
	currentTime := time.Now().UnixMilli()

	// Process each computer and its executors
	for _, computer := range computerResp.Computer {
		for _, executor := range computer.Executors {
			// Skip idle executors
			if executor.Idle || executor.CurrentExecutable == nil {
				continue
			}

			executable := executor.CurrentExecutable

			// Parse job name and build number from the full display name
			// Format is typically "jobName #buildNumber"; fallback to URL if needed
			jobName, buildNumber := parseJobNameAndBuildNumber(executable.FullDisplayName)
			if buildNumber == 0 {
				if n := parseBuildNumberFromURL(executable.URL); n > 0 {
					buildNumber = n
				}
			}

			// Compute human-friendly duration from ms and RFC3339 start time
			durMs := currentTime - executable.Timestamp
			startTime := time.Unix(0, executable.Timestamp*int64(time.Millisecond))
			runningBuild := RunningBuild{
				JobName:     jobName,
				BuildNumber: buildNumber,
				URL:         executable.URL,
				StartTime:   TimeMS(startTime),
				Duration:    DurationMS(time.Duration(durMs) * time.Millisecond),
				Progress:    executor.Progress,
			}

			runningBuilds = append(runningBuilds, runningBuild)
		}
	}

	return runningBuilds, nil
}

// getQueuedBuilds fetches queued builds from Jenkins queue API
func (opts *Client) GetQueuedBuilds(ctx context.Context) ([]QueuedBuild, error) {
	client := opts.Client
	resp, err := opts.CallJenkins(ctx, client, http.MethodGet, "/queue/api/json?tree=items[id,task[name,url],why,inQueueSince,stuck,buildable,params]", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, readLimitedErrBody(resp.Body))
	}

	var queueResp struct {
		Items []struct {
			ID   int `json:"id"`
			Task struct {
				Name string `json:"name"`
				URL  string `json:"url"`
			} `json:"task"`
			Why          string `json:"why"`
			InQueueSince int64  `json:"inQueueSince"`
			Stuck        bool   `json:"stuck"`
			Buildable    bool   `json:"buildable"`
			Params       string `json:"params"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&queueResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	queued := make([]QueuedBuild, 0, len(queueResp.Items))
	for _, it := range queueResp.Items {
		qb := QueuedBuild{
			JobName:     it.Task.Name,
			URL:         it.Task.URL,
			QueueID:     it.ID,
			Why:         it.Why,
			QueuedSince: TimeMS(time.Unix(0, it.InQueueSince*int64(time.Millisecond))),
			Stuck:       it.Stuck,
			Buildable:   it.Buildable,
			Parameters:  strings.TrimSpace(it.Params),
		}
		queued = append(queued, qb)
	}
	return queued, nil
}

// parseJobNameAndBuildNumber extracts job name and build number from Jenkins full display name
func parseJobNameAndBuildNumber(fullDisplayName string) (string, int) {
	// Try to find the pattern "jobName #buildNumber"
	parts := strings.Split(fullDisplayName, " #")
	if len(parts) == 2 {
		jobName := parts[0]
		buildNumberStr := parts[1]

		// Try to parse the build number
		var buildNumber int
		if _, err := fmt.Sscanf(buildNumberStr, "%d", &buildNumber); err == nil {
			return jobName, buildNumber
		}
	}

	// If parsing fails, return the full name as job name and 0 as build number
	return fullDisplayName, 0
}

// parseBuildNumberFromURL extracts the trailing numeric segment from a Jenkins build URL.
func parseBuildNumberFromURL(u string) int {
	if i := strings.IndexByte(u, '?'); i >= 0 {
		u = u[:i]
	}
	if i := strings.IndexByte(u, '#'); i >= 0 {
		u = u[:i]
	}
	parts := strings.Split(strings.TrimSuffix(u, "/"), "/")
	if len(parts) == 0 {
		return 0
	}
	last := parts[len(parts)-1]
	n, err := strconv.Atoi(last)
	if err != nil {
		return 0
	}
	return n
}
