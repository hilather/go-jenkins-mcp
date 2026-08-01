package jenkins

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// startJob triggers a Jenkins job, optionally with parameters, and optionally waits.
func (opts *Client) StartJob(ctx context.Context, jobName string, params map[string]any) (*StartJobToolResponse, error) {
	jobPath := BuildJobPath(jobName)

	// Always use buildWithParameters endpoint as it works for both parameterized and non-parameterized jobs
	apiPath := jobPath + "/buildWithParameters"

	form := url.Values{}
	for k, v := range params {
		form.Set(k, fmt.Sprint(v))
	}
	// If no parameters provided, still send the form (empty is fine for buildWithParameters)

	body := strings.NewReader(form.Encode())

	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	if f, c, ok, _ := opts.GetCrumb(ctx); ok {
		headers[f] = c
	}
	resp, err := opts.CallJenkins(ctx, opts.Client, http.MethodPost, apiPath, body, headers)
	if err != nil {
		return nil, fmt.Errorf("failed to start build: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, strings.TrimSpace(readLimitedErrBody(resp.Body)))
	}

	// Capture Location header if present. Jenkins typically returns a queue item URL,
	// but in some cases it may point directly to the build URL if it started immediately.
	loc := resp.Header.Get("Location")
	result := &StartJobToolResponse{JobName: jobName}
	if loc != "" {
		if strings.Contains(loc, "/queue/item/") {
			// Queue URL case
			result.QueueURL = loc
			if queueID := extractQueueID(loc); queueID > 0 {
				result.QueueID = queueID
				if buildNumber, buildURL := opts.GetQueueItemDetails(ctx, queueID, 30*time.Second); buildNumber > 0 {
					result.BuildNumber = buildNumber
					result.BuildURL = buildURL
				}
			}
		} else {
			// Likely a direct build URL
			if bn := parseBuildNumberFromURL(loc); bn > 0 {
				result.BuildNumber = bn
				result.BuildURL = loc
			}
		}
	}

	// Hardcoded 'queued' behavior: return immediately after getting queue URL
	return result, nil
}

// extractQueueID extracts queue item ID from queue URL.
func extractQueueID(queueURL string) int {
	parts := strings.Split(strings.TrimSuffix(queueURL, "/"), "/")
	if len(parts) == 0 {
		return 0
	}
	queueID, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		return 0
	}
	return queueID
}

// getQueueItem fetches a Jenkins queue item by ID.
func (opts *Client) GetQueueItem(ctx context.Context, queueID int) (*QueueItem, error) {
	apiPath := fmt.Sprintf("/queue/item/%d/api/json?tree=id,task[name,url],why,inQueueSince,stuck,buildable,params,cancelled,executable[number,url,building,result,timestamp,duration,estimatedDuration,displayName]", queueID)

	resp, err := opts.CallJenkins(ctx, opts.Client, http.MethodGet, apiPath, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch queue item: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("queue item #%d not found", queueID)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, strings.TrimSpace(readLimitedErrBody(resp.Body)))
	}

	var data struct {
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
		Cancelled    bool   `json:"cancelled"`
		Executable   *Build `json:"executable"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode queue item response: %w", err)
	}

	item := &QueueItem{
		QueueID:     data.ID,
		JobName:     data.Task.Name,
		URL:         data.Task.URL,
		Why:         data.Why,
		QueuedSince: TimeMS(time.Unix(0, data.InQueueSince*int64(time.Millisecond))),
		Stuck:       data.Stuck,
		Buildable:   data.Buildable,
		Parameters:  strings.TrimSpace(data.Params),
		Cancelled:   data.Cancelled,
		Executable:  data.Executable,
	}
	return item, nil
}

// getQueueItemDetails waits briefly for a queue item to receive an executable.
func (opts *Client) GetQueueItemDetails(ctx context.Context, queueID int, maxWait time.Duration) (int, string) {
	deadline := time.Now().Add(maxWait)
	pollIntervals := []time.Duration{1 * time.Second, 2 * time.Second, 3 * time.Second, 5 * time.Second, 8 * time.Second, 11 * time.Second}

	for i := 0; ; i++ {
		item, err := opts.GetQueueItem(ctx, queueID)
		if err == nil && item.Executable != nil && item.Executable.Number > 0 {
			return item.Executable.Number, item.Executable.URL
		}
		if time.Now().After(deadline) {
			break
		}
		interval := pollIntervals[min(i, len(pollIntervals)-1)]
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		if interval > remaining {
			interval = remaining
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0, ""
		case <-timer.C:
		}
	}

	return 0, ""
}

// stopBuild stops a running Jenkins build.
func (opts *Client) StopBuild(ctx context.Context, jobName string, buildNumber int) (*StopBuildToolResponse, error) {
	jobPath := BuildJobPath(jobName)
	apiPath := fmt.Sprintf("%s/%d/stop", jobPath, buildNumber)

	headers := map[string]string{}
	if f, c, ok, _ := opts.GetCrumb(ctx); ok {
		headers[f] = c
	}

	resp, err := opts.CallJenkins(ctx, opts.Client, http.MethodPost, apiPath, nil, headers)
	if err != nil {
		return nil, fmt.Errorf("failed to stop build: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("job '%s' build #%d not found", jobName, buildNumber)
	}
	// Jenkins returns 302 on successful stop
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, strings.TrimSpace(readLimitedErrBody(resp.Body)))
	}

	return &StopBuildToolResponse{
		JobName:     jobName,
		BuildNumber: buildNumber,
		Stopped:     true,
	}, nil
}

// CancelQueueItem cancels a Jenkins queue item via POST /queue/cancelItem?id=<id>
// (MUT-003). CSRF crumb is attached when the controller provides one.
// POST is never auto-retried (NET-003 / callJenkins non-idempotent path).
//
// Callers must verify the item is still cancellable (fresh GetQueueItem) before
// invoking this method: missing/already-left/already-cancelled targets must not
// be reported as a successful cancel at the tool layer.
func (opts *Client) CancelQueueItem(ctx context.Context, queueID int) (*CancelQueueItemToolResponse, error) {
	if queueID <= 0 {
		return nil, fmt.Errorf("queue_id must be positive")
	}
	apiPath := fmt.Sprintf("/queue/cancelItem?id=%d", queueID)

	headers := map[string]string{}
	if f, c, ok, _ := opts.GetCrumb(ctx); ok {
		headers[f] = c
	}

	resp, err := opts.CallJenkins(ctx, opts.Client, http.MethodPost, apiPath, nil, headers)
	if err != nil {
		return nil, fmt.Errorf("failed to cancel queue item: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Missing item is not a successful cancel (MUT-003 wrong-state).
		return nil, fmt.Errorf("queue item #%d not found", queueID)
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, strings.TrimSpace(readLimitedErrBody(resp.Body)))
	}
	// Jenkins commonly returns 302 on successful cancelItem; treat other 2xx/3xx as OK.
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, strings.TrimSpace(readLimitedErrBody(resp.Body)))
	}

	return &CancelQueueItemToolResponse{
		Status:  "cancelled",
		QueueID: queueID,
		Message: fmt.Sprintf("queue item #%d cancel requested", queueID),
	}, nil
}
