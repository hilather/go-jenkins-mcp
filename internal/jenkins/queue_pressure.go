package jenkins

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// GetQueuePressureToolArgs are the tool arguments for jenkins_queue_pressure.
type GetQueuePressureToolArgs struct {
	// No required arguments; optional profile is process-bound.
}

// QueuePressureSample is a short sample of a waiting item (no secrets).
type QueuePressureSample struct {
	QueueID     int    `json:"queueId"`
	JobName     string `json:"jobName,omitempty"`
	Stuck       bool   `json:"stuck,omitempty"`
	Buildable   bool   `json:"buildable,omitempty"`
	WaitSeconds int64  `json:"waitSeconds"`
	Why         string `json:"why,omitempty"`
}

// GetQueuePressureToolResponse summarizes queue depth and wait pressure (HEALTH-001).
type GetQueuePressureToolResponse struct {
	Depth             int                   `json:"depth"`
	StuckCount        int                   `json:"stuckCount"`
	BuildableCount    int                   `json:"buildableCount"`
	OldestWaitSeconds int64                 `json:"oldestWaitSeconds"`
	OldestJobName     string                `json:"oldestJobName,omitempty"`
	OldestQueueID     int                   `json:"oldestQueueId,omitempty"`
	Samples           []QueuePressureSample `json:"samples,omitempty"`
	Unauthorized      bool                  `json:"unauthorized,omitempty"`
	Message           string                `json:"message,omitempty"`
}

// maxQueuePressureSamples bounds sample rows in the response.
const maxQueuePressureSamples = 10

// queuePressureTree is the approved queue tree (no admin-only env fields).
const queuePressureTree = "items[id,task[name],why,inQueueSince,stuck,buildable]"

// GetQueuePressure fetches queue depth, stuck count, and oldest wait from /queue/api/json.
// On HTTP 403, returns Unauthorized=true so callers distinguish permission from empty queue.
func (opts *Client) GetQueuePressure(ctx context.Context) (*GetQueuePressureToolResponse, error) {
	if opts == nil {
		return nil, fmt.Errorf("jenkins client is nil")
	}
	apiPath := "/queue/api/json?tree=" + queuePressureTree
	resp, err := opts.CallJenkins(ctx, opts.Client, http.MethodGet, apiPath, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return &GetQueuePressureToolResponse{
			Unauthorized: true,
			Message:      "not authorized to read Jenkins queue (HTTP 403)",
		}, nil
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("jenkins api returned status 401: unauthorized")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, strings.TrimSpace(readLimitedErrBody(resp.Body)))
	}

	var queueResp struct {
		Items []struct {
			ID   int `json:"id"`
			Task struct {
				Name string `json:"name"`
			} `json:"task"`
			Why          string `json:"why"`
			InQueueSince int64  `json:"inQueueSince"`
			Stuck        bool   `json:"stuck"`
			Buildable    bool   `json:"buildable"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&queueResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	nowMS := time.Now().UnixMilli()
	out := &GetQueuePressureToolResponse{
		Depth: len(queueResp.Items),
	}
	var oldestSince int64
	for _, it := range queueResp.Items {
		if it.Stuck {
			out.StuckCount++
		}
		if it.Buildable {
			out.BuildableCount++
		}
		waitSec := int64(0)
		if it.InQueueSince > 0 && nowMS >= it.InQueueSince {
			waitSec = (nowMS - it.InQueueSince) / 1000
		}
		if it.InQueueSince > 0 && (oldestSince == 0 || it.InQueueSince < oldestSince) {
			oldestSince = it.InQueueSince
			out.OldestJobName = strings.TrimSpace(it.Task.Name)
			out.OldestQueueID = it.ID
		}
		if len(out.Samples) < maxQueuePressureSamples {
			out.Samples = append(out.Samples, QueuePressureSample{
				QueueID:     it.ID,
				JobName:     strings.TrimSpace(it.Task.Name),
				Stuck:       it.Stuck,
				Buildable:   it.Buildable,
				WaitSeconds: waitSec,
				Why:         sanitizeNodeText(scrubSecretsLike(it.Why)),
			})
		}
	}
	if oldestSince > 0 && nowMS >= oldestSince {
		out.OldestWaitSeconds = (nowMS - oldestSince) / 1000
	}
	return out, nil
}
