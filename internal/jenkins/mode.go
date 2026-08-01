package jenkins

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ControllerMode is a cheap, non-admin snapshot of root controller flags (HEALTH-002 / DIAG-007).
// Fields are populated only when the root api/json tree is readable; 403 is not fatal.
type ControllerMode struct {
	// QuietingDown is true when Jenkins is in quiet-down (no new builds accepted).
	QuietingDown bool `json:"quietingDown"`
	// Mode is the Jenkins node mode string when present (e.g. NORMAL, EXCLUSIVE).
	Mode string `json:"mode,omitempty"`
	// NumExecutors is the controller's configured executor count when present.
	NumExecutors int `json:"numExecutors,omitempty"`
	// JenkinsVersion from X-Jenkins when available on the same response.
	JenkinsVersion string `json:"jenkinsVersion,omitempty"`
	// Unauthorized is true when the root API returned 403 (degrade; not empty success).
	Unauthorized bool `json:"unauthorized,omitempty"`
	// Message is a short safe diagnostic when degraded.
	Message string `json:"message,omitempty"`
	// FetchedAt is wall-clock when this sample was taken.
	FetchedAt time.Time `json:"fetchedAt,omitempty"`
}

// modeAPITree is the approved root tree: no secrets, no full job list.
const modeAPITree = "quietingDown,mode,numExecutors"

// GetControllerMode fetches quiet-down / mode flags from /api/json with a minimal tree.
// Prefer this over a full jobs listing for health/diagnose paths.
func (opts *Client) GetControllerMode(ctx context.Context) (*ControllerMode, error) {
	if opts == nil {
		return nil, fmt.Errorf("jenkins client is nil")
	}
	apiPath := "/api/json?tree=" + modeAPITree
	resp, err := opts.CallJenkins(ctx, opts.Client, http.MethodGet, apiPath, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch controller mode: %w", err)
	}
	defer resp.Body.Close()

	out := &ControllerMode{FetchedAt: time.Now().UTC()}
	if v := strings.TrimSpace(resp.Header.Get("X-Jenkins")); v != "" {
		out.JenkinsVersion = v
	}

	if resp.StatusCode == http.StatusForbidden {
		out.Unauthorized = true
		out.Message = "not authorized to read controller mode (HTTP 403)"
		return out, nil
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("jenkins api returned status 401: unauthorized")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, strings.TrimSpace(readLimitedErrBody(resp.Body)))
	}

	var raw struct {
		QuietingDown bool   `json:"quietingDown"`
		Mode         string `json:"mode"`
		NumExecutors int    `json:"numExecutors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("failed to decode controller mode: %w", err)
	}
	out.QuietingDown = raw.QuietingDown
	out.Mode = strings.TrimSpace(raw.Mode)
	out.NumExecutors = raw.NumExecutors
	return out, nil
}
