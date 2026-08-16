package tools

import (
	"context"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
)

// Regression: the full-scan loop in runRegressionFullScan used `break` inside
// a `select` — it broke the select, not the for loop, so a cancelled scan kept
// iterating every remaining build: each appended a duplicate "scan cancelled"
// interval and was counted as scanned without being evaluated. The loop must
// stop at the first cancelled iteration.
func TestRunRegressionFullScan_StopsOnCancel(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled before the scan starts

	out := &FindRegressionWindowToolResponse{Job: "demo"}
	builds := []jenkins.Build{{Number: 10}, {Number: 9}, {Number: 8}, {Number: 6}, {Number: 5}}
	// No match criteria: evaluateCandidate never touches the client, so any
	// post-cancel iteration is observable purely via ScannedBuilds/intervals.
	cfg := regressionMatchConfig{}
	runRegressionFullScan(ctx, nil, regState{}, out, builds, cfg, 1024, 4096)

	if len(out.ScannedBuilds) != 0 {
		t.Fatalf("cancelled scan must not scan builds; scanned=%v", out.ScannedBuilds)
	}
	cancelNotes := 0
	for _, iv := range out.UncertainIntervals {
		if strings.Contains(iv.Reason, "scan cancelled") {
			cancelNotes++
		}
	}
	if cancelNotes != 1 {
		t.Fatalf("want exactly 1 'scan cancelled' interval, got %d: %+v", cancelNotes, out.UncertainIntervals)
	}
	if !out.Incomplete {
		t.Fatal("cancelled scan must mark Incomplete")
	}
}
