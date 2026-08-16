package jenkins

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Regression: a plain upstream→root→downstream DAG must NOT report
// CycleDetected. With direction=both the traversal follows each edge in both
// directions, so expanding deploy#3 sees the already-visited service#5 (the
// reverse of the edge just traversed) — that is a DAG cross-edge, not a
// cycle. Previously every such revisit set CycleDetected=true and could emit
// a phantom id→id "cycle_skipped" self-edge.
func TestGetBuildGraph_DAGDoesNotReportCycle(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setGraphFixture()

	g, err := f.opts().GetBuildGraph(context.Background(), GetBuildGraphToolArgs{
		JobName:     "service",
		BuildNumber: 5,
		MaxDepth:    3,
		MaxNodes:    20,
		Direction:   GraphDirectionBoth,
	})
	if err != nil {
		t.Fatal(err)
	}
	if g.CycleDetected {
		t.Fatalf("plain DAG must not report a cycle: %+v", g)
	}
	for _, e := range g.Edges {
		if e.From == e.To {
			t.Fatalf("phantom self-edge %s->%s (%s) on acyclic graph", e.From, e.To, e.Kind)
		}
		if e.Kind == "cycle_skipped" {
			t.Fatalf("cycle_skipped edge on acyclic graph: %+v", e)
		}
	}
	if g.NodeCount < 3 {
		t.Fatalf("expected deploy+service+smoke nodes, got %+v", g.Nodes)
	}
}

// Regression: a diamond (A triggers B and C; B and C both trigger D) enqueued
// D twice; the second dequeue emitted a phantom D→D "cycle_skipped" edge and
// set CycleDetected. Diamonds are acyclic.
func TestGetBuildGraph_DiamondNoPhantomSelfEdge(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()

	// root D#1 has upstreams B#1 and C#1; both have upstream A#1.
	f.buildJSON["job/d/1"] = `{
		"number": 1, "result": "FAILURE", "building": false,
		"timestamp": 1700000900000, "duration": 100,
		"actions": [{"_class":"hudson.model.CauseAction","causes":[
			{"_class":"hudson.model.Cause$UpstreamCause","upstreamProject":"b","upstreamBuild":1,"shortDescription":"b"},
			{"_class":"hudson.model.Cause$UpstreamCause","upstreamProject":"c","upstreamBuild":1,"shortDescription":"c"}
		]}]
	}`
	for _, n := range []string{"b", "c"} {
		f.buildJSON[fmt.Sprintf("job/%s/1", n)] = `{
			"number": 1, "result": "SUCCESS", "building": false,
			"timestamp": 1700000800000, "duration": 100,
			"actions": [{"_class":"hudson.model.CauseAction","causes":[
				{"_class":"hudson.model.Cause$UpstreamCause","upstreamProject":"a","upstreamBuild":1,"shortDescription":"a"}
			]}],
			"downstreamBuilds": [{"jobName":"d","buildNumber":1}]
		}`
	}
	f.buildJSON["job/a/1"] = `{
		"number": 1, "result": "SUCCESS", "building": false,
		"timestamp": 1700000700000, "duration": 100,
		"actions": [],
		"downstreamBuilds": [{"jobName":"b","buildNumber":1},{"jobName":"c","buildNumber":1}]
	}`

	g, err := f.opts().GetBuildGraph(context.Background(), GetBuildGraphToolArgs{
		JobName:     "d",
		BuildNumber: 1,
		MaxDepth:    4,
		MaxNodes:    20,
		Direction:   GraphDirectionBoth,
	})
	if err != nil {
		t.Fatal(err)
	}
	if g.CycleDetected {
		t.Fatalf("diamond is acyclic: %+v", g)
	}
	for _, e := range g.Edges {
		if e.From == e.To {
			t.Fatalf("phantom self-edge: %+v", e)
		}
	}
	// All four nodes discovered exactly once.
	seen := map[string]int{}
	for _, n := range g.Nodes {
		seen[n.ID]++
	}
	for _, id := range []string{"a#1", "b#1", "c#1", "d#1"} {
		if seen[id] != 1 {
			t.Fatalf("node %s seen %d times: %+v", id, seen[id], g.Nodes)
		}
	}
}

// Regression: when every waiter abandons a shared wait (caller context
// cancelled), the leader poll loop must stop promptly instead of polling
// Jenkins until the wait timeout (JEN-004 demux leak).
func TestWaitForQueueItem_AbandonedSharedLoopStops(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	// Pending-forever queue item 8 (same shape as the cancel test).
	f.queueJSON[8] = `{
		"id": 8,
		"task": {"name": "demo", "url": "http://jenkins/job/demo/"},
		"why": "waiting",
		"inQueueSince": 1700000000000,
		"stuck": false,
		"buildable": true,
		"params": "",
		"cancelled": false,
		"executable": null
	}`

	c := f.opts()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_, _ = c.WaitForQueueItem(ctx, 8, 30, 0) // 30s wait budget
		close(done)
	}()
	// Let the shared loop start and poll at least once.
	time.Sleep(400 * time.Millisecond)
	cancel()
	<-done // caller returns promptly with context_cancelled

	// The shared poll loop must now stop (no waiters remain). The loop writes
	// its poll snapshot on exit; before the fix it kept polling until the 30s
	// deadline, so no snapshot appeared and the loop kept running.
	deadline := time.After(5 * time.Second)
	for {
		if c.WaitPollCountQueue(8) > 0 {
			return // loop exited and recorded its polls
		}
		select {
		case <-deadline:
			t.Fatal("shared poll loop still running after all waiters abandoned")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// Regression: non-OK list responses embedded the entire (up to 4 MiB) body in
// the returned error. Errors must stay small and secret-safe.
func TestListViews_ErrorBodyTruncated(t *testing.T) {
	t.Parallel()
	big := strings.Repeat("E", 4<<20) // 4 MiB error page
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(big))
	}))
	defer srv.Close()

	c := &Client{URL: srv.URL, User: "u", Token: "t", Client: srv.Client()}
	_, err := c.ListViews(context.Background(), 0, 10)
	if err == nil {
		t.Fatal("want error")
	}
	if len(err.Error()) > 1024 {
		t.Fatalf("error embeds %d bytes of upstream body; want bounded", len(err.Error()))
	}
}

// Regression: running-build display names for folder jobs arrive as
// "folder » job #42" and were returned verbatim (not a typed path), and a
// job whose name itself contains " #" lost the build-number split.
func TestParseJobNameAndBuildNumber_FoldersAndHashInName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in    string
		wantJ string
		wantN int
	}{
		{"demo #7", "demo", 7},
		{"team » app #42", "team/app", 42},      // folder display separators
		{"my #job #5", "my #job", 5},            // " #" inside the job name
		{"a » b » c #100", "a/b/c", 100},        // nested folders
		{"no-number-here", "no-number-here", 0}, // no build number
	}
	for _, tc := range cases {
		j, n := parseJobNameAndBuildNumber(tc.in)
		if j != tc.wantJ || n != tc.wantN {
			t.Errorf("parseJobNameAndBuildNumber(%q) = (%q, %d), want (%q, %d)",
				tc.in, j, n, tc.wantJ, tc.wantN)
		}
	}
}

// Regression: a server-supplied Retry-After delta-seconds value above
// math.MaxInt64/1e9 overflowed time.Duration and wrapped negative, which the
// caller then clamped to 0 — producing immediate (un-backed-off) retries.
func TestParseRetryAfter_OverflowClamped(t *testing.T) {
	t.Parallel()
	now := time.Now()
	// 1e10 seconds × 1e9 ns/s overflows int64 and wraps negative pre-fix.
	d, ok := parseRetryAfter("10000000000", now)
	if !ok {
		t.Fatal("delta-seconds must parse")
	}
	if d < 0 {
		t.Fatalf("overflow wrapped negative: %v", d)
	}
	// Ordinary values unchanged.
	d2, ok := parseRetryAfter("5", now)
	if !ok || d2 != 5*time.Second {
		t.Fatalf("5s -> %v, %v", d2, ok)
	}
}

// Regression: GetControllerHealth scrubbed capability ProbeNotes in place on a
// cache-hit shallow copy, mutating the shared cache backing array and racing
// concurrent readers. Run with -race.
func TestGetControllerHealth_ConcurrentProbeNotesNoRace(t *testing.T) {
	t.Parallel()
	f := newJenkinsFixture()
	defer f.close()

	c := f.opts()
	// Warm the capability cache so health calls take the cache-hit path.
	if _, err := c.Capabilities(context.Background()); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				if _, err := c.GetControllerHealth(context.Background(), GetControllerHealthToolArgs{}); err != nil {
					t.Errorf("health: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}
