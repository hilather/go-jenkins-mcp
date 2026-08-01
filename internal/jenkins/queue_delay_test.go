package jenkins

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestExplainQueueDelay_NoExecutor(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	since := time.Now().Add(-120 * time.Second).UnixMilli()
	f.queueJSON[11] = fmt.Sprintf(`{
		"id": 11,
		"task": {"name": "busy-job"},
		"why": "Waiting for next available executor",
		"inQueueSince": %d,
		"stuck": true,
		"buildable": true,
		"blocked": false,
		"cancelled": false,
		"assignedLabel": null,
		"executable": null
	}`, since)
	f.runningJSON = `{
		"computer": [
			{"displayName": "master", "offline": false, "numExecutors": 2, "idle": false,
			 "assignedLabels": [{"name": "master"}], "executors": [{"idle": false}, {"idle": false}]}
		]
	}`
	f.queueAPIJSON = fmt.Sprintf(`{"items":[
		{"id":11,"task":{"name":"busy-job"},"why":"Waiting for next available executor","inQueueSince":%d,"stuck":true,"buildable":true}
	]}`, since)

	res, err := f.opts().ExplainQueueDelay(context.Background(), ExplainQueueDelayToolArgs{QueueItemID: 11})
	if err != nil {
		t.Fatal(err)
	}
	if res.PrimaryCategory != DelayCategoryNoExecutor {
		t.Fatalf("primary=%s want %s summary=%s cats=%v", res.PrimaryCategory, DelayCategoryNoExecutor, res.Summary, res.Categories)
	}
	if res.ETA.Heuristic != true {
		t.Fatal("ETA must be labeled heuristic")
	}
	if len(res.EvidenceEndpoints) == 0 {
		t.Fatal("evidence endpoints required")
	}
	if res.Freshness.IsZero() {
		t.Fatal("freshness required")
	}
	if res.WaitSeconds < 100 {
		t.Fatalf("wait seconds: %d", res.WaitSeconds)
	}
}

func TestExplainQueueDelay_OfflineLabel(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	since := time.Now().Add(-60 * time.Second).UnixMilli()
	f.queueJSON[12] = fmt.Sprintf(`{
		"id": 12,
		"task": {"name": "gpu-job"},
		"why": "There are no nodes with the label ‘gpu’",
		"inQueueSince": %d,
		"stuck": true,
		"buildable": true,
		"blocked": false,
		"assignedLabel": {"name": "gpu"},
		"executable": null
	}`, since)
	f.runningJSON = `{
		"computer": [
			{"displayName": "gpu-agent", "offline": true, "temporarilyOffline": true, "numExecutors": 1, "idle": true,
			 "offlineCauseReason": "Connection was broken",
			 "assignedLabels": [{"name": "gpu-agent"}, {"name": "gpu"}],
			 "executors": [{"idle": true}]},
			{"displayName": "master", "offline": false, "numExecutors": 1, "idle": true,
			 "assignedLabels": [{"name": "master"}], "executors": [{"idle": true}]}
		]
	}`

	res, err := f.opts().ExplainQueueDelay(context.Background(), ExplainQueueDelayToolArgs{QueueItemID: 12})
	if err != nil {
		t.Fatal(err)
	}
	if res.PrimaryCategory != DelayCategoryOfflineLabel {
		t.Fatalf("primary=%s want offline_label summary=%s cats=%v", res.PrimaryCategory, res.Summary, res.Categories)
	}
	if res.LabelMatch == nil || res.LabelMatch.MatchingOnline != 0 {
		t.Fatalf("label match: %+v", res.LabelMatch)
	}
	if res.ETA.Seconds != nil {
		t.Fatal("unsupported ETA must not set seconds for offline_label")
	}
}

func TestExplainQueueDelay_Throttling(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	since := time.Now().Add(-30 * time.Second).UnixMilli()
	f.queueJSON[13] = fmt.Sprintf(`{
		"id": 13,
		"task": {"name": "throttled-job"},
		"why": "Throttled: maximum number of concurrent builds reached",
		"inQueueSince": %d,
		"stuck": false,
		"buildable": false,
		"blocked": true,
		"assignedLabel": null,
		"executable": null
	}`, since)
	f.runningJSON = `{"computer":[{"displayName":"master","offline":false,"numExecutors":4,"idle":true,
		"assignedLabels":[{"name":"master"}],"executors":[{"idle":true},{"idle":true},{"idle":true},{"idle":true}]}]}`

	res, err := f.opts().ExplainQueueDelay(context.Background(), ExplainQueueDelayToolArgs{QueueItemID: 13})
	if err != nil {
		t.Fatal(err)
	}
	if res.PrimaryCategory != DelayCategoryThrottling {
		t.Fatalf("primary=%s want throttling summary=%s cats=%v", res.PrimaryCategory, res.Summary, res.Categories)
	}
	if res.ETA.Seconds != nil {
		t.Fatal("no factual ETA for throttling")
	}
}

func TestExplainQueueDelay_Blocked(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	since := time.Now().Add(-45 * time.Second).UnixMilli()
	f.queueJSON[14] = fmt.Sprintf(`{
		"id": 14,
		"task": {"name": "blocked-job"},
		"why": "Build is blocked",
		"inQueueSince": %d,
		"stuck": false,
		"buildable": false,
		"blocked": true,
		"assignedLabel": null,
		"executable": null
	}`, since)

	res, err := f.opts().ExplainQueueDelay(context.Background(), ExplainQueueDelayToolArgs{QueueItemID: 14})
	if err != nil {
		t.Fatal(err)
	}
	if res.PrimaryCategory != DelayCategoryBlocked {
		t.Fatalf("primary=%s want blocked summary=%s", res.PrimaryCategory, res.Summary)
	}
}

func TestExplainQueueDelay_UpstreamWait(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	since := time.Now().Add(-20 * time.Second).UnixMilli()
	f.queueJSON[15] = fmt.Sprintf(`{
		"id": 15,
		"task": {"name": "downstream"},
		"why": "Waiting for upstream project parent-job to complete",
		"inQueueSince": %d,
		"stuck": false,
		"buildable": false,
		"blocked": true,
		"assignedLabel": null,
		"executable": null
	}`, since)

	res, err := f.opts().ExplainQueueDelay(context.Background(), ExplainQueueDelayToolArgs{QueueItemID: 15})
	if err != nil {
		t.Fatal(err)
	}
	if res.PrimaryCategory != DelayCategoryUpstreamWait {
		t.Fatalf("primary=%s want upstream_wait cats=%v", res.PrimaryCategory, res.Categories)
	}
}

func TestExplainQueueDelay_QuietingDown(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.quietingDown = true
	since := time.Now().Add(-10 * time.Second).UnixMilli()
	f.queueJSON[16] = fmt.Sprintf(`{
		"id": 16,
		"task": {"name": "any-job"},
		"why": "Jenkins is about to shut down",
		"inQueueSince": %d,
		"stuck": false,
		"buildable": true,
		"blocked": false,
		"executable": null
	}`, since)

	res, err := f.opts().ExplainQueueDelay(context.Background(), ExplainQueueDelayToolArgs{QueueItemID: 16})
	if err != nil {
		t.Fatal(err)
	}
	if res.PrimaryCategory != DelayCategoryQuietingDown {
		t.Fatalf("primary=%s want quieting_down quietingDown=%v", res.PrimaryCategory, res.QuietingDown)
	}
	if !res.QuietingDown {
		t.Fatal("quietingDown flag")
	}
}

func TestExplainQueueDelay_ByJobName(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	since := time.Now().Add(-15 * time.Second).UnixMilli()
	f.queueAPIJSON = fmt.Sprintf(`{"items":[
		{"id": 21, "task": {"name": "pending-job"}, "why": "Waiting for next available executor",
		 "inQueueSince": %d, "stuck": true, "buildable": true, "blocked": false}
	]}`, since)
	f.queueJSON[21] = fmt.Sprintf(`{
		"id": 21,
		"task": {"name": "pending-job"},
		"why": "Waiting for next available executor",
		"inQueueSince": %d,
		"stuck": true,
		"buildable": true,
		"blocked": false,
		"executable": null
	}`, since)
	f.runningJSON = `{"computer":[{"displayName":"master","offline":false,"numExecutors":1,"idle":false,
		"assignedLabels":[{"name":"master"}],"executors":[{"idle":false}]}]}`

	res, err := f.opts().ExplainQueueDelay(context.Background(), ExplainQueueDelayToolArgs{JobName: "pending-job"})
	if err != nil {
		t.Fatal(err)
	}
	if res.QueueItemID != 21 || res.JobName != "pending-job" {
		t.Fatalf("%+v", res)
	}
	if res.PrimaryCategory != DelayCategoryNoExecutor {
		t.Fatalf("primary=%s", res.PrimaryCategory)
	}
}

func TestExplainQueueDelay_NotInQueue(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	res, err := f.opts().ExplainQueueDelay(context.Background(), ExplainQueueDelayToolArgs{JobName: "missing-job"})
	if err != nil {
		t.Fatal(err)
	}
	if res.PrimaryCategory != DelayCategoryNotInQueue {
		t.Fatalf("%+v", res)
	}
}

func TestExplainQueueDelay_RequiresInput(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	_, err := f.opts().ExplainQueueDelay(context.Background(), ExplainQueueDelayToolArgs{})
	if err == nil {
		t.Fatal("expected invalid argument")
	}
	if !strings.Contains(err.Error(), "queue_item_id") && !strings.Contains(err.Error(), "job_name") {
		t.Fatalf("err: %v", err)
	}
}

func TestExplainQueueDelay_RejectsJobURL(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	_, err := f.opts().ExplainQueueDelay(context.Background(), ExplainQueueDelayToolArgs{
		JobName: "https://jenkins.example/job/x",
	})
	if err == nil {
		t.Fatal("expected URL rejection")
	}
}

func TestGetControllerMode(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.quietingDown = true
	f.rootMode = "NORMAL"
	f.numExecutors = 4
	m, err := f.opts().GetControllerMode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !m.QuietingDown || m.Mode != "NORMAL" || m.NumExecutors != 4 {
		t.Fatalf("%+v", m)
	}
	if m.JenkinsVersion == "" {
		t.Fatal("expected X-Jenkins version on mode probe")
	}
}
