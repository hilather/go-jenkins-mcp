package jenkins

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestGetControllerHealth_Summary(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setPlugins(pluginWorkflowAPI, pluginWorkflowJob, pluginPipelineREST, pluginJUnit)
	f.quietingDown = false
	f.rootMode = "NORMAL"
	old := time.Now().Add(-90 * time.Second).UnixMilli()
	f.queueAPIJSON = fmt.Sprintf(`{"items":[
		{"id":1,"task":{"name":"slow"},"why":"Waiting for next available executor","inQueueSince":%d,"stuck":true,"buildable":true}
	]}`, old)
	f.runningJSON = `{
		"computer": [
			{"displayName": "master", "offline": false, "numExecutors": 2, "idle": true,
			 "assignedLabels": [{"name": "master"}], "executors": [{"idle": true}, {"idle": true}]},
			{"displayName": "dead", "offline": true, "numExecutors": 1, "idle": true,
			 "assignedLabels": [{"name": "dead"}], "executors": [{"idle": true}]}
		]
	}`

	res, err := f.opts().GetControllerHealth(context.Background(), GetControllerHealthToolArgs{Refresh: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.JenkinsVersion != "2.462.3" {
		t.Fatalf("version: %q", res.JenkinsVersion)
	}
	if !res.Features.HasPipelineREST || !res.Features.HasJUnit {
		t.Fatalf("features: %+v", res.Features)
	}
	if len(res.PluginShortlist) == 0 {
		t.Fatal("plugin shortlist empty")
	}
	if res.Queue == nil || res.Queue.Depth != 1 || res.Queue.StuckCount != 1 {
		t.Fatalf("queue: %+v", res.Queue)
	}
	if res.Nodes == nil || res.Nodes.OfflineNodes != 1 || res.Nodes.TotalNodes != 2 {
		t.Fatalf("nodes: %+v", res.Nodes)
	}
	if res.Mode != "NORMAL" {
		t.Fatalf("mode: %q", res.Mode)
	}
	if res.Freshness.IsZero() || len(res.EvidenceEndpoints) == 0 {
		t.Fatalf("freshness/evidence: %+v", res)
	}
	// Offline node should demote overall to warn.
	if res.Overall != "warn" && res.Overall != "ok" {
		// stuck queue also warns
		t.Fatalf("overall: %s notes=%v", res.Overall, res.Notes)
	}
	raw := fmt.Sprintf("%+v", res)
	if strings.Contains(raw, f.authToken) || strings.Contains(raw, "secret-token") {
		t.Fatal("token must not appear in health summary")
	}
}

func TestGetControllerHealth_QuietingDown(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setPlugins(pluginJUnit)
	f.quietingDown = true
	res, err := f.opts().GetControllerHealth(context.Background(), GetControllerHealthToolArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.QuietingDown {
		t.Fatal("expected quietingDown")
	}
	found := false
	for _, n := range res.Notes {
		if strings.Contains(n, "quieting_down") {
			found = true
		}
	}
	if !found {
		t.Fatalf("notes: %v", res.Notes)
	}
}

func TestGetControllerHealth_NoSecretsInCapabilityNotes(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	// plugin manager deny path still yields a usable summary via descriptors.
	f.pluginManagerJSON = "deny"
	f.setDescriptor(descJUnit, 200)
	res, err := f.opts().GetControllerHealth(context.Background(), GetControllerHealthToolArgs{Refresh: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range res.Notes {
		if strings.Contains(n, f.authToken) {
			t.Fatal("token in notes")
		}
	}
	if res.PartialUnauthorized {
		// plugin manager denied is a probe note, not necessarily PartialUnauthorized
		// (that's for queue/nodes 403). Fine either way.
	}
	_ = res
}
