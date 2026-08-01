package jenkins

import (
	"context"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

const sampleStageLog = `{
  "nodeId": "12",
  "nodeStatus": "FAILED",
  "length": 42,
  "hasMore": false,
  "text": "stage failed: assertion error\nline 2\n"
}`

func TestGetStageLog_ByID(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setPlugins(pluginPipelineREST)
	jobPath := BuildJobPath("demo")
	f.setWFAPILog(jobPath, 7, "12", sampleStageLog)

	sl, err := f.opts().GetStageLog(context.Background(), "demo", 7, "12", "", 8192)
	if err != nil {
		t.Fatal(err)
	}
	if sl.StageID != "12" || sl.NodeStatus != "FAILED" {
		t.Fatalf("stage = %+v", sl)
	}
	if !strings.Contains(sl.Logs, "assertion error") {
		t.Fatalf("logs = %q", sl.Logs)
	}
	if sl.SourceAPI == "" {
		t.Fatal("expected sourceApi")
	}
	if sl.LogKeyJob != StageLogKeyJob("demo", "12") {
		t.Fatalf("logKeyJob = %q", sl.LogKeyJob)
	}
	// Distinct from console job key.
	if sl.LogKeyJob == "demo" {
		t.Fatal("stage key must not equal console job name")
	}
}

func TestGetStageLog_ByName(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setPlugins(pluginPipelineREST)
	jobPath := BuildJobPath("demo")
	f.setWFAPI(jobPath, 7, sampleWFAPIDescribe)
	f.setWFAPINode(jobPath, 7, "10", sampleParallelChildren)
	f.setWFAPILog(jobPath, 7, "12", sampleStageLog)

	sl, err := f.opts().GetStageLog(context.Background(), "demo", 7, "", "windows", 8192)
	if err != nil {
		t.Fatal(err)
	}
	if sl.StageID != "12" || sl.StageName != "windows" {
		t.Fatalf("resolved = %+v", sl)
	}
}

func TestGetStageLog_NotFound(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setPlugins(pluginPipelineREST)
	// No log registered.
	_, err := f.opts().GetStageLog(context.Background(), "demo", 7, "99", "", 100)
	if err == nil {
		t.Fatal("expected not_found")
	}
	if !apperr.IsCode(err, apperr.CodeNotFound) {
		t.Fatalf("code = %v err = %v", apperr.CodeOf(err), err)
	}
}

func TestGetStageLog_CapabilityMissing(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	// No pipeline plugins.
	_, err := f.opts().GetStageLog(context.Background(), "demo", 7, "1", "", 100)
	if err == nil {
		t.Fatal("expected capability_missing")
	}
	if !apperr.IsCode(err, apperr.CodeCapabilityMissing) {
		t.Fatalf("code = %v err = %v", apperr.CodeOf(err), err)
	}
}

func TestGetStageLog_LengthCap(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setPlugins(pluginPipelineREST)
	longText := strings.Repeat("x", 5000)
	body := `{"nodeId":"1","nodeStatus":"SUCCESS","length":5000,"hasMore":false,"text":"` + longText + `"}`
	f.setWFAPILog(BuildJobPath("demo"), 1, "1", body)

	sl, err := f.opts().GetStageLog(context.Background(), "demo", 1, "1", "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(sl.Logs) != 100 {
		t.Fatalf("len = %d", len(sl.Logs))
	}
	if !sl.HasMore {
		t.Fatal("expected hasMore after truncation")
	}
}

func TestStageLogKeyJob_Distinct(t *testing.T) {
	if StageLogKeyJob("demo", "6") != "demo#stage:6" {
		t.Fatal(StageLogKeyJob("demo", "6"))
	}
}
