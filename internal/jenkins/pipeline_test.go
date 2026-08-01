package jenkins

import (
	"context"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

const sampleWFAPIDescribe = `{
  "name": "#7",
  "status": "FAILED",
  "startTimeMillis": 1700000000000,
  "durationMillis": 45000,
  "stages": [
    {
      "id": "6",
      "name": "Checkout",
      "status": "SUCCESS",
      "startTimeMillis": 1700000000000,
      "durationMillis": 5000,
      "type": "STAGE"
    },
    {
      "id": "10",
      "name": "Parallel Build",
      "status": "FAILED",
      "startTimeMillis": 1700000005000,
      "durationMillis": 30000,
      "type": "PARALLEL"
    },
    {
      "id": "20",
      "name": "Publish",
      "status": "SKIPPED",
      "startTimeMillis": 1700000035000,
      "durationMillis": 0,
      "type": "STAGE"
    }
  ]
}`

const sampleParallelChildren = `{
  "id": "10",
  "name": "Parallel Build",
  "status": "FAILED",
  "durationMillis": 30000,
  "stageFlowNodes": [
    {
      "id": "11",
      "name": "linux",
      "status": "SUCCESS",
      "durationMillis": 20000,
      "type": "PARALLEL_BRANCH"
    },
    {
      "id": "12",
      "name": "windows",
      "status": "FAILED",
      "durationMillis": 25000,
      "type": "PARALLEL_BRANCH"
    }
  ]
}`

func TestGetPipelineStages_GraphWithParallelChildren(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setPlugins(pluginPipelineREST)
	jobPath := BuildJobPath("demo")
	f.setWFAPI(jobPath, 7, sampleWFAPIDescribe)
	f.setWFAPINode(jobPath, 7, "10", sampleParallelChildren)

	ps, err := f.opts().GetPipelineStages(context.Background(), "demo", 7)
	if err != nil {
		t.Fatal(err)
	}
	if ps.Status != "FAILED" || ps.Name != "#7" {
		t.Fatalf("run = %+v", ps)
	}
	if len(ps.Stages) != 3 {
		t.Fatalf("stages = %d want 3", len(ps.Stages))
	}
	if ps.Stages[0].Name != "Checkout" || ps.Stages[0].Status != "SUCCESS" {
		t.Fatalf("stage0 = %+v", ps.Stages[0])
	}
	// Parallel parent should have children without flattening.
	par := ps.Stages[1]
	if par.Name != "Parallel Build" {
		t.Fatalf("parallel name = %q", par.Name)
	}
	if len(par.Children) != 2 {
		t.Fatalf("parallel children = %d want 2: %+v", len(par.Children), par.Children)
	}
	if par.Children[0].Name != "linux" || par.Children[1].Name != "windows" {
		t.Fatalf("children = %+v", par.Children)
	}
	if par.Children[1].Status != "FAILED" {
		t.Fatalf("windows status = %q", par.Children[1].Status)
	}
	if ps.StageCount < 5 {
		t.Fatalf("stageCount = %d want >= 5", ps.StageCount)
	}
}

func TestGetPipelineStages_EmbeddedStageFlowNodes(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setPlugins(pluginWorkflowAPI)
	// Embedded children — no secondary fetch needed.
	body := `{
	  "name": "#1",
	  "status": "SUCCESS",
	  "durationMillis": 1000,
	  "stages": [{
	    "id": "1",
	    "name": "Parallel",
	    "status": "SUCCESS",
	    "durationMillis": 1000,
	    "type": "PARALLEL",
	    "stageFlowNodes": [
	      {"id": "2", "name": "a", "status": "SUCCESS", "durationMillis": 500},
	      {"id": "3", "name": "b", "status": "SUCCESS", "durationMillis": 400}
	    ]
	  }]
	}`
	f.setWFAPI(BuildJobPath("demo"), 1, body)

	ps, err := f.opts().GetPipelineStages(context.Background(), "demo", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps.Stages) != 1 || len(ps.Stages[0].Children) != 2 {
		t.Fatalf("stages = %+v", ps.Stages)
	}
}

func TestGetPipelineStages_NotFound(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setPlugins(pluginPipelineREST)
	// No wfapi JSON registered → 404

	_, err := f.opts().GetPipelineStages(context.Background(), "demo", 99)
	if err == nil {
		t.Fatal("expected not_found")
	}
	if !apperr.IsCode(err, apperr.CodeNotFound) {
		t.Fatalf("code = %v err = %v", apperr.CodeOf(err), err)
	}
}

func TestGetPipelineStages_NestedFolderJob(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setPlugins(pluginPipelineREST)
	jobPath := BuildJobPath("team/app")
	f.setWFAPI(jobPath, 3, `{
	  "name": "#3",
	  "status": "SUCCESS",
	  "durationMillis": 100,
	  "stages": [{"id": "1", "name": "Build", "status": "SUCCESS", "durationMillis": 100}]
	}`)

	ps, err := f.opts().GetPipelineStages(context.Background(), "team/app", 3)
	if err != nil {
		t.Fatal(err)
	}
	if ps.JobName != "team/app" || ps.BuildNumber != 3 {
		t.Fatalf("ref = %+v", ps)
	}
	if len(ps.Stages) != 1 || ps.Stages[0].Name != "Build" {
		t.Fatalf("stages = %+v", ps.Stages)
	}
}
