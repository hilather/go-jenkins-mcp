//go:build live_jenkins

package live

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
)

// Smoke tests against a disposable Jenkins LTS (TST-001 residual harness).
// Skip when JENKINS_URL is unset so default `go test ./...` stays green without Docker.

func TestLive_WhoAmI(t *testing.T) {
	c := liveClient(t)
	token := strings.TrimSpace(os.Getenv("JENKINS_API_TOKEN"))
	if token == "" {
		token = strings.TrimSpace(os.Getenv("JENKINS_TOKEN"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	who, err := c.WhoAmI(ctx)
	if err != nil {
		assertNoSecret(t, token, err.Error())
		t.Fatalf("WhoAmI: %v", err)
	}
	assertNoSecret(t, token, who.ID, who.FullName)
	if who.Anonymous {
		t.Fatal("WhoAmI: expected authenticated session, got anonymous")
	}
	if !who.Authenticated {
		t.Fatal("WhoAmI: Authenticated=false")
	}
	if strings.TrimSpace(who.ID) == "" {
		t.Fatal("WhoAmI: empty id")
	}
	t.Logf("whoAmI id=%q authenticated=%v", who.ID, who.Authenticated)
}

func TestLive_ListJobs(t *testing.T) {
	c := liveClient(t)
	token := strings.TrimSpace(os.Getenv("JENKINS_API_TOKEN"))
	if token == "" {
		token = strings.TrimSpace(os.Getenv("JENKINS_TOKEN"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := c.ListJobs(ctx, jenkins.ListJobsToolArgs{Limit: 50})
	if err != nil {
		assertNoSecret(t, token, err.Error())
		t.Fatalf("ListJobs: %v", err)
	}
	if resp == nil {
		t.Fatal("ListJobs: nil response")
	}
	if len(resp.Jobs) == 0 {
		t.Fatal("ListJobs: expected at least one seeded job (sample-freestyle / sample-pipeline)")
	}
	var names []string
	for _, j := range resp.Jobs {
		names = append(names, j.FullName)
		assertNoSecret(t, token, j.FullName, j.Name, j.Description)
	}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "sample-freestyle") && !strings.Contains(joined, liveJobName()) {
		t.Fatalf("ListJobs: expected sample-freestyle or %q in %v", liveJobName(), names)
	}
	t.Logf("ListJobs total=%d jobs=%v", resp.Total, names)
}

func TestLive_GetBuild(t *testing.T) {
	c := liveClient(t)
	token := strings.TrimSpace(os.Getenv("JENKINS_API_TOKEN"))
	if token == "" {
		token = strings.TrimSpace(os.Getenv("JENKINS_TOKEN"))
	}
	job := liveJobName()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Prefer last completed build from history; fall back to #1.
	builds, err := c.ListBuilds(ctx, jenkins.ListBuildsToolArgs{JobName: job, Limit: 5})
	if err != nil {
		assertNoSecret(t, token, err.Error())
		t.Fatalf("ListBuilds(%q): %v", job, err)
	}
	buildNum := 1
	if builds != nil && len(builds.Builds) > 0 {
		buildNum = builds.Builds[0].Number
	}

	b, err := c.GetBuildDetailsByJob(ctx, job, buildNum)
	if err != nil {
		assertNoSecret(t, token, err.Error())
		t.Fatalf("GetBuildDetailsByJob(%q, %d): %v", job, buildNum, err)
	}
	if b == nil {
		t.Fatal("GetBuildDetailsByJob: nil build")
	}
	if b.Number != buildNum {
		t.Fatalf("build number: got %d want %d", b.Number, buildNum)
	}
	assertNoSecret(t, token, b.URL, b.DisplayName)
	t.Logf("build job=%s #%d building=%v result=%q", job, b.Number, b.Building, b.Result)
}

func TestLive_ProgressiveLogTail(t *testing.T) {
	c := liveClient(t)
	token := strings.TrimSpace(os.Getenv("JENKINS_API_TOKEN"))
	if token == "" {
		token = strings.TrimSpace(os.Getenv("JENKINS_TOKEN"))
	}
	job := liveJobName()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	builds, err := c.ListBuilds(ctx, jenkins.ListBuildsToolArgs{JobName: job, Limit: 5})
	if err != nil {
		assertNoSecret(t, token, err.Error())
		t.Fatalf("ListBuilds(%q): %v", job, err)
	}
	buildNum := 1
	if builds != nil && len(builds.Builds) > 0 {
		buildNum = builds.Builds[0].Number
	}

	logs, err := c.GetBuildLogTail(ctx, job, buildNum, 4096)
	if err != nil {
		assertNoSecret(t, token, err.Error())
		t.Fatalf("GetBuildLogTail(%q, %d): %v", job, buildNum, err)
	}
	if logs == nil {
		t.Fatal("GetBuildLogTail: nil")
	}
	assertNoSecret(t, token, logs.Logs)
	// Seeded freestyle echoes a known line; pipeline may differ — accept any non-empty or zero-size completed.
	if logs.TotalSize == 0 && strings.TrimSpace(logs.Logs) == "" {
		// Some controllers report size only after first progressive probe; try offset read.
		chunk, err2 := c.GetBuildLogs(ctx, job, buildNum, 0, 2048)
		if err2 != nil {
			assertNoSecret(t, token, err2.Error())
			t.Fatalf("GetBuildLogs fallback: %v", err2)
		}
		assertNoSecret(t, token, chunk.Logs)
		if strings.TrimSpace(chunk.Logs) == "" && chunk.TotalSize == 0 {
			t.Fatalf("progressive log empty for %s #%d (is the seed build finished?)", job, buildNum)
		}
		t.Logf("progressive fallback length=%d total=%d", chunk.Length, chunk.TotalSize)
		return
	}
	t.Logf("log tail length=%d total=%d hasMore=%v", logs.Length, logs.TotalSize, logs.HasMore)
}

func TestLive_CapabilityDiscovery(t *testing.T) {
	c := liveClient(t)
	token := strings.TrimSpace(os.Getenv("JENKINS_API_TOKEN"))
	if token == "" {
		token = strings.TrimSpace(os.Getenv("JENKINS_TOKEN"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	caps, err := c.RefreshCapabilities(ctx)
	if err != nil {
		assertNoSecret(t, token, err.Error())
		t.Fatalf("RefreshCapabilities: %v", err)
	}
	if strings.TrimSpace(caps.JenkinsVersion) == "" {
		// Version may come from X-Jenkins header; empty is soft — still require Source.
		t.Log("warning: JenkinsVersion empty (header/probe residual)")
	}
	if caps.Source != jenkins.CapabilitySourceLive {
		t.Fatalf("capabilities Source: got %q want %q", caps.Source, jenkins.CapabilitySourceLive)
	}
	// Disposable compose installs pipeline + junit; allow soft assert with log if descriptors lag.
	if !caps.HasPipelineREST {
		t.Log("HasPipelineREST=false (descriptor probe may need plugin warmup)")
	}
	if !caps.HasJUnit {
		t.Log("HasJUnit=false (descriptor probe may need plugin warmup)")
	}
	for _, n := range caps.ProbeNotes {
		assertNoSecret(t, token, n)
	}
	t.Logf("capabilities version=%q pipelineREST=%v junit=%v notes=%v",
		caps.JenkinsVersion, caps.HasPipelineREST, caps.HasJUnit, caps.ProbeNotes)
}

func TestLive_PipelineStages(t *testing.T) {
	c := liveClient(t)
	token := strings.TrimSpace(os.Getenv("JENKINS_API_TOKEN"))
	if token == "" {
		token = strings.TrimSpace(os.Getenv("JENKINS_TOKEN"))
	}
	job := envOr("JENKINS_LIVE_PIPELINE_JOB", "mock-inv-baseline-green")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	caps, err := c.RefreshCapabilities(ctx)
	if err != nil {
		assertNoSecret(t, token, err.Error())
		t.Fatalf("RefreshCapabilities: %v", err)
	}
	if !caps.HasPipelineREST {
		t.Fatal("HasPipelineREST=false; install pipeline-rest-api in lab plugins.txt")
	}

	builds, err := c.ListBuilds(ctx, jenkins.ListBuildsToolArgs{JobName: job, Limit: 3})
	if err != nil {
		assertNoSecret(t, token, err.Error())
		t.Fatalf("ListBuilds(%q): %v", job, err)
	}
	buildNum := 1
	if builds != nil && len(builds.Builds) > 0 {
		buildNum = builds.Builds[0].Number
	}

	stages, err := c.GetPipelineStages(ctx, job, buildNum)
	if err != nil {
		assertNoSecret(t, token, err.Error())
		t.Fatalf("GetPipelineStages(%q, %d): %v", job, buildNum, err)
	}
	if stages == nil || len(stages.Stages) == 0 {
		t.Fatalf("GetPipelineStages: expected stage graph for %q #%d", job, buildNum)
	}
	t.Logf("pipeline stages job=%s #%d count=%d status=%q", job, buildNum, stages.StageCount, stages.Status)
}

func TestLive_ListViews(t *testing.T) {
	c := liveClient(t)
	token := strings.TrimSpace(os.Getenv("JENKINS_API_TOKEN"))
	if token == "" {
		token = strings.TrimSpace(os.Getenv("JENKINS_TOKEN"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := c.ListViews(ctx, 0, 50)
	if err != nil {
		assertNoSecret(t, token, err.Error())
		t.Fatalf("ListViews: %v", err)
	}
	if resp == nil {
		t.Fatal("ListViews: nil response")
	}
	var names []string
	for _, v := range resp.Views {
		names = append(names, v.Name)
		assertNoSecret(t, token, v.Name, v.Description)
	}
	if !strings.Contains(strings.Join(names, ","), "mock-investigations") {
		t.Fatalf("ListViews: expected mock-investigations view in %v", names)
	}
	t.Logf("ListViews total=%d views=%v", resp.Summary.TotalViews, names)
}
