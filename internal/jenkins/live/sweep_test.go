//go:build live_jenkins

package live

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
)

// TestLive_SweepFixtureHTTP exercises common MCP client paths against seeded lab jobs.
// Failures here usually mean missing lab fixtures (404) or stale job definitions on volume.
func TestLive_SweepFixtureHTTP(t *testing.T) {
	c := liveClient(t)
	token := strings.TrimSpace(os.Getenv("JENKINS_API_TOKEN"))
	if token == "" {
		token = strings.TrimSpace(os.Getenv("JENKINS_TOKEN"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	type probe struct {
		name string
		fn   func(context.Context) error
		// allowNotFound permits apperr.CodeNotFound (expected negative fixtures).
		allowNotFound bool
	}

	jobsWithJUnit := []string{
		"mock-inv-baseline-green",
		"mock-inv-test-failure",
		"mock-inv-multi-artifact",
		"sample-freestyle",
	}
	jobsExpectNoJUnit := []string{
		"mock-inv-nested-stages",
		"mock-inv-compile-failure",
	}

	var probes []probe

	for _, job := range jobsWithJUnit {
		job := job
		probes = append(probes, probe{
			name: "testReport:" + job,
			fn: func(ctx context.Context) error {
				_, err := c.GetTestReport(ctx, job, 1, 25)
				return err
			},
		})
	}
	for _, job := range jobsExpectNoJUnit {
		job := job
		probes = append(probes, probe{
			name: "testReport_missing_ok:" + job,
			fn: func(ctx context.Context) error {
				_, err := c.GetTestReport(ctx, job, 1, 25)
				if err == nil {
					return nil
				}
				var ae *apperr.Error
				if errors.As(err, &ae) && ae != nil && ae.Code == apperr.CodeNotFound {
					return nil
				}
				return err
			},
		})
	}

	probes = append(probes,
		probe{
			name: "pipelineStages:mock-inv-baseline-green",
			fn: func(ctx context.Context) error {
				_, err := c.GetPipelineStages(ctx, "mock-inv-baseline-green", 1)
				return err
			},
		},
		probe{
			name: "pipelineStages:mock-inv-nested-stages",
			fn: func(ctx context.Context) error {
				_, err := c.GetPipelineStages(ctx, "mock-inv-nested-stages", 1)
				return err
			},
		},
		probe{
			name: "stageLog:mock-inv-nested-stages:Contract",
			fn: func(ctx context.Context) error {
				st, err := c.GetPipelineStages(ctx, "mock-inv-nested-stages", 1)
				if err != nil {
					return err
				}
				id := findStageID(st.Stages, "Contract")
				if id == "" {
					t.Log("stage Contract not found in graph; skip stage log")
					return nil
				}
				_, err = c.GetStageLog(ctx, "mock-inv-nested-stages", 1, id, "", 8192)
				return err
			},
		},
		probe{
			name: "artifacts:mock-inv-multi-artifact",
			fn: func(ctx context.Context) error {
				_, err := c.ListArtifacts(ctx, "mock-inv-multi-artifact", 1, 50)
				return err
			},
		},
		probe{
			name: "buildChanges:mock-inv-baseline-green",
			fn: func(ctx context.Context) error {
				_, err := c.GetBuildChanges(ctx, jenkins.GetBuildChangesToolArgs{
					JobName:     "mock-inv-baseline-green",
					BuildNumber: 1,
				})
				return err
			},
			allowNotFound: true,
		},
		probe{
			name: "buildGraph:mock-inv-baseline-green",
			fn: func(ctx context.Context) error {
				_, err := c.GetBuildGraph(ctx, jenkins.GetBuildGraphToolArgs{
					JobName:     "mock-inv-baseline-green",
					BuildNumber: 1,
					Direction:   "both",
					MaxDepth:    3,
					MaxNodes:    32,
				})
				return err
			},
		},
		probe{
			name: "sample-pipeline:testReport",
			fn: func(ctx context.Context) error {
				bn, err := lastBuildNumber(ctx, c, "sample-pipeline")
				if err != nil {
					return err
				}
				return requireTestReport(ctx, c, "sample-pipeline", bn)
			},
		},
		probe{
			name: "mock-inv-long-log:testReport",
			fn: func(ctx context.Context) error {
				bn, err := lastBuildNumber(ctx, c, "mock-inv-long-log")
				if err != nil {
					return err
				}
				return requireTestReport(ctx, c, "mock-inv-long-log", bn)
			},
		},
		probe{
			name: "mock-inv-unstable:testReport",
			fn: func(ctx context.Context) error {
				bn, err := lastBuildNumber(ctx, c, "mock-inv-unstable")
				if err != nil {
					return err
				}
				return requireTestReport(ctx, c, "mock-inv-unstable", bn)
			},
		},
		probe{
			name: "buildGraph:mock-inv-build-graph-downstream",
			fn: func(ctx context.Context) error {
				bn, err := lastBuildNumber(ctx, c, "mock-inv-build-graph-downstream")
				if err != nil {
					return err
				}
				graph, err := c.GetBuildGraph(ctx, jenkins.GetBuildGraphToolArgs{
					JobName:     "mock-inv-build-graph-downstream",
					BuildNumber: bn,
					Direction:   "upstream",
					MaxDepth:    2,
					MaxNodes:    16,
				})
				if err != nil {
					return err
				}
				if graph == nil || len(graph.Nodes) < 2 {
					return apperr.New(apperr.CodeNotFound, "expected downstream→upstream graph nodes")
				}
				return nil
			},
		},
		probe{
			name: "queuePressure:with-blocked",
			fn: func(ctx context.Context) error {
				_, err := c.GetQueuePressure(ctx)
				return err
			},
		},
	)

	var failed []string
	for _, p := range probes {
		p := p
		t.Run(p.name, func(t *testing.T) {
			err := p.fn(ctx)
			if err != nil {
				assertNoSecret(t, token, err.Error())
				if p.allowNotFound {
					var ae *apperr.Error
					if errors.As(err, &ae) && ae != nil && ae.Code == apperr.CodeNotFound {
						t.Logf("allowed not_found: %v", err)
						return
					}
				}
				failed = append(failed, p.name+": "+err.Error())
				t.Fatalf("%v", err)
			}
		})
	}
	if len(failed) > 0 {
		t.Fatalf("sweep failures: %d", len(failed))
	}
}

func lastBuildNumber(ctx context.Context, c *jenkins.Client, job string) (int, error) {
	builds, err := c.ListBuilds(ctx, jenkins.ListBuildsToolArgs{JobName: job, Limit: 1})
	if err != nil {
		return 0, err
	}
	if builds != nil && len(builds.Builds) > 0 {
		return builds.Builds[0].Number, nil
	}
	return 1, nil
}

func requireTestReport(ctx context.Context, c *jenkins.Client, job string, buildNum int) error {
	rep, err := c.GetTestReport(ctx, job, buildNum, 25)
	if err != nil {
		return err
	}
	if rep == nil || !rep.Available {
		return apperr.New(apperr.CodeNotFound, job+" build #"+strconv.Itoa(buildNum)+" missing test report fixture")
	}
	return nil
}

func findStageID(stages []jenkins.StageNode, name string) string {
	for _, s := range stages {
		if strings.EqualFold(strings.TrimSpace(s.Name), name) {
			return s.ID
		}
		if id := findStageID(s.Children, name); id != "" {
			return id
		}
	}
	return ""
}
