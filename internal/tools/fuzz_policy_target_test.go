package tools

import (
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

// wantFrom applies the same TrimSpace + NormalizeJobFullName path as policyTargetFromArgs.
func wantFrom(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if norm, ok := policy.NormalizeJobFullName(s); ok {
		return norm
	}
	return ""
}

// QA-001 Wave 21: policyTargetFromArgs pure reflection binding (POL-004).
// Package-internal: unexported helper used by registration middleware.

// FuzzPolicyTargetFromArgs exercises job_name / name / build_number extraction
// across seed tool arg structs and non-struct garbage.
func FuzzPolicyTargetFromArgs(f *testing.F) {
	f.Add("demo", "legacy-name", 1)
	f.Add("folder/job", "", 42)
	f.Add("", "only-name", 0)
	f.Add("  padded  ", "x", -1)
	f.Add("http://evil/job", "n", 1)
	f.Add("secret-folder/a", "secret-folder/a", 99)
	f.Add("", "", 0)
	f.Add(strings.Repeat("j", 200), strings.Repeat("n", 50), 1<<30)
	// Wave 30: path normalize seeds
	f.Add("prod//secret", "", 1)
	f.Add("/secret", "legacy", 2)
	f.Add("..", "fallback-name", 3)
	f.Add("a/../b", "", 0)
	f.Add("//", "", 1)

	f.Fuzz(func(t *testing.T, jobName, name string, build int) {
		if len(jobName) > fuzzMaxArg || len(name) > fuzzMaxArg {
			return
		}

		// Zero / non-struct paths.
		if got := policyTargetFromArgs(nil); got.JobName != "" || got.BuildNumber != 0 {
			t.Fatalf("nil: %+v", got)
		}
		if got := policyTargetFromArgs("not-a-struct"); got.JobName != "" || got.BuildNumber != 0 {
			t.Fatalf("string: %+v", got)
		}
		if got := policyTargetFromArgs(123); got.JobName != "" {
			t.Fatalf("int: %+v", got)
		}
		var nilPtr *jenkins.GetBuildToolArgs
		if got := policyTargetFromArgs(nilPtr); got.JobName != "" {
			t.Fatalf("nil ptr: %+v", got)
		}

		// job_name preferred when both present.
		getJob := policyTargetFromArgs(jenkins.GetJobToolArgs{
			Name:    name,
			JobName: jobName,
		})
		// Pointer form.
		_ = policyTargetFromArgs(&jenkins.GetJobToolArgs{Name: name, JobName: jobName})

		buildTgt := policyTargetFromArgs(jenkins.GetBuildToolArgs{
			JobName:     jobName,
			BuildNumber: build,
		})
		logsTgt := policyTargetFromArgs(jenkins.GetBuildLogsToolArgs{
			Name:        jobName,
			BuildNumber: build,
		})
		tailTgt := policyTargetFromArgs(jenkins.GetBuildLogTailToolArgs{
			JobName:     jobName,
			BuildNumber: build,
		})

		// Determinism on same args.
		buildTgt2 := policyTargetFromArgs(jenkins.GetBuildToolArgs{
			JobName:     jobName,
			BuildNumber: build,
		})
		if buildTgt != buildTgt2 {
			t.Fatalf("non-deterministic build target: %+v vs %+v", buildTgt, buildTgt2)
		}

		// job_name wins over name when non-empty after trim; then NormalizeJobFullName
		// (Wave 30: collapse //, leading /; ".." → empty).
		rawJob := strings.TrimSpace(jobName)
		if rawJob == "" {
			rawJob = strings.TrimSpace(name)
		}
		wantJob := ""
		if rawJob != "" {
			if norm, ok := policy.NormalizeJobFullName(rawJob); ok {
				wantJob = norm
			}
		}
		if getJob.JobName != wantJob {
			t.Fatalf("GetJob job=%q name=%q → JobName=%q want %q",
				jobName, name, getJob.JobName, wantJob)
		}
		if buildTgt.JobName != wantFrom(jobName) {
			t.Fatalf("build JobName=%q want %q (raw %q)", buildTgt.JobName, wantFrom(jobName), jobName)
		}
		if logsTgt.JobName != wantFrom(jobName) {
			t.Fatalf("logs JobName=%q want %q", logsTgt.JobName, wantFrom(jobName))
		}

		// Build number only when > 0.
		if build > 0 {
			if buildTgt.BuildNumber != int64(build) {
				t.Fatalf("build number: got %d want %d", buildTgt.BuildNumber, build)
			}
			if logsTgt.BuildNumber != int64(build) {
				t.Fatalf("logs build: got %d", logsTgt.BuildNumber)
			}
			if tailTgt.BuildNumber != int64(build) {
				t.Fatalf("tail build: got %d", tailTgt.BuildNumber)
			}
		} else if buildTgt.BuildNumber != 0 {
			t.Fatalf("non-positive build must yield 0, got %d", buildTgt.BuildNumber)
		}

		// Empty-job struct yields empty JobName.
		_ = policyTargetFromArgs(jenkins.GetJobsToolArgs{})
	})
}
