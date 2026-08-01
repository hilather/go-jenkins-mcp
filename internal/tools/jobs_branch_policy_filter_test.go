package tools

import (
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

// Wave 37: unit filter for deny_branch_names on list_jobs rows.
func TestFilterDeniedBranchJobs_Unit(t *testing.T) {
	t.Parallel()
	jobs := []jenkins.JobSummary{
		{FullName: "team/mb/main", Name: "main", Kind: jenkins.JobKindBranch},
		{FullName: "team/mb/feature-x", Name: "feature-x", Kind: jenkins.JobKindBranch},
		{FullName: "team/mb", Name: "mb", Kind: jenkins.JobKindMultibranch},
		// Folder leaf named "main" must NOT be hidden by deny_branch_names:["main"].
		{FullName: "main", Name: "main", Kind: jenkins.JobKindFolder},
		{FullName: "team/matrix/axis-a", Name: "axis-a", Kind: jenkins.JobKindMatrixChild},
		{FullName: "plain-job", Name: "plain-job", Kind: "job"},
	}

	kept, omitted := FilterDeniedBranchJobs([]string{"main", "axis-*"}, jobs)
	if omitted != 2 {
		t.Fatalf("omitted=%d want 2 kept=%v", omitted, kept)
	}
	// Expect: feature-x branch, multibranch parent, folder main, plain-job.
	if len(kept) != 4 {
		t.Fatalf("kept len=%d: %+v", len(kept), kept)
	}
	for _, j := range kept {
		if j.Kind == jenkins.JobKindBranch && j.Name == "main" {
			t.Fatalf("branch main must be omitted: %+v", j)
		}
		if j.Kind == jenkins.JobKindMatrixChild && j.Name == "axis-a" {
			t.Fatalf("matrix_child axis-a must be omitted: %+v", j)
		}
	}
	// Folder named main retained.
	foundFolderMain := false
	for _, j := range kept {
		if j.Kind == jenkins.JobKindFolder && j.Name == "main" {
			foundFolderMain = true
		}
	}
	if !foundFolderMain {
		t.Fatal("folder named main must be kept (Kind gate)")
	}

	// Empty patterns → full shallow copy.
	keptAll, om0 := FilterDeniedBranchJobs(nil, jobs)
	if om0 != 0 || len(keptAll) != len(jobs) {
		t.Fatalf("empty patterns: kept=%d omitted=%d", len(keptAll), om0)
	}

	// FullName match when leaf Name does not match pattern (path-style deny).
	pathJobs := []jenkins.JobSummary{
		{FullName: "team/mb/release/1.2", Name: "1.2", Kind: jenkins.JobKindBranch},
		{FullName: "team/mb/dev", Name: "dev", Kind: jenkins.JobKindBranch},
	}
	keptPath, omPath := FilterDeniedBranchJobs([]string{"team/mb/release/**"}, pathJobs)
	if omPath != 1 || len(keptPath) != 1 || keptPath[0].Name != "dev" {
		t.Fatalf("FullName pattern: kept=%+v omitted=%d", keptPath, omPath)
	}
}

func TestApplyJobPolicyFilters_Compose(t *testing.T) {
	t.Parallel()
	jobs := []jenkins.JobSummary{
		{FullName: "a/main", Name: "main", Kind: jenkins.JobKindBranch},
		{FullName: "b/dev", Name: "dev", Kind: jenkins.JobKindBranch},
		{FullName: "c", Name: "c", Kind: "job"},
	}
	// Compose branch deny + custom keep (simulates future job-prefix filter).
	branchKeep := KeepUnlessBranchDenied([]string{"main"})
	prefixKeep := JobRowKeep(func(j jenkins.JobSummary) bool {
		// Drop full name starting with "b/" (stand-in for deny_job_prefixes).
		return j.FullName == "" || j.FullName[0] != 'b'
	})
	kept, omitted := ApplyJobPolicyFilters(jobs, branchKeep, prefixKeep)
	if omitted != 2 || len(kept) != 1 || kept[0].Name != "c" {
		t.Fatalf("compose: kept=%+v omitted=%d", kept, omitted)
	}
	// No keeps → copy.
	all, om := ApplyJobPolicyFilters(jobs)
	if om != 0 || len(all) != 3 {
		t.Fatalf("no keeps: %d %d", len(all), om)
	}
}

func TestApplyListJobsPolicyFilters_Live(t *testing.T) {
	t.Parallel()
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyBranchNames: []string{"main"},
	})
	st := regState{policy: ev}
	res := &jenkins.ListJobsToolResponse{
		Jobs: []jenkins.JobSummary{
			{FullName: "mb/main", Name: "main", Kind: jenkins.JobKindBranch},
			{FullName: "mb/dev", Name: "dev", Kind: jenkins.JobKindBranch},
		},
		Total: 2,
	}
	out := applyListJobsPolicyFilters(res, st)
	if !out.PolicyFiltered || out.PolicyOmittedCount != 1 {
		t.Fatalf("flags: filtered=%v omitted=%d", out.PolicyFiltered, out.PolicyOmittedCount)
	}
	if len(out.Jobs) != 1 || out.Jobs[0].Name != "dev" {
		t.Fatalf("jobs=%+v", out.Jobs)
	}

	// Empty policy → unchanged.
	st2 := regState{}
	res2 := &jenkins.ListJobsToolResponse{
		Jobs: []jenkins.JobSummary{
			{FullName: "mb/main", Name: "main", Kind: jenkins.JobKindBranch},
		},
	}
	out2 := applyListJobsPolicyFilters(res2, st2)
	if out2.PolicyFiltered || out2.PolicyOmittedCount != 0 || len(out2.Jobs) != 1 {
		t.Fatalf("empty policy: %+v", out2)
	}
}
