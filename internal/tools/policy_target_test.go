package tools

import (
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

func TestPolicyTargetFromArgs_JobAndBuild(t *testing.T) {
	t.Parallel()
	tgt := policyTargetFromArgs(jenkins.GetBuildToolArgs{
		JobName:     " folder/demo ",
		BuildNumber: 42,
	})
	if tgt.JobName != "folder/demo" || tgt.BuildNumber != 42 {
		t.Fatalf("target=%+v", tgt)
	}
}

func TestPolicyTargetFromArgs_JobNameJSONTagOnNameField(t *testing.T) {
	t.Parallel()
	// jenkins_get_build_logs uses field Name with json:"job_name".
	tgt := policyTargetFromArgs(jenkins.GetBuildLogsToolArgs{
		Name:        "secret-folder/job-a",
		BuildNumber: 7,
	})
	if tgt.JobName != "secret-folder/job-a" || tgt.BuildNumber != 7 {
		t.Fatalf("target=%+v", tgt)
	}
}

func TestPolicyTargetFromArgs_GetJobNameField(t *testing.T) {
	t.Parallel()
	// jenkins_get_job seed shape: Name with json:"name".
	tgt := policyTargetFromArgs(jenkins.GetJobToolArgs{
		Name: " secret-folder/job-a ",
	})
	if tgt.JobName != "secret-folder/job-a" {
		t.Fatalf("get_job name → JobName: %+v", tgt)
	}
	// Empty name yields empty target job.
	if got := policyTargetFromArgs(jenkins.GetJobToolArgs{}); got.JobName != "" {
		t.Fatalf("empty get_job args: %+v", got)
	}
}

func TestPolicyTargetFromArgs_JobNamePreferredOverName(t *testing.T) {
	t.Parallel()
	// When both job_name and name are present, job_name wins.
	tgt := policyTargetFromArgs(jenkins.GetJobToolArgs{
		Name:    "from-name",
		JobName: " from-job-name ",
	})
	if tgt.JobName != "from-job-name" {
		t.Fatalf("prefer job_name: %+v", tgt)
	}
	// job_name only.
	tgt2 := policyTargetFromArgs(jenkins.GetJobToolArgs{JobName: "alias-only"})
	if tgt2.JobName != "alias-only" {
		t.Fatalf("job_name only: %+v", tgt2)
	}
}

func TestPolicyTargetFromArgs_AdapterArgs(t *testing.T) {
	t.Parallel()
	ext := policyTargetFromArgs(QueryExternalLogsToolArgs{JobName: "ext-job", BuildNumber: 3})
	if ext.JobName != "ext-job" || ext.BuildNumber != 3 {
		t.Fatalf("ext=%+v", ext)
	}
	corr := policyTargetFromArgs(GetChangeCorrelationToolArgs{JobName: "corr-job", BuildNumber: 9})
	if corr.JobName != "corr-job" || corr.BuildNumber != 9 {
		t.Fatalf("corr=%+v", corr)
	}
}

func TestPolicyTargetFromArgs_EmptyAndNonStruct(t *testing.T) {
	t.Parallel()
	if got := policyTargetFromArgs(nil); got != (policy.Target{}) {
		t.Fatalf("nil: %+v", got)
	}
	if got := policyTargetFromArgs("not-a-struct"); got != (policy.Target{}) {
		t.Fatalf("string: %+v", got)
	}
	if got := policyTargetFromArgs(jenkins.GetJobsToolArgs{}); got.JobName != "" || got.BuildNumber != 0 {
		t.Fatalf("no job fields: %+v", got)
	}
	// Zero / negative build number is omitted.
	tgt := policyTargetFromArgs(jenkins.GetBuildToolArgs{JobName: "demo", BuildNumber: 0})
	if tgt.JobName != "demo" || tgt.BuildNumber != 0 {
		t.Fatalf("zero build: %+v", tgt)
	}
}

// Wave 35: node_name / view_name / seed view bind into Target.
func TestPolicyTargetFromArgs_NodeAndView(t *testing.T) {
	t.Parallel()
	type nodeArgs struct {
		NodeName string `json:"node_name"`
	}
	type viewNameArgs struct {
		ViewName string `json:"view_name"`
	}
	type bothArgs struct {
		NodeName string `json:"node_name"`
		ViewName string `json:"view_name"`
		View     string `json:"view"`
	}

	tgt := policyTargetFromArgs(nodeArgs{NodeName: "  prod-agent-01  "})
	if tgt.NodeName != "prod-agent-01" || tgt.JobName != "" || tgt.ViewName != "" {
		t.Fatalf("node_name: %+v", tgt)
	}
	// Go field name NodeName without json tag.
	type nodeField struct {
		NodeName string
	}
	if got := policyTargetFromArgs(nodeField{NodeName: "agent-x"}); got.NodeName != "agent-x" {
		t.Fatalf("NodeName field: %+v", got)
	}
	// view_name explicit.
	if got := policyTargetFromArgs(viewNameArgs{ViewName: " secret-view "}); got.ViewName != "secret-view" {
		t.Fatalf("view_name: %+v", got)
	}
	// Seed jenkins_list_jobs View / json:"view".
	listTgt := policyTargetFromArgs(jenkins.ListJobsToolArgs{View: " my-view "})
	if listTgt.ViewName != "my-view" {
		t.Fatalf("list_jobs view: %+v", listTgt)
	}
	// view_name wins over view when both set.
	both := policyTargetFromArgs(bothArgs{
		ViewName: "from-view-name",
		View:     "from-view",
	})
	if both.ViewName != "from-view-name" {
		t.Fatalf("prefer view_name: %+v", both)
	}
	// Path normalize on node/view (collapse //; ".." → empty).
	if got := policyTargetFromArgs(nodeArgs{NodeName: "pool//agent-a"}); got.NodeName != "pool/agent-a" {
		t.Fatalf("node normalize: %+v", got)
	}
	if got := policyTargetFromArgs(viewNameArgs{ViewName: ".."}); got.ViewName != "" {
		t.Fatalf("view traversal fail closed: %+v", got)
	}
	// Combined node + view.
	combo := policyTargetFromArgs(bothArgs{NodeName: "n1", ViewName: "v1"})
	if combo.NodeName != "n1" || combo.ViewName != "v1" {
		t.Fatalf("combo: %+v", combo)
	}
}

// Wave 36: path / artifact_path bind into Target.ArtifactPath (not JobName).
func TestPolicyTargetFromArgs_ArtifactPath(t *testing.T) {
	t.Parallel()
	// jenkins_get_artifact_text uses Path with json:"path".
	tgt := policyTargetFromArgs(jenkins.GetArtifactTextToolArgs{
		JobName:     " demo-job ",
		BuildNumber: 3,
		Path:        " reports//out.txt ",
	})
	if tgt.JobName != "demo-job" || tgt.BuildNumber != 3 {
		t.Fatalf("job+build preserved: %+v", tgt)
	}
	if tgt.ArtifactPath != "reports/out.txt" {
		t.Fatalf("path collapse //: %+v", tgt)
	}
	// jenkins_inspect_artifact same shape.
	insp := policyTargetFromArgs(jenkins.InspectArtifactToolArgs{
		JobName:     "j",
		BuildNumber: 1,
		Path:        "secrets/key.pem",
	})
	if insp.ArtifactPath != "secrets/key.pem" || insp.JobName != "j" {
		t.Fatalf("inspect: %+v", insp)
	}
	// Explicit artifact_path field wins over path when both set.
	type bothPath struct {
		ArtifactPath string `json:"artifact_path"`
		Path         string `json:"path"`
	}
	both := policyTargetFromArgs(bothPath{ArtifactPath: " from-artifact ", Path: "from-path"})
	if both.ArtifactPath != "from-artifact" {
		t.Fatalf("prefer artifact_path: %+v", both)
	}
	// path must never overwrite JobName.
	type pathOnly struct {
		Path string `json:"path"`
	}
	if got := policyTargetFromArgs(pathOnly{Path: "reports/a.txt"}); got.JobName != "" || got.ArtifactPath != "reports/a.txt" {
		t.Fatalf("path ≠ job: %+v", got)
	}
	// Absolute-like and ".." fail closed to empty ArtifactPath (no-match).
	if got := policyTargetFromArgs(pathOnly{Path: "/etc/passwd"}); got.ArtifactPath != "" {
		t.Fatalf("absolute → empty: %+v", got)
	}
	if got := policyTargetFromArgs(pathOnly{Path: "../escape"}); got.ArtifactPath != "" {
		t.Fatalf(".. → empty: %+v", got)
	}
	if got := policyTargetFromArgs(pathOnly{Path: "a/../b"}); got.ArtifactPath != "" {
		t.Fatalf("mid .. → empty: %+v", got)
	}
	if got := policyTargetFromArgs(pathOnly{Path: "https://evil/x"}); got.ArtifactPath != "" {
		t.Fatalf("url-like → empty: %+v", got)
	}
	// Relative path with leading spaces still binds.
	if got := policyTargetFromArgs(pathOnly{Path: "  ok.txt  "}); got.ArtifactPath != "ok.txt" {
		t.Fatalf("trim: %+v", got)
	}
	// Regression Wave 36 review: "." segments must collapse so exact deny
	// patterns cannot be bypassed (SanitizeArtifactPath also path.Cleans).
	if got := policyTargetFromArgs(pathOnly{Path: "exact/./creds.txt"}); got.ArtifactPath != "exact/creds.txt" {
		t.Fatalf("dot mid-path: %+v", got)
	}
	if got := policyTargetFromArgs(pathOnly{Path: "./exact/creds.txt"}); got.ArtifactPath != "exact/creds.txt" {
		t.Fatalf("dot prefix: %+v", got)
	}
	if got := policyTargetFromArgs(pathOnly{Path: "a/./b/./c.txt"}); got.ArtifactPath != "a/b/c.txt" {
		t.Fatalf("multi-dot: %+v", got)
	}
}

// Wave 37: branch_name / BranchName and seed branch / Branch bind into Target.BranchName.
func TestPolicyTargetFromArgs_BranchName(t *testing.T) {
	t.Parallel()
	type branchNameArgs struct {
		BranchName string `json:"branch_name"`
	}
	type branchAlias struct {
		Branch string `json:"branch"`
	}
	type bothBranch struct {
		BranchName string `json:"branch_name"`
		Branch     string `json:"branch"`
	}

	tgt := policyTargetFromArgs(branchNameArgs{BranchName: "  release/1.2  "})
	if tgt.BranchName != "release/1.2" || tgt.JobName != "" {
		t.Fatalf("branch_name: %+v", tgt)
	}
	// Go field name BranchName without json tag.
	type branchField struct {
		BranchName string
	}
	if got := policyTargetFromArgs(branchField{BranchName: "main"}); got.BranchName != "main" {
		t.Fatalf("BranchName field: %+v", got)
	}
	// Seed branch alias.
	if got := policyTargetFromArgs(branchAlias{Branch: " feature/x "}); got.BranchName != "feature/x" {
		t.Fatalf("branch alias: %+v", got)
	}
	// branch_name wins over branch when both set.
	both := policyTargetFromArgs(bothBranch{BranchName: "from-branch-name", Branch: "from-branch"})
	if both.BranchName != "from-branch-name" {
		t.Fatalf("prefer branch_name: %+v", both)
	}
	// Path normalize (collapse //; ".." → empty).
	if got := policyTargetFromArgs(branchNameArgs{BranchName: "release//1.2"}); got.BranchName != "release/1.2" {
		t.Fatalf("branch normalize: %+v", got)
	}
	if got := policyTargetFromArgs(branchNameArgs{BranchName: ".."}); got.BranchName != "" {
		t.Fatalf("branch traversal fail closed: %+v", got)
	}
	if got := policyTargetFromArgs(branchNameArgs{BranchName: "a/../b"}); got.BranchName != "" {
		t.Fatalf("mid traversal: %+v", got)
	}
	// branch must never overwrite JobName.
	type branchOnly struct {
		Branch string `json:"branch"`
	}
	if got := policyTargetFromArgs(branchOnly{Branch: "main"}); got.JobName != "" || got.BranchName != "main" {
		t.Fatalf("branch ≠ job: %+v", got)
	}
}

// Wave 30: Target.JobName uses policy.NormalizeJobFullName (collapse //, leading /;
// ".." fail-closed empty).
func TestPolicyTargetFromArgs_JobPathNormalize(t *testing.T) {
	t.Parallel()
	cases := []struct {
		job  string
		want string
		note string
	}{
		{"prod//secret", "prod/secret", "collapse empty segs"},
		{"/secret", "secret", "leading slash"},
		{"//secret/a", "secret/a", "double leading + path"},
		{"folder///job", "folder/job", "multi empty"},
		{"  /secret/  ", "secret", "trim + slash collapse"},
		{"..", "", "dotdot alone → empty target"},
		{"prod/../secret", "", "mid traversal → empty"},
		{"../secret", "", "leading traversal → empty"},
		{"//", "", "only slashes → empty"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.note, func(t *testing.T) {
			t.Parallel()
			tgt := policyTargetFromArgs(jenkins.GetBuildToolArgs{
				JobName:     tc.job,
				BuildNumber: 1,
			})
			if tgt.JobName != tc.want {
				t.Fatalf("JobName=%q want %q (raw %q)", tgt.JobName, tc.want, tc.job)
			}
			if tc.want != "" && tgt.BuildNumber != 1 {
				t.Fatalf("build preserved: %+v", tgt)
			}
		})
	}
	// Legacy name field also normalized.
	tgt := policyTargetFromArgs(jenkins.GetJobToolArgs{Name: "prod//secret"})
	if tgt.JobName != "prod/secret" {
		t.Fatalf("name field normalize: %+v", tgt)
	}
	// job_name preferred, then normalized.
	tgt2 := policyTargetFromArgs(jenkins.GetJobToolArgs{
		Name:    "from-name",
		JobName: "/secret",
	})
	if tgt2.JobName != "secret" {
		t.Fatalf("prefer job_name then normalize: %+v", tgt2)
	}
}
