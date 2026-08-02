package contracts_test

import (
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/contracts"
)

func TestRefValidityAndString(t *testing.T) {
	t.Parallel()

	job := contracts.JobRef{Profile: "corp", FullName: "folder/job"}
	if !job.Valid() {
		t.Fatal("expected valid job")
	}
	if job.String() != "folder/job@corp" {
		t.Fatalf("job string: %q", job.String())
	}

	build := contracts.BuildRef{Job: job, Number: 42}
	if !build.Valid() || build.String() != "folder/job@corp#42" {
		t.Fatalf("build: valid=%v str=%q", build.Valid(), build.String())
	}

	q := contracts.QueueItemRef{Profile: "corp", ID: 7}
	if !q.Valid() || q.String() != "queue:7@corp" {
		t.Fatalf("queue: %q", q.String())
	}

	logRef := contracts.LogGenerationRef{Build: build, Generation: "g1"}
	if !logRef.Valid() {
		t.Fatal("log gen")
	}

	stage := contracts.StageRef{Build: build, ID: "s1", Name: "Build"}
	if !stage.Valid() {
		t.Fatal("stage")
	}

	testRef := contracts.TestRef{Build: build, Suite: "s", ClassName: "C", Name: "t"}
	if !testRef.Valid() {
		t.Fatal("test")
	}

	art := contracts.ArtifactRef{Build: build, Path: "out/a.jar"}
	if !art.Valid() {
		t.Fatal("artifact")
	}

	node := contracts.NodeRef{Profile: "corp", Name: "agent-1"}
	if !node.Valid() || node.String() != "node:agent-1@corp" {
		t.Fatalf("node: %q", node.String())
	}
}

func TestInvalidRefs(t *testing.T) {
	t.Parallel()
	if (contracts.JobRef{}).Valid() {
		t.Error("empty job should be invalid")
	}
	if (contracts.BuildRef{Job: contracts.JobRef{FullName: "j"}, Number: 0}).Valid() {
		t.Error("build number 0 invalid")
	}
	if (contracts.ProfileID("")).Valid() {
		t.Error("empty profile invalid")
	}
}
