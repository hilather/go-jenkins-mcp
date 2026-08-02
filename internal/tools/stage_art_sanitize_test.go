package tools_test

import (
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/tools"
)

func TestPrepareStageLogForModel_Redacts(t *testing.T) {
	sl := &jenkins.StageLog{
		JobName: "demo", BuildNumber: 7, StageID: "12",
		SourceAPI: "pipeline-rest-api:wfapi/log",
		Logs:      "password=supersecret-token-value\nfail",
	}
	out := tools.PrepareStageLogForModel(sl)
	if !out.Untrusted || out.ContentKind != tools.ContentKindStageLog {
		t.Fatalf("labels: %+v", out)
	}
	if strings.Contains(out.Logs, "supersecret") {
		t.Fatalf("leaked: %q", out.Logs)
	}
	if out.SourceAPI == "" || out.StageID != "12" {
		t.Fatalf("evidence lost: %+v", out)
	}
}

func TestPrepareArtifactTextForModel_Redacts(t *testing.T) {
	at := &jenkins.ArtifactText{
		JobName: "demo", BuildNumber: 1, Path: "a.txt",
		Content: "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc.def\n",
		SHA256:  "deadbeef",
	}
	out := tools.PrepareArtifactTextForModel(at)
	if !out.Untrusted || out.ContentKind != tools.ContentKindArtifactText {
		t.Fatalf("labels: %+v", out)
	}
	if strings.Contains(out.Content, "eyJhbGci") {
		t.Fatalf("leaked JWT: %q", out.Content)
	}
	if out.SHA256 != "deadbeef" || out.Path != "a.txt" {
		t.Fatalf("meta lost: %+v", out)
	}
}

func TestPrepareTestAnalysisForModel(t *testing.T) {
	an := &jenkins.TestAnalysis{
		JobName: "demo", BuildNumber: 3, Lookback: 5, SampleSize: 2,
		CurrentAvailable: true, CurrentFailCount: 1,
		Classifications: []jenkins.TestClassification{{
			Name: "t", Kind: jenkins.ClassNewFailure, Confidence: jenkins.ConfidenceLow, SampleSize: 0,
		}},
	}
	out := tools.PrepareTestAnalysisForModel(an)
	if !out.Untrusted || out.ContentKind != tools.ContentKindTestAnalysis {
		t.Fatalf("%+v", out)
	}
	if len(out.Classifications) != 1 {
		t.Fatal(out.Classifications)
	}
}

func TestPrepareArtifactInspectionForModel_Redacts(t *testing.T) {
	ins := &jenkins.ArtifactInspection{
		JobName: "demo", BuildNumber: 1, Path: "a.txt", Kind: jenkins.InspectKindText,
		Text: "password=supersecret-token-value\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc.def\n",
	}
	out := tools.PrepareArtifactInspectionForModel(ins)
	if !out.Untrusted || out.ContentKind != tools.ContentKindArtifactInspect {
		t.Fatalf("%+v", out)
	}
	if strings.Contains(out.Text, "supersecret") || strings.Contains(out.Text, "eyJhbGci") {
		t.Fatalf("leaked: %q", out.Text)
	}
}

func TestPrepareBuildChangesForModel_Redacts(t *testing.T) {
	bc := &jenkins.BuildChanges{
		JobName: "demo", BuildNumber: 9,
		ChangeSets: []jenkins.SCMChangeSet{{
			Kind:     "git",
			RepoURLs: []string{"https://github.com/acme/app.git"},
			Commits: []jenkins.SCMCommit{{
				ID: "abc", Message: "password=supersecret-token-value", Author: "Jane",
			}},
		}},
		Culprits: []jenkins.SCMCulprit{{FullName: "Jane", Note: "Jenkins-reported correlation, not proof of cause"}},
	}
	out := tools.PrepareBuildChangesForModel(bc)
	if !out.Untrusted || out.ContentKind != tools.ContentKindSCMChanges {
		t.Fatalf("%+v", out)
	}
	if len(out.ChangeSets) != 1 || len(out.ChangeSets[0].Commits) != 1 {
		t.Fatalf("%+v", out)
	}
	if strings.Contains(out.ChangeSets[0].Commits[0].Message, "supersecret") {
		t.Fatalf("leaked commit msg: %q", out.ChangeSets[0].Commits[0].Message)
	}
	if !strings.Contains(out.Culprits[0].Note, "correlation") {
		t.Fatalf("culprit note lost: %+v", out.Culprits)
	}
}
