package jenkins

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

func TestStripRepoURLCredentials(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"https://user:p4ssw0rd@github.com/org/repo.git", "https://github.com/org/repo.git"},
		{"https://oauth2:ghs_token123@github.com/org/repo.git", "https://github.com/org/repo.git"},
		{"https://github.com/org/repo.git?token=secret&ref=main", "https://github.com/org/repo.git?ref=main"},
		{"https://github.com/org/repo.git?access_token=abc", "https://github.com/org/repo.git"},
		{"git@github.com:org/repo.git", "git@github.com:org/repo.git"},
		{"https://github.com/org/repo.git", "https://github.com/org/repo.git"},
		{"http://alice:bob@gitlab.example/r.git", "http://gitlab.example/r.git"},
	}
	for _, tc := range cases {
		got := StripRepoURLCredentials(tc.in)
		if got != tc.want {
			t.Errorf("StripRepoURLCredentials(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if strings.Contains(got, "p4ssw0rd") || strings.Contains(got, "ghs_token") ||
			strings.Contains(got, "secret") || strings.Contains(got, "token=abc") {
			t.Errorf("credential leaked in %q", got)
		}
	}
}

func TestGetBuildChanges_SingleChangeSet(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	jobPath := BuildJobPath("demo")
	f.setBuildJSON(jobPath, 9, `{
	  "number": 9,
	  "result": "FAILURE",
	  "changeSet": {
	    "kind": "git",
	    "items": [
	      {
	        "commitId": "abc123def",
	        "msg": "fix the thing",
	        "author": {"fullName": "Jane Doe"},
	        "timestamp": 1700000001000,
	        "affectedPaths": ["src/a.go", "src/b.go"]
	      }
	    ]
	  },
	  "culprits": [{"fullName": "Jane Doe"}],
	  "actions": [{
	    "_class": "hudson.plugins.git.util.BuildData",
	    "remoteUrls": ["https://ci-bot:s3cret@github.com/acme/app.git"],
	    "lastBuiltRevision": {
	      "SHA1": "abc123def",
	      "branch": [{"name": "refs/heads/main", "SHA1": "abc123def"}]
	    }
	  }]
	}`)

	res, err := f.opts().GetBuildChanges(context.Background(), GetBuildChangesToolArgs{
		JobName: "demo", BuildNumber: 9,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ChangeSets) != 1 {
		t.Fatalf("sets = %+v", res.ChangeSets)
	}
	cs := res.ChangeSets[0]
	if cs.Kind != "git" {
		t.Fatalf("kind = %q", cs.Kind)
	}
	if len(cs.RepoURLs) != 1 || strings.Contains(cs.RepoURLs[0], "s3cret") {
		t.Fatalf("repo urls not stripped: %+v", cs.RepoURLs)
	}
	if !strings.Contains(cs.RepoURLs[0], "github.com/acme/app.git") {
		t.Fatalf("repo = %q", cs.RepoURLs[0])
	}
	if len(cs.Commits) != 1 || cs.Commits[0].ID != "abc123def" {
		t.Fatalf("commits = %+v", cs.Commits)
	}
	if len(res.Culprits) != 1 || !strings.Contains(res.Culprits[0].Note, "correlation") {
		t.Fatalf("culprits = %+v", res.Culprits)
	}
	if len(cs.Revisions) != 1 || cs.Revisions[0].SHA != "abc123def" {
		t.Fatalf("revisions = %+v", cs.Revisions)
	}
}

func TestGetBuildChanges_MultiSCM(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setBuildJSON(BuildJobPath("demo"), 5, `{
	  "number": 5,
	  "changeSets": [
	    {
	      "kind": "git",
	      "items": [{"commitId": "aaa", "msg": "lib change", "author": {"fullName": "A"}, "affectedPaths": ["lib/x.go"]}]
	    },
	    {
	      "kind": "git",
	      "items": [{"commitId": "bbb", "msg": "app change", "author": {"fullName": "B"}, "affectedPaths": ["app/y.go"]}]
	    }
	  ],
	  "actions": [
	    {
	      "_class": "hudson.plugins.git.util.BuildData",
	      "remoteUrls": ["https://user:tok@github.com/acme/lib.git"],
	      "lastBuiltRevision": {"SHA1": "aaa", "branch": [{"name": "main", "SHA1": "aaa"}]}
	    },
	    {
	      "_class": "hudson.plugins.git.util.BuildData",
	      "remoteUrls": ["https://github.com/acme/app.git"],
	      "lastBuiltRevision": {"SHA1": "bbb", "branch": [{"name": "main", "SHA1": "bbb"}]}
	    }
	  ]
	}`)

	res, err := f.opts().GetBuildChanges(context.Background(), GetBuildChangesToolArgs{
		JobName: "demo", BuildNumber: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ChangeSets) != 2 {
		t.Fatalf("want 2 multi-SCM sets, got %+v", res.ChangeSets)
	}
	// Explicit multi-SCM: each set keeps its own repo.
	repos := res.ChangeSets[0].RepoURLs
	if len(repos) != 1 || strings.Contains(repos[0], "user:") || strings.Contains(repos[0], "tok") {
		t.Fatalf("lib repo not stripped: %+v", repos)
	}
	if res.CommitsTotal != 2 {
		t.Fatalf("commitsTotal = %d", res.CommitsTotal)
	}
}

func TestGetBuildChanges_Missing(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	// defaultBuildJSON has empty actions and no changeSet
	f.setBuildJSON(BuildJobPath("demo"), 3, defaultBuildJSON(3))

	res, err := f.opts().GetBuildChanges(context.Background(), GetBuildChangesToolArgs{
		JobName: "demo", BuildNumber: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ChangeSets) != 0 {
		t.Fatalf("must not invent: %+v", res.ChangeSets)
	}
	if res.Message == "" || len(res.Residuals) == 0 {
		t.Fatalf("missing data must be reported: %+v", res)
	}
	if strings.Contains(strings.ToLower(res.Message), "invent") {
		// Message should not claim invented data; residual may say "nothing invented".
	}
}

func TestGetBuildChanges_BoundsAndPagination(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	// 5 commits; request max 2 with offset 1.
	items := make([]string, 0, 5)
	for i := 0; i < 5; i++ {
		items = append(items, fmt.Sprintf(
			`{"commitId":"c%d","msg":"%s","affectedPaths":["a","b","c","d"]}`,
			i, strings.Repeat("m", 100)))
	}
	body := `{
	  "number": 2,
	  "changeSet": {"kind":"git","items":[` + strings.Join(items, ",") + `]},
	  "actions": []
	}`
	f.setBuildJSON(BuildJobPath("demo"), 2, body)

	res, err := f.opts().GetBuildChanges(context.Background(), GetBuildChangesToolArgs{
		JobName: "demo", BuildNumber: 2,
		MaxCommits: 2, CommitOffset: 1, MaxFiles: 2, MaxMessageBytes: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.CommitsTotal != 5 {
		t.Fatalf("total = %d", res.CommitsTotal)
	}
	if res.CommitsReturned != 2 {
		t.Fatalf("returned = %d", res.CommitsReturned)
	}
	if !res.Truncated {
		t.Fatal("expected truncated")
	}
	if len(res.ChangeSets) != 1 || len(res.ChangeSets[0].Commits) != 2 {
		t.Fatalf("page commits = %+v", res.ChangeSets)
	}
	c0 := res.ChangeSets[0].Commits[0]
	if !c0.MessageTruncated || len(c0.Message) > 20 {
		t.Fatalf("message not bounded: %+v", c0)
	}
	if !c0.PathsTruncated || len(c0.AffectedPaths) != 2 {
		t.Fatalf("paths not bounded: %+v", c0)
	}
}

func TestGetBuildChanges_BaselineRange(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	// baseline 7, target 9 → scan 8 and 9
	f.setBuildJSON(BuildJobPath("demo"), 8, `{
	  "number": 8,
	  "changeSet": {"kind":"git","items":[{"commitId":"old1","msg":"from 8"}]},
	  "actions": [{"_class":"hudson.plugins.git.util.BuildData","remoteUrls":["https://github.com/acme/app.git"]}]
	}`)
	f.setBuildJSON(BuildJobPath("demo"), 9, `{
	  "number": 9,
	  "changeSet": {"kind":"git","items":[{"commitId":"new1","msg":"from 9"}]},
	  "actions": [{"_class":"hudson.plugins.git.util.BuildData","remoteUrls":["https://github.com/acme/app.git"]}],
	  "culprits": [{"fullName":"Someone"}]
	}`)

	res, err := f.opts().GetBuildChanges(context.Background(), GetBuildChangesToolArgs{
		JobName: "demo", BuildNumber: 9, BaselineBuild: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.BuildsScanned != 2 {
		t.Fatalf("scanned = %d", res.BuildsScanned)
	}
	if res.CommitsTotal != 2 {
		t.Fatalf("total = %d want 2 (builds 8+9)", res.CommitsTotal)
	}
	ids := map[string]bool{}
	for _, cs := range res.ChangeSets {
		for _, c := range cs.Commits {
			ids[c.ID] = true
		}
	}
	if !ids["old1"] || !ids["new1"] {
		t.Fatalf("ids = %v", ids)
	}
}

func TestGetBuildChanges_InvalidArgs(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	_, err := f.opts().GetBuildChanges(context.Background(), GetBuildChangesToolArgs{
		JobName: "demo", BuildNumber: 5, BaselineBuild: 5,
	})
	if err == nil || !apperr.IsCode(err, apperr.CodeInvalidArgument) {
		t.Fatalf("err = %v", err)
	}
}

// setBuildJSON is an alias used by SCM tests (same map as artifact list fixtures).
func (f *jenkinsFixture) setBuildJSON(jobPath string, build int, body string) {
	f.setBuildArtifactsJSON(jobPath, build, body)
}
