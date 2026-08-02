package contracts_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/contracts"
)

func TestIsAbsoluteHTTPURL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"folder/job", false},
		{"demo", false},
		{"http://jenkins.example/job/x", true},
		{"https://jenkins.example/job/x", true},
		{"HTTP://evil", true},
		{"//jenkins.example/job/x", true},
		{"  https://x  ", true},
	}
	for _, tc := range cases {
		if got := contracts.IsAbsoluteHTTPURL(tc.in); got != tc.want {
			t.Errorf("IsAbsoluteHTTPURL(%q)=%v want %v", tc.in, got, tc.want)
		}
	}
}

func TestParseJobFullName_AcceptsPaths(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"demo",
		"folder/job",
		"folder/sub/job",
		"team/app/feature-branch",
		"a b/c",  // spaces ok; client path-escapes later
		"jdk:17", // colon in name is not a URL scheme we reject
	} {
		ref, err := contracts.ParseJobFullName("job_name", name)
		if err != nil {
			t.Fatalf("%q: %v", name, err)
		}
		if ref.FullName != name {
			t.Fatalf("FullName=%q", ref.FullName)
		}
		if !ref.Valid() {
			t.Fatal("expected valid")
		}
	}
}

func TestParseJobFullName_RejectsAbsoluteURLs(t *testing.T) {
	t.Parallel()
	// Regression: model-constructed browser/API URLs must not be accepted as job_name.
	for _, bad := range []string{
		"http://jenkins/job/x",
		"https://jenkins.example.com/job/folder/job/x/",
		"//evil.example/job/x",
		"jenkins://host/job/x",
	} {
		_, err := contracts.ParseJobFullName("job_name", bad)
		if err == nil {
			t.Fatalf("expected error for %q", bad)
		}
		var fe *contracts.FieldError
		if !errors.As(err, &fe) {
			t.Fatalf("want FieldError, got %T %v", err, err)
		}
		if fe.Field != "job_name" {
			t.Fatalf("field=%q", fe.Field)
		}
		msg := err.Error()
		if !strings.Contains(msg, "allowed form") {
			t.Fatalf("missing allowed form in %q", msg)
		}
		if !strings.Contains(msg, "not an http") && !strings.Contains(msg, "URL") {
			t.Fatalf("message should mention URL rejection: %q", msg)
		}
	}
}

func TestParseJobFullName_EmptyAndControl(t *testing.T) {
	t.Parallel()
	_, err := contracts.ParseJobFullName("name", "  ")
	if err == nil {
		t.Fatal("empty")
	}
	_, err = contracts.ParseJobFullName("name", "job\x00evil")
	if err == nil {
		t.Fatal("nul")
	}
}

// Wave 31: ParseJobFullName rejects path traversal / absolute path forms so
// handlers never call Jenkins with ".." segments (aligns with NormalizeJobFullName fail-closed).
func TestParseJobFullName_RejectsPathTraversalAndAbsoluteForms(t *testing.T) {
	t.Parallel()
	// Regression: folder/../job and related forms must fail closed (invalid_argument FieldError).
	cases := []struct {
		in   string
		want string // substring expected in error message
		note string
	}{
		{"..", "path segment", "dotdot alone"},
		{"../x", "path segment", "leading traversal"},
		{"folder/../job", "path segment", "mid traversal"},
		{"a/..", "path segment", "trailing traversal"},
		{".", "path segment", "dot alone"},
		{"folder/./job", "path segment", "mid current-dir"},
		{"a/.", "path segment", "trailing current-dir"},
		{"/folder/job", "absolute path", "leading slash absolute"},
		{"folder//job", "empty path segment", "double slash"},
		{"folder/job/", "empty path segment", "trailing slash"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.note+"/"+tc.in, func(t *testing.T) {
			t.Parallel()
			_, err := contracts.ParseJobFullName("job_name", tc.in)
			if err == nil {
				t.Fatalf("expected error for %q", tc.in)
			}
			var fe *contracts.FieldError
			if !errors.As(err, &fe) {
				t.Fatalf("want FieldError, got %T %v", err, err)
			}
			if fe.Field != "job_name" {
				t.Fatalf("field=%q", fe.Field)
			}
			msg := err.Error()
			if !strings.Contains(msg, tc.want) {
				t.Fatalf("message %q missing %q", msg, tc.want)
			}
			if !strings.Contains(msg, "allowed form") {
				t.Fatalf("missing allowed form in %q", msg)
			}
		})
	}
}

func TestParseBuildRef(t *testing.T) {
	t.Parallel()
	b, err := contracts.ParseBuildRef("job_name", "folder/job", "build_number", 42)
	if err != nil || !b.Valid() || b.Number != 42 || b.Job.FullName != "folder/job" {
		t.Fatalf("got %+v err=%v", b, err)
	}
	_, err = contracts.ParseBuildRef("job_name", "folder/job", "build_number", 0)
	if err == nil {
		t.Fatal("build 0")
	}
	_, err = contracts.ParseBuildRef("job_name", "https://evil/job/x", "build_number", 1)
	if err == nil {
		t.Fatal("url job")
	}
	if !strings.Contains(err.Error(), "job_name") {
		t.Fatalf("field: %v", err)
	}
}

func TestParseQueueItemRef(t *testing.T) {
	t.Parallel()
	q, err := contracts.ParseQueueItemRef("queue_id", 7, "corp")
	if err != nil || !q.Valid() || q.ID != 7 || q.Profile != "corp" {
		t.Fatalf("%+v %v", q, err)
	}
	_, err = contracts.ParseQueueItemRef("queue_id", 0, "")
	if err == nil {
		t.Fatal("zero id")
	}
	if !strings.Contains(err.Error(), "queue_id") {
		t.Fatalf("%v", err)
	}
}

func TestParseLogEvidenceRef(t *testing.T) {
	t.Parallel()
	le, err := contracts.ParseLogEvidenceRef("job_name", "demo", "build_number", 3, 0, 0, "", 8192)
	if err != nil {
		t.Fatal(err)
	}
	if le.Length != 8192 || !le.Valid() {
		t.Fatalf("%+v", le)
	}
	le, err = contracts.ParseLogEvidenceRef("job_name", "demo", "build_number", 3, 10, 100, "", 0)
	if err != nil || le.Offset != 10 || le.Length != 100 {
		t.Fatalf("%+v %v", le, err)
	}
	// Generation handle form.
	le, err = contracts.ParseLogEvidenceRef("job_name", "demo", "build_number", 3, 0, 0, "gen-1", 0)
	if err != nil || le.Generation != "gen-1" || !le.Valid() {
		t.Fatalf("%+v %v", le, err)
	}
	_, err = contracts.ParseLogEvidenceRef("job_name", "demo", "build_number", 3, -1, 10, "", 0)
	if err == nil {
		t.Fatal("negative offset")
	}
}

func TestFieldErrorMessage(t *testing.T) {
	t.Parallel()
	err := &contracts.FieldError{Field: "job_name", Message: "missing or empty", Allowed: contracts.AllowedJobForm}
	s := err.Error()
	if !strings.HasPrefix(s, "job_name:") {
		t.Fatalf("%q", s)
	}
	if !strings.Contains(s, "allowed form:") {
		t.Fatalf("%q", s)
	}
}
