package tools

import (
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

func TestJobFullName_AcceptAndReject(t *testing.T) {
	t.Parallel()
	got, err := jobFullName("job_name", "folder/job")
	if err != nil || got != "folder/job" {
		t.Fatalf("got %q err=%v", got, err)
	}

	// Regression: absolute job URL rejected as invalid_argument (MCP-002).
	_, err = jobFullName("job_name", "http://jenkins/job/x")
	if err == nil {
		t.Fatal("expected reject absolute URL")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code=%q", apperr.CodeOf(err))
	}
	msg := err.Error()
	if !strings.Contains(msg, "job_name") {
		t.Fatalf("want field in message: %q", msg)
	}
	if !strings.Contains(msg, "allowed form") {
		t.Fatalf("want allowed form: %q", msg)
	}
	// Must not echo a usable attack URL as a path to fetch — message may mention
	// URL rejection but must not look like a successful parse.
	if strings.Contains(msg, "missing or empty") {
		t.Fatalf("wrong error class: %q", msg)
	}
}

func TestBuildRef_Validation(t *testing.T) {
	t.Parallel()
	ref, err := buildRef("job_name", "demo", "build_number", 9)
	if err != nil || ref.Number != 9 || ref.Job.FullName != "demo" {
		t.Fatalf("%+v %v", ref, err)
	}
	_, err = buildRef("job_name", "demo", "build_number", 0)
	if err == nil || apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("%v", err)
	}
	_, err = buildRef("job_name", "https://evil/job/x", "build_number", 1)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "url") {
		t.Fatalf("%v", err)
	}
}

func TestQueueItemRef_Validation(t *testing.T) {
	t.Parallel()
	ref, err := queueItemRef("queue_id", 42, "corp")
	if err != nil || ref.ID != 42 || string(ref.Profile) != "corp" {
		t.Fatalf("%+v %v", ref, err)
	}
	_, err = queueItemRef("queue_id", -1, "")
	if err == nil || apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("%v", err)
	}
}

func TestLogEvidence_DefaultsLength(t *testing.T) {
	t.Parallel()
	le, err := logEvidence("job_name", "demo", "build_number", 1, 0, 0, DefaultLogLength)
	if err != nil || le.Length != DefaultLogLength {
		t.Fatalf("%+v %v", le, err)
	}
	le, err = logEvidence("job_name", "demo", "build_number", 1, 100, 50, DefaultLogLength)
	if err != nil || le.Offset != 100 || le.Length != 50 {
		t.Fatalf("%+v %v", le, err)
	}
}
