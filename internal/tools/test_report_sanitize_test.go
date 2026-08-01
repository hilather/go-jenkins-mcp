package tools_test

import (
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/redact"
	"github.com/simonfxr/go-jenkins-mcp/internal/tools"
)

func TestPrepareTestReportForModel_RedactsFailureText(t *testing.T) {
	rep := &jenkins.TestReport{
		JobName:     "demo",
		BuildNumber: 7,
		Available:   true,
		FailCount:   1,
		PassCount:   0,
		TotalCount:  1,
		FailedTests: []jenkins.FailedTest{{
			Name:            "testSecret",
			ClassName:       "com.example.T",
			Status:          "FAILED",
			ErrorDetails:    "password=supersecret-token-value",
			ErrorStackTrace: "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc.def\n\tat T.java:1",
		}},
	}
	out := tools.PrepareTestReportForModel(rep)
	if !out.Untrusted || out.ContentKind != tools.ContentKindTestFailure {
		t.Fatalf("labels: untrusted=%v kind=%q", out.Untrusted, out.ContentKind)
	}
	if len(out.FailedTests) != 1 {
		t.Fatalf("failed = %+v", out.FailedTests)
	}
	if strings.Contains(out.FailedTests[0].ErrorDetails, "supersecret") {
		t.Fatalf("details leaked secret: %q", out.FailedTests[0].ErrorDetails)
	}
	if strings.Contains(out.FailedTests[0].ErrorStackTrace, "eyJhbGci") {
		t.Fatalf("trace leaked JWT: %q", out.FailedTests[0].ErrorStackTrace)
	}
	if !strings.Contains(out.FailedTests[0].ErrorDetails, redact.Replacement) &&
		out.FailedTests[0].ErrorDetails == rep.FailedTests[0].ErrorDetails {
		// At least one redaction path should change the string for password= patterns.
		t.Logf("details after sanitize: %q (may vary by pattern coverage)", out.FailedTests[0].ErrorDetails)
	}
}

func TestPrepareTestReportForModel_Nil(t *testing.T) {
	out := tools.PrepareTestReportForModel(nil)
	if out.Available {
		t.Fatal("nil report must not be available")
	}
	if !out.Untrusted {
		t.Fatal("expected untrusted")
	}
}
