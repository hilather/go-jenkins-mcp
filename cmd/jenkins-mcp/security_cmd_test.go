package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/diagnostics"
)

func TestSecuritySelfCheck_CLI_JSON(t *testing.T) {
	// Capture stdout from runSecuritySelfCheck.
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	errRun := runSecuritySelfCheck([]string{"--json"})
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	if errRun != nil {
		// Fail only on hard failures; absent policy is ok.
		if !strings.Contains(errRun.Error(), "security self-check") {
			t.Fatalf("run: %v\nout=%s", errRun, buf.String())
		}
	}
	out := buf.String()
	if strings.Contains(out, "QA005_SELFCHECK_CANARY") {
		t.Fatal("canary leaked to CLI stdout")
	}
	var rep diagnostics.SelfCheckReport
	if err := json.Unmarshal(buf.Bytes(), &rep); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if !rep.IndependentReviewRequired {
		t.Fatal("independent_review_required")
	}
	if len(rep.Items) == 0 {
		t.Fatal("no items")
	}
}

func TestSecuritySelfCheck_CLI_RequiresSubcommand(t *testing.T) {
	err := runSecurity(nil)
	if err == nil || !strings.Contains(err.Error(), "self-check") {
		t.Fatalf("%v", err)
	}
	err = runSecurity([]string{"pen-test"})
	if err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("%v", err)
	}
}

func TestSecurityUsageMentionsResiduals(t *testing.T) {
	u := securityUsage()
	if !strings.Contains(u, "self-check") {
		t.Fatal(u)
	}
	if !strings.Contains(u, "penetration") && !strings.Contains(u, "independent") {
		t.Fatal("must disclaim pen-test / independent review")
	}
}
