package tools

import (
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/redact"
)

func TestRedactParamMap(t *testing.T) {
	t.Parallel()
	in := map[string]string{
		"BRANCH":   "main",
		"PASSWORD": "should-not-leak",
		"note":     "Bearer super-secret-token-value",
	}
	out := redactParamMap(in)
	if out["PASSWORD"] != redact.Replacement {
		t.Fatalf("PASSWORD: %q", out["PASSWORD"])
	}
	if out["BRANCH"] != "main" {
		t.Fatalf("BRANCH: %q", out["BRANCH"])
	}
	if strings.Contains(out["note"], "super-secret-token-value") {
		t.Fatalf("note: %q", out["note"])
	}
}

func TestPrepareSearchBuildsForModel(t *testing.T) {
	t.Parallel()
	res := &jenkins.SearchBuildsToolResponse{
		Scanned: 3,
		Builds: []jenkins.Build{
			{
				Number: 1,
				Parameters: map[string]string{
					"API_TOKEN": "raw-token-xyz",
					"ENV":       "prod",
				},
			},
		},
	}
	out := prepareSearchBuildsForModel(res)
	if out.Builds[0].Parameters["API_TOKEN"] != redact.Replacement {
		t.Fatalf("%v", out.Builds[0].Parameters)
	}
	if out.Builds[0].Parameters["ENV"] != "prod" {
		t.Fatalf("ENV over-redacted: %v", out.Builds[0].Parameters)
	}
	// Original not mutated.
	if res.Builds[0].Parameters["API_TOKEN"] != "raw-token-xyz" {
		t.Fatal("mutated input")
	}
}
