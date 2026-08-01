package policy_test

import (
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

func TestDenyArtifactPathsFromEvaluator(t *testing.T) {
	if got := policy.DenyArtifactPathsFromEvaluator(nil); got != nil {
		t.Fatalf("nil evaluator: %v", got)
	}
	if got := policy.DenyArtifactPathsFromEvaluator(policy.AllowAllEvaluator{}); got != nil {
		t.Fatalf("AllowAll: %v", got)
	}
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:              policy.ModePilot,
		DenyArtifactPaths: []string{"secrets/**", "*.pem"},
	})
	got := policy.DenyArtifactPathsFromEvaluator(ev)
	if len(got) != 2 || got[0] != "secrets/**" {
		t.Fatalf("DenyOnly: %v", got)
	}
	// Mutation of returned slice must not affect Document.
	got[0] = "mutated"
	again := policy.DenyArtifactPathsFromEvaluator(ev)
	if again[0] != "secrets/**" {
		t.Fatalf("returned slice must be a copy: %v", again)
	}
	ev2 := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	if got := policy.DenyArtifactPathsFromEvaluator(ev2); got != nil {
		t.Fatalf("empty deny list: %v", got)
	}
}

func TestDenyBranchNamesFromEvaluator(t *testing.T) {
	if got := policy.DenyBranchNamesFromEvaluator(nil); got != nil {
		t.Fatalf("nil evaluator: %v", got)
	}
	if got := policy.DenyBranchNamesFromEvaluator(policy.AllowAllEvaluator{}); got != nil {
		t.Fatalf("AllowAll: %v", got)
	}
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyBranchNames: []string{"release/*", "main"},
	})
	got := policy.DenyBranchNamesFromEvaluator(ev)
	if len(got) != 2 || got[0] != "release/*" {
		t.Fatalf("DenyOnly: %v", got)
	}
	ev2 := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	if got := policy.DenyBranchNamesFromEvaluator(ev2); got != nil {
		t.Fatalf("empty deny list: %v", got)
	}
}

func TestDenyJobPrefixesFromEvaluator(t *testing.T) {
	if got := policy.DenyJobPrefixesFromEvaluator(nil); got != nil {
		t.Fatalf("nil evaluator: %v", got)
	}
	if got := policy.DenyJobPrefixesFromEvaluator(policy.AllowAllEvaluator{}); got != nil {
		t.Fatalf("AllowAll: %v", got)
	}
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"secret-folder/**", "hr/payroll"},
	})
	got := policy.DenyJobPrefixesFromEvaluator(ev)
	if len(got) != 2 || got[0] != "secret-folder/**" {
		t.Fatalf("DenyOnly: %v", got)
	}
	// Empty document → nil.
	ev2 := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	if got := policy.DenyJobPrefixesFromEvaluator(ev2); got != nil {
		t.Fatalf("empty deny list: %v", got)
	}
	// NameDeniedByPatterns works for job full names (Wave 37).
	if !policy.NameDeniedByPatterns(got, "secret-folder/job-a") {
		t.Fatal("secret-folder/job-a must match secret-folder/**")
	}
	if policy.NameDeniedByPatterns(got, "public/app") {
		t.Fatal("public/app must not match deny_job_prefixes")
	}
}

func TestDenyNodeNamesFromEvaluator(t *testing.T) {
	if got := policy.DenyNodeNamesFromEvaluator(nil); got != nil {
		t.Fatalf("nil evaluator: %v", got)
	}
	// AllowAllEvaluator has no Document() — no filter.
	if got := policy.DenyNodeNamesFromEvaluator(policy.AllowAllEvaluator{}); got != nil {
		t.Fatalf("AllowAll: %v", got)
	}
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:          policy.ModePilot,
		DenyNodeNames: []string{"prod-agent-*", "secret-node"},
	})
	got := policy.DenyNodeNamesFromEvaluator(ev)
	if len(got) != 2 || got[0] != "prod-agent-*" {
		t.Fatalf("DenyOnly: %v", got)
	}
	// Empty document → nil.
	ev2 := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	if got := policy.DenyNodeNamesFromEvaluator(ev2); got != nil {
		t.Fatalf("empty deny list: %v", got)
	}
}

func TestNameDeniedByPatterns_ProdAgent(t *testing.T) {
	patterns := []string{"prod-agent-*"}
	if !policy.NameDeniedByPatterns(patterns, "prod-agent-01") {
		t.Fatal("prod-agent-01 must match prod-agent-*")
	}
	if policy.NameDeniedByPatterns(patterns, "ci-1") {
		t.Fatal("ci-1 must not match prod-agent-*")
	}
	if policy.NameDeniedByPatterns(nil, "prod-agent-01") {
		t.Fatal("empty patterns deny nothing")
	}
	if policy.NameDeniedByPatterns(patterns, "") {
		t.Fatal("empty name is not denied")
	}
	if policy.NameDeniedByPatterns(patterns, "  ") {
		t.Fatal("whitespace-only name is not denied")
	}
}

func TestDenyViewNamesFromEvaluator(t *testing.T) {
	if got := policy.DenyViewNamesFromEvaluator(nil); got != nil {
		t.Fatalf("nil evaluator: %v", got)
	}
	if got := policy.DenyViewNamesFromEvaluator(policy.AllowAllEvaluator{}); got != nil {
		t.Fatalf("AllowAll: %v", got)
	}
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:          policy.ModePilot,
		DenyViewNames: []string{"secret-view", "hr/**"},
	})
	got := policy.DenyViewNamesFromEvaluator(ev)
	if len(got) != 2 || got[0] != "secret-view" {
		t.Fatalf("DenyOnly: %v", got)
	}
	// Mutation of returned slice must not affect Document.
	got[0] = "mutated"
	again := policy.DenyViewNamesFromEvaluator(ev)
	if again[0] != "secret-view" {
		t.Fatalf("returned slice must be a copy: %v", again)
	}
	ev2 := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	if got := policy.DenyViewNamesFromEvaluator(ev2); got != nil {
		t.Fatalf("empty deny list: %v", got)
	}
}
