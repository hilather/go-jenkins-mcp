package policy_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

// Wave 40 / POL-005 conformance expansion for Wave 39–40 list privacy.
// Hard-asserts Wave 39 BranchDenyCandidates slashy behavior (must pass on main).
// Wave 40 list privacy symbols live in internal/tools (hard-asserted there);
// this package only keeps deny-only Document canaries (no tools import cycle).

// TestWave40_BranchDenyCandidates_SlashyPathsStillDeny proves Wave 39 candidates
// still deny multi-segment JobName and slashy BranchName (POL-005 regression gate).
func TestWave40_BranchDenyCandidates_SlashyPathsStillDeny(t *testing.T) {
	t.Parallel()

	// Candidates for team/mb/release/1.2 must include leaf, intermediate release,
	// multi-segment suffix release/1.2, and full path — never folder-only "team".
	cands := policy.BranchDenyCandidates("team/mb/release/1.2")
	if len(cands) < 4 {
		t.Fatalf("candidates too short: %v", cands)
	}
	wantAny := map[string]bool{
		"1.2":                 false,
		"release":             false,
		"mb":                  false,
		"release/1.2":         false,
		"mb/release/1.2":      false,
		"team/mb/release/1.2": false,
	}
	for _, c := range cands {
		if _, ok := wantAny[c]; ok {
			wantAny[c] = true
		}
		if c == "team" {
			t.Fatalf("first path segment alone must not be a candidate: %v", cands)
		}
	}
	for k, seen := range wantAny {
		if !seen {
			t.Fatalf("missing candidate %q in %v", k, cands)
		}
	}

	// Single-segment / empty → nil (root freestyle not branch-denied via JobName).
	if got := policy.BranchDenyCandidates("main"); got != nil {
		t.Fatalf("single-segment: %v", got)
	}
	if got := policy.BranchDenyCandidates(""); got != nil {
		t.Fatalf("empty: %v", got)
	}

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyBranchNames: []string{"release/*", "hotfix"},
	})
	action := policy.Action{ToolName: "jenkins_get_job", Class: policy.EffectRead}

	// Slashy JobName intermediate suffix.
	d := ev.Evaluate(fixtureAdmin, action, policy.Target{JobName: "team/mb/release/1.2"})
	if !d.Denied() || d.ReasonCode != policy.ReasonResourcePatternDeny {
		t.Fatalf("want slashy JobName deny, got %+v", d)
	}
	if d.MatchedRule != "deny_branch_name:release/*" {
		t.Fatalf("matched_rule=%q", d.MatchedRule)
	}

	// Exact intermediate segment name as pattern.
	evHot := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyBranchNames: []string{"hotfix"},
	})
	dHot := evHot.Evaluate(fixtureAdmin, action, policy.Target{JobName: "org/app/hotfix/build"})
	if !dHot.Denied() {
		t.Fatalf("intermediate segment hotfix must deny: %+v", dHot)
	}

	// Explicit slashy BranchName (Wave 39).
	dBr := ev.Evaluate(fixtureAdmin,
		policy.Action{ToolName: "jenkins_list_jobs", Class: policy.EffectRead},
		policy.Target{BranchName: "release/1.2"})
	if !dBr.Denied() || dBr.MatchedRule != "deny_branch_name:release/*" {
		t.Fatalf("slashy BranchName must deny: %+v", dBr)
	}

	// Public multi-segment + single-segment root freestyle still allow.
	dOK := ev.Evaluate(fixtureAdmin, action, policy.Target{JobName: "team/mb/main"})
	if !dOK.Allowed() {
		t.Fatalf("team/mb/main vs release/* must allow: %+v", dOK)
	}
	dRoot := ev.Evaluate(fixtureAdmin, action, policy.Target{JobName: "main"})
	if !dRoot.Allowed() {
		t.Fatalf("single-segment main must allow: %+v", dRoot)
	}

	// Monotonicity: adding slashy deny never increases access.
	base := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	targets := []policy.Target{
		{JobName: "team/mb/release/1.2"},
		{JobName: "team/mb/main"},
		{BranchName: "release/9"},
		{JobName: "main"},
	}
	for _, tg := range targets {
		dBase := base.Evaluate(fixtureAdmin, action, tg)
		dRest := ev.Evaluate(fixtureAdmin, action, tg)
		if dBase.Denied() && dRest.Allowed() {
			t.Fatalf("adding deny_branch_names increased access for %+v: base=%+v rest=%+v", tg, dBase, dRest)
		}
	}
}

// TestWave40_DenyListSurfacesStillOnDocument hard-asserts Document still carries
// all Wave 35–40 deny list fields used by tools-layer fingerprints/filters.
// (PolicyFingerprintMaterial / listArtifactsWithPolicyFilter live in tools —
// hard-asserted in internal/tools wave40 conformance.)
func TestWave40_DenyListSurfacesStillOnDocument(t *testing.T) {
	t.Parallel()

	pt := reflect.TypeOf(policy.Document{})
	for _, name := range []string{
		"DenyJobPrefixes",
		"DenyBranchNames",
		"DenyArtifactPaths",
		"DenyNodeNames",
		"DenyViewNames",
	} {
		if _, ok := pt.FieldByName(name); !ok {
			t.Fatalf("Document.%s missing (list privacy / fingerprint source)", name)
		}
	}
	// Deny*FromEvaluator copy-outs remain the live source for tools filters.
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:              policy.ModePilot,
		DenyJobPrefixes:   []string{"secret-folder"},
		DenyBranchNames:   []string{"release/*"},
		DenyArtifactPaths: []string{"secrets/**"},
	})
	if got := policy.DenyJobPrefixesFromEvaluator(ev); len(got) != 1 || got[0] != "secret-folder" {
		t.Fatalf("DenyJobPrefixesFromEvaluator: %v", got)
	}
	if got := policy.DenyBranchNamesFromEvaluator(ev); len(got) != 1 || got[0] != "release/*" {
		t.Fatalf("DenyBranchNamesFromEvaluator: %v", got)
	}
	if got := policy.DenyArtifactPathsFromEvaluator(ev); len(got) != 1 || got[0] != "secrets/**" {
		t.Fatalf("DenyArtifactPathsFromEvaluator: %v", got)
	}
}

// TestWave40_DenyOnlyStillNeverElevates is a POL-005 canary: empty deny sets and
// public targets stay allow; deny-only language has no grant fields.
func TestWave40_DenyOnlyStillNeverElevates(t *testing.T) {
	t.Parallel()

	docType := reflect.TypeOf(policy.Document{})
	for i := 0; i < docType.NumField(); i++ {
		name := docType.Field(i).Name
		lower := strings.ToLower(name)
		if strings.Contains(lower, "allow_tool") ||
			strings.Contains(lower, "grant") ||
			strings.HasPrefix(lower, "allowjob") {
			t.Fatalf("Document must not grow elevation fields: %s", name)
		}
	}

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:              policy.ModePilot,
		DenyBranchNames:   []string{"release/*"},
		DenyArtifactPaths: []string{"secrets/**"},
		DenyJobPrefixes:   []string{"secret-folder"},
	})
	// Public job + public artifact path + no branch → allow.
	d := ev.Evaluate(fixtureAdmin,
		policy.Action{ToolName: "jenkins_get_artifact_text", Class: policy.EffectRead},
		policy.Target{JobName: "public/app", ArtifactPath: "reports/out.txt"})
	if !d.Allowed() {
		t.Fatalf("public target must allow under deny-only: %+v", d)
	}
	// Secret job still deny.
	dJob := ev.Evaluate(fixtureAdmin,
		policy.Action{ToolName: "jenkins_get_job", Class: policy.EffectRead},
		policy.Target{JobName: "secret-folder/job-a"})
	if !dJob.Denied() {
		t.Fatalf("secret-folder must deny: %+v", dJob)
	}
}
