package policy_test

import (
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

// Wave 38 / POL-005 conformance expansion for Wave 35–37 resource denials.
// Tests compile and pass against main (Wave 37 surfaces). Intended Wave 38
// leaf-branch / list_views / absolute hard-max behavior is documented as
// residuals when symbols are not yet present.

// TestWave38_Monotonicity_DenyBranchNamesOnlyRestricts: adding deny_branch_names
// never increases the allow set (same property as deny_tools / deny_job_prefixes).
func TestWave38_Monotonicity_DenyBranchNamesOnlyRestricts(t *testing.T) {
	t.Parallel()

	base := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	restricted := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyBranchNames: []string{"release/*", "main"},
	})

	type caseT struct {
		name   string
		tool   string
		target policy.Target
	}
	cases := []caseT{
		{"empty_target", "jenkins_list_jobs", policy.Target{}},
		{"public_branch", "jenkins_list_jobs", policy.Target{BranchName: "feature/foo"}},
		{"denied_release", "jenkins_list_jobs", policy.Target{BranchName: "release/1.2"}},
		{"denied_main", "jenkins_get_job", policy.Target{BranchName: "main"}},
		{"job_only_no_branch", "jenkins_get_job", policy.Target{JobName: "public/app"}},
		{"branch_plus_job", "jenkins_get_job", policy.Target{JobName: "mb/main", BranchName: "main"}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			a := policy.Action{ToolName: tc.tool, Class: policy.EffectRead}
			dBase := base.Evaluate(fixtureAdmin, a, tc.target)
			dRest := restricted.Evaluate(fixtureAdmin, a, tc.target)
			if dBase.Denied() && dRest.Allowed() {
				t.Fatalf("adding deny_branch_names increased access: base=%+v rest=%+v", dBase, dRest)
			}
			if dRest.Allowed() && dBase.Denied() {
				t.Fatalf("impossible allow under stricter branch policy: base=%+v rest=%+v", dBase, dRest)
			}
		})
	}

	// Explicit: denied branch must flip allow → deny; public stays allow.
	dRel := restricted.Evaluate(fixtureAdmin,
		policy.Action{ToolName: "jenkins_list_jobs", Class: policy.EffectRead},
		policy.Target{BranchName: "release/1.2"})
	if !dRel.Denied() || dRel.ReasonCode != policy.ReasonResourcePatternDeny {
		t.Fatalf("release/* must deny: %+v", dRel)
	}
	if dRel.MatchedRule != "deny_branch_name:release/*" {
		t.Fatalf("matched_rule=%q", dRel.MatchedRule)
	}
	dOK := restricted.Evaluate(fixtureAdmin,
		policy.Action{ToolName: "jenkins_list_jobs", Class: policy.EffectRead},
		policy.Target{BranchName: "feature/foo"})
	if !dOK.Allowed() {
		t.Fatalf("public branch must remain allow: %+v", dOK)
	}

	// Combining with another restriction is intersection (at least as strict).
	combo := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyBranchNames: []string{"main"},
		DenyJobPrefixes: []string{"secret"},
	})
	// secret job + public branch → job deny
	dJob := combo.Evaluate(fixtureAdmin,
		policy.Action{ToolName: "jenkins_get_job", Class: policy.EffectRead},
		policy.Target{JobName: "secret/app", BranchName: "feature/x"})
	if !dJob.Denied() || dJob.ReasonCode != policy.ReasonJobPatternDeny {
		t.Fatalf("job deny must still apply with branch rules present: %+v", dJob)
	}
	// public job + main branch → branch deny
	dBr := combo.Evaluate(fixtureAdmin,
		policy.Action{ToolName: "jenkins_get_job", Class: policy.EffectRead},
		policy.Target{JobName: "public/app", BranchName: "main"})
	if !dBr.Denied() || dBr.ReasonCode != policy.ReasonResourcePatternDeny {
		t.Fatalf("branch deny with public job: %+v", dBr)
	}
}

// TestWave38_Compose_ArtifactAndNodeWithJobAllow: deny_artifact_paths and
// deny_node_names compose independently of job allow (deny-only intersection).
func TestWave38_Compose_ArtifactAndNodeWithJobAllow(t *testing.T) {
	t.Parallel()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:              policy.ModePilot,
		DenyJobPrefixes:   []string{"secret-folder"},
		DenyArtifactPaths: []string{"secrets/**", "*.pem"},
		DenyNodeNames:     []string{"prod-agent-*"},
	})
	actionArt := policy.Action{ToolName: "jenkins_get_artifact_text", Class: policy.EffectRead}
	actionNode := policy.Action{ToolName: "jenkins_get_node", Class: policy.EffectRead}

	// Job allow + public artifact → allow.
	dOK := ev.Evaluate(fixtureAdmin, actionArt, policy.Target{
		JobName:      "public/app",
		ArtifactPath: "reports/out.txt",
	})
	if !dOK.Allowed() {
		t.Fatalf("public job + public artifact: %+v", dOK)
	}

	// Job allow + denied artifact → resource deny (artifact rule).
	dArt := ev.Evaluate(fixtureAdmin, actionArt, policy.Target{
		JobName:      "public/app",
		ArtifactPath: "secrets/prod/key.pem",
	})
	if !dArt.Denied() || dArt.ReasonCode != policy.ReasonResourcePatternDeny {
		t.Fatalf("artifact deny on allowed job: %+v", dArt)
	}
	if !strings.HasPrefix(dArt.MatchedRule, "deny_artifact_path:") {
		t.Fatalf("matched_rule=%q want deny_artifact_path:", dArt.MatchedRule)
	}

	// Job deny wins order when job + artifact both match (job checked first).
	dJobFirst := ev.Evaluate(fixtureAdmin, actionArt, policy.Target{
		JobName:      "secret-folder/job-a",
		ArtifactPath: "secrets/x",
	})
	if !dJobFirst.Denied() || dJobFirst.ReasonCode != policy.ReasonJobPatternDeny {
		t.Fatalf("job deny should win order: %+v", dJobFirst)
	}

	// Job allow + denied node → resource deny.
	dNode := ev.Evaluate(fixtureAdmin, actionNode, policy.Target{
		JobName:  "public/app", // informational; node rule keys NodeName
		NodeName: "prod-agent-01",
	})
	if !dNode.Denied() || dNode.ReasonCode != policy.ReasonResourcePatternDeny {
		t.Fatalf("node deny on allowed job context: %+v", dNode)
	}
	if dNode.MatchedRule != "deny_node_name:prod-agent-*" {
		t.Fatalf("matched_rule=%q", dNode.MatchedRule)
	}

	// Public node + public job context → allow.
	dNodeOK := ev.Evaluate(fixtureAdmin, actionNode, policy.Target{
		NodeName: "dev-agent-01",
	})
	if !dNodeOK.Allowed() {
		t.Fatalf("public node: %+v", dNodeOK)
	}

	// Compose both resource fields: node deny when both present and node matches
	// (node is checked before artifact in Evaluate).
	dBoth := ev.Evaluate(fixtureAdmin, actionArt, policy.Target{
		JobName:      "public/app",
		NodeName:     "prod-agent-99",
		ArtifactPath: "reports/out.txt",
	})
	if !dBoth.Denied() || dBoth.MatchedRule != "deny_node_name:prod-agent-*" {
		t.Fatalf("node should win when both resource fields set: %+v", dBoth)
	}
	// Artifact deny when node is public.
	dArtOnly := ev.Evaluate(fixtureAdmin, actionArt, policy.Target{
		JobName:      "public/app",
		NodeName:     "dev-agent-01",
		ArtifactPath: "tls.pem",
	})
	if !dArtOnly.Denied() || !strings.HasPrefix(dArtOnly.MatchedRule, "deny_artifact_path:") {
		t.Fatalf("artifact deny with public node: %+v", dArtOnly)
	}
}

// TestWave38_EmptySubjectDeniesBeforeResourceChecks: subject validation runs
// before job/node/view/artifact/branch resource patterns. Empty/anonymous
// subjects never reach resource allow even when resource targets are empty
// (would otherwise allow under pilot).
func TestWave38_EmptySubjectDeniesBeforeResourceChecks(t *testing.T) {
	t.Parallel()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:              policy.ModePilot,
		DenyJobPrefixes:   []string{"secret"},
		DenyNodeNames:     []string{"prod-agent-*"},
		DenyViewNames:     []string{"secret-view"},
		DenyArtifactPaths: []string{"secrets/**"},
		DenyBranchNames:   []string{"main"},
	})

	// Targets that would ALLOW for a valid subject (no matching resource deny).
	allowTargets := []policy.Target{
		{},
		{JobName: "public/app"},
		{NodeName: "dev-agent-01"},
		{ViewName: "public-view"},
		{ArtifactPath: "reports/out.txt"},
		{BranchName: "feature/x"},
	}
	// Targets that would DENY for a valid subject.
	denyTargets := []policy.Target{
		{JobName: "secret/job"},
		{NodeName: "prod-agent-01"},
		{ViewName: "secret-view"},
		{ArtifactPath: "secrets/x"},
		{BranchName: "main"},
	}

	subjects := []struct {
		name    string
		subject policy.Subject
		reason  string
	}{
		{"empty", policy.Subject{}, policy.ReasonSubjectEmpty},
		{"anonymous", policy.NewSubject("corp", "anonymous", true), policy.ReasonSubjectAnon},
	}

	action := policy.Action{ToolName: "jenkins_get_job", Class: policy.EffectRead}
	for _, sub := range subjects {
		for _, target := range append(append([]policy.Target{}, allowTargets...), denyTargets...) {
			d := ev.Evaluate(sub.subject, action, target)
			if !d.Denied() || d.ReasonCode != sub.reason {
				t.Fatalf("%s subject target=%+v: got %+v want reason %s",
					sub.name, target, d, sub.reason)
			}
			// Must not report resource/job deny for empty subject (ordering).
			if d.ReasonCode == policy.ReasonJobPatternDeny ||
				d.ReasonCode == policy.ReasonResourcePatternDeny {
				t.Fatalf("%s subject must deny before resource checks: %+v", sub.name, d)
			}
			if err := d.Err(); err == nil || apperr.CodeOf(err) != apperr.CodePolicyDenial {
				t.Fatalf("%s err=%v", sub.name, err)
			}
		}
	}

	// Control: valid subject still sees resource deny vs allow.
	dRes := ev.Evaluate(fixtureAdmin, action, policy.Target{BranchName: "main"})
	if !dRes.Denied() || dRes.ReasonCode != policy.ReasonResourcePatternDeny {
		t.Fatalf("valid subject branch deny: %+v", dRes)
	}
	dOK := ev.Evaluate(fixtureAdmin, action, policy.Target{BranchName: "feature/x"})
	if !dOK.Allowed() {
		t.Fatalf("valid subject public branch: %+v", dOK)
	}
}

// TestWave38_StatusMap_DenyBranchNamesCount: LoadResult.StatusMap exposes
// deny_branch_names_count when the overlay carries the field (doctor/policy
// check Details). No secrets in keys/values.
func TestWave38_StatusMap_DenyBranchNamesCount(t *testing.T) {
	t.Parallel()

	o := &policy.Overlay{
		Version:           1,
		ForceReadOnly:     true,
		Mode:              policy.ModePilot,
		DenyTools:         []string{"jenkins_get_build_logs"},
		DenyJobPrefixes:   []string{"secret-folder"},
		DenyNodeNames:     []string{"prod-agent-*"},
		DenyViewNames:     []string{"secret-view"},
		DenyArtifactPaths: []string{"secrets/**"},
		DenyBranchNames:   []string{"release/*", "main", "hotfix/**"},
	}
	res := policy.LoadResult{
		Overlay:        o,
		Path:           "/etc/jenkins-mcp/policy/overlay.json",
		Present:        true,
		SignatureState: "unverified_pilot",
	}
	m := res.StatusMap()
	if m["deny_branch_names_count"] != 3 {
		t.Fatalf("deny_branch_names_count=%v want 3 full=%v", m["deny_branch_names_count"], m)
	}
	if m["deny_artifact_paths_count"] != 1 {
		t.Fatalf("deny_artifact_paths_count=%v", m["deny_artifact_paths_count"])
	}
	if m["deny_node_names_count"] != 1 {
		t.Fatalf("deny_node_names_count=%v", m["deny_node_names_count"])
	}
	// Counts only — never pattern bodies or signature material.
	for k, v := range m {
		s := strings.ToLower(k + " ")
		if strings.Contains(s, "token") || strings.Contains(s, "password") || strings.Contains(s, "secret") {
			// Keys like "deny_*" are ok; values must not be pattern strings that
			// are not counts. StatusMap values for counts are ints.
			if _, ok := v.(string); ok {
				if strings.Contains(strings.ToLower(v.(string)), "token") {
					t.Fatalf("status leaked secret-ish: %v=%v", k, v)
				}
			}
		}
	}
	// Absent overlay fields → zero counts still present when Overlay non-nil.
	empty := policy.LoadResult{
		Overlay:        &policy.Overlay{Version: 1},
		Present:        true,
		SignatureState: "unverified_pilot",
	}
	em := empty.StatusMap()
	if em["deny_branch_names_count"] != 0 {
		t.Fatalf("empty overlay branch count=%v", em["deny_branch_names_count"])
	}
}

// TestWave38_JobNameLeafBranchDeny_Hard asserts Wave 38 leaf matching is active:
// multi-segment JobName leaf matches deny_branch_names when BranchName is empty.
func TestWave38_JobNameLeafBranchDeny_Hard(t *testing.T) {
	t.Parallel()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyBranchNames: []string{"main"},
	})
	// Explicit BranchName still denies (Wave 37 Done*).
	d := ev.Evaluate(fixtureAdmin,
		policy.Action{ToolName: "jenkins_get_job", Class: policy.EffectRead},
		policy.Target{BranchName: "main"})
	if !d.Denied() {
		t.Fatal("Wave 37 BranchName deny missing")
	}

	// JobName leaf only (no BranchName): multi-segment must deny (Wave 38).
	dLeaf := ev.Evaluate(fixtureAdmin,
		policy.Action{ToolName: "jenkins_get_job", Class: policy.EffectRead},
		policy.Target{JobName: "multibranch/main"})
	if !dLeaf.Denied() || dLeaf.ReasonCode != policy.ReasonResourcePatternDeny {
		t.Fatalf("want leaf deny for multibranch/main, got %+v", dLeaf)
	}
	// Single-segment freestyle root still allows (no leaf branch rule).
	dRoot := ev.Evaluate(fixtureAdmin,
		policy.Action{ToolName: "jenkins_get_job", Class: policy.EffectRead},
		policy.Target{JobName: "main"})
	if !dRoot.Allowed() {
		t.Fatalf("single-segment main must allow: %+v", dRoot)
	}
}

// TestWave39_SlashyIntermediateBranchDeny_Hard asserts Wave 39 intermediate /
// slashy suffix matching: team/mb/release/1.2 matches release/*; single-segment
// JobName still does not apply branch deny.
func TestWave39_SlashyIntermediateBranchDeny_Hard(t *testing.T) {
	t.Parallel()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyBranchNames: []string{"release/*"},
	})
	d := ev.Evaluate(fixtureAdmin,
		policy.Action{ToolName: "jenkins_get_job", Class: policy.EffectRead},
		policy.Target{JobName: "team/mb/release/1.2"})
	if !d.Denied() || d.MatchedRule != "deny_branch_name:release/*" {
		t.Fatalf("want slashy suffix deny, got %+v", d)
	}
	dMiss := ev.Evaluate(fixtureAdmin,
		policy.Action{ToolName: "jenkins_get_job", Class: policy.EffectRead},
		policy.Target{JobName: "team/mb/main"})
	if !dMiss.Allowed() {
		t.Fatalf("team/mb/main vs release/* must allow: %+v", dMiss)
	}
	// Monotonicity: BranchDenyCandidates never empty for multi-segment.
	if c := policy.BranchDenyCandidates("team/mb/release/1.2"); len(c) < 4 {
		t.Fatalf("candidates too short: %v", c)
	}
}
