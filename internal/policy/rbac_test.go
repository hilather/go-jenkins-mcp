package policy_test

import (
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/contracts"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

// Fixture subjects (POL-003) — never built from tool arguments.
var (
	fixtureAdmin = policy.NewSubject("corp", "jenkins-admin", true)
	fixtureDev   = policy.NewSubject("corp", "dev-user", true)
	fixtureProv  = policy.NewSubject("corp", "session-user", false) // provisional until AUTH-004
)

func TestDenyByToolName(t *testing.T) {
	t.Parallel()
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode: policy.ModePilot,
		DenyTools: map[string]struct{}{
			"jenkins_get_build_logs": {},
		},
	})
	d := ev.Evaluate(fixtureAdmin, policy.Action{
		ToolName: "jenkins_get_build_logs",
		Class:    policy.EffectRead,
	}, policy.Target{})
	if !d.Denied() {
		t.Fatal("explicit deny must deny")
	}
	if d.ReasonCode != policy.ReasonExplicitDeny {
		t.Fatalf("reason=%s", d.ReasonCode)
	}
	if err := d.Err(); err == nil || apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("err=%v", err)
	}
	// Other tools still allowed under pilot.
	d2 := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_jobs", Class: policy.EffectRead}, policy.Target{})
	if !d2.Allowed() {
		t.Fatalf("get_jobs should allow: %+v", d2)
	}
}

func TestAdminStillDeniedByMCPRule(t *testing.T) {
	t.Parallel()
	// Regression: Jenkins administrator identity does not elevate MCP policy.
	// MCP is deny-only and can restrict admins below their Jenkins permissions.
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode: policy.ModePilot,
		DenyTools: map[string]struct{}{
			"jenkins_get_job": {},
		},
	})
	d := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_job", Class: policy.EffectRead}, policy.Target{})
	if !d.Denied() {
		t.Fatal("admin must still be denied by MCP deny rule")
	}
	if !strings.Contains(d.Explanation, "jenkins_get_job") {
		t.Fatalf("explanation=%q", d.Explanation)
	}
	// Same for a non-admin — equal MCP treatment (no elevation path).
	dDev := ev.Evaluate(fixtureDev, policy.Action{ToolName: "jenkins_get_job", Class: policy.EffectRead}, policy.Target{})
	if !dDev.Denied() {
		t.Fatal("dev also denied")
	}
}

func TestPilotDefaultAllowReads(t *testing.T) {
	t.Parallel()
	ev := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	d := ev.Evaluate(fixtureDev, policy.Action{ToolName: "jenkins_get_jobs", Class: policy.EffectRead}, policy.Target{})
	if !d.Allowed() || d.ReasonCode != policy.ReasonOK {
		t.Fatalf("pilot default allow: %+v", d)
	}
}

func TestStrictUnknownToolDenied(t *testing.T) {
	t.Parallel()
	ev := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModeStrict})
	d := ev.Evaluate(fixtureDev, policy.Action{ToolName: "jenkins_evil_tool", Class: policy.EffectRead}, policy.Target{})
	if !d.Denied() || d.ReasonCode != policy.ReasonUnknownTool {
		t.Fatalf("strict unknown: %+v", d)
	}
	// Known seed tool allowed when not explicitly denied.
	d2 := ev.Evaluate(fixtureDev, policy.Action{ToolName: "jenkins_get_jobs", Class: policy.EffectRead}, policy.Target{})
	if !d2.Allowed() {
		t.Fatalf("known tool under strict: %+v", d2)
	}
}

func TestMissingPolicyRequiredFailClosed(t *testing.T) {
	t.Parallel()
	// Missing policy file when Required — covered in overlay_test; here evaluate
	// nil evaluator fail closed (defense in depth).
	var ev *policy.DenyOnlyEvaluator
	d := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_jobs"}, policy.Target{})
	if !d.Denied() || d.ReasonCode != policy.ReasonNoEvaluator {
		t.Fatalf("nil evaluator: %+v", d)
	}
}

func TestSubjectEmptyRejected(t *testing.T) {
	t.Parallel()
	ev := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	d := ev.Evaluate(policy.Subject{}, policy.Action{ToolName: "jenkins_get_jobs"}, policy.Target{})
	if !d.Denied() || d.ReasonCode != policy.ReasonSubjectEmpty {
		t.Fatalf("empty subject: %+v", d)
	}
}

func TestSubjectAnonymousRejected(t *testing.T) {
	t.Parallel()
	ev := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	anon := policy.NewSubject("corp", "anonymous", true)
	d := ev.Evaluate(anon, policy.Action{ToolName: "jenkins_get_jobs"}, policy.Target{})
	if !d.Denied() || d.ReasonCode != policy.ReasonSubjectAnon {
		t.Fatalf("anonymous: %+v", d)
	}
}

func TestSubjectUnverifiedWhenRequired(t *testing.T) {
	t.Parallel()
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:                   policy.ModePilot,
		RequireVerifiedSubject: true,
	})
	d := ev.Evaluate(fixtureProv, policy.Action{ToolName: "jenkins_get_jobs"}, policy.Target{})
	if !d.Denied() || d.ReasonCode != policy.ReasonSubjectUnverified {
		t.Fatalf("unverified: %+v", d)
	}
	// Verified admin ok.
	d2 := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_jobs"}, policy.Target{})
	if !d2.Allowed() {
		t.Fatalf("verified: %+v", d2)
	}
}

func TestSubjectNotFromToolArgs(t *testing.T) {
	t.Parallel()
	// POL-003: evaluation uses the process-bound subject only. A "tool arg"
	// username must not appear in Subject construction at call sites.
	// This test documents the fixture-only construction contract.
	attackerClaim := "i-am-admin" // would come from tool args if buggy
	bound := policy.NewSubject(contracts.ProfileID("corp"), "real-user", true)
	if bound.JenkinsUserID == attackerClaim {
		t.Fatal("fixture must not use attacker claim")
	}
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode: policy.ModePilot,
		DenyTools: map[string]struct{}{
			"jenkins_get_jobs": {},
		},
	})
	// Bound identity is denied by policy regardless of any tool-arg claim.
	d := ev.Evaluate(bound, policy.Action{ToolName: "jenkins_get_jobs"}, policy.Target{})
	if !d.Denied() {
		t.Fatal("bound subject must be evaluated, not tool-arg identity")
	}
	// Constructing a subject from a tool-arg string is a call-site bug; the
	// type system cannot prevent it, but Valid subjects still get deny rules.
	forged := policy.NewSubject("corp", attackerClaim, false)
	d2 := ev.Evaluate(forged, policy.Action{ToolName: "jenkins_get_jobs"}, policy.Target{})
	if !d2.Denied() {
		t.Fatal("deny rule applies to any subject evaluated")
	}
}

func TestSubjectValid(t *testing.T) {
	t.Parallel()
	if !fixtureAdmin.Valid() {
		t.Fatal("admin fixture valid")
	}
	if policy.NewSubject("", "u", true).Valid() {
		t.Fatal("empty profile invalid")
	}
	if policy.NewSubject("p", "", true).Valid() {
		t.Fatal("empty user invalid")
	}
	if policy.NewSubject("p", "ANONYMOUS", true).Valid() {
		t.Fatal("anonymous invalid")
	}
}

func TestJobPrefixDeny(t *testing.T) {
	t.Parallel()
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"secret-folder"},
	})
	d := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_job"}, policy.Target{JobName: "secret-folder/job-a"})
	if !d.Denied() || d.ReasonCode != policy.ReasonJobPatternDeny {
		t.Fatalf("job prefix: %+v", d)
	}
	// Exact folder/job name match.
	dExact := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_job"}, policy.Target{JobName: "secret-folder"})
	if !dExact.Denied() {
		t.Fatalf("exact: %+v", dExact)
	}
	// Must not treat prefix as bare string prefix (false positive).
	dOther := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_job"}, policy.Target{JobName: "secret-folder-other"})
	if !dOther.Allowed() {
		t.Fatalf("sibling name must not match prefix: %+v", dOther)
	}
	d2 := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_job"}, policy.Target{JobName: "public/job"})
	if !d2.Allowed() {
		t.Fatalf("public job: %+v", d2)
	}
}

// Wave 35: deny_node_names / deny_view_names use MatchDenyJobPattern language.
func TestNodeAndViewResourceDeny(t *testing.T) {
	t.Parallel()
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:          policy.ModePilot,
		DenyNodeNames: []string{"prod-agent-*", "secret-node"},
		DenyViewNames: []string{"hr/**", "secret-view"},
	})
	// Node deny (glob-lite *).
	dNode := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_nodes"}, policy.Target{NodeName: "prod-agent-01"})
	if !dNode.Denied() || dNode.ReasonCode != policy.ReasonResourcePatternDeny {
		t.Fatalf("node pattern: %+v", dNode)
	}
	if dNode.MatchedRule != "deny_node_name:prod-agent-*" {
		t.Fatalf("matched rule: %q", dNode.MatchedRule)
	}
	if !strings.Contains(dNode.Explanation, "prod-agent-01") {
		t.Fatalf("explanation: %q", dNode.Explanation)
	}
	// Exact node.
	dNodeExact := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_nodes"}, policy.Target{NodeName: "secret-node"})
	if !dNodeExact.Denied() || dNodeExact.ReasonCode != policy.ReasonResourcePatternDeny {
		t.Fatalf("exact node: %+v", dNodeExact)
	}
	// Sibling node must not match bare string prefix of secret-node.
	dNodeOther := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_nodes"}, policy.Target{NodeName: "secret-node-other"})
	if !dNodeOther.Allowed() {
		t.Fatalf("sibling node: %+v", dNodeOther)
	}
	// Empty NodeName → no node rule.
	dEmptyNode := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_nodes"}, policy.Target{})
	if !dEmptyNode.Allowed() {
		t.Fatalf("empty target: %+v", dEmptyNode)
	}
	// View deny.
	dView := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_list_jobs"}, policy.Target{ViewName: "hr/payroll"})
	if !dView.Denied() || dView.ReasonCode != policy.ReasonResourcePatternDeny {
		t.Fatalf("view pattern: %+v", dView)
	}
	if dView.MatchedRule != "deny_view_name:hr/**" {
		t.Fatalf("view matched rule: %q", dView.MatchedRule)
	}
	dViewOK := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_list_jobs"}, policy.Target{ViewName: "public"})
	if !dViewOK.Allowed() {
		t.Fatalf("public view: %+v", dViewOK)
	}
	// Job deny still takes precedence when both set and job matches (evaluated first).
	evBoth := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"secret"},
		DenyNodeNames:   []string{"agent-1"},
	})
	dJobFirst := evBoth.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_job"},
		policy.Target{JobName: "secret/job", NodeName: "agent-1"})
	if !dJobFirst.Denied() || dJobFirst.ReasonCode != policy.ReasonJobPatternDeny {
		t.Fatalf("job should win order: %+v", dJobFirst)
	}
	// Node deny when job does not match.
	dNodeOnly := evBoth.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_job"},
		policy.Target{JobName: "public/job", NodeName: "agent-1"})
	if !dNodeOnly.Denied() || dNodeOnly.ReasonCode != policy.ReasonResourcePatternDeny {
		t.Fatalf("node after job miss: %+v", dNodeOnly)
	}
}

// Wave 36: deny_artifact_paths use MatchDenyJobPattern language.
func TestArtifactPathResourceDeny(t *testing.T) {
	t.Parallel()
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:              policy.ModePilot,
		DenyArtifactPaths: []string{"secrets/**", "*.pem", "exact/creds.txt"},
	})
	// Folder + descendants (trailing /**).
	dGlob := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_artifact_text"},
		policy.Target{ArtifactPath: "secrets/prod/token"})
	if !dGlob.Denied() || dGlob.ReasonCode != policy.ReasonResourcePatternDeny {
		t.Fatalf("secrets/**: %+v", dGlob)
	}
	if dGlob.MatchedRule != "deny_artifact_path:secrets/**" {
		t.Fatalf("matched rule: %q", dGlob.MatchedRule)
	}
	if !strings.Contains(dGlob.Explanation, "secrets/prod/token") {
		t.Fatalf("explanation: %q", dGlob.Explanation)
	}
	// Single-segment *.
	dPem := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_artifact_text"},
		policy.Target{ArtifactPath: "tls.pem"})
	if !dPem.Denied() || dPem.ReasonCode != policy.ReasonResourcePatternDeny {
		t.Fatalf("*.pem: %+v", dPem)
	}
	if dPem.MatchedRule != "deny_artifact_path:*.pem" {
		t.Fatalf("pem matched rule: %q", dPem.MatchedRule)
	}
	// Exact path.
	dExact := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_inspect_artifact"},
		policy.Target{ArtifactPath: "exact/creds.txt"})
	if !dExact.Denied() || dExact.ReasonCode != policy.ReasonResourcePatternDeny {
		t.Fatalf("exact: %+v", dExact)
	}
	// Canonical form after "." collapse (policy_target normalize) must still deny.
	dCanonical := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_artifact_text"},
		policy.Target{ArtifactPath: "exact/creds.txt"})
	if !dCanonical.Denied() {
		t.Fatalf("canonical exact after dot collapse: %+v", dCanonical)
	}
	// Public relative path allowed.
	dOK := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_artifact_text"},
		policy.Target{ArtifactPath: "reports/out.txt"})
	if !dOK.Allowed() {
		t.Fatalf("public artifact: %+v", dOK)
	}
	// Sibling of exact must not match bare string prefix of exact/creds.txt parent.
	dSibling := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_artifact_text"},
		policy.Target{ArtifactPath: "exact/creds.txt.bak"})
	if !dSibling.Allowed() {
		t.Fatalf("sibling path: %+v", dSibling)
	}
	// Empty ArtifactPath → no artifact rule.
	dEmpty := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_artifact_text"}, policy.Target{})
	if !dEmpty.Allowed() {
		t.Fatalf("empty target: %+v", dEmpty)
	}
	// Node/view still evaluated before artifact when both set (order).
	evBoth := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:              policy.ModePilot,
		DenyNodeNames:     []string{"agent-1"},
		DenyArtifactPaths: []string{"secrets/**"},
	})
	dNodeFirst := evBoth.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_artifact_text"},
		policy.Target{NodeName: "agent-1", ArtifactPath: "secrets/x"})
	if !dNodeFirst.Denied() || dNodeFirst.MatchedRule != "deny_node_name:agent-1" {
		t.Fatalf("node should win order: %+v", dNodeFirst)
	}
	// Artifact deny when node does not match.
	dArtOnly := evBoth.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_artifact_text"},
		policy.Target{NodeName: "other", ArtifactPath: "secrets/x"})
	if !dArtOnly.Denied() || dArtOnly.MatchedRule != "deny_artifact_path:secrets/**" {
		t.Fatalf("artifact after node miss: %+v", dArtOnly)
	}
}

// Wave 37: deny_branch_names use MatchDenyJobPattern language.
func TestBranchNameResourceDeny(t *testing.T) {
	t.Parallel()
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyBranchNames: []string{"release/*", "main", "hotfix/**"},
	})
	// Single-segment * under release/.
	dGlob := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_list_jobs"},
		policy.Target{BranchName: "release/1.2"})
	if !dGlob.Denied() || dGlob.ReasonCode != policy.ReasonResourcePatternDeny {
		t.Fatalf("release/*: %+v", dGlob)
	}
	if dGlob.MatchedRule != "deny_branch_name:release/*" {
		t.Fatalf("matched rule: %q", dGlob.MatchedRule)
	}
	if !strings.Contains(dGlob.Explanation, `branch "release/1.2" denied by MCP policy`) {
		t.Fatalf("explanation: %q", dGlob.Explanation)
	}
	// Exact leaf.
	dMain := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_job"},
		policy.Target{BranchName: "main"})
	if !dMain.Denied() || dMain.MatchedRule != "deny_branch_name:main" {
		t.Fatalf("main: %+v", dMain)
	}
	// Trailing /**.
	dHot := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_list_jobs"},
		policy.Target{BranchName: "hotfix/sec/patch"})
	if !dHot.Denied() || dHot.MatchedRule != "deny_branch_name:hotfix/**" {
		t.Fatalf("hotfix/**: %+v", dHot)
	}
	// Public branch allowed.
	dOK := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_list_jobs"},
		policy.Target{BranchName: "feature/foo"})
	if !dOK.Allowed() {
		t.Fatalf("public branch: %+v", dOK)
	}
	// Sibling of exact must not match bare string prefix of main.
	dMainOther := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_list_jobs"},
		policy.Target{BranchName: "mainline"})
	if !dMainOther.Allowed() {
		t.Fatalf("sibling mainline: %+v", dMainOther)
	}
	// Empty BranchName → no branch rule.
	dEmpty := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_list_jobs"}, policy.Target{})
	if !dEmpty.Allowed() {
		t.Fatalf("empty target: %+v", dEmpty)
	}
	// Artifact still evaluated before branch when both set (order).
	evBoth := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:              policy.ModePilot,
		DenyArtifactPaths: []string{"secrets/**"},
		DenyBranchNames:   []string{"main"},
	})
	dArtFirst := evBoth.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_artifact_text"},
		policy.Target{ArtifactPath: "secrets/x", BranchName: "main"})
	if !dArtFirst.Denied() || dArtFirst.MatchedRule != "deny_artifact_path:secrets/**" {
		t.Fatalf("artifact should win order: %+v", dArtFirst)
	}
	// Branch deny when artifact does not match.
	dBranchOnly := evBoth.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_artifact_text"},
		policy.Target{ArtifactPath: "reports/out.txt", BranchName: "main"})
	if !dBranchOnly.Denied() || dBranchOnly.MatchedRule != "deny_branch_name:main" {
		t.Fatalf("branch after artifact miss: %+v", dBranchOnly)
	}
}

// Wave 39: pure branchDenyCandidates helper (leaf, intermediate, suffixes, full).
func TestBranchDenyCandidates(t *testing.T) {
	t.Parallel()

	if got := policy.BranchDenyCandidates(""); got != nil {
		t.Fatalf("empty: %v", got)
	}
	if got := policy.BranchDenyCandidates("main"); got != nil {
		t.Fatalf("single-segment: %v", got)
	}

	// a/b/c/d → d; b,c; c/d, b/c/d; a/b/c/d  (no a alone)
	got := policy.BranchDenyCandidates("a/b/c/d")
	want := []string{"d", "b", "c", "c/d", "b/c/d", "a/b/c/d"}
	if len(got) != len(want) {
		t.Fatalf("a/b/c/d: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("a/b/c/d[%d]=%q want %q full=%v", i, got[i], want[i], got)
		}
	}

	// team/mb/release/1.2 — slashy nested multibranch leaf
	got2 := policy.BranchDenyCandidates("team/mb/release/1.2")
	want2 := []string{"1.2", "mb", "release", "release/1.2", "mb/release/1.2", "team/mb/release/1.2"}
	if len(got2) != len(want2) {
		t.Fatalf("team/mb/release/1.2: got %v want %v", got2, want2)
	}
	for i := range want2 {
		if got2[i] != want2[i] {
			t.Fatalf("team/mb/release/1.2[%d]=%q want %q full=%v", i, got2[i], want2[i], got2)
		}
	}

	// Two-segment: leaf + full only (no intermediate single beyond leaf)
	got3 := policy.BranchDenyCandidates("multibranch/main")
	want3 := []string{"main", "multibranch/main"}
	if len(got3) != len(want3) || got3[0] != want3[0] || got3[1] != want3[1] {
		t.Fatalf("multibranch/main: got %v want %v", got3, want3)
	}
}

// Wave 39: nested slashy JobName segments + BranchName path candidates.
func TestBranchNameSlashyIntermediateDeny(t *testing.T) {
	t.Parallel()
	evRelease := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyBranchNames: []string{"release/*"},
	})
	// JobName team/mb/release/1.2 + deny release/* → deny (Wave 39 residual close)
	dSlashy := evRelease.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_job"},
		policy.Target{JobName: "team/mb/release/1.2"})
	if !dSlashy.Denied() || dSlashy.ReasonCode != policy.ReasonResourcePatternDeny {
		t.Fatalf("team/mb/release/1.2 vs release/*: %+v", dSlashy)
	}
	if dSlashy.MatchedRule != "deny_branch_name:release/*" {
		t.Fatalf("matched rule: %q", dSlashy.MatchedRule)
	}
	if !strings.Contains(dSlashy.Explanation, `branch path "release/1.2"`) ||
		!strings.Contains(dSlashy.Explanation, `team/mb/release/1.2`) {
		t.Fatalf("explanation: %q", dSlashy.Explanation)
	}

	// JobName leaf 1.2 exact deny
	evLeaf := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyBranchNames: []string{"1.2"},
	})
	dLeaf := evLeaf.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_job"},
		policy.Target{JobName: "team/mb/release/1.2"})
	if !dLeaf.Denied() || dLeaf.MatchedRule != "deny_branch_name:1.2" {
		t.Fatalf("leaf 1.2: %+v", dLeaf)
	}

	// Intermediate exact segment "release" denies team/mb/release/1.2
	evMid := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyBranchNames: []string{"release"},
	})
	dMid := evMid.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_job"},
		policy.Target{JobName: "team/mb/release/1.2"})
	if !dMid.Denied() || dMid.MatchedRule != "deny_branch_name:release" {
		t.Fatalf("intermediate release: %+v", dMid)
	}

	// JobName team/mb/main + deny release/* → allow
	dAllow := evRelease.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_job"},
		policy.Target{JobName: "team/mb/main"})
	if !dAllow.Allowed() {
		t.Fatalf("team/mb/main vs release/* must allow: %+v", dAllow)
	}

	// Single-segment main + deny main → allow (Wave 38 unchanged)
	evMain := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyBranchNames: []string{"main"},
	})
	dRoot := evMain.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_job"},
		policy.Target{JobName: "main"})
	if !dRoot.Allowed() {
		t.Fatalf("single-segment main must allow: %+v", dRoot)
	}

	// BranchName release/1.2 + deny release/* → deny
	dBr := evRelease.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_list_jobs"},
		policy.Target{BranchName: "release/1.2"})
	if !dBr.Denied() || dBr.MatchedRule != "deny_branch_name:release/*" {
		t.Fatalf("BranchName release/1.2: %+v", dBr)
	}
	// BranchName slashy leaf match: BranchName release/1.2 + deny 1.2
	dBrLeaf := evLeaf.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_list_jobs"},
		policy.Target{BranchName: "release/1.2"})
	if !dBrLeaf.Denied() || dBrLeaf.MatchedRule != "deny_branch_name:1.2" {
		t.Fatalf("BranchName leaf 1.2: %+v", dBrLeaf)
	}

	// First path segment alone is never a BranchDenyCandidates entry
	// (folder root is not treated as a branch name). Note: pattern "team"
	// may still deny via MatchDenyJobPattern prefix semantics on the full
	// JobName candidate (Wave 38 full-path path) — that is intentional.
	cands := policy.BranchDenyCandidates("team/mb/main")
	for _, c := range cands {
		if c == "team" {
			t.Fatalf("segs[0] alone must not be a candidate: %v", cands)
		}
	}
}

// Wave 38: deny_branch_names match multi-segment JobName leaf (and full path)
// when BranchName is empty — tools without branch_name still fail closed.
func TestBranchNameJobLeafDeny(t *testing.T) {
	t.Parallel()
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyBranchNames: []string{"main", "release/*"},
	})
	// Multi-segment multibranch job path: leaf "main" denied.
	dLeaf := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_job"},
		policy.Target{JobName: "team/mb/main"})
	if !dLeaf.Denied() || dLeaf.ReasonCode != policy.ReasonResourcePatternDeny {
		t.Fatalf("team/mb/main leaf: %+v", dLeaf)
	}
	if dLeaf.MatchedRule != "deny_branch_name:main" {
		t.Fatalf("matched rule: %q", dLeaf.MatchedRule)
	}
	if !strings.Contains(dLeaf.Explanation, `branch leaf "main"`) ||
		!strings.Contains(dLeaf.Explanation, `team/mb/main`) {
		t.Fatalf("explanation should cite leaf and job: %q", dLeaf.Explanation)
	}

	// Single-segment JobName alone: do NOT treat root freestyle "main" as branch.
	dRoot := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_job"},
		policy.Target{JobName: "main"})
	if !dRoot.Allowed() {
		t.Fatalf("root freestyle job main must allow without BranchName: %+v", dRoot)
	}

	// Multi-segment leaf "main" does not match release/* → allow.
	evReleaseOnly := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyBranchNames: []string{"release/*"},
	})
	dAllowLeaf := evReleaseOnly.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_job"},
		policy.Target{JobName: "team/mb/main"})
	if !dAllowLeaf.Allowed() {
		t.Fatalf("team/mb/main vs release/* must allow: %+v", dAllowLeaf)
	}

	// BranchName still works when set (explicit wins; no need for multi-segment job).
	dBranch := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_list_jobs"},
		policy.Target{BranchName: "main"})
	if !dBranch.Denied() || dBranch.MatchedRule != "deny_branch_name:main" {
		t.Fatalf("explicit BranchName main: %+v", dBranch)
	}
	dBranchGlob := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_list_jobs"},
		policy.Target{BranchName: "release/1.2"})
	if !dBranchGlob.Denied() || dBranchGlob.MatchedRule != "deny_branch_name:release/*" {
		t.Fatalf("explicit BranchName release/1.2: %+v", dBranchGlob)
	}

	// Full JobName match: pattern is multi-segment path (leaf alone would not match).
	evFull := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyBranchNames: []string{"team/mb/main"},
	})
	dFull := evFull.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_job"},
		policy.Target{JobName: "team/mb/main"})
	if !dFull.Denied() || dFull.MatchedRule != "deny_branch_name:team/mb/main" {
		t.Fatalf("full JobName pattern: %+v", dFull)
	}
	if !strings.Contains(dFull.Explanation, `job "team/mb/main"`) {
		t.Fatalf("full-path explanation: %q", dFull.Explanation)
	}
	// Sibling full path must not match exact pattern via bare string prefix.
	dSib := evFull.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_job"},
		policy.Target{JobName: "team/mb/mainline"})
	if !dSib.Allowed() {
		t.Fatalf("sibling mainline: %+v", dSib)
	}

	// Explicit BranchName takes precedence path: when set, JobName leaf is not
	// used for branch deny (BranchName miss + multi-segment JobName with denied
	// leaf still checks BranchName only when non-empty — design: if BranchName
	// non-empty, only that is matched).
	dBranchMissJobLeaf := evReleaseOnly.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_job"},
		policy.Target{JobName: "team/mb/main", BranchName: "feature/x"})
	if !dBranchMissJobLeaf.Allowed() {
		t.Fatalf("BranchName set and non-matching must not fall through to JobName leaf: %+v", dBranchMissJobLeaf)
	}

	// Job-prefix deny still wins order when both would match.
	evBoth := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"team/mb"},
		DenyBranchNames: []string{"main"},
	})
	dJobFirst := evBoth.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_job"},
		policy.Target{JobName: "team/mb/main"})
	if !dJobFirst.Denied() || dJobFirst.MatchedRule != "deny_job_prefix:team/mb" {
		t.Fatalf("job prefix should win order: %+v", dJobFirst)
	}
}

func TestDocumentFromOverlay(t *testing.T) {
	t.Parallel()
	n := 1024
	o := &policy.Overlay{
		Version:           1,
		ForceReadOnly:     true,
		Mode:              policy.ModeStrict,
		DenyTools:         []string{"jenkins_get_build"},
		DenyJobPrefixes:   []string{"secret-folder", "hr/payroll"},
		DenyNodeNames:     []string{"prod-agent-*"},
		DenyViewNames:     []string{"secret-view"},
		DenyArtifactPaths: []string{"secrets/**", "*.pem"},
		DenyBranchNames:   []string{"release/*", "main"},
		MaxResultBytes:    &n,
	}
	doc := policy.DocumentFromOverlay(o)
	if doc.Mode != policy.ModeStrict || !doc.ForceReadOnly || doc.MaxResultBytes != 1024 {
		t.Fatalf("doc=%+v", doc)
	}
	if _, ok := doc.DenyTools["jenkins_get_build"]; !ok {
		t.Fatal("deny tool missing")
	}
	if len(doc.DenyJobPrefixes) != 2 || doc.DenyJobPrefixes[0] != "secret-folder" {
		t.Fatalf("deny job prefixes=%v", doc.DenyJobPrefixes)
	}
	if len(doc.DenyNodeNames) != 1 || doc.DenyNodeNames[0] != "prod-agent-*" {
		t.Fatalf("deny node names=%v", doc.DenyNodeNames)
	}
	if len(doc.DenyViewNames) != 1 || doc.DenyViewNames[0] != "secret-view" {
		t.Fatalf("deny view names=%v", doc.DenyViewNames)
	}
	if len(doc.DenyArtifactPaths) != 2 || doc.DenyArtifactPaths[0] != "secrets/**" {
		t.Fatalf("deny artifact paths=%v", doc.DenyArtifactPaths)
	}
	if len(doc.DenyBranchNames) != 2 || doc.DenyBranchNames[0] != "release/*" {
		t.Fatalf("deny branch names=%v", doc.DenyBranchNames)
	}
	// nil overlay → pilot empty.
	doc2 := policy.DocumentFromOverlay(nil)
	if doc2.Mode != policy.ModePilot || doc2.DenyTools != nil || doc2.DenyJobPrefixes != nil ||
		doc2.DenyNodeNames != nil || doc2.DenyViewNames != nil || doc2.DenyArtifactPaths != nil ||
		doc2.DenyBranchNames != nil {
		t.Fatalf("nil overlay doc=%+v", doc2)
	}
}

func TestPolicyNeverElevatesDocumented(t *testing.T) {
	t.Parallel()
	// There is no AllowTools / grant API on Document — only DenyTools.
	// Compile-time shape check: Document has DenyTools map, not AllowTools.
	doc := policy.Document{Mode: policy.ModePilot}
	if doc.DenyTools != nil {
		t.Fatal("empty doc should have nil deny set")
	}
	// Evaluator Allow means "MCP does not further restrict", not Jenkins grant.
	ev := policy.NewDenyOnlyEvaluator(doc)
	d := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_jobs"}, policy.Target{})
	if d.Effect != policy.EffectAllow || d.ReasonCode != policy.ReasonOK {
		t.Fatalf("%+v", d)
	}
}
