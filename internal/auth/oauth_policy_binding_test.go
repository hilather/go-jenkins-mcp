package auth_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/auth"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

// OAUTH-006: map extracted groups into policy.Subject; deny_tools still applies;
// force_read_only cannot be weakened by claims; identity A cannot act as B;
// adding deny never increases access; revocation fails closed.

func TestOAuthPolicyBinding_DenyToolsStillApplies(t *testing.T) {
	t.Parallel()
	// Groups claim includes "admins" — must not elevate past deny_tools.
	subj := policy.NewSubject("corp", "alice", true).
		WithExternal("entra-alice").
		WithGateway("tenant-1", "wl", []string{"admins", "ops"})

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode: policy.ModePilot,
		DenyTools: map[string]struct{}{
			"jenkins_get_build_logs": {},
		},
	})
	d := ev.Evaluate(subj, policy.Action{
		ToolName: "jenkins_get_build_logs",
		Class:    policy.EffectRead,
	}, policy.Target{})
	if !d.Denied() {
		t.Fatal("deny_tools must apply regardless of group claims")
	}

	// Allowed tool still allowed under pilot.
	d2 := ev.Evaluate(subj, policy.Action{ToolName: "jenkins_get_jobs", Class: policy.EffectRead}, policy.Target{})
	if !d2.Allowed() {
		t.Fatalf("get_jobs: %+v", d2)
	}
}

func TestOAuthPolicyBinding_ForceReadOnlyNotWeakenedByClaims(t *testing.T) {
	t.Parallel()
	// Even with "mutation-allowed" style groups, enterprise force_read_only wins.
	subj := policy.NewSubject("corp", "admin", true).
		WithGateway("t", "w", []string{"jenkins-admins", "mutation-operators"})

	gate := policy.NewReadOnlyGate(policy.Inputs{
		Force:          policy.StaticForce{Force: true, Present: true},
		AllowMutations: true, // would clear builtin RO if force absent
	})
	if !gate.Effective() {
		t.Fatal("force_read_only must remain effective")
	}
	if err := policy.CheckToolAccess(context.Background(), gate, nil, subj, "jenkins_build_job", policy.EffectMutate); err == nil {
		t.Fatal("mutation must be denied under force_read_only")
	} else if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code %v err %v", apperr.CodeOf(err), err)
	}
}

func TestOAuthPolicyBinding_IdentityACannotAuthorizeAsB(t *testing.T) {
	t.Parallel()
	claimsA := map[string]any{"groups": []string{"team-a-only"}, "sub": "sub-a"}
	claimsB := map[string]any{"groups": []string{"team-b-only"}, "sub": "sub-b"}

	ga, err := auth.ExtractGroups(claimsA, auth.DefaultGroupClaimConfig())
	if err != nil {
		t.Fatal(err)
	}
	gb, err := auth.ExtractGroups(claimsB, auth.DefaultGroupClaimConfig())
	if err != nil {
		t.Fatal(err)
	}

	subjA := policy.NewSubject("corp", "alice", true).WithExternal("sub-a").WithGateway("t", "", ga.Groups)
	subjB := policy.NewSubject("corp", "bob", true).WithExternal("sub-b").WithGateway("t", "", gb.Groups)

	// Fingerprints must differ — A cannot present as B.
	fpA := auth.IdentityFingerprint("sub-a", "t", "alice", ga.Groups)
	fpB := auth.IdentityFingerprint("sub-b", "t", "bob", gb.Groups)
	if fpA == fpB {
		t.Fatal("distinct identities must have distinct fingerprints")
	}

	guard := auth.NewSessionGuard(fpA)
	if err := guard.CheckIdentity(fpA); err != nil {
		t.Fatal(err)
	}
	// Attempt to use B's identity on A's session fails closed.
	if err := guard.CheckIdentity(fpB); err == nil {
		t.Fatal("identity A session must not accept B fingerprint")
	}
	// Subsequent tool path also blocked (session revoked on mismatch).
	if err := guard.Check(); err == nil {
		t.Fatal("stale/mismatched session must fail closed")
	}

	// Subjects remain distinct for policy evaluation.
	if subjA.JenkinsUserID == subjB.JenkinsUserID || subjA.ExternalSubject == subjB.ExternalSubject {
		t.Fatal("subjects collapsed")
	}
	if len(subjA.Groups) != 1 || subjA.Groups[0] != "team-a-only" {
		t.Fatalf("A groups: %v", subjA.Groups)
	}
	if len(subjB.Groups) != 1 || subjB.Groups[0] != "team-b-only" {
		t.Fatalf("B groups: %v", subjB.Groups)
	}
}

func TestOAuthPolicyBinding_AddingDenyNeverIncreasesAccess(t *testing.T) {
	t.Parallel()
	subj := policy.NewSubject("corp", "dev", true).WithGateway("t", "", []string{"developers"})

	base := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	tools := []string{"jenkins_get_jobs", "jenkins_get_job", "jenkins_get_build_logs", "jenkins_get_build"}

	allowedBefore := map[string]bool{}
	for _, tool := range tools {
		d := base.Evaluate(subj, policy.Action{ToolName: tool, Class: policy.EffectRead}, policy.Target{})
		allowedBefore[tool] = d.Allowed()
	}

	// Add deny for get_build_logs — access can only shrink.
	restricted := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode: policy.ModePilot,
		DenyTools: map[string]struct{}{
			"jenkins_get_build_logs": {},
		},
	})
	for _, tool := range tools {
		d := restricted.Evaluate(subj, policy.Action{ToolName: tool, Class: policy.EffectRead}, policy.Target{})
		if d.Allowed() && !allowedBefore[tool] {
			t.Fatalf("tool %s allowed after deny but was denied before (non-monotonic)", tool)
		}
		if tool == "jenkins_get_build_logs" && d.Allowed() {
			t.Fatal("denied tool still allowed")
		}
	}

	// Add another deny — still monotonic.
	more := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode: policy.ModePilot,
		DenyTools: map[string]struct{}{
			"jenkins_get_build_logs": {},
			"jenkins_get_build":      {},
		},
	})
	for _, tool := range tools {
		dRest := restricted.Evaluate(subj, policy.Action{ToolName: tool, Class: policy.EffectRead}, policy.Target{})
		dMore := more.Evaluate(subj, policy.Action{ToolName: tool, Class: policy.EffectRead}, policy.Target{})
		if dMore.Allowed() && !dRest.Allowed() {
			t.Fatalf("non-monotonic at %s", tool)
		}
	}
}

func TestOAuthRevocation_ToolPathFailsClosed(t *testing.T) {
	t.Parallel()
	// Simulate: authenticated session with groups → revoke → tool path blocked.
	claims := map[string]any{"sub": "sub-a", "groups": []string{"ops"}}
	gr, err := auth.ExtractGroups(claims, auth.DefaultGroupClaimConfig())
	if err != nil {
		t.Fatal(err)
	}
	subj := policy.NewSubject("corp", "alice", true).WithExternal("sub-a").WithGateway("t", "", gr.Groups)
	fp := auth.IdentityFingerprint("sub-a", "t", "alice", gr.Groups)
	guard := auth.NewSessionGuard(fp)

	ev := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	// Pre-revocation: policy allows + guard allows.
	if err := guard.Check(); err != nil {
		t.Fatal(err)
	}
	if d := ev.Evaluate(subj, policy.Action{ToolName: "jenkins_get_jobs", Class: policy.EffectRead}, policy.Target{}); !d.Allowed() {
		t.Fatalf("%+v", d)
	}

	// Token marked revoked: subsequent tool path fails closed (cannot use stale session).
	guard.MarkRevoked()
	if err := guard.Check(); err == nil {
		t.Fatal("expected revoke fail closed")
	} else if apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("code %v", apperr.CodeOf(err))
	}
	// Policy subject object may still evaluate in isolation, but tool path must
	// check guard first — simulate combined PEP.
	if err := toolPath(guard, ev, subj, "jenkins_get_jobs"); err == nil {
		t.Fatal("combined tool path must fail after revoke")
	}

	// Refresh failure path.
	guard2 := auth.NewSessionGuard(fp)
	guard2.MarkRefreshFailed()
	if err := toolPath(guard2, ev, subj, "jenkins_get_jobs"); err == nil {
		t.Fatal("refresh failure must fail closed")
	}
	err2 := toolPath(guard2, ev, subj, "jenkins_get_jobs")
	if apperr.CodeOf(err2) != apperr.CodeAuthentication {
		t.Fatalf("expected auth failure on refresh: %v", err2)
	}
	if !strings.Contains(err2.Error(), "refresh") {
		t.Fatalf("expected refresh wording: %v", err2)
	}
}

func TestOAuthGroupOverage_CannotSilentlyBroaden(t *testing.T) {
	t.Parallel()
	// Even with 100 "admin-like" groups, only MaxStoredGroups are stored;
	// deny_tools still applies to the bound subject.
	groups := make([]string, 100)
	for i := range groups {
		groups[i] = "elevated-" + itoa(i)
	}
	res, err := auth.BoundGroups(groups, auth.MaxStoredGroups, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || len(res.Groups) != auth.MaxStoredGroups {
		t.Fatalf("%+v", res)
	}
	subj := policy.NewSubject("corp", "alice", true).WithGateway("t", "", res.Groups)
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:      policy.ModePilot,
		DenyTools: map[string]struct{}{"jenkins_get_job": {}},
	})
	if d := ev.Evaluate(subj, policy.Action{ToolName: "jenkins_get_job", Class: policy.EffectRead}, policy.Target{}); !d.Denied() {
		t.Fatal("overage groups must not bypass deny_tools")
	}
	if res.ResidualNote == "" {
		t.Fatal("expected residual note on truncate")
	}
}

func toolPath(g *auth.SessionGuard, ev policy.PolicyEvaluator, subj policy.Subject, tool string) error {
	if err := g.Check(); err != nil {
		return err
	}
	return ev.Evaluate(subj, policy.Action{ToolName: tool, Class: policy.EffectRead}, policy.Target{}).Err()
}
