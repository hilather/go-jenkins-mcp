package policy_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/contracts"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

func pol006Subject(user string, groups ...string) policy.Subject {
	s := policy.NewSubject(contracts.ProfileID("corp"), user, true)
	if len(groups) > 0 {
		s = s.WithGateway("", "", groups)
	}
	return s
}

func TestPOL006_UserOnlyDeny(t *testing.T) {
	t.Parallel()
	ov := &policy.Overlay{
		Version: 1,
		Mode:    policy.ModePilot,
		Subjects: &policy.SubjectBindings{
			Users: []policy.UserBinding{{
				JenkinsUserID: "alice",
				DenyTools:     []string{"jenkins_get_build_logs"},
			}},
		},
	}
	if err := ov.Validate(); err != nil {
		t.Fatal(err)
	}
	ev := policy.NewDenyOnlyFromOverlay(ov)
	alice := pol006Subject("alice")
	bob := pol006Subject("bob")
	act := policy.Action{ToolName: "jenkins_get_build_logs", Class: policy.EffectRead}

	if d := ev.Evaluate(alice, act, policy.Target{}); d.Allowed() {
		t.Fatalf("alice should be denied: %+v", d)
	}
	if d := ev.Evaluate(bob, act, policy.Target{}); d.Denied() {
		t.Fatalf("bob should be allowed: %+v", d)
	}
}

func TestPOL006_GroupOnlyDeny(t *testing.T) {
	t.Parallel()
	ov := &policy.Overlay{
		Version: 1,
		Subjects: &policy.SubjectBindings{
			Groups: []policy.GroupBinding{{
				GroupID:   "contractors",
				DenyTools: []string{"jenkins_list_jobs"},
			}},
		},
	}
	if err := ov.Validate(); err != nil {
		t.Fatal(err)
	}
	ev := policy.NewDenyOnlyFromOverlay(ov)
	act := policy.Action{ToolName: "jenkins_list_jobs", Class: policy.EffectRead}

	contractor := pol006Subject("carol", "contractors", "readers")
	employee := pol006Subject("dave", "employees")
	nogroups := pol006Subject("erin")

	if d := ev.Evaluate(contractor, act, policy.Target{}); d.Allowed() {
		t.Fatalf("contractor should be denied: %+v", d)
	}
	if d := ev.Evaluate(employee, act, policy.Target{}); d.Denied() {
		t.Fatalf("employee without contractors group should be allowed: %+v", d)
	}
	if d := ev.Evaluate(nogroups, act, policy.Target{}); d.Denied() {
		t.Fatalf("empty groups must not invent membership: %+v", d)
	}
}

func TestPOL006_UserAndGroupBothMostRestrictive(t *testing.T) {
	t.Parallel()
	ov := &policy.Overlay{
		Version:   1,
		DenyTools: []string{"jenkins_get_queue_item"}, // global
		Subjects: &policy.SubjectBindings{
			Users: []policy.UserBinding{{
				JenkinsUserID:   "alice",
				DenyTools:       []string{"jenkins_get_build_logs"},
				DenyJobPrefixes: []string{"secret/**"},
			}},
			Groups: []policy.GroupBinding{{
				GroupID:   "restricted",
				DenyTools: []string{"jenkins_list_artifacts"},
			}},
		},
	}
	if err := ov.Validate(); err != nil {
		t.Fatal(err)
	}
	ev := policy.NewDenyOnlyFromOverlay(ov)
	// alice in restricted: global + user + group denials
	alice := pol006Subject("alice", "restricted")
	for _, tool := range []string{
		"jenkins_get_queue_item",
		"jenkins_get_build_logs",
		"jenkins_list_artifacts",
	} {
		d := ev.Evaluate(alice, policy.Action{ToolName: tool, Class: policy.EffectRead}, policy.Target{})
		if d.Allowed() {
			t.Fatalf("alice should be denied %s: %+v", tool, d)
		}
	}
	// job pattern from user binding
	d := ev.Evaluate(alice, policy.Action{ToolName: "jenkins_get_job", Class: policy.EffectRead},
		policy.Target{JobName: "secret/payroll"})
	if d.Allowed() {
		t.Fatalf("alice job deny: %+v", d)
	}
	// bob in restricted: only global + group
	bob := pol006Subject("bob", "restricted")
	if d := ev.Evaluate(bob, policy.Action{ToolName: "jenkins_get_build_logs", Class: policy.EffectRead}, policy.Target{}); d.Denied() {
		t.Fatalf("bob should not get alice user deny: %+v", d)
	}
	if d := ev.Evaluate(bob, policy.Action{ToolName: "jenkins_list_artifacts", Class: policy.EffectRead}, policy.Target{}); d.Allowed() {
		t.Fatalf("bob group deny: %+v", d)
	}
}

func TestPOL006_MultiGroupMostRestrictiveUnion(t *testing.T) {
	t.Parallel()
	ov := &policy.Overlay{
		Version: 1,
		Subjects: &policy.SubjectBindings{
			Groups: []policy.GroupBinding{
				{GroupID: "g1", DenyTools: []string{"jenkins_get_build_logs"}},
				{GroupID: "g2", DenyTools: []string{"jenkins_list_jobs"}},
			},
		},
	}
	if err := ov.Validate(); err != nil {
		t.Fatal(err)
	}
	ev := policy.NewDenyOnlyFromOverlay(ov)
	// Member of both groups: both denials apply
	both := pol006Subject("u1", "g1", "g2")
	if d := ev.Evaluate(both, policy.Action{ToolName: "jenkins_get_build_logs", Class: policy.EffectRead}, policy.Target{}); d.Allowed() {
		t.Fatal("g1 deny missing")
	}
	if d := ev.Evaluate(both, policy.Action{ToolName: "jenkins_list_jobs", Class: policy.EffectRead}, policy.Target{}); d.Allowed() {
		t.Fatal("g2 deny missing")
	}
	// Membership change: drop g2 → list_jobs allowed again
	onlyG1 := pol006Subject("u1", "g1")
	if d := ev.Evaluate(onlyG1, policy.Action{ToolName: "jenkins_list_jobs", Class: policy.EffectRead}, policy.Target{}); d.Denied() {
		t.Fatalf("after leaving g2, list_jobs should allow: %+v", d)
	}
}

func TestPOL006_UnknownGroupNoInventMembership(t *testing.T) {
	t.Parallel()
	ov := &policy.Overlay{
		Version: 1,
		Subjects: &policy.SubjectBindings{
			Groups: []policy.GroupBinding{{
				GroupID:   "secret-ops",
				DenyTools: []string{"jenkins_get_build_logs"},
			}},
		},
	}
	if err := ov.Validate(); err != nil {
		t.Fatal(err)
	}
	ev := policy.NewDenyOnlyFromOverlay(ov)
	// Subject claims a different group — must not match secret-ops
	s := pol006Subject("u", "other-group")
	if d := ev.Evaluate(s, policy.Action{ToolName: "jenkins_get_build_logs", Class: policy.EffectRead}, policy.Target{}); d.Denied() {
		t.Fatalf("must not invent secret-ops membership: %+v", d)
	}
}

func TestPOL006_BudgetLowerOnlyMerge(t *testing.T) {
	t.Parallel()
	global := 65536
	userCap := 8192
	groupCap := 4096
	ov := &policy.Overlay{
		Version:        1,
		MaxResultBytes: &global,
		Subjects: &policy.SubjectBindings{
			Users: []policy.UserBinding{{
				JenkinsUserID:  "alice",
				MaxResultBytes: &userCap,
			}},
			Groups: []policy.GroupBinding{{
				GroupID:        "tight",
				MaxResultBytes: &groupCap,
			}},
		},
	}
	if err := ov.Validate(); err != nil {
		t.Fatal(err)
	}
	ev := policy.NewDenyOnlyFromOverlay(ov)
	// alice + tight → min(65536, 8192, 4096) = 4096
	alice := pol006Subject("alice", "tight")
	eff := ev.EffectiveDocument(alice)
	if eff.MaxResultBytes != 4096 {
		t.Fatalf("want most restrictive 4096, got %d", eff.MaxResultBytes)
	}
	// bob no bindings → global only
	bob := pol006Subject("bob")
	if got := ev.EffectiveDocument(bob).MaxResultBytes; got != 65536 {
		t.Fatalf("bob global cap: %d", got)
	}
}

func TestPOL006_ExternalSubjectMatch(t *testing.T) {
	t.Parallel()
	ov := &policy.Overlay{
		Version: 1,
		Subjects: &policy.SubjectBindings{
			Users: []policy.UserBinding{{
				ExternalSubject: "oidc|alice-sub",
				DenyTools:       []string{"jenkins_get_build_logs"},
			}},
		},
	}
	if err := ov.Validate(); err != nil {
		t.Fatal(err)
	}
	ev := policy.NewDenyOnlyFromOverlay(ov)
	alice := policy.NewSubject(contracts.ProfileID("corp"), "alice", true).
		WithExternal("oidc|alice-sub")
	other := policy.NewSubject(contracts.ProfileID("corp"), "alice", true).
		WithExternal("oidc|other")
	act := policy.Action{ToolName: "jenkins_get_build_logs", Class: policy.EffectRead}
	if d := ev.Evaluate(alice, act, policy.Target{}); d.Allowed() {
		t.Fatal("external match should deny")
	}
	if d := ev.Evaluate(other, act, policy.Target{}); d.Denied() {
		t.Fatal("wrong external must not deny")
	}
}

func TestPOL006_ValidateRejectsBadBindings(t *testing.T) {
	t.Parallel()
	cases := []policy.Overlay{
		{Version: 1, Subjects: &policy.SubjectBindings{
			Users: []policy.UserBinding{{DenyTools: []string{"x"}}}, // no identity
		}},
		{Version: 1, Subjects: &policy.SubjectBindings{
			Users: []policy.UserBinding{{JenkinsUserID: "anonymous", DenyTools: []string{"x"}}},
		}},
		{Version: 1, Subjects: &policy.SubjectBindings{
			Groups: []policy.GroupBinding{{GroupID: "", DenyTools: []string{"x"}}},
		}},
		{Version: 1, Subjects: &policy.SubjectBindings{
			Groups: []policy.GroupBinding{{GroupID: "g", DenyJobPrefixes: []string{"*"}}},
		}},
	}
	for i, ov := range cases {
		if err := ov.Validate(); err == nil {
			t.Fatalf("case %d: expected validation error", i)
		}
	}
}

func TestPOL006_JSONRoundTripOverlay(t *testing.T) {
	t.Parallel()
	raw := `{
		"version": 1,
		"force_read_only": true,
		"deny_tools": ["jenkins_get_queue_item"],
		"subjects": {
			"users": [
				{"jenkins_user_id": "alice", "deny_tools": ["jenkins_get_build_logs"]}
			],
			"groups": [
				{"group_id": "contractors", "deny_job_prefixes": ["legacy/**"]}
			]
		}
	}`
	var ov policy.Overlay
	if err := json.Unmarshal([]byte(raw), &ov); err != nil {
		t.Fatal(err)
	}
	if err := ov.Validate(); err != nil {
		t.Fatal(err)
	}
	ev := policy.NewDenyOnlyFromOverlay(&ov)
	alice := pol006Subject("alice", "contractors")
	if d := ev.Evaluate(alice, policy.Action{ToolName: "jenkins_get_build_logs", Class: policy.EffectRead}, policy.Target{}); d.Allowed() {
		t.Fatal("user deny from JSON")
	}
	if d := ev.Evaluate(alice, policy.Action{ToolName: "jenkins_get_job", Class: policy.EffectRead},
		policy.Target{JobName: "legacy/old"}); d.Allowed() {
		t.Fatal("group job deny from JSON")
	}
	// force_read_only still global
	if !ev.Document().ForceReadOnly {
		t.Fatal("force RO should remain global")
	}
}

func TestPOL006_DualKeyUserAND(t *testing.T) {
	t.Parallel()
	ov := &policy.Overlay{
		Version: 1,
		Subjects: &policy.SubjectBindings{
			Users: []policy.UserBinding{{
				JenkinsUserID:   "alice",
				ExternalSubject: "oidc|alice",
				DenyTools:       []string{"jenkins_get_build_logs"},
			}},
		},
	}
	if err := ov.Validate(); err != nil {
		t.Fatal(err)
	}
	ev := policy.NewDenyOnlyFromOverlay(ov)
	act := policy.Action{ToolName: "jenkins_get_build_logs", Class: policy.EffectRead}

	both := policy.NewSubject(contracts.ProfileID("corp"), "alice", true).WithExternal("oidc|alice")
	if d := ev.Evaluate(both, act, policy.Target{}); d.Allowed() {
		t.Fatal("both keys matching should deny")
	}
	// Only jenkins matches
	onlyJU := policy.NewSubject(contracts.ProfileID("corp"), "alice", true).WithExternal("oidc|other")
	if d := ev.Evaluate(onlyJU, act, policy.Target{}); d.Denied() {
		t.Fatalf("AND binding must not match jenkins-only: %+v", d)
	}
	// Only external matches
	onlyExt := policy.NewSubject(contracts.ProfileID("corp"), "bob", true).WithExternal("oidc|alice")
	if d := ev.Evaluate(onlyExt, act, policy.Target{}); d.Denied() {
		t.Fatalf("AND binding must not match external-only: %+v", d)
	}
}

func TestPOL006_ListPrivacySubjectAware(t *testing.T) {
	t.Parallel()
	ov := &policy.Overlay{
		Version: 1,
		Subjects: &policy.SubjectBindings{
			Users: []policy.UserBinding{{
				JenkinsUserID:   "alice",
				DenyJobPrefixes: []string{"secret/**"},
			}},
			Groups: []policy.GroupBinding{{
				GroupID:       "contractors",
				DenyNodeNames: []string{"prod-agent-*"},
			}},
		},
	}
	if err := ov.Validate(); err != nil {
		t.Fatal(err)
	}
	ev := policy.NewDenyOnlyFromOverlay(ov)
	alice := pol006Subject("alice")
	bob := pol006Subject("bob")
	contractor := pol006Subject("carol", "contractors")

	// Global FromEvaluator has no job denies
	if got := policy.DenyJobPrefixesFromEvaluator(ev); len(got) != 0 {
		t.Fatalf("global job denies should be empty: %v", got)
	}
	// Alice effective has secret/**
	if got := policy.DenyJobPrefixesForSubject(ev, alice); len(got) != 1 || got[0] != "secret/**" {
		t.Fatalf("alice job denies: %v", got)
	}
	if got := policy.DenyJobPrefixesForSubject(ev, bob); len(got) != 0 {
		t.Fatalf("bob job denies should be empty: %v", got)
	}
	if got := policy.DenyNodeNamesForSubject(ev, contractor); len(got) != 1 || got[0] != "prod-agent-*" {
		t.Fatalf("contractor node denies: %v", got)
	}
	if got := policy.DenyNodeNamesForSubject(ev, bob); len(got) != 0 {
		t.Fatalf("bob node denies: %v", got)
	}
}

func TestPOL006_ToolArgsCannotChooseSubject(t *testing.T) {
	t.Parallel()
	// Binding targets are only JenkinsUserID / ExternalSubject / Groups from
	// Subject — there is no API that accepts tool-arg principal. Prove evaluate
	// uses the provided subject only.
	ov := &policy.Overlay{
		Version: 1,
		Subjects: &policy.SubjectBindings{
			Users: []policy.UserBinding{{
				JenkinsUserID: "alice",
				DenyTools:     []string{"jenkins_get_build_logs"},
			}},
		},
	}
	ev := policy.NewDenyOnlyFromOverlay(ov)
	// Attacker-controlled tool target string is not an identity field.
	bob := pol006Subject("bob")
	d := ev.Evaluate(bob, policy.Action{ToolName: "jenkins_get_build_logs", Class: policy.EffectRead},
		policy.Target{JobName: "alice"}) // job named alice must not become subject
	if d.Denied() {
		t.Fatalf("job name must not spoof subject: %+v", d)
	}
	if !strings.Contains(string(bob.JenkinsUserID), "bob") {
		t.Fatal("sanity")
	}
}
