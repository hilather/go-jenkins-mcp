package policy_test

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

// POL-005 adversarial / conformance suite for global RO + deny-only MCP RBAC.
//
// Narrative (unit-level): MCP policy is deny-only. An Evaluate result of Allow
// means "MCP does not further restrict"; it never grants Jenkins access, never
// returns a grant_jenkins capability, and never overrides a Jenkins denial.
// Effective access is always Jenkins allow ∩ global RO ∩ MCP policy ∩ budgets.

func TestConformance_EffectiveRO_OROfSources(t *testing.T) {
	t.Parallel()
	// Property-style table: effective RO is OR (most restrictive) of sources.
	// Adding any true RO source never decreases restrictiveness.
	tru := true
	fals := false
	cases := []struct {
		name string
		in   policy.Inputs
		want bool
	}{
		{"builtin_default", policy.Inputs{}, true},
		{"allow_mutations_only", policy.Inputs{AllowMutations: true}, false},
		{"flag", policy.Inputs{AllowMutations: true, FlagReadOnly: true}, true},
		{"env", policy.Inputs{AllowMutations: true, EnvReadOnly: true}, true},
		{"profile", policy.Inputs{AllowMutations: true, ProfileReadOnly: &tru}, true},
		{"profile_false_ignored", policy.Inputs{AllowMutations: true, ProfileReadOnly: &fals}, false},
		{"enterprise_force", policy.Inputs{AllowMutations: true, Force: policy.StaticForce{Force: true, Present: true}}, true},
		{"flag_and_env", policy.Inputs{AllowMutations: true, FlagReadOnly: true, EnvReadOnly: true}, true},
		{"skip_builtin", policy.Inputs{SkipBuiltinDefault: true}, false},
		// Monotonic: allow-mutations + any force source → still RO.
		{"force_beats_allow", policy.Inputs{
			AllowMutations: true,
			FlagReadOnly:   true,
			EnvReadOnly:    true,
			Force:          policy.StaticForce{Force: true, Present: true},
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := policy.ComputeEffectiveReadOnly(tc.in)
			if st.Effective != tc.want {
				t.Fatalf("effective=%v want %v sources=%v", st.Effective, tc.want, st.Sources)
			}
			// Monotonicity: flipping any source to more restrictive keeps RO.
			if !st.Effective {
				return
			}
			// Already RO; adding another source stays RO.
			more := tc.in
			more.FlagReadOnly = true
			st2 := policy.ComputeEffectiveReadOnly(more)
			if !st2.Effective {
				t.Fatal("adding flag RO must not reduce restrictiveness")
			}
		})
	}
}

func TestConformance_AllowMutationsDefeatedByForceOverlay(t *testing.T) {
	t.Parallel()
	// CFG-002 + POL-001: enterprise force_read_only cannot be defeated.
	o := &policy.Overlay{Version: 1, ForceReadOnly: true, Mode: policy.ModePilot}
	force := policy.AsEnterpriseForce(o)
	st := policy.ComputeEffectiveReadOnly(policy.Inputs{
		AllowMutations: true,
		Force:          force,
	})
	if !st.Effective {
		t.Fatal("force_read_only must win over --allow-mutations")
	}
	gate := policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true, Force: force})
	if gate.AllowMutationRegistration() {
		t.Fatal("AllowMutationRegistration (write-enabled) must be false under force RO")
	}
	// Wave 30: opt-in still allows attaching mutation tools under force RO;
	// DenyMutation + ListTools keep discovery/dispatch fail-closed.
	if !gate.AllowMutationsOptIn() || !gate.ShouldRegisterMutations() {
		t.Fatal("allow-mutations + force: ShouldRegisterMutations true (Wave 30)")
	}
	if err := gate.DenyMutation(policy.ToolStartJob); err == nil {
		t.Fatal("DenyMutation under force RO")
	}
}

func TestConformance_EmptyAndAnonymousSubjectDenyWhenPolicyPresent(t *testing.T) {
	t.Parallel()
	ev := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	action := policy.Action{ToolName: "jenkins_get_jobs", Class: policy.EffectRead}

	for _, tc := range []struct {
		name    string
		subject policy.Subject
		reason  string
	}{
		{"empty", policy.Subject{}, policy.ReasonSubjectEmpty},
		{"anonymous", policy.NewSubject("corp", "anonymous", true), policy.ReasonSubjectAnon},
		{"anon_case", policy.NewSubject("corp", "ANONYMOUS", true), policy.ReasonSubjectAnon},
		{"no_profile", policy.Subject{JenkinsUserID: "u", Verified: true}, policy.ReasonSubjectInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := ev.Evaluate(tc.subject, action, policy.Target{})
			if !d.Denied() || d.ReasonCode != tc.reason {
				t.Fatalf("got %+v want reason %s", d, tc.reason)
			}
			if err := d.Err(); err == nil || apperr.CodeOf(err) != apperr.CodePolicyDenial {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestConformance_EvaluatorNeverGrantJenkins(t *testing.T) {
	t.Parallel()
	// Document shape: only DenyTools, no AllowTools / GrantJenkins fields.
	docType := reflect.TypeOf(policy.Document{})
	for i := 0; i < docType.NumField(); i++ {
		name := docType.Field(i).Name
		lower := strings.ToLower(name)
		if strings.Contains(lower, "allowtool") ||
			strings.Contains(lower, "grant") ||
			strings.Contains(lower, "elevate") ||
			strings.Contains(lower, "permittool") {
			t.Fatalf("Document must not expose elevation field %q", name)
		}
	}

	// DecisionEffect closed set: allow | deny only — "allow" is not grant_jenkins.
	ev := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	d := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_jobs", Class: policy.EffectRead}, policy.Target{})
	if d.Effect != policy.EffectAllow {
		t.Fatalf("effect=%q", d.Effect)
	}
	if string(d.Effect) == "grant_jenkins" || strings.Contains(strings.ToLower(d.ReasonCode), "grant") {
		t.Fatal("evaluator must never return grant_jenkins")
	}
	// Explicit deny still deny for Jenkins admin (no elevation).
	ev2 := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:      policy.ModePilot,
		DenyTools: map[string]struct{}{"jenkins_get_jobs": {}},
	})
	d2 := ev2.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_jobs", Class: policy.EffectRead}, policy.Target{})
	if !d2.Denied() {
		t.Fatal("admin still denied by MCP rule")
	}

	// Reason codes never include grant/elevate language.
	for _, code := range []string{
		policy.ReasonOK, policy.ReasonExplicitDeny, policy.ReasonUnknownTool,
		policy.ReasonSubjectEmpty, policy.ReasonSubjectAnon, policy.ReasonSubjectUnverified,
		policy.ReasonSubjectInvalid, policy.ReasonNoEvaluator, policy.ReasonJobPatternDeny,
		policy.ReasonResourcePatternDeny,
	} {
		if strings.Contains(strings.ToLower(code), "grant") || strings.Contains(strings.ToLower(code), "elevate") {
			t.Fatalf("reason code %q looks like elevation", code)
		}
	}
}

func TestConformance_AddingDenyNeverIncreasesAccess(t *testing.T) {
	t.Parallel()
	// Property: starting from pilot empty, adding deny_tools is monotonic restrict.
	base := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	restricted := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode: policy.ModePilot,
		DenyTools: map[string]struct{}{
			"jenkins_get_build_logs": {},
			"jenkins_get_job":        {},
		},
	})
	tools := []string{"jenkins_get_jobs", "jenkins_get_job", "jenkins_get_build_logs", "jenkins_search_builds"}
	for _, tool := range tools {
		a := policy.Action{ToolName: tool, Class: policy.EffectRead}
		dBase := base.Evaluate(fixtureAdmin, a, policy.Target{})
		dRest := restricted.Evaluate(fixtureAdmin, a, policy.Target{})
		// If base denied, restricted must deny. If restricted allows, base must allow.
		if dBase.Denied() && dRest.Allowed() {
			t.Fatalf("tool %s: restriction increased access", tool)
		}
		if dRest.Allowed() && dBase.Denied() {
			t.Fatalf("tool %s: impossible allow under stricter policy", tool)
		}
		// Tools in deny set must be denied under restricted.
		if tool == "jenkins_get_job" || tool == "jenkins_get_build_logs" {
			if !dRest.Denied() {
				t.Fatalf("%s must be denied", tool)
			}
		}
	}
}

func TestConformance_StrictUnknownFailClosed(t *testing.T) {
	t.Parallel()
	ev := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModeStrict})
	d := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_unclassified_future", Class: policy.EffectMutate}, policy.Target{})
	if !d.Denied() {
		t.Fatal("unclassified tool must deny under strict")
	}
	if d.ReasonCode != policy.ReasonUnknownTool {
		t.Fatalf("reason=%s", d.ReasonCode)
	}
	// Known seed tools remain allow under strict when not explicitly denied.
	dOK := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_get_jobs", Class: policy.EffectRead}, policy.Target{})
	if !dOK.Allowed() {
		t.Fatalf("known tool under strict: %+v", dOK)
	}
	// Store read synthetic action is classified (not unknown).
	dStore := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: policy.StoreReadAction, Class: policy.EffectRead}, policy.Target{})
	if !dStore.Allowed() {
		t.Fatalf("store_cached_read under strict: %+v", dStore)
	}
}

// TestConformance_MonotonicityPropertyCombinations is a property-style table:
// adding any restriction (deny tool, deny job prefix, strict mode, RO force,
// require verified subject) never increases the allow set.
func TestConformance_MonotonicityPropertyCombinations(t *testing.T) {
	t.Parallel()
	tools := []string{
		"jenkins_get_jobs",
		"jenkins_get_job",
		"jenkins_get_build_logs",
		"jenkins_start_job",
		"jenkins_evil_unknown",
		policy.StoreReadAction,
	}
	jobs := []string{"", "public/job", "secret/job", "secret-folder-other"}

	type restriction struct {
		name string
		doc  policy.Document
		ro   policy.Inputs
	}
	// Base: pilot, no denials, mutations allowed at RO layer for isolation of RBAC.
	base := restriction{
		name: "base_pilot",
		doc:  policy.Document{Mode: policy.ModePilot},
		ro:   policy.Inputs{AllowMutations: true, SkipBuiltinDefault: true},
	}
	// Increasingly restrictive overlays (each alone and combined).
	extras := []restriction{
		{
			name: "deny_logs",
			doc: policy.Document{
				Mode:      policy.ModePilot,
				DenyTools: map[string]struct{}{"jenkins_get_build_logs": {}},
			},
		},
		{
			name: "deny_store",
			doc: policy.Document{
				Mode:      policy.ModePilot,
				DenyTools: map[string]struct{}{policy.StoreReadAction: {}},
			},
		},
		{
			name: "deny_job_prefix_secret",
			doc: policy.Document{
				Mode:            policy.ModePilot,
				DenyJobPrefixes: []string{"secret"},
			},
		},
		{
			name: "strict_mode",
			doc:  policy.Document{Mode: policy.ModeStrict},
		},
		{
			name: "require_verified",
			doc: policy.Document{
				Mode:                   policy.ModePilot,
				RequireVerifiedSubject: true,
			},
		},
		{
			name: "force_ro",
			doc:  policy.Document{Mode: policy.ModePilot},
			ro: policy.Inputs{
				AllowMutations: true,
				Force:          policy.StaticForce{Force: true, Present: true},
			},
		},
		{
			name: "combo_strict_deny_logs_force_ro",
			doc: policy.Document{
				Mode:      policy.ModeStrict,
				DenyTools: map[string]struct{}{"jenkins_get_build_logs": {}},
			},
			ro: policy.Inputs{
				AllowMutations: true,
				Force:          policy.StaticForce{Force: true, Present: true},
			},
		},
	}

	// allowFn returns whether the subject may proceed for tool+job under restriction.
	allowFn := func(r restriction, subj policy.Subject, tool, job string) bool {
		ev := policy.NewDenyOnlyEvaluator(r.doc)
		class := policy.ToolEffect(tool)
		if tool == policy.StoreReadAction {
			class = policy.EffectRead
		}
		d := ev.Evaluate(subj, policy.Action{ToolName: tool, Class: class}, policy.Target{JobName: job})
		if d.Denied() {
			return false
		}
		// RO gate for mutations.
		if class == policy.EffectMutate {
			gate := policy.NewReadOnlyGate(r.ro)
			if err := gate.DenyMutation(tool); err != nil {
				return false
			}
		}
		// Store path.
		if tool == policy.StoreReadAction {
			if err := policy.CheckStoreRead(context.Background(), ev, subj, job); err != nil {
				return false
			}
		}
		return true
	}

	subjects := []policy.Subject{
		fixtureAdmin,
		fixtureDev,
		fixtureProv, // provisional (Verified=false)
		policy.NewSubject("corp", "anonymous", true),
		{},
	}

	// Base allow set vs each stricter restriction: no newly-allowed (tool,job,subject).
	for _, extra := range extras {
		// Merge base doc denials with extra (extra alone is already stricter or equal).
		t.Run(extra.name, func(t *testing.T) {
			for _, subj := range subjects {
				for _, tool := range tools {
					for _, job := range jobs {
						baseOK := allowFn(base, subj, tool, job)
						restOK := allowFn(extra, subj, tool, job)
						if !baseOK && restOK {
							t.Fatalf("monotonicity violated: restriction %q increased access for subject=%q tool=%s job=%q",
								extra.name, subj.JenkinsUserID, tool, job)
						}
					}
				}
			}
		})
	}

	// Combining two restrictions is at least as strict as either alone.
	t.Run("intersection_of_two_denies", func(t *testing.T) {
		a := restriction{
			name: "a",
			doc: policy.Document{
				Mode:      policy.ModePilot,
				DenyTools: map[string]struct{}{"jenkins_get_build_logs": {}},
			},
		}
		b := restriction{
			name: "b",
			doc: policy.Document{
				Mode:            policy.ModePilot,
				DenyJobPrefixes: []string{"secret"},
			},
		}
		both := restriction{
			name: "both",
			doc: policy.Document{
				Mode: policy.ModePilot,
				DenyTools: map[string]struct{}{
					"jenkins_get_build_logs": {},
				},
				DenyJobPrefixes: []string{"secret"},
			},
		}
		for _, tool := range tools {
			for _, job := range jobs {
				aOK := allowFn(a, fixtureAdmin, tool, job)
				bOK := allowFn(b, fixtureAdmin, tool, job)
				bothOK := allowFn(both, fixtureAdmin, tool, job)
				// both allow ⇒ a and b allow
				if bothOK && (!aOK || !bOK) {
					t.Fatalf("intersection broke for tool=%s job=%q a=%v b=%v both=%v", tool, job, aOK, bOK, bothOK)
				}
				// if either denies, both must deny
				if (!aOK || !bOK) && bothOK {
					t.Fatalf("combined policy allowed when a component denied tool=%s job=%q", tool, job)
				}
			}
		}
	})
}

// TestConformance_StoreReadDeniedAfterPolicyRestrict models policy reload /
// revocation: content that was readable under pilot becomes denied after
// deny_tools or job-prefix is added (POL-005 cache/store PEP).
func TestConformance_StoreReadDeniedAfterPolicyRestrict(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	resource := "secret-folder/job-a"

	open := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	if err := policy.CheckStoreRead(ctx, open, fixtureAdmin, resource); err != nil {
		t.Fatalf("open policy store read: %v", err)
	}

	// After "reload": deny store action globally.
	closedStore := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode: policy.ModePilot,
		DenyTools: map[string]struct{}{
			policy.StoreReadAction: {},
		},
	})
	if err := policy.CheckStoreRead(ctx, closedStore, fixtureAdmin, resource); err == nil {
		t.Fatal("store_cached_read deny must block cached content")
	} else if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code=%s err=%v", apperr.CodeOf(err), err)
	}

	// Job-prefix revocation: public stays open, secret denied.
	closedJob := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"secret-folder"},
	})
	if err := policy.CheckStoreRead(ctx, closedJob, fixtureAdmin, resource); err == nil {
		t.Fatal("job prefix must deny store read for secret-folder/job-a")
	}
	if err := policy.CheckStoreRead(ctx, closedJob, fixtureAdmin, "public/job"); err != nil {
		t.Fatalf("public job store read: %v", err)
	}

	// Empty subject always fails closed when evaluator present (revocation of identity).
	if err := policy.CheckStoreRead(ctx, open, policy.Subject{}, resource); err == nil {
		t.Fatal("empty subject store read")
	}
}

// TestConformance_ForceRegisterMutationUnderRO proves that even if a mutation
// tool is force-registered (discovery bypass), CheckToolAccess + DenyMutation
// still deny under effective RO (handler middleware contract).
func TestConformance_ForceRegisterMutationUnderRO(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	gate := policy.NewDefaultReadOnlyGate()
	if gate.AllowMutationRegistration() {
		t.Fatal("default RO must not allow mutation registration")
	}
	// Alias-style names: seed mutations and a crafted alias must both fail RO.
	aliases := []string{
		policy.ToolStartJob,
		policy.ToolStopBuild,
		policy.ToolCancelQueueItem,
		"jenkins_start_job", // exact seed
		"StartJob",          // non-seed alias still blocked as mutate class
	}
	for _, name := range aliases {
		err := policy.CheckToolAccess(ctx, gate, nil, fixtureAdmin, name, policy.EffectMutate)
		if err == nil {
			t.Fatalf("ForceRegister-style mutate %q must deny under RO", name)
		}
		if apperr.CodeOf(err) != apperr.CodePolicyDenial {
			t.Fatalf("%s code=%s", name, apperr.CodeOf(err))
		}
	}
	// Allow-mutations defeated by enterprise force still denies force-registered path.
	forceGate := policy.NewReadOnlyGate(policy.Inputs{
		AllowMutations: true,
		Force:          policy.StaticForce{Force: true, Present: true},
	})
	if err := policy.CheckToolAccess(ctx, forceGate, nil, fixtureAdmin, policy.ToolStartJob, policy.EffectMutate); err == nil {
		t.Fatal("force_read_only must deny force-registered start_job")
	}
	// When RO is off, mutate class passes gate (RBAC still may deny).
	openGate := policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true, SkipBuiltinDefault: true})
	if err := policy.CheckToolAccess(ctx, openGate, nil, fixtureAdmin, policy.ToolStartJob, policy.EffectMutate); err != nil {
		t.Fatalf("mutations allowed path: %v", err)
	}
	// Explicit deny_tools still blocks even when RO off.
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:      policy.ModePilot,
		DenyTools: map[string]struct{}{policy.ToolStartJob: {}},
	})
	if err := policy.CheckToolAccess(ctx, openGate, ev, fixtureAdmin, policy.ToolStartJob, policy.EffectMutate); err == nil {
		t.Fatal("deny_tools must block mutation even when RO off")
	}
}

// TestConformance_SubjectSpoofViaToolArgsRejected ensures gateway identity
// spoof keys in tool args fail closed (GWY-002 / POL-005). Trusted subject
// comes only from Binding / auth session — never tool arguments.
func TestConformance_SubjectSpoofViaToolArgsRejected(t *testing.T) {
	t.Parallel()
	// Clean args ok.
	if err := gateway.RejectIdentityToolArgs(map[string]any{
		"job_name":     "demo",
		"build_number": 1,
	}); err != nil {
		t.Fatal(err)
	}
	// Spoof keys must deny with policy_denial.
	for _, key := range gateway.ForbiddenIdentityArgKeys {
		err := gateway.RejectIdentityToolArgs(map[string]any{
			"job_name": "demo",
			key:        "attacker",
		})
		if err == nil {
			t.Fatalf("key %q must be rejected", key)
		}
		if apperr.CodeOf(err) != apperr.CodePolicyDenial {
			t.Fatalf("key %q code=%s", key, apperr.CodeOf(err))
		}
		if strings.Contains(err.Error(), "attacker") {
			t.Fatalf("spoof value must not echo in error: %v", err)
		}
	}
	// Case-insensitive.
	if err := gateway.RejectIdentityToolArgs(map[string]any{"As_User": "x"}); err == nil {
		t.Fatal("case-insensitive as_user")
	}
	// Evaluator still uses process subject, not arg-derived identity: even if
	// args claimed admin, empty process subject denies.
	ev := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	d := ev.Evaluate(policy.Subject{}, policy.Action{ToolName: "jenkins_get_jobs", Class: policy.EffectRead}, policy.Target{})
	if !d.Denied() || d.ReasonCode != policy.ReasonSubjectEmpty {
		t.Fatalf("empty process subject: %+v", d)
	}
}

// TestConformance_StrictModeUnknownToolsDenied table-covers strict pilot contrast.
func TestConformance_StrictModeUnknownToolsDenied(t *testing.T) {
	t.Parallel()
	unknowns := []string{
		"jenkins_unclassified_future",
		"jenkins_evil_new_tool",
		"custom_adapter_tool",
		"  ",
		"",
	}
	strict := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModeStrict})
	pilot := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	for _, name := range unknowns {
		name := name
		t.Run("strict/"+name, func(t *testing.T) {
			d := strict.Evaluate(fixtureAdmin, policy.Action{ToolName: name, Class: policy.EffectRead}, policy.Target{})
			if name == "" || strings.TrimSpace(name) == "" {
				if !d.Denied() {
					t.Fatal("empty tool name must deny")
				}
				return
			}
			if !d.Denied() || d.ReasonCode != policy.ReasonUnknownTool {
				t.Fatalf("strict unknown: %+v", d)
			}
		})
		t.Run("pilot/"+name, func(t *testing.T) {
			if name == "" || strings.TrimSpace(name) == "" {
				return
			}
			// Pilot allows unknown read tools (still no Jenkins elevation).
			d := pilot.Evaluate(fixtureAdmin, policy.Action{ToolName: name, Class: policy.EffectRead}, policy.Target{})
			if !d.Allowed() {
				t.Fatalf("pilot should allow unknown read unless denied: %+v", d)
			}
		})
	}
}

// TestConformance_JenkinsAdminStillMCPDenied documents that MCP allow never
// elevates: a Jenkins admin subject is still denied by explicit MCP deny.
func TestConformance_JenkinsAdminStillMCPDenied(t *testing.T) {
	t.Parallel()
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode: policy.ModePilot,
		DenyTools: map[string]struct{}{
			"jenkins_get_build_logs": {},
			policy.ToolStartJob:      {},
		},
	})
	for _, tool := range []string{"jenkins_get_build_logs", policy.ToolStartJob} {
		d := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: tool, Class: policy.ToolEffect(tool)}, policy.Target{})
		if !d.Denied() {
			t.Fatalf("admin must not bypass MCP deny for %s", tool)
		}
	}
}
