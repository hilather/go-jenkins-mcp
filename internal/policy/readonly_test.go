package policy_test

import (
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

func TestDefaultReadOnly(t *testing.T) {
	t.Parallel()
	st := policy.ComputeEffectiveReadOnly(policy.Inputs{})
	if !st.Effective {
		t.Fatal("pilot default must be read-only")
	}
	if !contains(st.Sources, policy.SourceBuiltinDefault) {
		t.Fatalf("sources=%v want builtin_default", st.Sources)
	}
}

func TestEnvForcesReadOnly(t *testing.T) {
	t.Parallel()
	st := policy.ComputeEffectiveReadOnly(policy.Inputs{
		AllowMutations: true, // would otherwise clear default
		EnvReadOnly:    true,
	})
	if !st.Effective {
		t.Fatal("JENKINS_MCP_READ_ONLY must force RO even with allow-mutations")
	}
	if !contains(st.Sources, policy.SourceEnv) {
		t.Fatalf("sources=%v", st.Sources)
	}
}

func TestFlagForcesReadOnly(t *testing.T) {
	t.Parallel()
	st := policy.ComputeEffectiveReadOnly(policy.Inputs{
		AllowMutations: true,
		FlagReadOnly:   true,
	})
	if !st.Effective {
		t.Fatal("--read-only must force RO")
	}
	if !contains(st.Sources, policy.SourceCLIFlag) {
		t.Fatalf("sources=%v", st.Sources)
	}
}

func TestProfileReadOnly(t *testing.T) {
	t.Parallel()
	tru := true
	st := policy.ComputeEffectiveReadOnly(policy.Inputs{
		AllowMutations:  true,
		ProfileReadOnly: &tru,
	})
	if !st.Effective {
		t.Fatal("profile read_only=true must force RO")
	}
	if !contains(st.Sources, policy.SourceProfile) {
		t.Fatalf("sources=%v", st.Sources)
	}

	// Explicit false does not force RO (and does not clear stronger sources).
	f := false
	st2 := policy.ComputeEffectiveReadOnly(policy.Inputs{
		AllowMutations:  true,
		ProfileReadOnly: &f,
	})
	if st2.Effective {
		t.Fatal("profile read_only=false with allow-mutations should not be RO")
	}
}

func TestEnterpriseForceBlocksAllowMutations(t *testing.T) {
	t.Parallel()
	st := policy.ComputeEffectiveReadOnly(policy.Inputs{
		AllowMutations: true,
		Force:          policy.StaticForce{Force: true, Present: true},
	})
	if !st.Effective {
		t.Fatal("enterprise force_read_only must win over --allow-mutations")
	}
	if !contains(st.Sources, policy.SourceEnterpriseForce) {
		t.Fatalf("sources=%v", st.Sources)
	}

	// Missing enterprise force is ignored.
	st2 := policy.ComputeEffectiveReadOnly(policy.Inputs{
		AllowMutations: true,
		Force:          policy.StaticForce{Force: true, Present: false},
	})
	if st2.Effective {
		t.Fatal("absent enterprise force must be ignored")
	}
}

func TestAllowMutationsOptIn(t *testing.T) {
	t.Parallel()
	st := policy.ComputeEffectiveReadOnly(policy.Inputs{AllowMutations: true})
	if st.Effective {
		t.Fatal("--allow-mutations with no stronger source must disable RO")
	}
	if !contains(st.Sources, policy.SourceAllowMutations) {
		t.Fatalf("sources=%v want allow_mutations recorded", st.Sources)
	}
}

// Wave 30: AllowMutationsOptIn / ShouldRegisterMutations are independent of Effective.
func TestAllowMutationsOptInAndShouldRegister(t *testing.T) {
	t.Parallel()

	// Default pilot: no opt-in, Effective RO → do not register mutations.
	def := policy.NewDefaultReadOnlyGate()
	if def.AllowMutationsOptIn() {
		t.Fatal("default gate must not report AllowMutations opt-in")
	}
	if def.ShouldRegisterMutations() {
		t.Fatal("default RO must not register mutations")
	}
	if def.AllowMutationRegistration() {
		t.Fatal("default RO: AllowMutationRegistration false")
	}

	// Opt-in alone: write-enabled.
	rw := policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true})
	if !rw.AllowMutationsOptIn() || !rw.ShouldRegisterMutations() || !rw.AllowMutationRegistration() {
		t.Fatal("allow-mutations alone: opt-in + register + write-enabled")
	}

	// Opt-in + enterprise force: Effective RO but still register (Wave 30).
	forceRO := policy.NewReadOnlyGate(policy.Inputs{
		AllowMutations: true,
		Force:          policy.StaticForce{Force: true, Present: true},
	})
	if !forceRO.Effective() {
		t.Fatal("force must make Effective")
	}
	if forceRO.AllowMutationRegistration() {
		t.Fatal("force RO: AllowMutationRegistration remains false (dispatch/write)")
	}
	if !forceRO.AllowMutationsOptIn() {
		t.Fatal("force RO + opt-in: AllowMutationsOptIn true")
	}
	if !forceRO.ShouldRegisterMutations() {
		t.Fatal("Wave 30: ShouldRegisterMutations true under allow-mutations + force RO")
	}

	// Env RO + opt-in: same — register but deny dispatch.
	envRO := policy.NewReadOnlyGate(policy.Inputs{
		AllowMutations: true,
		EnvReadOnly:    true,
	})
	if !envRO.ShouldRegisterMutations() || envRO.AllowMutationRegistration() {
		t.Fatal("env RO + opt-in: register yes, write-enabled no")
	}

	// Nil gate fail-closed.
	var nilGate *policy.ReadOnlyGate
	if nilGate.AllowMutationsOptIn() || nilGate.ShouldRegisterMutations() {
		t.Fatal("nil gate: opt-in and register must be false")
	}
}

func TestParseEnvReadOnly(t *testing.T) {
	t.Parallel()
	for _, v := range []string{"true", "TRUE", "1", "yes", "on", " Yes "} {
		if !policy.ParseEnvReadOnly(v) {
			t.Errorf("ParseEnvReadOnly(%q)=false want true", v)
		}
	}
	for _, v := range []string{"", "false", "0", "no", "off", "maybe"} {
		if policy.ParseEnvReadOnly(v) {
			t.Errorf("ParseEnvReadOnly(%q)=true want false", v)
		}
	}
}

func TestGateDenyMutation(t *testing.T) {
	t.Parallel()
	ro := policy.NewDefaultReadOnlyGate()
	err := ro.DenyMutation(policy.ToolStartJob)
	if err == nil {
		t.Fatal("expected denial")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code=%q want policy_denial", apperr.CodeOf(err))
	}
	msg := err.Error()
	if strings.Contains(msg, "token") || strings.Contains(msg, "secret") {
		t.Fatalf("denial leaked secret-ish text: %q", msg)
	}
	if !strings.Contains(msg, policy.ToolStartJob) {
		t.Fatalf("msg should name tool: %q", msg)
	}

	// Write-enabled gate allows.
	rw := policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true})
	if err := rw.DenyMutation(policy.ToolStopBuild); err != nil {
		t.Fatalf("allow-mutations should permit: %v", err)
	}
}

func TestNilGateFailClosed(t *testing.T) {
	t.Parallel()
	var g *policy.ReadOnlyGate
	if !g.Effective() {
		t.Fatal("nil gate must be read-only (fail closed)")
	}
	if err := g.DenyMutation("x"); err == nil {
		t.Fatal("nil gate must deny mutations")
	}
	if apperr.CodeOf(g.DenyMutation("x")) != apperr.CodePolicyDenial {
		t.Fatal("want policy_denial")
	}
}

func TestGateStatusMap(t *testing.T) {
	t.Parallel()
	g := policy.NewDefaultReadOnlyGate()
	m := g.StatusMap()
	if m["read_only"] != true {
		t.Fatalf("status=%v", m)
	}
	srcs, ok := m["sources"].([]string)
	if !ok || len(srcs) == 0 {
		t.Fatalf("sources missing: %v", m)
	}
}

func TestToolEffectClassification(t *testing.T) {
	t.Parallel()
	// Every seed tool must have a stable classification.
	seed := []string{
		"jenkins_get_jobs",
		"jenkins_get_job",
		"jenkins_get_running_builds",
		"jenkins_get_build",
		"jenkins_get_build_logs",
		"jenkins_get_build_log_tail",
		"jenkins_start_job",
		"jenkins_get_queue_item",
		"jenkins_wait_for_queue_item",
		"jenkins_search_builds",
		"jenkins_stop_build",
		"jenkins_cancel_queue_item",
		"jenkins_wait_for_running_build",
	}
	for _, name := range seed {
		eff := policy.ToolEffect(name)
		wantMut := policy.IsMutationTool(name)
		if wantMut && eff != policy.EffectMutate {
			t.Errorf("%s: want mutate got %s", name, eff)
		}
		if !wantMut && eff != policy.EffectRead {
			t.Errorf("%s: want read got %s", name, eff)
		}
	}
	if !policy.IsMutationTool(policy.ToolStartJob) || !policy.IsMutationTool(policy.ToolCancelQueueItem) || policy.IsMutationTool("jenkins_get_jobs") {
		t.Fatal("IsMutationTool mismatch")
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
