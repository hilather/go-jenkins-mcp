package policy_test

import (
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/contracts"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

// BenchmarkPolicyEvaluate_Allow is a CI-safe microbench for QA-003 regression.
// Deny-only evaluator, no I/O.
func BenchmarkPolicyEvaluate_Allow(b *testing.B) {
	ov := &policy.Overlay{
		Version:   policy.CurrentOverlayVersion,
		DenyTools: []string{"jenkins_build_job"},
	}
	ev := policy.NewDenyOnlyFromOverlay(ov)
	sub := policy.NewSubject(contracts.ProfileID("corp"), "alice", true)
	act := policy.Action{ToolName: "jenkins_get_build", Class: policy.EffectRead}
	tgt := policy.Target{}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d := ev.Evaluate(sub, act, tgt)
		if d.Denied() {
			b.Fatal("unexpected deny")
		}
	}
}

// BenchmarkPolicyEvaluate_Deny exercises an explicit deny path.
func BenchmarkPolicyEvaluate_Deny(b *testing.B) {
	ov := &policy.Overlay{
		Version:   policy.CurrentOverlayVersion,
		DenyTools: []string{"jenkins_build_job"},
	}
	ev := policy.NewDenyOnlyFromOverlay(ov)
	sub := policy.NewSubject(contracts.ProfileID("corp"), "alice", true)
	act := policy.Action{ToolName: "jenkins_build_job", Class: policy.EffectMutate}
	tgt := policy.Target{}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d := ev.Evaluate(sub, act, tgt)
		if d.Allowed() {
			b.Fatal("unexpected allow")
		}
	}
}
