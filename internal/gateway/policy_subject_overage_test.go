package gateway_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/gateway"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

// Regression: when inbound group claims exceed the bound (count overage or
// oversize name) under FailOnGroupOverage, the non-meta wrapper used by the
// production RBAC wiring must fail closed. Previously it returned a fully
// usable subject with Groups=nil — and because group bindings are deny-only
// (matching groups only ever add denies), dropping all groups silently
// broadened access: every group-targeted deny stopped applying to that user.
func TestPolicySubjectFromHTTPInbound_GroupOverageFailsClosed(t *testing.T) {
	t.Parallel()
	defaults := policy.Subject{ProfileID: "corp"}

	over := make([]string, gateway.MaxInboundGroups+1)
	for i := range over {
		over[i] = "g" + strconv.Itoa(i)
	}
	in := gateway.HTTPInbound{
		ExternalSubject:  "alice-sub",
		JenkinsPrincipal: "alice-j",
		Groups:           over,
		Verified:         true,
	}

	// The production wiring wrapper must not return a usable subject.
	s := gateway.PolicySubjectFromHTTPInbound(in, "corp", defaults)
	if !s.IsEmpty() {
		t.Fatalf("group overage must yield an empty (fail-closed) subject, got %+v", s)
	}

	// And policy evaluation must deny everything for it.
	ev := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	d := ev.Evaluate(s, policy.Action{ToolName: "jenkins_get_jobs", Class: policy.EffectRead}, policy.Target{})
	if !d.Denied() {
		t.Fatalf("over-overage subject must be denied at Evaluate: %+v", d)
	}
}

// Regression: same fail-closed behavior when a single group name exceeds the
// byte cap (the other boundGroups error path).
func TestPolicySubjectFromHTTPInbound_OversizeGroupNameFailsClosed(t *testing.T) {
	t.Parallel()
	defaults := policy.Subject{ProfileID: "corp"}
	in := gateway.HTTPInbound{
		ExternalSubject:  "bob-sub",
		JenkinsPrincipal: "bob-j",
		Groups:           []string{"ops", strings.Repeat("x", 300)},
		Verified:         true,
	}
	s := gateway.PolicySubjectFromHTTPInbound(in, "corp", defaults)
	if !s.IsEmpty() {
		t.Fatalf("oversize group name must yield an empty (fail-closed) subject, got %+v", s)
	}
}

// Regression (positive control): an in-bounds group set still binds, and a
// group-targeted deny applies to it.
func TestPolicySubjectFromHTTPInbound_InBoundsGroupsStillBind(t *testing.T) {
	t.Parallel()
	defaults := policy.Subject{ProfileID: "corp"}
	in := gateway.HTTPInbound{
		ExternalSubject:  "alice-sub",
		JenkinsPrincipal: "alice-j",
		Groups:           []string{"contractors"},
		Verified:         true,
	}
	s := gateway.PolicySubjectFromHTTPInbound(in, "corp", defaults)
	if s.IsEmpty() || len(s.Groups) != 1 {
		t.Fatalf("in-bounds groups must bind: %+v", s)
	}
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:          policy.ModePilot,
		GroupBindings: []policy.GroupBinding{{GroupID: "contractors", DenyTools: []string{"jenkins_get_build_logs"}}},
	})
	d := ev.Evaluate(s, policy.Action{ToolName: "jenkins_get_build_logs", Class: policy.EffectRead}, policy.Target{})
	if !d.Denied() {
		t.Fatalf("group-targeted deny must apply to bound group: %+v", d)
	}
}
