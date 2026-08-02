package gateway_test

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/contracts"
	"github.com/hilather/go-jenkins-mcp/internal/gateway"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

func TestContextWithPolicySubject_RoundTrip(t *testing.T) {
	t.Parallel()
	want := policy.Subject{
		ProfileID:       contracts.ProfileID("corp"),
		JenkinsUserID:   "alice-j",
		ExternalSubject: "alice-sub",
		Verified:        true,
		Tenant:          "t1",
		WorkloadID:      "w1",
	}
	ctx := gateway.ContextWithPolicySubject(context.Background(), want)
	got, ok := gateway.PolicySubjectFromContext(ctx)
	if !ok {
		t.Fatal("expected subject")
	}
	if got.JenkinsUserID != want.JenkinsUserID || got.ExternalSubject != want.ExternalSubject ||
		got.ProfileID != want.ProfileID || !got.Verified {
		t.Fatalf("got %+v want %+v", got, want)
	}
	if _, ok := gateway.PolicySubjectFromContext(context.Background()); ok {
		t.Fatal("background must not have subject")
	}
	if _, ok := gateway.PolicySubjectFromContext(nil); ok {
		t.Fatal("nil ctx")
	}
	// Nil parent becomes Background.
	ctx2 := gateway.ContextWithPolicySubject(nil, want)
	if _, ok := gateway.PolicySubjectFromContext(ctx2); !ok {
		t.Fatal("nil parent")
	}
}

func TestContextWithCallerAndPolicySubject(t *testing.T) {
	t.Parallel()
	c := gateway.Caller{
		Subject:   "alice-sub",
		Tenant:    "t1",
		ProfileID: contracts.ProfileID("corp"),
	}
	s := policy.NewSubject("corp", "alice-j", true).WithExternal("alice-sub")
	ctx := gateway.ContextWithCallerAndPolicySubject(context.Background(), c, s)
	gotC, okC := gateway.CallerFromContext(ctx)
	gotS, okS := gateway.PolicySubjectFromContext(ctx)
	if !okC || !okS {
		t.Fatalf("caller_ok=%v subject_ok=%v", okC, okS)
	}
	if gotC.Subject != c.Subject || gotS.JenkinsUserID != "alice-j" {
		t.Fatalf("caller=%+v subject=%+v", gotC, gotS)
	}
}

func TestPolicySubjectFromHTTPInbound(t *testing.T) {
	t.Parallel()
	defaults := policy.Subject{
		ProfileID:       contracts.ProfileID("corp"),
		JenkinsUserID:   "process-bob",
		ExternalSubject: "process-sub",
		Verified:        true,
		Tenant:          "tenant-default",
		WorkloadID:      "wl-default",
		Groups:          []string{"process-group"},
	}
	in := gateway.HTTPInbound{
		ExternalSubject:  "alice-sub",
		JenkinsPrincipal: "alice-j",
		// Tenant empty — fill from defaults
		Verified: true,
	}
	s := gateway.PolicySubjectFromHTTPInbound(in, contracts.ProfileID("corp"), defaults)
	if s.JenkinsUserID != "alice-j" {
		t.Fatalf("jenkins: %q", s.JenkinsUserID)
	}
	if s.ExternalSubject != "alice-sub" {
		t.Fatalf("external: %q", s.ExternalSubject)
	}
	if s.Tenant != "tenant-default" {
		t.Fatalf("tenant from defaults: %q", s.Tenant)
	}
	if s.WorkloadID != "wl-default" {
		t.Fatalf("workload from defaults: %q", s.WorkloadID)
	}
	if !s.Verified || !s.Valid() {
		t.Fatalf("expected valid verified: %+v", s)
	}
	if len(s.Groups) != 0 {
		t.Fatalf("must not inherit process groups: %v", s.Groups)
	}

	// Inbound groups map through with bounds (OAUTH-006 / GWY-002 residual lite).
	withGroups := gateway.HTTPInbound{
		ExternalSubject:  "alice-sub",
		JenkinsPrincipal: "alice-j",
		Groups:           []string{"ops", "dev", "ops"},
		Verified:         true,
	}
	sg := gateway.PolicySubjectFromHTTPInbound(withGroups, contracts.ProfileID("corp"), defaults)
	if len(sg.Groups) != 2 || sg.Groups[0] != "ops" || sg.Groups[1] != "dev" {
		t.Fatalf("inbound groups dedupe: %v", sg.Groups)
	}
	// Process groups still not merged in.
	for _, g := range sg.Groups {
		if g == "process-group" {
			t.Fatal("must not merge process groups")
		}
	}

	// Must not elevate JenkinsUserID from process defaults when inbound empty.
	partial := gateway.HTTPInbound{
		ExternalSubject: "eve-sub",
		Verified:        true,
	}
	s2 := gateway.PolicySubjectFromHTTPInbound(partial, "corp", defaults)
	if s2.JenkinsUserID != "" {
		t.Fatalf("must not elevate jenkins principal from process: %q", s2.JenkinsUserID)
	}
	if s2.Verified {
		t.Fatal("verified requires jenkins principal")
	}
	if s2.Valid() {
		t.Fatal("empty jenkins must be invalid")
	}

	// Anonymous principal stripped.
	anon := gateway.HTTPInbound{
		ExternalSubject:  "anon-sub",
		JenkinsPrincipal: policy.AnonymousJenkinsUser,
		Verified:         true,
	}
	s3 := gateway.PolicySubjectFromHTTPInbound(anon, "corp", defaults)
	if s3.JenkinsUserID != "" || s3.Verified {
		t.Fatalf("anonymous stripped: %+v", s3)
	}

	// Verified=false from untrusted path.
	untrusted := gateway.HTTPInbound{
		ExternalSubject:  "u-sub",
		JenkinsPrincipal: "u-j",
		Verified:         false,
	}
	s4 := gateway.PolicySubjectFromHTTPInbound(untrusted, "corp", defaults)
	if s4.Verified {
		t.Fatal("unverified inbound must not mark Verified")
	}
	if s4.JenkinsUserID != "u-j" {
		t.Fatalf("principal still set: %q", s4.JenkinsUserID)
	}
}

func TestPolicySubjectFromHTTPInbound_GroupOverageAndDenyOnly(t *testing.T) {
	t.Parallel()
	defaults := policy.Subject{
		ProfileID: contracts.ProfileID("corp"),
		Groups:    []string{"process-admin"},
	}

	// Overage with default fail-closed: groups dropped; process groups not used.
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
	s, meta, err := gateway.PolicySubjectFromHTTPInboundWithMeta(in, "corp", defaults, nil)
	if err == nil {
		t.Fatal("expected overage fail closed")
	}
	if len(s.Groups) != 0 {
		t.Fatalf("overage must drop groups: %v", s.Groups)
	}
	if meta.Count != 0 {
		t.Fatalf("meta: %+v", meta)
	}
	// Truncate mode keeps max groups.
	opts := gateway.BindOptions{MaxGroups: 3, FailOnGroupOverage: false}
	s2, meta2, err := gateway.PolicySubjectFromHTTPInboundWithMeta(in, "corp", defaults, &opts)
	if err != nil {
		t.Fatal(err)
	}
	if !meta2.Truncated || len(s2.Groups) != 3 {
		t.Fatalf("truncate: groups=%v meta=%+v", s2.Groups, meta2)
	}

	// Groups never elevate past deny_tools.
	subj := gateway.PolicySubjectFromHTTPInbound(gateway.HTTPInbound{
		ExternalSubject:  "alice-sub",
		JenkinsPrincipal: "alice-j",
		Groups:           []string{"admins", "ops"},
		Verified:         true,
	}, "corp", defaults)
	if len(subj.Groups) != 2 {
		t.Fatalf("groups: %v", subj.Groups)
	}
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:      policy.ModePilot,
		DenyTools: map[string]struct{}{"jenkins_get_build_logs": {}},
	})
	d := ev.Evaluate(subj, policy.Action{ToolName: "jenkins_get_build_logs", Class: policy.EffectRead}, policy.Target{})
	if !d.Denied() {
		t.Fatal("deny_tools must apply regardless of inbound groups")
	}
}

// Canary: helpers never embed secret-looking keys in StatusMap.
func TestPolicySubjectContext_NoSecretFields(t *testing.T) {
	t.Parallel()
	s := policy.Subject{JenkinsUserID: "u", ProfileID: "p", ExternalSubject: "e"}
	sm := s.StatusMap()
	blob := strings.ToLower(strings.Join(func() []string {
		var keys []string
		for k := range sm {
			keys = append(keys, k)
		}
		return keys
	}(), " "))
	for _, bad := range []string{"token", "password", "secret", "authorization"} {
		if strings.Contains(blob, bad) {
			t.Fatalf("status map key looks secret: %q in %v", bad, sm)
		}
	}
}
