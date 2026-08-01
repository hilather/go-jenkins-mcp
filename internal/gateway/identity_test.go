package gateway_test

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/contracts"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

func itoa(i int) string { return strconv.Itoa(i) }

func TestBindSubject_OK(t *testing.T) {
	t.Parallel()
	s, err := gateway.BindSubject(gateway.InboundClaims{
		Subject:          "entra-sub",
		Tenant:           "tid",
		WorkloadID:       "wl-1",
		JenkinsPrincipal: "alice",
		ProfileID:        "corp",
		Groups:           []string{"g1", "g2", "g1"},
		Verified:         true,
	}, gateway.DefaultBindOptions())
	if err != nil {
		t.Fatal(err)
	}
	if s.ExternalSubject != "entra-sub" || s.JenkinsUserID != "alice" {
		t.Fatalf("%+v", s)
	}
	if s.Tenant != "tid" || s.WorkloadID != "wl-1" {
		t.Fatalf("%+v", s)
	}
	if !s.Verified || !s.Valid() {
		t.Fatalf("%+v", s)
	}
	if len(s.Groups) != 2 {
		t.Fatalf("groups dedupe: %v", s.Groups)
	}
	m := s.StatusMap()
	if m["has_tenant"] != true || m["group_count"] != 2 {
		t.Fatalf("%v", m)
	}
}

func TestBindSubject_MissingRequired_Table(t *testing.T) {
	t.Parallel()
	opts := gateway.DefaultBindOptions()
	base := gateway.InboundClaims{
		Subject:    "s",
		Tenant:     "t",
		WorkloadID: "w",
		ProfileID:  "corp",
		Verified:   true,
	}
	tests := []struct {
		name    string
		mutate  func(c gateway.InboundClaims) gateway.InboundClaims
		opts    gateway.BindOptions
		wantSub string // substring in error
	}{
		{
			name: "missing_subject",
			mutate: func(c gateway.InboundClaims) gateway.InboundClaims {
				c.Subject = ""
				return c
			},
			opts:    opts,
			wantSub: "subject",
		},
		{
			name: "missing_profile",
			mutate: func(c gateway.InboundClaims) gateway.InboundClaims {
				c.ProfileID = ""
				return c
			},
			opts:    opts,
			wantSub: "profile",
		},
		{
			name: "missing_tenant",
			mutate: func(c gateway.InboundClaims) gateway.InboundClaims {
				c.Tenant = ""
				return c
			},
			opts:    opts,
			wantSub: "tenant",
		},
		{
			name: "missing_workload",
			mutate: func(c gateway.InboundClaims) gateway.InboundClaims {
				c.WorkloadID = ""
				return c
			},
			opts:    opts,
			wantSub: "workload",
		},
		{
			name: "not_verified",
			mutate: func(c gateway.InboundClaims) gateway.InboundClaims {
				c.Verified = false
				return c
			},
			opts:    opts,
			wantSub: "verified",
		},
		{
			name: "missing_jenkins_when_required",
			mutate: func(c gateway.InboundClaims) gateway.InboundClaims {
				c.JenkinsPrincipal = ""
				return c
			},
			opts: func() gateway.BindOptions {
				o := opts
				o.RequireJenkinsPrincipal = true
				return o
			}(),
			wantSub: "jenkins principal",
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := gateway.BindSubject(tc.mutate(base), tc.opts)
			if err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
				t.Fatalf("want authentication error, got %v", err)
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.wantSub)) {
				t.Fatalf("error %q should mention %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestBindSubject_AnonymousJenkins(t *testing.T) {
	t.Parallel()
	_, err := gateway.BindSubject(gateway.InboundClaims{
		Subject: "s", Tenant: "t", WorkloadID: "w", ProfileID: "corp",
		JenkinsPrincipal: "anonymous", Verified: true,
	}, gateway.DefaultBindOptions())
	if err == nil {
		t.Fatal("expected anonymous reject")
	}
}

func TestBindSubject_JenkinsPrincipalMismatch(t *testing.T) {
	t.Parallel()
	opts := gateway.DefaultBindOptions()
	opts.RequireJenkinsPrincipal = true
	opts.ExpectedJenkinsPrincipal = "alice"
	_, err := gateway.BindSubject(gateway.InboundClaims{
		Subject: "s", Tenant: "t", WorkloadID: "w", ProfileID: "corp",
		JenkinsPrincipal: "bob", Verified: true,
	}, opts)
	if err == nil || !strings.Contains(err.Error(), "whoAmI") {
		t.Fatalf("expected mismatch deny: %v", err)
	}
	// Match succeeds and Valid() for RBAC.
	s, err := gateway.BindSubject(gateway.InboundClaims{
		Subject: "s", Tenant: "t", WorkloadID: "w", ProfileID: "corp",
		JenkinsPrincipal: "alice", Verified: true,
	}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Valid() || s.JenkinsUserID != "alice" {
		t.Fatalf("%+v", s)
	}
}

func TestBindSubject_ValidOnlyWithJenkinsPrincipal(t *testing.T) {
	t.Parallel()
	// Binding can succeed without Jenkins principal (RequireJenkinsPrincipal=false),
	// but Subject.Valid() remains false — not RBAC-ready.
	s, err := gateway.BindSubject(gateway.InboundClaims{
		Subject: "s", Tenant: "t", WorkloadID: "w", ProfileID: "corp",
		Verified: true,
	}, gateway.DefaultBindOptions())
	if err != nil {
		t.Fatal(err)
	}
	if s.Valid() {
		t.Fatal("Valid() must be false without Jenkins principal")
	}
	if s.Verified {
		t.Fatal("Verified must be false without Jenkins principal")
	}
	s2, err := gateway.BindSubject(gateway.InboundClaims{
		Subject: "s", Tenant: "t", WorkloadID: "w", ProfileID: "corp",
		JenkinsPrincipal: "alice", Verified: true,
	}, gateway.DefaultBindOptions())
	if err != nil {
		t.Fatal(err)
	}
	if !s2.Valid() || !s2.Verified {
		t.Fatalf("RBAC-ready subject expected: %+v", s2)
	}
}

func TestBindSubject_GroupOverage(t *testing.T) {
	t.Parallel()
	groups := make([]string, gateway.MaxInboundGroups+1)
	for i := range groups {
		groups[i] = "group-" + itoa(i)
	}
	opts := gateway.DefaultBindOptions()
	_, err := gateway.BindSubject(gateway.InboundClaims{
		Subject: "s", Tenant: "t", WorkloadID: "w", ProfileID: "corp",
		Groups: groups, Verified: true,
	}, opts)
	if err == nil {
		t.Fatal("expected overage fail")
	}
	if !strings.Contains(err.Error(), "bound of") {
		t.Fatalf("overage wording: %v", err)
	}
	opts.FailOnGroupOverage = false
	s, meta, err := gateway.BindSubjectWithMeta(gateway.InboundClaims{
		Subject: "s", Tenant: "t", WorkloadID: "w", ProfileID: "corp",
		Groups: groups, Verified: true, JenkinsPrincipal: "alice",
	}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Groups) > gateway.MaxInboundGroups {
		t.Fatalf("truncate: %d", len(s.Groups))
	}
	if !meta.Truncated || meta.ResidualNote == "" {
		t.Fatalf("expected residual on truncate: %+v", meta)
	}
	if meta.Count != gateway.MaxInboundGroups {
		t.Fatalf("count: %d", meta.Count)
	}
	if !strings.Contains(meta.ResidualNote, "group_overage_truncated") {
		t.Fatalf("residual: %s", meta.ResidualNote)
	}
	// Custom MaxGroups.
	opts.MaxGroups = 3
	opts.FailOnGroupOverage = true
	_, err = gateway.BindSubject(gateway.InboundClaims{
		Subject: "s", Tenant: "t", WorkloadID: "w", ProfileID: "corp",
		Groups: []string{"a", "b", "c", "d"}, Verified: true,
	}, opts)
	if err == nil {
		t.Fatal("expected custom MaxGroups fail")
	}
}

func TestBindSubject_GroupNameTooLong(t *testing.T) {
	t.Parallel()
	longName := strings.Repeat("x", gateway.MaxInboundGroupNameBytes+1)
	_, err := gateway.BindSubject(gateway.InboundClaims{
		Subject: "s", Tenant: "t", WorkloadID: "w", ProfileID: "corp",
		Groups: []string{longName}, Verified: true,
	}, gateway.DefaultBindOptions())
	if err == nil || !strings.Contains(err.Error(), "length bound") {
		t.Fatalf("expected name length fail: %v", err)
	}
}

func TestBindSubject_IgnoresToolArgsShape(t *testing.T) {
	t.Parallel()
	// Regression: BindSubject has no tool-args parameter; identity comes only
	// from InboundClaims. Attacker-shaped maps are rejected separately and
	// must not be confusable with claims construction.
	claims := gateway.InboundClaims{
		Subject: "real-sub", Tenant: "tid", WorkloadID: "wl",
		JenkinsPrincipal: "alice", ProfileID: "corp", Verified: true,
	}
	// Tool args with spoof keys must fail closed via RejectIdentityToolArgs.
	toolArgs := map[string]any{
		"subject":      "attacker-sub",
		"jenkins_user": "eve",
		"tenant":       "evil-tenant",
		"workload_id":  "evil-wl",
		"as_user":      "root",
		"job":          "harmless",
	}
	if err := gateway.RejectIdentityToolArgs(toolArgs); err == nil {
		t.Fatal("expected tool-arg identity rejection")
	}
	// BindSubject uses claims only — not the toolArgs map.
	s, err := gateway.BindSubject(claims, gateway.DefaultBindOptions())
	if err != nil {
		t.Fatal(err)
	}
	if s.ExternalSubject != "real-sub" || s.JenkinsUserID != "alice" || s.Tenant != "tid" {
		t.Fatalf("claims only: %+v", s)
	}
	if !s.Valid() {
		t.Fatal("expected valid subject from claims")
	}
}

func TestBindSubjectFromEnviron(t *testing.T) {
	t.Parallel()
	env := map[string]string{
		gateway.EnvGatewaySubject:  "entra-sub",
		gateway.EnvGatewayTenant:   "tid",
		gateway.EnvGatewayWorkload: "wl-1",
	}
	getenv := func(k string) string { return env[k] }

	s, err := gateway.BindSubjectFromEnviron("corp", "alice", getenv)
	if err != nil {
		t.Fatal(err)
	}
	if s.ExternalSubject != "entra-sub" || s.JenkinsUserID != "alice" || !s.Valid() {
		t.Fatalf("%+v", s)
	}

	// Env principal matches whoAmI.
	env[gateway.EnvGatewayJenkinsPrincipal] = "alice"
	s, err = gateway.BindSubjectFromEnviron("corp", "alice", getenv)
	if err != nil {
		t.Fatal(err)
	}
	if s.JenkinsUserID != "alice" {
		t.Fatalf("%+v", s)
	}

	// Env principal disagrees with whoAmI → deny.
	env[gateway.EnvGatewayJenkinsPrincipal] = "bob"
	_, err = gateway.BindSubjectFromEnviron("corp", "alice", getenv)
	if err == nil || !strings.Contains(err.Error(), "whoAmI") {
		t.Fatalf("mismatch: %v", err)
	}

	// Missing tenant fails closed.
	delete(env, gateway.EnvGatewayTenant)
	env[gateway.EnvGatewayJenkinsPrincipal] = ""
	_, err = gateway.BindSubjectFromEnviron("corp", "alice", getenv)
	if err == nil || !strings.Contains(err.Error(), "tenant") {
		t.Fatalf("tenant: %v", err)
	}
}

func TestBindSubjectFromEnviron_MissingFields_Table(t *testing.T) {
	t.Parallel()
	full := map[string]string{
		gateway.EnvGatewaySubject:  "sub",
		gateway.EnvGatewayTenant:   "tid",
		gateway.EnvGatewayWorkload: "wl",
	}
	tests := []struct {
		name    string
		omit    string
		wantSub string
	}{
		{"missing_subject", gateway.EnvGatewaySubject, "subject"},
		{"missing_tenant", gateway.EnvGatewayTenant, "tenant"},
		{"missing_workload", gateway.EnvGatewayWorkload, "workload"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env := make(map[string]string, len(full))
			for k, v := range full {
				if k == tc.omit {
					continue
				}
				env[k] = v
			}
			_, err := gateway.BindSubjectFromEnviron("corp", "alice", func(k string) string { return env[k] })
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), tc.wantSub) {
				t.Fatalf("want %q in error, got %v", tc.wantSub, err)
			}
		})
	}
	// Missing profile fails.
	_, err := gateway.BindSubjectFromEnviron("", "alice", func(k string) string { return full[k] })
	if err == nil || !strings.Contains(err.Error(), "profile") {
		t.Fatalf("profile: %v", err)
	}
}

func TestRejectIdentityToolArgs(t *testing.T) {
	t.Parallel()
	if err := gateway.RejectIdentityToolArgs(map[string]any{"job": "foo"}); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"subject", "jenkins_user", "tenant", "impersonate", "workloadId"} {
		err := gateway.RejectIdentityToolArgs(map[string]any{k: "attacker"})
		if err == nil || apperr.CodeOf(err) != apperr.CodePolicyDenial {
			t.Fatalf("%s: %v", k, err)
		}
	}
}

func TestBinding_RevalidateMismatch(t *testing.T) {
	t.Parallel()
	claims := gateway.InboundClaims{
		Subject: "s1", Tenant: "t", WorkloadID: "w", ProfileID: "corp",
		JenkinsPrincipal: "alice", Verified: true,
	}
	b, err := gateway.NewBinding(claims, gateway.DefaultBindOptions(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !b.Fresh() {
		t.Fatal("fresh")
	}
	// Same claims OK.
	if _, err := b.Revalidate(claims, gateway.DefaultBindOptions()); err != nil {
		t.Fatal(err)
	}
	// Identity change fails closed.
	changed := claims
	changed.Subject = "s2"
	_, err = b.Revalidate(changed, gateway.DefaultBindOptions())
	if err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("got %v", err)
	}
}

func TestBinding_TTLExpiryRebind(t *testing.T) {
	t.Parallel()
	claims := gateway.InboundClaims{
		Subject: "s1", Tenant: "t", WorkloadID: "w", ProfileID: contracts.ProfileID("corp"),
		JenkinsPrincipal: "alice", Verified: true,
	}
	b, err := gateway.NewBinding(claims, gateway.DefaultBindOptions(), time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	// Expired but same claims: re-bind succeeds.
	s, err := b.Revalidate(claims, gateway.DefaultBindOptions())
	if err != nil {
		t.Fatal(err)
	}
	if s.JenkinsUserID != "alice" {
		t.Fatalf("%+v", s)
	}
}

func TestGatewaySubject_CannotBypassDenyOnlyOrRO(t *testing.T) {
	t.Parallel()
	// GWY-002: gateway-bound subject still subject to deny-only + read-only.
	subj, err := gateway.BindSubject(gateway.InboundClaims{
		Subject: "admin-entra", Tenant: "t", WorkloadID: "w",
		JenkinsPrincipal: "jenkins-admin", ProfileID: "corp",
		Groups: []string{"admins"}, Verified: true,
	}, gateway.DefaultBindOptions())
	if err != nil {
		t.Fatal(err)
	}
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:      policy.ModePilot,
		DenyTools: map[string]struct{}{"jenkins_get_build_logs": {}},
	})
	d := ev.Evaluate(subj, policy.Action{ToolName: "jenkins_get_build_logs", Class: policy.EffectRead}, policy.Target{})
	if !d.Denied() {
		t.Fatal("deny_tools must still deny gateway subject")
	}
	gate := policy.NewReadOnlyGate(policy.Inputs{}) // builtin default RO
	if err := policy.CheckToolAccess(context.Background(), gate, ev, subj, "jenkins_build_job", policy.EffectMutate); err == nil {
		t.Fatal("RO must deny mutations for gateway subject")
	} else if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code %v err %v", apperr.CodeOf(err), err)
	}
	// Tool-arg identity override rejected before policy.
	if err := gateway.RejectIdentityToolArgs(map[string]any{"as_user": "other"}); err == nil {
		t.Fatal("expected identity arg rejection")
	}
}
