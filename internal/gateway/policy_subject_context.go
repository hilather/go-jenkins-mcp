package gateway

import (
	"context"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/contracts"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

// policySubjectCtxKey stores a per-request policy.Subject for multi-user RBAC
// rebind (HOST multi-user residual close). Never secrets.
type policySubjectCtxKey struct{}

// ContextWithPolicySubject returns a child context carrying a trusted
// policy.Subject for deny-only MCP RBAC (multi-user). Subject must be built
// only from verified/lab/JWT identity paths — never tool arguments.
// Nil parent becomes context.Background().
func ContextWithPolicySubject(ctx context.Context, s policy.Subject) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, policySubjectCtxKey{}, s)
}

// PolicySubjectFromContext returns the policy.Subject previously stored by
// ContextWithPolicySubject (or HTTP AfterIdentity wire). ok is false when unset.
// When ok is true the subject may still be !Valid() (fail closed at Evaluate).
// Never contains tokens.
func PolicySubjectFromContext(ctx context.Context) (policy.Subject, bool) {
	if ctx == nil {
		return policy.Subject{}, false
	}
	s, ok := ctx.Value(policySubjectCtxKey{}).(policy.Subject)
	if !ok {
		return policy.Subject{}, false
	}
	return s, true
}

// ContextWithCallerAndPolicySubject stores both gateway.Caller (Obtain) and
// policy.Subject (RBAC) on the request context for multi-user HTTP serve.
// Prefer this over separate With* calls so AfterIdentity stays atomic.
func ContextWithCallerAndPolicySubject(ctx context.Context, c Caller, s policy.Subject) context.Context {
	return ContextWithPolicySubject(ContextWithCaller(ctx, c), s)
}

// PolicySubjectFromHTTPInbound maps trusted HTTPInbound + process profile to
// policy.Subject for multi-user RBAC rebind (GWY-002 / HOST / OAUTH-006 lite).
//
// Rules (never tool args):
//   - ProfileID is always the process profile (defaults when inbound empty).
//   - JenkinsUserID is only from JenkinsPrincipal — never elevated from process
//     defaults (prevents Alice inheriting process Bob's RBAC principal).
//   - ExternalSubject from inbound (required for multi-user identity).
//   - Tenant / WorkloadID fill from defaults when inbound empty (same as
//     MergeCallerDefaults).
//   - Groups come only from inbound (JWT groups/roles or lab header). Never
//     inherited from process defaults for a different ExternalSubject.
//     Bounded with MaxInboundGroups / MaxInboundGroupNameBytes and
//     FailOnGroupOverage=true (production gateway default). On count overage or
//     oversize name, groups are dropped (empty) so unbounded claims cannot
//     attach — cannot broaden deny-only / RO.
//   - Entra group overage without a full groups claim fails earlier at
//     ValidateAccessToken / ResolveHTTPInbound (auth.CheckIncompleteGroupOverage)
//     so multi-user JWT subjects never bind with invented empty membership.
//     Microsoft Graph membership expansion remains residual (OAUTH-010).
//   - Verified is true only when inbound.Verified and JenkinsUserID is non-empty
//     and non-anonymous.
func PolicySubjectFromHTTPInbound(in HTTPInbound, profileID contracts.ProfileID, defaults policy.Subject) policy.Subject {
	s, _, _ := PolicySubjectFromHTTPInboundWithMeta(in, profileID, defaults, nil)
	return s
}

// PolicySubjectFromHTTPInboundWithMeta is PolicySubjectFromHTTPInbound plus
// group overage residual metadata and optional BindOptions for group bounds.
// opts nil uses MaxInboundGroups + FailOnGroupOverage=true (gateway default).
// Group bind errors yield Groups=nil (fail closed for elevation; subject
// otherwise still built for audit / Obtain caller path).
func PolicySubjectFromHTTPInboundWithMeta(
	in HTTPInbound,
	profileID contracts.ProfileID,
	defaults policy.Subject,
	opts *BindOptions,
) (policy.Subject, GroupMeta, error) {
	pid := contracts.ProfileID(strings.TrimSpace(string(profileID)))
	if pid == "" {
		pid = contracts.ProfileID(strings.TrimSpace(string(defaults.ProfileID)))
	}
	jenkins := strings.TrimSpace(in.JenkinsPrincipal)
	if strings.EqualFold(jenkins, policy.AnonymousJenkinsUser) {
		jenkins = ""
	}
	tenant := strings.TrimSpace(in.Tenant)
	if tenant == "" {
		tenant = strings.TrimSpace(defaults.Tenant)
	}
	workload := strings.TrimSpace(in.WorkloadID)
	if workload == "" {
		workload = strings.TrimSpace(defaults.WorkloadID)
	}
	verified := in.Verified && jenkins != ""

	maxGroups := MaxInboundGroups
	failOverage := true
	if opts != nil {
		if opts.MaxGroups > 0 {
			maxGroups = opts.MaxGroups
		}
		failOverage = opts.FailOnGroupOverage
	}
	groups, meta, gerr := boundGroups(in.Groups, maxGroups, failOverage)
	// On group bind error: fail closed for elevation — Groups stay nil; do not
	// inherit process Groups. Other subject fields still built for audit/Obtain.
	if gerr != nil {
		groups = nil
		meta = GroupMeta{}
	}
	return policy.Subject{
		ProfileID:       pid,
		JenkinsUserID:   jenkins,
		ExternalSubject: strings.TrimSpace(in.ExternalSubject),
		Verified:        verified,
		Tenant:          tenant,
		WorkloadID:      workload,
		Groups:          groups,
	}, meta, gerr
}
