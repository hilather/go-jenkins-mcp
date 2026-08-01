package main

import (
	"context"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
	"github.com/simonfxr/go-jenkins-mcp/internal/mutation"
)

// mutationBindingFromGatewayCtx builds the multi-user mutation confirm Binding
// from trusted request context (HOST-006 / MUT-001).
//
// Preference order (never tool args):
//  1. policy.Subject when present and Valid — PrincipalID = JenkinsUserID
//     (from HTTP JenkinsPrincipal claim / lab header X-Jenkins-MCP-Lab-Jenkins-Principal;
//     Mode A vault multi-user should send that header matching vault username).
//     ProfileID / ExternalSubject / Tenant come from the same subject.
//  2. gateway.Caller when Valid — ExternalSubject/Tenant/Profile from Caller;
//     PrincipalID prefers PrincipalCache (SubjectKey → Obtain/Mode A vault
//     username recorded by AuthProviderCtx) when non-empty, else processPrincipal
//     (session-start / process Jenkins user). AuthProviderCtx cannot write onto
//     request context; PrincipalCache is the mid-call rewrite path (Binding here;
//     policy RBAC via policySubjectFromGatewayCtx prefers cache after Obtain).
//
// ok is false when neither trusted source is usable.
func mutationBindingFromGatewayCtx(ctx context.Context, processPrincipal string) (mutation.Binding, bool) {
	return mutationBindingFromGatewayCtxWithCache(ctx, processPrincipal, gateway.ProcessPrincipalCache())
}

// mutationBindingFromGatewayCtxWithCache is the injectable variant for tests.
func mutationBindingFromGatewayCtxWithCache(ctx context.Context, processPrincipal string, cache *gateway.PrincipalCache) (mutation.Binding, bool) {
	processPrincipal = strings.TrimSpace(processPrincipal)
	if s, ok := gateway.PolicySubjectFromContext(ctx); ok && s.Valid() {
		return mutation.Binding{
			ProfileID:       strings.TrimSpace(string(s.ProfileID)),
			PrincipalID:     strings.TrimSpace(s.JenkinsUserID),
			ExternalSubject: strings.TrimSpace(s.ExternalSubject),
			Tenant:          strings.TrimSpace(s.Tenant),
		}, true
	}
	if c, ok := gateway.CallerFromContext(ctx); ok && c.Valid() {
		// Prefer non-empty Profile/External/Tenant from PolicySubject when present
		// even if !Valid (e.g. inbound without Jenkins principal yet), else Caller.
		profileID := strings.TrimSpace(string(c.ProfileID))
		ext := strings.TrimSpace(c.Subject)
		tenant := strings.TrimSpace(c.Tenant)
		if s, ok := gateway.PolicySubjectFromContext(ctx); ok {
			if p := strings.TrimSpace(string(s.ProfileID)); p != "" {
				profileID = p
			}
			if e := strings.TrimSpace(s.ExternalSubject); e != "" {
				ext = e
			}
			if t := strings.TrimSpace(s.Tenant); t != "" {
				tenant = t
			}
			// Principal only from Valid PolicySubject (handled above). !Valid
			// subject does not elevate; Obtain principal may still come from cache.
		}
		principalID := processPrincipal
		if cache != nil {
			if p, ok := cache.Get(gateway.SubjectKey(c)); ok && strings.TrimSpace(p) != "" {
				principalID = strings.TrimSpace(p)
			}
		}
		return mutation.Binding{
			ProfileID:       profileID,
			PrincipalID:     principalID,
			ExternalSubject: ext,
			Tenant:          tenant,
		}, true
	}
	return mutation.Binding{}, false
}
