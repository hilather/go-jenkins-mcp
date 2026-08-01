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
//     PrincipalID falls back to processPrincipal (session-start / process Jenkins
//     user). AuthProviderCtx cannot re-inject Obtain JenkinsPrincipal onto ctx
//     after whoAmI mid-call — that remains a residual; multi-user principal for
//     Binding is the HTTP claim / lab path (goal 2).
//
// ok is false when neither trusted source is usable.
func mutationBindingFromGatewayCtx(ctx context.Context, processPrincipal string) (mutation.Binding, bool) {
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
			// Principal only from subject when Valid (handled above). Residual:
			// non-empty JenkinsUserID with empty Profile is not Valid — keep process.
		}
		return mutation.Binding{
			ProfileID:       profileID,
			PrincipalID:     processPrincipal,
			ExternalSubject: ext,
			Tenant:          tenant,
		}, true
	}
	return mutation.Binding{}, false
}
