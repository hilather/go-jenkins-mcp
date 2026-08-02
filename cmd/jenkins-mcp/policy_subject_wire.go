package main

import (
	"context"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/gateway"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

// policySubjectFromGatewayCtx builds the multi-user policy.Subject for
// tools.RegisterOptions.SubjectFromContext (HOST multi-user RBAC).
//
// tools does not import gateway (FND-004); serve wires this adapter instead of
// bare gateway.PolicySubjectFromContext so Obtain can rewrite JenkinsUserID.
//
// Preference order for JenkinsUserID (never tool args):
//  1. PrincipalCache after successful Obtain (SubjectKey → Mode A vault
//     username / Credential.JenkinsPrincipal recorded by AuthProviderCtx)
//  2. HTTP/lab PolicySubject.JenkinsUserID when present on context
//  3. empty — Valid() fails closed at Evaluate (never elevates to process default)
//
// When Caller is Valid and the process PrincipalCache has a non-empty,
// non-anonymous principal for SubjectKey(caller):
//   - JenkinsUserID is set to that principal (vault username wins over HTTP claim)
//   - Verified is set true (Obtain-confirmed principal; same non-empty /
//     non-anonymous bar as Valid for the Jenkins field)
//
// When the cache is empty/miss, prefer the HTTP/lab PolicySubject principal
// (and its Verified flag) when already stored on context. Caller-only contexts
// (no PolicySubject) still return ok=true with a skeleton subject so multi-user
// partial identity fails closed at Evaluate rather than elevating to the
// process RegisterOptions.Subject.
//
// Groups are never invented or elevated from process defaults; only fields
// already on the trusted PolicySubject (or non-secret Caller labels) are kept.
// Never returns tokens.
func policySubjectFromGatewayCtx(ctx context.Context) (policy.Subject, bool) {
	return policySubjectFromGatewayCtxWithCache(ctx, gateway.ProcessPrincipalCache())
}

// policySubjectFromGatewayCtxWithCache is the injectable variant for tests
// (private PrincipalCache). Production wire uses ProcessPrincipalCache.
func policySubjectFromGatewayCtxWithCache(ctx context.Context, cache gateway.PrincipalStore) (policy.Subject, bool) {
	if ctx == nil {
		return policy.Subject{}, false
	}
	s, hasPS := gateway.PolicySubjectFromContext(ctx)
	c, hasCaller := gateway.CallerFromContext(ctx)
	callerOK := hasCaller && c.Valid()
	if !hasPS && !callerOK {
		return policy.Subject{}, false
	}

	// Start from trusted PolicySubject when present; else skeleton from Caller.
	if !hasPS {
		s = policy.Subject{
			ProfileID:       c.ProfileID,
			ExternalSubject: strings.TrimSpace(c.Subject),
			Tenant:          strings.TrimSpace(c.Tenant),
			WorkloadID:      strings.TrimSpace(c.WorkloadID),
		}
	} else if callerOK {
		// Fill identity gaps from Caller without elevating JenkinsUserID or Groups.
		if strings.TrimSpace(string(s.ProfileID)) == "" {
			s.ProfileID = c.ProfileID
		}
		if strings.TrimSpace(s.ExternalSubject) == "" {
			s.ExternalSubject = strings.TrimSpace(c.Subject)
		}
		if strings.TrimSpace(s.Tenant) == "" {
			s.Tenant = strings.TrimSpace(c.Tenant)
		}
		if strings.TrimSpace(s.WorkloadID) == "" {
			s.WorkloadID = strings.TrimSpace(c.WorkloadID)
		}
	}

	// JenkinsUserID preference (1) PrincipalCache after Obtain.
	if callerOK && cache != nil {
		if p, ok := cache.Get(gateway.SubjectKey(c)); ok {
			p = strings.TrimSpace(p)
			if p != "" && !strings.EqualFold(p, policy.AnonymousJenkinsUser) {
				s.JenkinsUserID = p
				// Obtain-confirmed principal: verified when non-empty non-anonymous.
				s.Verified = true
				return s, true
			}
		}
	}

	// (2) HTTP/lab PolicySubject.JenkinsUserID when present; (3) empty.
	// Normalize anonymous → empty so Valid() fails closed.
	if strings.EqualFold(strings.TrimSpace(s.JenkinsUserID), policy.AnonymousJenkinsUser) {
		s.JenkinsUserID = ""
		s.Verified = false
	}
	return s, true
}
