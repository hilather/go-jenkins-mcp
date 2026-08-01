package policy

import (
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/contracts"
)

// AnonymousJenkinsUser is rejected as a policy subject (POL-003).
const AnonymousJenkinsUser = "anonymous"

// Subject is the trusted identity used for MCP policy evaluation (POL-003).
//
// Subjects MUST be built from verified principals (profile + Jenkins user),
// never from MCP tool arguments, model text, or untrusted headers.
// AUTH-004 will strengthen verification; until then callers may mark
// Verified=false for provisional session usernames (fail closed for RBAC).
//
// Gateway fields (Tenant, WorkloadID, Groups) are set only by the gateway
// identity binder (GWY-002). They never elevate MCP deny-only or read-only.
type Subject struct {
	// ProfileID is the connection profile that authenticated this principal.
	ProfileID contracts.ProfileID

	// JenkinsUserID is the verified (or provisional) Jenkins principal label.
	// Empty or "anonymous" is never a valid policy subject.
	JenkinsUserID string

	// ExternalSubject is an optional validated external IdP subject (OAuth later).
	// Empty for API-token mode. Gateway mode sets Entra/OIDC sub here (GWY-002).
	ExternalSubject string

	// Verified is true only when JenkinsUserID was confirmed via an approved
	// identity endpoint (AUTH-004) or gateway-exchanged Jenkins principal.
	// Provisional session usernames must leave this false; RequireVerified
	// evaluation rejects them.
	Verified bool

	// Tenant is the optional IdP tenant id (gateway / OAuth). Empty for API-token.
	Tenant string

	// WorkloadID is the optional AgentCore / gateway workload identity (GWY-002).
	WorkloadID string

	// Groups is an optional bounded list of IdP group/role ids (gateway).
	// Never used to grant tools denied by MCP deny-only or force_read_only.
	Groups []string
}

// NewSubject builds a subject from trusted process identity inputs.
// It does not accept tool arguments — call sites must pass values from the
// auth session / identity verification path only.
func NewSubject(profileID contracts.ProfileID, jenkinsUserID string, verified bool) Subject {
	return Subject{
		ProfileID:     profileID,
		JenkinsUserID: strings.TrimSpace(jenkinsUserID),
		Verified:      verified,
	}
}

// WithExternal returns a copy with an optional external IdP subject attached.
func (s Subject) WithExternal(external string) Subject {
	s.ExternalSubject = strings.TrimSpace(external)
	return s
}

// WithGateway returns a copy with optional gateway identity fields (GWY-002).
// groups is copied; callers may pass nil.
func (s Subject) WithGateway(tenant, workloadID string, groups []string) Subject {
	s.Tenant = strings.TrimSpace(tenant)
	s.WorkloadID = strings.TrimSpace(workloadID)
	if len(groups) > 0 {
		s.Groups = append([]string(nil), groups...)
	} else {
		s.Groups = nil
	}
	return s
}

// IsEmpty reports whether the subject lacks a Jenkins principal.
func (s Subject) IsEmpty() bool {
	return strings.TrimSpace(s.JenkinsUserID) == ""
}

// IsAnonymous reports whether the principal is the Jenkins anonymous user.
func (s Subject) IsAnonymous() bool {
	return strings.EqualFold(strings.TrimSpace(s.JenkinsUserID), AnonymousJenkinsUser)
}

// Valid reports whether the subject has a non-empty, non-anonymous Jenkins
// principal and a non-empty profile id (POL-003 minimum binding).
func (s Subject) Valid() bool {
	if s.IsEmpty() || s.IsAnonymous() {
		return false
	}
	if strings.TrimSpace(string(s.ProfileID)) == "" {
		return false
	}
	return true
}

// StatusMap is a non-secret identity summary for status/doctor/audit.
// Never includes tokens or secrets.
func (s Subject) StatusMap() map[string]any {
	return map[string]any{
		"profile_id":    string(s.ProfileID),
		"jenkins_user":  s.JenkinsUserID,
		"verified":      s.Verified,
		"has_external":  s.ExternalSubject != "",
		"has_tenant":    strings.TrimSpace(s.Tenant) != "",
		"has_workload":  strings.TrimSpace(s.WorkloadID) != "",
		"group_count":   len(s.Groups),
		"subject_valid": s.Valid(),
	}
}
