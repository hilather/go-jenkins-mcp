package resourcecache

import "context"

// AuthorizationScope is the intended share boundary for a cache entry.
type AuthorizationScope string

const (
	// ScopeSubjectPrivate: only the verifying subject may reuse (default).
	ScopeSubjectPrivate AuthorizationScope = "subject_private"
	// ScopeProfileShared: any subject on the same profile after revalidation.
	ScopeProfileShared AuthorizationScope = "profile_shared"
	// ScopeFleetShared: fleet-eligible (default-off until protocol v2 ships).
	ScopeFleetShared AuthorizationScope = "fleet_shared"
)

// AccessContext is required on every cache read/fetch. Cache presence is not access.
type AccessContext struct {
	// SubjectKey is a non-secret subject handle (hash or verified id), never a token.
	SubjectKey string
	// PrincipalID is the verified Jenkins/IdP principal label (non-secret).
	PrincipalID string
	// ProfileID is the connection profile id.
	ProfileID string
	// Groups are verified group ids for policy (optional).
	Groups []string
}

// AuthorizationVerifier re-validates job/artifact/member policy on hit and miss.
// Implementations call MCP policy + Jenkins ACL proofs. Deny must fail closed.
// Authorization denials must not be stored as shared tombstones.
type AuthorizationVerifier interface {
	// AuthorizeJob fails closed if the subject may not access the job.
	AuthorizeJob(ctx context.Context, ac AccessContext, jobFullName string) error
	// AuthorizeArtifact fails closed if the subject may not access the artifact path.
	// Empty path ⇒ job-level only (catalogs/stages/tests/changes).
	AuthorizeArtifact(ctx context.Context, ac AccessContext, jobFullName, artifactPath string) error
}

// AllowAllVerifier is a test/dev verifier that always allows (never production default).
type AllowAllVerifier struct{}

func (AllowAllVerifier) AuthorizeJob(context.Context, AccessContext, string) error {
	return nil
}
func (AllowAllVerifier) AuthorizeArtifact(context.Context, AccessContext, string, string) error {
	return nil
}
