package gateway

import (
	"context"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

// CallerFromBoundSubject builds a gateway.Caller from a bound policy.Subject (HOST-003).
// Identity fields come only from the subject (GWY-002) — never tool arguments.
// Subject maps ExternalSubject → Caller.Subject (Entra/OIDC sub).
func CallerFromBoundSubject(s policy.Subject) Caller {
	return Caller{
		Subject:    strings.TrimSpace(s.ExternalSubject),
		Tenant:     strings.TrimSpace(s.Tenant),
		WorkloadID: strings.TrimSpace(s.WorkloadID),
		ProfileID:  s.ProfileID,
	}
}

// ObtainHTTPAuth is the HOST-003 Obtain → Jenkins HTTP auth mapping.
//
// Fail closed: nil provider, Obtain error, empty token, or mapping failure
// return an error. Never falls back to ambient keyring, another subject, or a
// shared Jenkins service account. Secrets must never appear in returned errors.
func ObtainHTTPAuth(ctx context.Context, p CredentialProvider, caller Caller) (HTTPAuth, error) {
	if err := ctx.Err(); err != nil {
		return HTTPAuth{}, apperr.Wrap(apperr.CodeCancelled, "gateway credential obtain cancelled", err)
	}
	if p == nil {
		return HTTPAuth{}, notConfigured("gateway credential provider is nil")
	}
	cred, err := p.Obtain(ctx, caller)
	if err != nil {
		return HTTPAuth{}, err
	}
	return HTTPAuthFromCredential(cred)
}
