package auth

import (
	"context"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/contracts"
)

// Method identifies how credentials were obtained for a profile.
type Method string

const (
	// MethodAPIToken is personal Jenkins user:api_token via keyring (first path).
	MethodAPIToken Method = "api_token"
	// MethodOIDC is reserved for OAuth/OIDC PKCE flows (later epics).
	MethodOIDC Method = "oidc"
)

// Profile is a non-secret view of a connection profile used by credential providers.
// Full profile persistence lives in package profile; this keeps auth free of storage I/O.
type Profile struct {
	ID  contracts.ProfileID
	URL string
	// User is the Jenkins principal label (not a secret). Required for api_token keyring lookup.
	User string

	// Non-secret OIDC fields for refresh/logout (OAUTH-004 / OAUTH-007).
	// Never include client secrets or tokens here.
	OIDCIssuer             string
	OIDCClientID           string
	OIDCTokenEndpoint      string // optional; discovery used when empty and Issuer set
	OIDCRevocationEndpoint string // optional; best-effort revoke on logout
}

// Session is a short-lived, in-memory auth session. It must not be logged or
// serialized into MCP output. Token material is intentionally not a package-level
// global string (FND-004 / AUTH-001).
type Session struct {
	ProfileID contracts.ProfileID
	Method    Method
	User      string
	// Secret is memory-only credential material (api token or access token).
	// Callers must not put Secret into logs, errors, or CLI argv.
	Secret    string
	ExpiresAt time.Time
	// Principal is the verified Jenkins identity when AUTH-004 verification
	// has bound this session. Never contains secrets.
	Principal Principal
}

// Status is a sanitized view safe for status commands and diagnostics.
// It must never include tokens or other secret material (AUTH-003 / OAUTH-007).
type Status struct {
	ProfileID         contracts.ProfileID
	Method            Method
	Authenticated     bool
	HasCredential     bool   // keyring (or session) has material; never the token itself
	HasRefresh        bool   // OIDC: refresh token present (bool only; never the token)
	User              string // configured / session username label; never the token
	PrincipalID       string // last verified whoAmI id (empty if not verified/stored)
	PrincipalFullName string
	ExpiresAt         time.Time
	ErrorCode         string // stable apperr code when not authenticated
	ErrorMessageSafe  string
	// RecoveryHint is operator re-auth guidance (e.g. login command); never secrets.
	RecoveryHint string
}

// CredentialProvider obtains and clears credentials for a profile.
// Implementations use keyring (and later OIDC); they never read secrets from
// process-global mutable strings as the sole store.
type CredentialProvider interface {
	Authenticate(ctx context.Context, profile Profile) (Session, error)
	Status(ctx context.Context, profile Profile) (Status, error)
	Logout(ctx context.Context, profile Profile) error
}
