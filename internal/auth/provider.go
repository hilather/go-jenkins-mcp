package auth

import (
	"context"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/contracts"
	"github.com/hilather/go-jenkins-mcp/internal/keyring"
	"github.com/hilather/go-jenkins-mcp/internal/profile"
)

// APITokenProvider loads personal Jenkins API tokens from the keyring.
// It never reads a process-global mutable credential string as the sole store.
type APITokenProvider struct {
	Keyring *keyring.Store
	// SessionTTL bounds in-memory session lifetime (0 = default 12h).
	SessionTTL time.Duration
}

// NewAPITokenProvider constructs a provider over the given keyring store.
func NewAPITokenProvider(kr *keyring.Store) *APITokenProvider {
	return &APITokenProvider{Keyring: kr}
}

func (p *APITokenProvider) ttl() time.Duration {
	if p.SessionTTL > 0 {
		return p.SessionTTL
	}
	return 12 * time.Hour
}

// Authenticate loads the token for the profile and returns a short-lived Session.
func (p *APITokenProvider) Authenticate(ctx context.Context, pr Profile) (Session, error) {
	if err := ctx.Err(); err != nil {
		return Session{}, apperr.Wrap(apperr.CodeCancelled, "authentication cancelled", err)
	}
	if p == nil || p.Keyring == nil {
		return Session{}, apperr.New(apperr.CodeInternal, "credential provider is not configured")
	}
	if pr.ID == "" || strings.TrimSpace(pr.URL) == "" {
		return Session{}, apperr.New(apperr.CodeInvalidArgument, "profile id and URL are required")
	}
	user := strings.TrimSpace(pr.User)
	if user == "" {
		return Session{}, apperr.New(apperr.CodeAuthentication,
			"profile has no username; run login for this profile")
	}
	origin, err := profile.NormalizedOrigin(pr.URL)
	if err != nil {
		return Session{}, err
	}
	ref := keyring.CredentialRef{
		ProfileID: string(pr.ID),
		Origin:    origin,
		Method:    string(MethodAPIToken),
		Account:   user,
	}
	token, err := p.Keyring.GetAPIToken(ref)
	if err != nil {
		return Session{}, err
	}
	// Never put token into Status or errors.
	return Session{
		ProfileID: pr.ID,
		Method:    MethodAPIToken,
		User:      user,
		Secret:    token,
		ExpiresAt: time.Now().Add(p.ttl()),
	}, nil
}

// Status returns a sanitized view (no token bytes).
// HasCredential reflects keyring presence; Principal* fields are not filled here
// (callers merge last-verified metadata from the profile document).
func (p *APITokenProvider) Status(ctx context.Context, pr Profile) (Status, error) {
	if err := ctx.Err(); err != nil {
		return Status{}, apperr.Wrap(apperr.CodeCancelled, "status cancelled", err)
	}
	st := Status{
		ProfileID:  pr.ID,
		Method:     MethodAPIToken,
		User:       strings.TrimSpace(pr.User),
		HasRefresh: false, // API tokens have no OAuth refresh material
	}
	sess, err := p.Authenticate(ctx, pr)
	if err != nil {
		st.Authenticated = false
		st.HasCredential = false
		st.ErrorCode = string(apperr.CodeOf(err))
		st.ErrorMessageSafe = apperr.ModelMessage(err)
		// Canary: never surface secret material.
		if prLooksLikeSecret(st.ErrorMessageSafe) {
			st.ErrorMessageSafe = "authentication failed"
		}
		st.RecoveryHint = RecoveryLoginCommand(pr.ID)
		return st, nil
	}
	st.Authenticated = true
	st.HasCredential = true
	st.User = sess.User
	st.ExpiresAt = sess.ExpiresAt
	if sess.Principal.ID != "" {
		st.PrincipalID = sess.Principal.ID
		st.PrincipalFullName = sess.Principal.FullName
	}
	return st, nil
}

// Logout deletes the keyring credential for the profile account.
func (p *APITokenProvider) Logout(ctx context.Context, pr Profile) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "logout cancelled", err)
	}
	if p == nil || p.Keyring == nil {
		return apperr.New(apperr.CodeInternal, "credential provider is not configured")
	}
	user := strings.TrimSpace(pr.User)
	if user == "" {
		// Nothing stored under a known account.
		return nil
	}
	origin, err := profile.NormalizedOrigin(pr.URL)
	if err != nil {
		return err
	}
	ref := keyring.CredentialRef{
		ProfileID: string(pr.ID),
		Origin:    origin,
		Method:    string(MethodAPIToken),
		Account:   user,
	}
	return p.Keyring.DeleteAPIToken(ref)
}

// StoreAPIToken writes a token for the profile (used by login). Token is not logged.
func (p *APITokenProvider) StoreAPIToken(pr Profile, token string) error {
	if p == nil || p.Keyring == nil {
		return apperr.New(apperr.CodeInternal, "credential provider is not configured")
	}
	user := strings.TrimSpace(pr.User)
	if user == "" {
		return apperr.New(apperr.CodeInvalidArgument, "username is required")
	}
	if strings.TrimSpace(token) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "api token is required")
	}
	origin, err := profile.NormalizedOrigin(pr.URL)
	if err != nil {
		return err
	}
	ref := keyring.CredentialRef{
		ProfileID: string(pr.ID),
		Origin:    origin,
		Method:    string(MethodAPIToken),
		Account:   user,
	}
	return p.Keyring.SetAPIToken(ref, token)
}

// NewProvider selects a CredentialProvider for the profile auth method.
// OIDC uses keyring-backed TokenStore (OAUTH-004); browser PKCE login is OAUTH-002.
func NewProvider(method profile.AuthMethod, kr *keyring.Store) (CredentialProvider, error) {
	switch method {
	case profile.AuthMethodAPIToken, "":
		return NewAPITokenProvider(kr), nil
	case profile.AuthMethodOIDC:
		return NewOIDCProvider(kr, nil), nil
	case profile.AuthMethodAgentCoreDelegated:
		return nil, apperr.New(apperr.CodeCapabilityMissing,
			"agentcore_delegated authentication is not implemented yet")
	default:
		return nil, apperr.New(apperr.CodeInvalidArgument,
			"unsupported auth method")
	}
}

// ProfileFrom loads auth.Profile from a stored profile document.
func ProfileFrom(p *profile.Profile) Profile {
	if p == nil {
		return Profile{}
	}
	out := Profile{
		ID:   p.ID,
		URL:  p.JenkinsURL,
		User: p.Username,
	}
	if p.OIDC != nil {
		out.OIDCIssuer = p.OIDC.Issuer
		out.OIDCClientID = p.OIDC.ClientID
		out.OIDCJenkinsAudience = p.OIDC.JenkinsAudience
	}
	return out
}

// ApplySession copies short-lived session credentials onto a target that
// exposes User/Token fields (e.g. jenkins.Client). Tools must not access
// Session.Secret directly.
func ApplySession(sess Session) (user, token string, profileID contracts.ProfileID) {
	return sess.User, sess.Secret, sess.ProfileID
}

// prLooksLikeSecret is a coarse canary for status sanitization tests.
func prLooksLikeSecret(s string) bool {
	// Long opaque tokens without spaces are suspicious in error text.
	if len(s) > 40 && !strings.Contains(s, " ") {
		return true
	}
	return false
}

// HTTPAuthScheme is how credentials are applied on the wire to Jenkins (OAUTH-005).
type HTTPAuthScheme string

const (
	// HTTPAuthBasic is username + API token (or password) via HTTP Basic.
	HTTPAuthBasic HTTPAuthScheme = "basic"
	// HTTPAuthBearer is Authorization: Bearer <access_token> for OIDC sessions.
	HTTPAuthBearer HTTPAuthScheme = "bearer"
)

// SessionCredentials is the wire-facing credential view derived from a Session.
// Secret must not be logged.
type SessionCredentials struct {
	User   string
	Secret string
	Scheme HTTPAuthScheme
}

// SessionCredentialsFrom maps a Session to Jenkins wire auth (OAUTH-005).
// MethodOIDC → Bearer with access token in Secret; otherwise Basic.
func SessionCredentialsFrom(sess Session) SessionCredentials {
	scheme := HTTPAuthBasic
	if sess.Method == MethodOIDC {
		scheme = HTTPAuthBearer
	}
	return SessionCredentials{
		User:   sess.User,
		Secret: sess.Secret,
		Scheme: scheme,
	}
}
