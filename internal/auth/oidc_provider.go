package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/contracts"
	"github.com/hilather/go-jenkins-mcp/internal/keyring"
	"golang.org/x/sync/singleflight"
)

// OIDCProvider loads and refreshes external-IdP OIDC tokens (OAUTH-004 / OAUTH-007).
// Browser PKCE login is OAUTH-002 (writes via StoreTokens); this provider restores
// sessions from the keyring, single-flight refreshes, and clears on logout.
type OIDCProvider struct {
	// Tokens is the durable OIDC blob store (keyring-backed in production).
	Tokens TokenStore
	// HTTP is used for refresh and optional revocation. Required for refresh.
	HTTP *http.Client
	// RefreshSkew refreshes when access expires within this window (0 → DefaultRefreshSkew).
	RefreshSkew time.Duration
	// Now overrides the clock (tests).
	Now func() time.Time
	// Epoch is optional non-secret session.epoch store. Bumped on StoreTokens
	// and Logout so a running serve process fail-closes without waiting for
	// refresh failure (cross-process invalidation).
	Epoch *SessionEpochStore

	// In-memory session material (process-local). Cleared on Logout.
	memMu sync.Mutex
	mem   map[string]TokenBundle // profile id → last known bundle

	// Single-flight refresh coordination per profile id.
	sf singleflight.Group
}

// NewOIDCProvider constructs a provider over the given keyring (and optional HTTP client).
// httpClient may be nil until refresh is needed; tests inject httptest clients.
func NewOIDCProvider(kr *keyring.Store, httpClient *http.Client) *OIDCProvider {
	var store TokenStore
	if kr != nil {
		store = NewKeyringTokenStore(kr)
	}
	return &OIDCProvider{
		Tokens: store,
		HTTP:   httpClient,
		mem:    make(map[string]TokenBundle),
	}
}

// NewOIDCProviderWithStore is for tests and OAUTH-002 wiring with a custom TokenStore.
func NewOIDCProviderWithStore(store TokenStore, httpClient *http.Client) *OIDCProvider {
	return &OIDCProvider{
		Tokens: store,
		HTTP:   httpClient,
		mem:    make(map[string]TokenBundle),
	}
}

func (p *OIDCProvider) clock() time.Time {
	if p != nil && p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *OIDCProvider) skew() time.Duration {
	if p != nil && p.RefreshSkew > 0 {
		return p.RefreshSkew
	}
	return DefaultRefreshSkew
}

// StoreTokens persists a TokenBundle after successful browser login (OAUTH-002)
// or test setup. Never logs token material.
func (p *OIDCProvider) StoreTokens(ctx context.Context, profileID string, bundle TokenBundle) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "store tokens cancelled", err)
	}
	if p == nil || p.Tokens == nil {
		return apperr.New(apperr.CodeInternal, "oidc token store is not configured")
	}
	profileID = strings.TrimSpace(profileID)
	if profileID == "" {
		return apperr.New(apperr.CodeInvalidArgument, "profile id is required")
	}
	if bundle.Empty() {
		return apperr.New(apperr.CodeInvalidArgument, "token bundle is empty")
	}
	if err := p.Tokens.Set(ctx, profileID, bundle); err != nil {
		return err
	}
	p.remember(profileID, bundle)
	// Cross-process: invalidate other serves for this profile (non-secret bump).
	if p.Epoch != nil {
		if _, err := p.Epoch.Bump(); err != nil {
			return err
		}
	}
	return nil
}

// Authenticate loads keyring tokens, refreshes when access is expired, and returns
// a short-lived Session. Concurrent callers share one refresh via singleflight.
func (p *OIDCProvider) Authenticate(ctx context.Context, pr Profile) (Session, error) {
	if err := ctx.Err(); err != nil {
		return Session{}, apperr.Wrap(apperr.CodeCancelled, "authentication cancelled", err)
	}
	if p == nil || p.Tokens == nil {
		return Session{}, apperr.New(apperr.CodeInternal, "oidc credential provider is not configured")
	}
	if pr.ID == "" {
		return Session{}, apperr.New(apperr.CodeInvalidArgument, "profile id is required")
	}

	bundle, err := p.ensureValidBundle(ctx, pr)
	if err != nil {
		return Session{}, err
	}
	user := strings.TrimSpace(pr.User)
	if user == "" {
		// Non-secret label; OIDC may not set username until whoAmI (OAUTH-005 residual).
		user = "oidc"
	}
	return Session{
		ProfileID: pr.ID,
		Method:    MethodOIDC,
		User:      user,
		Secret:    bundle.AccessToken,
		ExpiresAt: bundle.ExpiresAt,
	}, nil
}

// ensureValidBundle returns a usable access token, refreshing under singleflight
// when the access token is expired/near-expiry and a refresh token is present.
func (p *OIDCProvider) ensureValidBundle(ctx context.Context, pr Profile) (TokenBundle, error) {
	if err := ctx.Err(); err != nil {
		return TokenBundle{}, apperr.Wrap(apperr.CodeCancelled, "authentication cancelled", err)
	}
	pid := string(pr.ID)
	// Fast path: valid in-memory access without hitting keyring/network.
	if b, ok := p.memoryGet(pid); ok && b.AccessValid(p.clock(), p.skew()) {
		return b, nil
	}

	// Detach from the caller's cancel so one cancelled waiter cannot poison
	// concurrent singleflight peers; re-check ctx after the shared work.
	v, err, _ := p.sf.Do(pid, func() (interface{}, error) {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		return p.ensureOnce(rctx, pr)
	})
	if err != nil {
		return TokenBundle{}, err
	}
	if err := ctx.Err(); err != nil {
		return TokenBundle{}, apperr.Wrap(apperr.CodeCancelled, "authentication cancelled", err)
	}
	b, ok := v.(TokenBundle)
	if !ok || !b.HasAccess() {
		return TokenBundle{}, apperr.New(apperr.CodeAuthentication,
			authFailureWithRecovery(pr.ID, "oidc session is not available"))
	}
	return b, nil
}

func (p *OIDCProvider) ensureOnce(ctx context.Context, pr Profile) (TokenBundle, error) {
	pid := string(pr.ID)

	// Re-check memory after winning singleflight (another waiter may have finished).
	if b, ok := p.memoryGet(pid); ok && b.AccessValid(p.clock(), p.skew()) {
		return b, nil
	}

	bundle, err := p.Tokens.Get(ctx, pid)
	if err != nil {
		// Corrupt keyring: clear and demand re-login (no crash).
		if apperr.CodeOf(err) == apperr.CodeCorruptCache {
			_ = p.Tokens.Delete(ctx, pid)
			p.memoryDelete(pid)
			return TokenBundle{}, apperr.New(apperr.CodeAuthentication,
				authFailureWithRecovery(pr.ID, "oidc credentials are corrupt; re-authenticate"))
		}
		return TokenBundle{}, mapAuthErrWithRecovery(pr.ID, err)
	}

	if bundle.AccessValid(p.clock(), p.skew()) {
		p.remember(pid, bundle)
		return bundle, nil
	}

	// Access expired/missing — refresh when possible.
	if !bundle.HasRefresh() {
		_ = p.Tokens.Delete(ctx, pid)
		p.memoryDelete(pid)
		return TokenBundle{}, apperr.New(apperr.CodeAuthentication,
			authFailureWithRecovery(pr.ID, "access token expired and no refresh token is available"))
	}

	tokenEndpoint, err := p.resolveTokenEndpoint(ctx, pr)
	if err != nil {
		return TokenBundle{}, err
	}
	clientID := strings.TrimSpace(pr.OIDCClientID)
	if clientID == "" {
		return TokenBundle{}, apperr.New(apperr.CodeInvalidArgument,
			"oidc client id is required for token refresh")
	}

	next, err := doRefreshTokenExchange(ctx, p.HTTP, tokenEndpoint, clientID, bundle.RefreshToken, p.clock(), pr.OIDCJenkinsAudience)
	if err != nil {
		if isRefreshAuthError(err) {
			// invalid_grant / revoked — fail closed: clear durable + memory.
			_ = p.Tokens.Delete(ctx, pid)
			p.memoryDelete(pid)
			return TokenBundle{}, apperr.New(apperr.CodeAuthentication,
				authFailureWithRecovery(pr.ID, "refresh token rejected; re-authenticate"))
		}
		return TokenBundle{}, mapAuthErrWithRecovery(pr.ID, err)
	}
	merged := mergeRefreshRotation(bundle, next)
	if err := p.Tokens.Set(ctx, pid, merged); err != nil {
		return TokenBundle{}, err
	}
	p.remember(pid, merged)
	return merged, nil
}

func (p *OIDCProvider) resolveTokenEndpoint(ctx context.Context, pr Profile) (string, error) {
	if ep := strings.TrimSpace(pr.OIDCTokenEndpoint); ep != "" {
		return ep, nil
	}
	issuer := strings.TrimSpace(pr.OIDCIssuer)
	if issuer == "" {
		return "", apperr.New(apperr.CodeInvalidArgument,
			"oidc token endpoint or issuer is required for refresh")
	}
	if p.HTTP == nil {
		return "", apperr.New(apperr.CodeInternal, "oidc HTTP client is required for discovery refresh")
	}
	doc, err := FetchDiscovery(ctx, p.HTTP, issuer)
	if err != nil {
		return "", err
	}
	ep := strings.TrimSpace(doc.TokenEndpoint)
	if ep == "" {
		return "", apperr.New(apperr.CodeUpstreamProtocol, "discovery document missing token_endpoint")
	}
	return ep, nil
}

// Status returns a sanitized view: method=oidc, authenticated, expires_at,
// has_refresh (bool only) — never token bytes (OAUTH-007).
func (p *OIDCProvider) Status(ctx context.Context, pr Profile) (Status, error) {
	if err := ctx.Err(); err != nil {
		return Status{}, apperr.Wrap(apperr.CodeCancelled, "status cancelled", err)
	}
	st := Status{
		ProfileID: pr.ID,
		Method:    MethodOIDC,
		User:      strings.TrimSpace(pr.User),
	}
	if p == nil || p.Tokens == nil {
		st.Authenticated = false
		st.ErrorCode = string(apperr.CodeInternal)
		st.ErrorMessageSafe = "oidc credential provider is not configured"
		st.RecoveryHint = RecoveryLoginCommand(pr.ID)
		return st, nil
	}

	bundle, err := p.Tokens.Get(ctx, string(pr.ID))
	if err != nil {
		st.Authenticated = false
		st.HasCredential = false
		st.HasRefresh = false
		if apperr.CodeOf(err) == apperr.CodeCorruptCache {
			// Partial/corrupt material: do not crash; surface recovery.
			_ = p.Tokens.Delete(ctx, string(pr.ID))
			p.memoryDelete(string(pr.ID))
			st.ErrorCode = string(apperr.CodeAuthentication)
			st.ErrorMessageSafe = "oidc credentials are corrupt"
			st.RecoveryHint = RecoveryLoginCommand(pr.ID)
			return st, nil
		}
		st.ErrorCode = string(apperr.CodeOf(err))
		st.ErrorMessageSafe = apperr.ModelMessage(err)
		if prLooksLikeSecret(st.ErrorMessageSafe) {
			st.ErrorMessageSafe = "authentication failed"
		}
		st.RecoveryHint = RecoveryLoginCommand(pr.ID)
		return st, nil
	}

	st.HasCredential = true
	st.HasRefresh = bundle.HasRefresh()
	st.ExpiresAt = bundle.ExpiresAt
	// Session is usable when access is valid or a refresh token can restore it.
	if bundle.AccessValid(p.clock(), 0) || bundle.HasRefresh() {
		st.Authenticated = true
	} else {
		st.Authenticated = false
		st.ErrorCode = string(apperr.CodeAuthentication)
		st.ErrorMessageSafe = "oidc session expired"
		st.RecoveryHint = RecoveryLoginCommand(pr.ID)
	}
	return st, nil
}

// LogoutDetails describes OAuth logout outcome (OAUTH-007).
// Local clear always runs; IdP revocation is best-effort when endpoint is known.
type LogoutDetails struct {
	LocalCleared        bool
	RevocationAttempted bool
	RevocationOK        bool
	// RevocationMessage is secret-free operator text (empty on success/skip).
	RevocationMessage string
}

// Logout clears durable OIDC material and in-memory session. Implements CredentialProvider.
// IdP revocation is attempted when OIDCRevocationEndpoint is set (best-effort).
func (p *OIDCProvider) Logout(ctx context.Context, pr Profile) error {
	_, err := p.LogoutDetailed(ctx, pr)
	return err
}

// LogoutDetailed performs logout and returns revocation diagnostics (never tokens).
func (p *OIDCProvider) LogoutDetailed(ctx context.Context, pr Profile) (LogoutDetails, error) {
	if err := ctx.Err(); err != nil {
		return LogoutDetails{}, apperr.Wrap(apperr.CodeCancelled, "logout cancelled", err)
	}
	details := LogoutDetails{}
	if p == nil || p.Tokens == nil {
		return details, apperr.New(apperr.CodeInternal, "oidc credential provider is not configured")
	}
	pid := string(pr.ID)
	if strings.TrimSpace(pid) == "" {
		return details, apperr.New(apperr.CodeInvalidArgument, "profile id is required")
	}

	// Best-effort IdP revocation before local delete (need refresh/access from store).
	revEP := strings.TrimSpace(pr.OIDCRevocationEndpoint)
	if revEP != "" && p.HTTP != nil {
		bundle, err := p.Tokens.Get(ctx, pid)
		if err == nil {
			tok := bundle.RefreshToken
			hint := "refresh_token"
			if tok == "" {
				tok = bundle.AccessToken
				hint = "access_token"
			}
			if tok != "" {
				details.RevocationAttempted = true
				if err := doRevokeToken(ctx, p.HTTP, revEP, pr.OIDCClientID, tok, hint); err != nil {
					details.RevocationOK = false
					details.RevocationMessage = apperr.ModelMessage(err)
					if prLooksLikeSecret(details.RevocationMessage) {
						details.RevocationMessage = "identity provider revocation failed"
					}
				} else {
					details.RevocationOK = true
				}
			}
		}
	}

	// Always clear local material (even if revocation failed).
	if err := p.Tokens.Delete(ctx, pid); err != nil {
		return details, err
	}
	p.memoryDelete(pid)
	details.LocalCleared = true
	// Cross-process: bump session.epoch so running serve fails closed immediately.
	if p.Epoch != nil {
		if _, err := p.Epoch.Bump(); err != nil {
			return details, err
		}
	}
	return details, nil
}

// ClearMemory drops process-local cached bundles (all profiles or one).
func (p *OIDCProvider) ClearMemory(profileID string) {
	if p == nil {
		return
	}
	if strings.TrimSpace(profileID) == "" {
		p.memMu.Lock()
		p.mem = make(map[string]TokenBundle)
		p.memMu.Unlock()
		return
	}
	p.memoryDelete(strings.TrimSpace(profileID))
}

func (p *OIDCProvider) remember(profileID string, b TokenBundle) {
	if p == nil {
		return
	}
	p.memMu.Lock()
	defer p.memMu.Unlock()
	if p.mem == nil {
		p.mem = make(map[string]TokenBundle)
	}
	p.mem[profileID] = b
}

func (p *OIDCProvider) memoryGet(profileID string) (TokenBundle, bool) {
	if p == nil {
		return TokenBundle{}, false
	}
	p.memMu.Lock()
	defer p.memMu.Unlock()
	b, ok := p.mem[profileID]
	return b, ok
}

func (p *OIDCProvider) memoryDelete(profileID string) {
	if p == nil {
		return
	}
	p.memMu.Lock()
	defer p.memMu.Unlock()
	delete(p.mem, profileID)
}

// RecoveryLoginCommand is the operator re-auth hint (never includes secrets).
func RecoveryLoginCommand(profileID contracts.ProfileID) string {
	id := strings.TrimSpace(string(profileID))
	if id == "" {
		id = "<id>"
	}
	return fmt.Sprintf("jenkins-mcp login --profile %s", id)
}

func authFailureWithRecovery(profileID contracts.ProfileID, msg string) string {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		msg = "authentication failed"
	}
	return msg + "; " + RecoveryLoginCommand(profileID)
}

func mapAuthErrWithRecovery(profileID contracts.ProfileID, err error) error {
	if err == nil {
		return nil
	}
	code := apperr.CodeOf(err)
	if code == apperr.CodeAuthentication {
		// Preserve safe message; append recovery if not already present.
		msg := apperr.ModelMessage(err)
		if !strings.Contains(msg, "jenkins-mcp login") {
			msg = authFailureWithRecovery(profileID, msg)
		}
		return apperr.New(code, msg)
	}
	return err
}
