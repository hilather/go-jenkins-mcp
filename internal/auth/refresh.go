package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// DefaultRefreshSkew refreshes slightly before absolute expiry to avoid races.
const DefaultRefreshSkew = 60 * time.Second

// tokenEndpointResponse is the OAuth token endpoint JSON (RFC 6749).
// Fields are secrets or metadata — never log the struct as a whole.
type tokenEndpointResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

// doRefreshTokenExchange POSTs grant_type=refresh_token to tokenEndpoint.
// On invalid_grant the caller must clear the store (fail closed).
// Returned TokenBundle never logs tokens; errors are secret-free.
func doRefreshTokenExchange(
	ctx context.Context,
	client *http.Client,
	tokenEndpoint, clientID, refreshToken string,
	now time.Time,
) (TokenBundle, error) {
	if err := ctx.Err(); err != nil {
		return TokenBundle{}, apperr.Wrap(apperr.CodeCancelled, "token refresh cancelled", err)
	}
	if client == nil {
		return TokenBundle{}, apperr.New(apperr.CodeInternal, "token refresh HTTP client is required")
	}
	tokenEndpoint = strings.TrimSpace(tokenEndpoint)
	if tokenEndpoint == "" {
		return TokenBundle{}, apperr.New(apperr.CodeInvalidArgument, "token endpoint is required for refresh")
	}
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return TokenBundle{}, apperr.New(apperr.CodeInvalidArgument, "client id is required for refresh")
	}
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return TokenBundle{}, apperr.New(apperr.CodeAuthentication, "refresh token is missing; re-authenticate")
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", clientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenBundle{}, apperr.Wrap(apperr.CodeInternal, "failed to build token refresh request", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return TokenBundle{}, apperr.Wrap(apperr.CodeCancelled, "token refresh cancelled", err)
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return TokenBundle{}, apperr.Wrap(apperr.CodeTimeout, "token refresh timed out", err)
		}
		return TokenBundle{}, apperr.Wrap(apperr.CodeUpstreamProtocol, "token refresh request failed", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxTokenResponseBytes+1))
	if err != nil {
		return TokenBundle{}, apperr.Wrap(apperr.CodeUpstreamProtocol, "failed to read token refresh body", err)
	}
	if len(body) > MaxTokenResponseBytes {
		return TokenBundle{}, apperr.New(apperr.CodeUpstreamProtocol, "token refresh response exceeds size limit")
	}

	var tr tokenEndpointResponse
	// Best-effort JSON parse even on error status (IdPs return error JSON).
	_ = json.Unmarshal(body, &tr)

	oauthErr := strings.TrimSpace(tr.Error)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || oauthErr != "" {
		if oauthErr == "" {
			oauthErr = fmt.Sprintf("http_%d", resp.StatusCode)
		}
		// Permanent auth failures → fail closed (caller clears store).
		switch oauthErr {
		case "invalid_grant", "invalid_token", "expired_token":
			return TokenBundle{}, &refreshAuthError{code: oauthErr}
		}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return TokenBundle{}, &refreshAuthError{code: oauthErr}
		}
		// Do not embed error_description (may contain token fragments from buggy IdPs).
		return TokenBundle{}, apperr.New(apperr.CodeUpstreamProtocol,
			fmt.Sprintf("token refresh failed (%s)", safeOAuthErrorCode(oauthErr)))
	}

	access := strings.TrimSpace(tr.AccessToken)
	if access == "" {
		return TokenBundle{}, apperr.New(apperr.CodeUpstreamProtocol, "token refresh response missing access_token")
	}
	bundle := TokenBundle{
		AccessToken:  access,
		RefreshToken: strings.TrimSpace(tr.RefreshToken), // may be empty → caller keeps old
		TokenType:    strings.TrimSpace(tr.TokenType),
		IDToken:      strings.TrimSpace(tr.IDToken),
	}
	if bundle.TokenType == "" {
		bundle.TokenType = "Bearer"
	}
	if tr.ExpiresIn > 0 {
		bundle.ExpiresAt = now.Add(time.Duration(tr.ExpiresIn) * time.Second)
	} else {
		// No expires_in — force near-term revalidation rather than treating as immortal.
		bundle.ExpiresAt = now.Add(5 * time.Minute)
	}
	return bundle, nil
}

// refreshAuthError marks permanent auth failures (invalid_grant family).
// Callers clear local tokens and surface CodeAuthentication + recovery.
type refreshAuthError struct {
	code string
}

func (e *refreshAuthError) Error() string {
	if e == nil || e.code == "" {
		return "token refresh rejected by identity provider"
	}
	return "token refresh rejected by identity provider (" + safeOAuthErrorCode(e.code) + ")"
}

func isRefreshAuthError(err error) bool {
	var rae *refreshAuthError
	return errors.As(err, &rae)
}

func safeOAuthErrorCode(code string) string {
	code = strings.TrimSpace(strings.ToLower(code))
	// Allow only short snake_case-ish codes; drop anything that looks like a secret.
	if code == "" || len(code) > 64 || strings.Contains(code, " ") {
		return "error"
	}
	for _, r := range code {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return "error"
	}
	return code
}

// mergeRefreshRotation applies token rotation rules:
// new access always wins; refresh is replaced only when the IdP returns a new one.
func mergeRefreshRotation(previous, next TokenBundle) TokenBundle {
	out := next
	if !out.HasRefresh() && previous.HasRefresh() {
		out.RefreshToken = previous.RefreshToken
	}
	// Preserve id_token when IdP omits it on refresh (common).
	if strings.TrimSpace(out.IDToken) == "" && strings.TrimSpace(previous.IDToken) != "" {
		out.IDToken = previous.IDToken
	}
	return out
}

// doRevokeToken best-effort RFC 7009 token revocation. Never fails closed for
// local logout — caller always clears keyring regardless of this result.
// Returns a secret-free error when the attempt fails.
func doRevokeToken(
	ctx context.Context,
	client *http.Client,
	revocationEndpoint, clientID, token, tokenTypeHint string,
) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "token revocation cancelled", err)
	}
	if client == nil {
		return apperr.New(apperr.CodeInternal, "token revocation HTTP client is required")
	}
	revocationEndpoint = strings.TrimSpace(revocationEndpoint)
	if revocationEndpoint == "" {
		return apperr.New(apperr.CodeInvalidArgument, "revocation endpoint is empty")
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return nil // nothing to revoke
	}
	form := url.Values{}
	form.Set("token", token)
	if hint := strings.TrimSpace(tokenTypeHint); hint != "" {
		form.Set("token_type_hint", hint)
	}
	if cid := strings.TrimSpace(clientID); cid != "" {
		form.Set("client_id", cid)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, revocationEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to build token revocation request", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return apperr.Wrap(apperr.CodeUpstreamProtocol, "token revocation request failed", err)
	}
	defer resp.Body.Close()
	// Drain bounded body so connections reuse; discard contents (may be HTML).
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	// RFC 7009: 200 OK even if token was already invalid.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return apperr.New(apperr.CodeUpstreamProtocol,
			fmt.Sprintf("token revocation HTTP %d", resp.StatusCode))
	}
	return nil
}
