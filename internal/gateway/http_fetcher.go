package gateway

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

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// MaxTokenFetchBodyBytes bounds AS/mock token endpoint JSON (never log body).
const MaxTokenFetchBodyBytes = 1 << 20 // 1 MiB

// DefaultTokenFetchTimeout bounds HTTPTokenFetcher when neither client nor context
// has a deadline.
const DefaultTokenFetchTimeout = 20 * time.Second

// HTTPTokenFetcher posts to a configured token endpoint (AgentCore / mock AS)
// and maps a bounded JSON response into a Credential.
//
// Safety (mirrors adapter/extlogs + auth token discipline):
//   - https-only token URL (no http, no userinfo)
//   - no redirects
//   - body size cap; response body never included in errors
//   - access_token never logged
//
// Not wired by NewAgentCoreProvider (Live=false, Fetcher=nil by default).
// Operators / tests construct explicitly and set provider.Live + Fetcher.
// Live Entra / AgentCore production pin remains GWY-003 residual.
type HTTPTokenFetcher struct {
	// Client is optional; when nil a default client is built (no redirects, timeout).
	Client *http.Client
	// Now is optional clock for expires_in → ExpiresAt (tests).
	Now func() time.Time
}

// NewHTTPTokenFetcher builds a fetcher. client may be nil (default safe client).
func NewHTTPTokenFetcher(client *http.Client) *HTTPTokenFetcher {
	return &HTTPTokenFetcher{Client: client}
}

// FetchJenkinsCredential implements TokenFetcher.
func (f *HTTPTokenFetcher) FetchJenkinsCredential(ctx context.Context, caller Caller, cfg AgentCoreConfig) (Credential, error) {
	if err := ctx.Err(); err != nil {
		return Credential{}, apperr.Wrap(apperr.CodeCancelled, "gateway credential fetch cancelled", err)
	}
	if f == nil {
		return Credential{}, apperr.New(apperr.CodeCapabilityMissing, "http token fetcher is nil")
	}
	if !caller.Valid() {
		return Credential{}, apperr.New(apperr.CodeAuthentication,
			"gateway caller subject and profile are required")
	}
	if err := ValidateProviderConfig(cfg); err != nil {
		return Credential{}, err
	}

	tokenURL, err := resolveTokenEndpointURL(cfg)
	if err != nil {
		return Credential{}, err
	}
	if err := requireHTTPSTokenURL(tokenURL); err != nil {
		return Credential{}, err
	}

	mode := NormalizeMode(cfg.Mode)
	if mode == "" {
		mode = ModeAuthorizationCode
	}

	form := url.Values{}
	form.Set("client_id", strings.TrimSpace(cfg.ClientID))
	form.Set("resource", strings.TrimSpace(cfg.Audience))
	form.Set("audience", strings.TrimSpace(cfg.Audience))
	// Non-secret labels only — never client secrets or prior tokens.
	form.Set("subject", strings.TrimSpace(caller.Subject))
	form.Set("tenant", strings.TrimSpace(caller.Tenant))
	form.Set("workload_id", strings.TrimSpace(caller.WorkloadID))
	form.Set("profile_id", strings.TrimSpace(string(caller.ProfileID)))
	switch mode {
	case ModeTokenExchange:
		form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	default:
		// Mock/offline authorization_code residual: exchange-style POST without
		// embedding real auth codes (live 3LO consent remains AgentCore residual).
		form.Set("grant_type", "authorization_code")
	}

	client := f.client()
	reqCtx := ctx
	var cancel context.CancelFunc
	if client.Timeout == 0 {
		if _, ok := ctx.Deadline(); !ok {
			reqCtx, cancel = context.WithTimeout(ctx, DefaultTokenFetchTimeout)
			defer cancel()
		}
	}

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return Credential{}, apperr.Wrap(apperr.CodeInternal, "failed to build token request", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")
	// Never attach Authorization with secrets here — residual keyring/vault.

	resp, err := client.Do(httpReq)
	if err != nil {
		if errors.Is(reqCtx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
			return Credential{}, apperr.Wrap(apperr.CodeCancelled, "token request cancelled", err)
		}
		if errors.Is(reqCtx.Err(), context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return Credential{}, apperr.Wrap(apperr.CodeTimeout, "token request timed out", err)
		}
		return Credential{}, apperr.Wrap(apperr.CodeUpstreamProtocol, "token request failed", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxTokenFetchBodyBytes+1))
	if err != nil {
		return Credential{}, apperr.Wrap(apperr.CodeUpstreamProtocol, "failed to read token response", err)
	}
	if len(body) > MaxTokenFetchBodyBytes {
		return Credential{}, apperr.New(apperr.CodeUpstreamProtocol, "token response exceeds size limit")
	}

	// Consent path: 401/403 with consent metadata JSON (no tokens).
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		if cr, ok := parseConsentBody(body); ok {
			return Credential{}, cr
		}
	}

	var tr tokenFetchResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		// Never include body (may contain tokens).
		return Credential{}, apperr.Wrap(apperr.CodeUpstreamProtocol, "token response JSON is invalid", err)
	}
	// Consent signaled via JSON (error=consent_required or auth URL + session).
	if strings.EqualFold(strings.TrimSpace(tr.Error), "consent_required") ||
		(strings.TrimSpace(tr.AuthorizationURL) != "" && strings.TrimSpace(tr.SessionID) != "" &&
			strings.TrimSpace(tr.AccessToken) == "") {
		if cr, ok := parseConsentFromFields(tr.AuthorizationURL, tr.SessionID, tr.Provider); ok {
			return Credential{}, cr
		}
		return Credential{}, apperr.New(apperr.CodeAuthentication, "consent required but metadata incomplete")
	}
	if tr.Error != "" {
		// OAuth error response; message is short error code only.
		return Credential{}, apperr.New(apperr.CodeAuthentication,
			fmt.Sprintf("token endpoint error=%s", safeOAuthError(tr.Error)))
	}
	if resp.StatusCode != http.StatusOK {
		return Credential{}, apperr.New(apperr.CodeUpstreamProtocol,
			fmt.Sprintf("token endpoint HTTP %d", resp.StatusCode))
	}
	if strings.TrimSpace(tr.AccessToken) == "" {
		return Credential{}, apperr.New(apperr.CodeAuthentication, "token response missing access_token")
	}

	// Wrong-audience residual: when AS returns audience/resource, require exact match.
	expectedAud := strings.TrimSpace(cfg.Audience)
	for _, got := range []string{tr.Audience, tr.Resource} {
		got = strings.TrimSpace(got)
		if got == "" {
			continue
		}
		if got != expectedAud {
			return Credential{}, wrongAudienceError(got)
		}
	}

	expiresAt := f.clock().Add(time.Hour) // default when expires_in absent
	if tr.ExpiresIn > 0 {
		expiresAt = f.clock().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}

	// Principal from response label only (non-secret); empty is ok (GWY-002 binds later).
	principal := strings.TrimSpace(tr.JenkinsPrincipal)
	if principal == "" {
		principal = strings.TrimSpace(tr.Principal)
	}

	return Credential{
		AccessToken:      tr.AccessToken,
		ExpiresAt:        expiresAt,
		JenkinsPrincipal: principal,
		Mode:             mode,
	}, nil
}

type tokenFetchResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	Audience         string `json:"audience"`
	Resource         string `json:"resource"`
	JenkinsPrincipal string `json:"jenkins_principal"`
	Principal        string `json:"principal"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	// Consent metadata (never tokens).
	AuthorizationURL string `json:"authorization_url"`
	SessionID        string `json:"session_id"`
	Provider         string `json:"provider"`
}

func (f *HTTPTokenFetcher) client() *http.Client {
	// Always refuse redirects (origin/token-endpoint pin). Clone if a caller
	// supplied a client so we never follow hops even when Transport is shared.
	refuseRedirect := func(*http.Request, []*http.Request) error {
		return fmt.Errorf("redirect refused (token endpoint pin)")
	}
	if f != nil && f.Client != nil {
		c := *f.Client
		c.CheckRedirect = refuseRedirect
		return &c
	}
	return &http.Client{
		Timeout:       DefaultTokenFetchTimeout,
		CheckRedirect: refuseRedirect,
	}
}

func (f *HTTPTokenFetcher) clock() time.Time {
	if f != nil && f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

// resolveTokenEndpointURL returns an absolute token URL from config.
func resolveTokenEndpointURL(cfg AgentCoreConfig) (string, error) {
	raw := strings.TrimSpace(cfg.TokenEndpoint)
	if raw == "" {
		return "", apperr.New(apperr.CodeCapabilityMissing,
			"gateway token endpoint is required for HTTPTokenFetcher")
	}
	if strings.Contains(raw, "://") {
		return raw, nil
	}
	// Relative path under AS base.
	if !strings.HasPrefix(raw, "/") {
		return "", apperr.New(apperr.CodeInvalidArgument,
			"token endpoint must be an absolute URL or a path starting with /")
	}
	base := strings.TrimSpace(cfg.AuthorizationServerBaseURL)
	if base == "" {
		return "", apperr.New(apperr.CodeInvalidArgument,
			"authorization server base URL required to resolve relative token endpoint")
	}
	base = strings.TrimRight(base, "/")
	return base + raw, nil
}

// requireHTTPSTokenURL rejects non-https and userinfo (fail closed).
func requireHTTPSTokenURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return apperr.New(apperr.CodeInvalidArgument, "token endpoint URL is invalid")
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return apperr.New(apperr.CodeInvalidArgument, "token endpoint must use https")
	}
	if u.User != nil {
		return apperr.New(apperr.CodeInvalidArgument, "token endpoint must not contain userinfo")
	}
	return nil
}

func safeOAuthError(code string) string {
	code = strings.TrimSpace(code)
	if code == "" {
		return "unknown"
	}
	// Bound length; alphanumeric + underscore only for safe display.
	var b strings.Builder
	for i, r := range code {
		if i >= 64 {
			break
		}
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

func parseConsentBody(body []byte) (error, bool) {
	var tr tokenFetchResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, false
	}
	return parseConsentFromFields(tr.AuthorizationURL, tr.SessionID, tr.Provider)
}

func parseConsentFromFields(authURL, sessionID, provider string) (error, bool) {
	info := ConsentInfo{
		AuthorizationURL: strings.TrimSpace(authURL),
		SessionID:        strings.TrimSpace(sessionID),
		Provider:         strings.TrimSpace(provider),
	}
	if !info.Valid() {
		return nil, false
	}
	if info.Provider == "" {
		info.Provider = "agentcore"
	}
	return NewConsentRequired(info), true
}
