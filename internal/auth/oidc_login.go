package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/profile"
)

// DefaultOIDCLoginTimeout bounds the browser callback wait (OAUTH-002).
const DefaultOIDCLoginTimeout = 5 * time.Minute

// MaxTokenResponseBytes bounds IdP token endpoint JSON (fail closed).
const MaxTokenResponseBytes = 1 << 20 // 1 MiB

// DefaultTokenHTTPTimeout bounds token exchange when neither client nor context has a deadline.
const DefaultTokenHTTPTimeout = 20 * time.Second

// AuthorizeParams are non-secret inputs for building the authorization URL.
type AuthorizeParams struct {
	ClientID      string
	RedirectURI   string
	Scopes        []string
	State         string
	Nonce         string
	CodeChallenge string
	// Resource is the RFC 8707 resource indicator (Jenkins API audience).
	// Sent when profile.OIDC.JenkinsAudience is set so the access token is
	// requested for Jenkins, not Graph or a generic gateway audience.
	Resource string
}

// LoginOptions configures OIDC Authorization Code + PKCE browser login.
// Tests inject HTTPClient (httptest), OpenBrowser (capture URL / drive callback),
// and TokenStore (memory).
type LoginOptions struct {
	// HTTPClient is used for discovery and token exchange (required).
	HTTPClient *http.Client
	// OpenBrowser opens the authorize URL; nil uses OpenSystemBrowser.
	// Tests should inject a stub (e.g. NoopBrowser) and drive the callback.
	OpenBrowser BrowserOpener
	// TokenStore persists opaque OIDC material; nil skips persistence
	// (session still returned with access token in memory). OAUTH-004 shape.
	TokenStore TokenStore
	// Epoch is optional; when set, bumped after successful token persistence so
	// a running serve for this profile fail-closes (cross-process invalidation).
	Epoch *SessionEpochStore
	// Timeout for the full login flow when ctx has no deadline (default 5m).
	Timeout time.Duration
	// Now overrides the clock (tests).
	Now func() time.Time
	// RedirectURI selects a specific allowlisted redirect; empty uses the first
	// valid loopback (127.0.0.1) entry from the profile.
	RedirectURI string
}

// LoginResult is the non-secret outcome plus in-memory session material.
// Session.Secret holds the access token; never log LoginResult or Session.
type LoginResult struct {
	Session Session
	// HasRefresh is true when a refresh_token was returned (value not exposed).
	HasRefresh bool
	// RedirectURI is the exact callback used (safe to display).
	RedirectURI string
	// Issuer is the validated IdP issuer (safe).
	Issuer string
}

// LoginOIDC runs Authorization Code + PKCE against the external IdP in the
// profile (not Jenkins — ADR 0003). Corporate passwords never enter this process.
//
// Flow: validate profile → discovery → bind 127.0.0.1 callback → open browser →
// validate state → exchange code (public client + code_verifier) →
// ValidateAccessToken for JWT-shaped access tokens (opaque skips JWT parse) →
// persist blob → return Session{Method: MethodOIDC}.
//
// ID tokens are never placed in Session.Secret (only access_token). Live Jenkins
// bearer transport / jwt-auth-filter lab remain OAUTH-005 / OAUTH-009 residual.
func LoginOIDC(ctx context.Context, p *profile.Profile, opts LoginOptions) (LoginResult, error) {
	var zero LoginResult
	if err := ctx.Err(); err != nil {
		return zero, apperr.Wrap(apperr.CodeCancelled, "oidc login cancelled", err)
	}
	if p == nil {
		return zero, apperr.New(apperr.CodeInvalidArgument, "profile is nil")
	}
	if err := ValidateOIDCProfileOffline(p); err != nil {
		return zero, err
	}
	if opts.HTTPClient == nil {
		return zero, apperr.New(apperr.CodeInternal, "oidc login HTTP client is required")
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultOIDCLoginTimeout
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	open := opts.OpenBrowser
	if open == nil {
		open = OpenSystemBrowser
	}

	// Select and validate loopback redirect before network (fail closed on open redirect).
	redirectURI, listenHost, listenPort, err := SelectLoopbackRedirect(p.OIDC.RedirectURIs, opts.RedirectURI)
	if err != nil {
		return zero, err
	}

	doc, err := FetchAndValidateDiscovery(ctx, opts.HTTPClient, p.OIDC.Issuer, p.JenkinsURL)
	if err != nil {
		return zero, err
	}

	// Cryptographic CSRF state, OIDC nonce, and PKCE verifier (memory only; never log).
	state, err := randomURLToken(32)
	if err != nil {
		return zero, err
	}
	nonce, err := randomURLToken(32)
	if err != nil {
		return zero, err
	}
	verifier, err := GenerateCodeVerifier()
	if err != nil {
		return zero, err
	}
	challenge, err := CodeChallengeS256(verifier)
	if err != nil {
		return zero, err
	}

	authURL, err := BuildAuthorizeURL(doc, AuthorizeParams{
		ClientID:      p.OIDC.ClientID,
		RedirectURI:   redirectURI,
		Scopes:        p.OIDC.Scopes,
		State:         state,
		Nonce:         nonce,
		CodeChallenge: challenge,
		Resource:      strings.TrimSpace(p.OIDC.JenkinsAudience),
	})
	if err != nil {
		return zero, err
	}

	// Loopback callback server: bind only 127.0.0.1 (not 0.0.0.0).
	code, err := waitForAuthCode(ctx, listenHost, listenPort, redirectURI, state, open, authURL)
	if err != nil {
		return zero, err
	}

	tok, err := exchangeAuthorizationCode(ctx, opts.HTTPClient, doc.TokenEndpoint, tokenExchangeRequest{
		ClientID:     p.OIDC.ClientID,
		Code:         code,
		RedirectURI:  redirectURI,
		CodeVerifier: verifier,
		Resource:     strings.TrimSpace(p.OIDC.JenkinsAudience),
	})
	if err != nil {
		return zero, err
	}
	// Clear verifier from outer scope as soon as exchange completes (best-effort hygiene).
	verifier = ""

	access := strings.TrimSpace(tok.AccessToken)
	if access == "" {
		return zero, apperr.New(apperr.CodeAuthentication, "token endpoint returned empty access_token")
	}

	expiresAt := time.Time{}
	if tok.ExpiresIn > 0 {
		expiresAt = now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	}

	// OAUTH-003: JWT-shaped access tokens must pass the full claim matrix before
	// persistence. Opaque reference tokens skip local JWT parse and rely on
	// Jenkins whoAmI (AUTH-004) at serve for identity binding.
	var tokenResult AccessTokenResult
	if ClassifyAccessToken(access) == TokenFormJWT {
		params := AccessTokenParamsFromOIDC(
			p.OIDC.Issuer,
			p.OIDC.JenkinsAudience,
			p.OIDC.ClientID,
			p.OIDC.TenantID,
		)
		params.Now = now
		jwks, jerr := FetchJWKSFromDiscovery(ctx, opts.HTTPClient, doc)
		if jerr != nil {
			return zero, jerr
		}
		vres, verr := ValidateAccessToken(access, jwks, params)
		if verr != nil {
			return zero, verr
		}
		tokenResult = vres
	} else {
		tokenResult = AccessTokenResult{Form: TokenFormOpaque}
	}

	bundle := TokenBundle{
		AccessToken:  access,
		RefreshToken: tok.RefreshToken,
		// ID token is stored separately for diagnostics only; never used as Jenkins bearer.
		IDToken:   tok.IDToken,
		TokenType: tok.TokenType,
		ExpiresAt: expiresAt,
	}
	if opts.TokenStore != nil {
		if err := opts.TokenStore.Set(ctx, string(p.ID), bundle); err != nil {
			return zero, err
		}
		// Bump after durable store so other processes drop stale in-memory sessions.
		if opts.Epoch != nil {
			if _, err := opts.Epoch.Bump(); err != nil {
				return zero, err
			}
		}
	}

	user := strings.TrimSpace(p.Username)
	sess := Session{
		ProfileID: p.ID,
		Method:    MethodOIDC,
		User:      user,
		Secret:    access, // access token only — never id_token
		ExpiresAt: expiresAt,
	}
	sess = BindAccessTokenSession(sess, access, tokenResult)
	return LoginResult{
		Session:     sess,
		HasRefresh:  strings.TrimSpace(tok.RefreshToken) != "",
		RedirectURI: redirectURI,
		Issuer:      doc.Issuer,
	}, nil
}

// BuildAuthorizeURL constructs the IdP authorization request URL (OAuth 2.1 / OIDC).
// Includes PKCE S256 and optional RFC 8707 resource indicator.
func BuildAuthorizeURL(doc *DiscoveryDocument, p AuthorizeParams) (string, error) {
	if doc == nil {
		return "", apperr.New(apperr.CodeInvalidArgument, "discovery document is nil")
	}
	authz := strings.TrimSpace(doc.AuthorizationEndpoint)
	if authz == "" {
		return "", apperr.New(apperr.CodeInvalidArgument, "authorization_endpoint is required")
	}
	if strings.TrimSpace(p.ClientID) == "" {
		return "", apperr.New(apperr.CodeInvalidArgument, "client_id is required")
	}
	if strings.TrimSpace(p.RedirectURI) == "" {
		return "", apperr.New(apperr.CodeInvalidArgument, "redirect_uri is required")
	}
	if strings.TrimSpace(p.State) == "" {
		return "", apperr.New(apperr.CodeInvalidArgument, "state is required")
	}
	if strings.TrimSpace(p.CodeChallenge) == "" {
		return "", apperr.New(apperr.CodeInvalidArgument, "code_challenge is required")
	}

	u, err := url.Parse(authz)
	if err != nil {
		return "", apperr.New(apperr.CodeInvalidArgument, "authorization_endpoint is not a valid URL")
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", p.ClientID)
	q.Set("redirect_uri", p.RedirectURI)
	q.Set("state", p.State)
	q.Set("code_challenge", p.CodeChallenge)
	q.Set("code_challenge_method", "S256")
	scopes := make([]string, 0, len(p.Scopes))
	for _, s := range p.Scopes {
		s = strings.TrimSpace(s)
		if s != "" {
			scopes = append(scopes, s)
		}
	}
	if len(scopes) == 0 {
		scopes = append(scopes, "openid")
	}
	q.Set("scope", strings.Join(scopes, " "))
	if n := strings.TrimSpace(p.Nonce); n != "" {
		q.Set("nonce", n)
	}
	// RFC 8707: request access token for the Jenkins API resource/audience.
	if r := strings.TrimSpace(p.Resource); r != "" {
		q.Set("resource", r)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// SelectLoopbackRedirect picks an exact redirect URI for local PKCE.
// Only http://127.0.0.1:<port>/... is accepted for the MVP callback server
// (fail closed: no public hosts, no 0.0.0.0, no bare localhost → IPv6 surprises).
// preferred, when non-empty, must appear in allowlist and pass the same checks.
func SelectLoopbackRedirect(allowlist []string, preferred string) (redirectURI, listenHost string, listenPort int, err error) {
	preferred = strings.TrimSpace(preferred)
	if preferred != "" {
		if !redirectInAllowlist(allowlist, preferred) {
			return "", "", 0, apperr.New(apperr.CodeInvalidArgument,
				"redirect_uri is not in the profile allowlist (open redirect rejected)")
		}
		host, port, err := parseLoopbackRedirect(preferred)
		if err != nil {
			return "", "", 0, err
		}
		return preferred, host, port, nil
	}
	if len(allowlist) == 0 {
		return "", "", 0, apperr.New(apperr.CodeInvalidArgument,
			"oidc.redirectUris must include a loopback http://127.0.0.1:<port>/... entry for browser login")
	}
	var firstErr error
	for _, raw := range allowlist {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		host, port, perr := parseLoopbackRedirect(raw)
		if perr != nil {
			if firstErr == nil {
				firstErr = perr
			}
			continue
		}
		return raw, host, port, nil
	}
	if firstErr != nil {
		return "", "", 0, firstErr
	}
	return "", "", 0, apperr.New(apperr.CodeInvalidArgument,
		"no usable loopback redirect URI (require http://127.0.0.1:<port>/...)")
}

func redirectInAllowlist(allowlist []string, candidate string) bool {
	for _, a := range allowlist {
		if strings.TrimSpace(a) == candidate {
			return true
		}
	}
	return false
}

func parseLoopbackRedirect(raw string) (host string, port int, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", 0, apperr.New(apperr.CodeInvalidArgument, "redirect_uri is not a valid URL")
	}
	if u.Scheme != "http" {
		// Local public clients use http://127.0.0.1 (RFC 8252); https loopback is rare.
		return "", 0, apperr.New(apperr.CodeInvalidArgument,
			"browser login redirect_uri must use http on 127.0.0.1")
	}
	if u.User != nil {
		return "", 0, apperr.New(apperr.CodeInvalidArgument, "redirect_uri must not embed credentials")
	}
	h := strings.ToLower(u.Hostname())
	if h != "127.0.0.1" {
		return "", 0, apperr.New(apperr.CodeInvalidArgument,
			"browser login redirect host must be 127.0.0.1 (loopback only; open redirect rejected)")
	}
	portStr := u.Port()
	if portStr == "" {
		return "", 0, apperr.New(apperr.CodeInvalidArgument,
			"redirect_uri must include an explicit port for the loopback callback")
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p < 1 || p > 65535 {
		return "", 0, apperr.New(apperr.CodeInvalidArgument, "redirect_uri port is invalid")
	}
	return "127.0.0.1", p, nil
}

// waitForAuthCode starts the loopback server, opens the browser, and returns the code.
func waitForAuthCode(ctx context.Context, host string, port int, redirectURI, expectedState string, open BrowserOpener, authURL string) (string, error) {
	if host != "127.0.0.1" {
		return "", apperr.New(apperr.CodeInternal, "callback listen host must be 127.0.0.1")
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", apperr.Wrap(apperr.CodeInternal,
			fmt.Sprintf("failed to bind loopback callback on %s (port in use or not permitted)", addr), err)
	}

	redirURL, err := url.Parse(redirectURI)
	if err != nil {
		_ = ln.Close()
		return "", apperr.New(apperr.CodeInvalidArgument, "redirect_uri is not a valid URL")
	}
	callbackPath := redirURL.Path
	if callbackPath == "" {
		callbackPath = "/"
	}

	type result struct {
		code string
		err  error
	}
	resCh := make(chan result, 1)
	var once sync.Once
	deliver := func(code string, err error) {
		once.Do(func() {
			resCh <- result{code: code, err: err}
		})
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Exact path match only (reject probes / open-redirect style path confusion).
		if r.URL.Path != callbackPath {
			http.NotFound(w, r)
			return
		}
		// Only GET callbacks (authorization response).
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		q := r.URL.Query()
		if errParam := q.Get("error"); errParam != "" {
			// Never echo IdP error_description verbatim if it might be huge; keep short.
			msg := "authorization server returned error=" + errParam
			deliver("", apperr.New(apperr.CodeAuthentication, msg))
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "Authentication failed. You can close this window.\n")
			return
		}
		gotState := q.Get("state")
		if gotState == "" || gotState != expectedState {
			deliver("", apperr.New(apperr.CodeAuthentication, "oauth state mismatch (CSRF protection)"))
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		}
		code := q.Get("code")
		if strings.TrimSpace(code) == "" {
			deliver("", apperr.New(apperr.CodeAuthentication, "authorization code missing from callback"))
			http.Error(w, "missing code", http.StatusBadRequest)
			return
		}
		// Success: accept first valid callback only (duplicate → already delivered).
		deliver(code, nil)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "Authentication complete. You can close this window and return to the terminal.\n")
	})

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		// BaseContext ties request handlers to the login ctx.
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	go func() {
		// Serve until closed; ignore ErrServerClosed.
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			deliver("", apperr.Wrap(apperr.CodeInternal, "callback server failed", err))
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		_ = ln.Close()
	}()

	if err := open(ctx, authURL); err != nil {
		return "", err
	}

	select {
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "", apperr.Wrap(apperr.CodeTimeout, "oidc login timed out waiting for browser callback", ctx.Err())
		}
		return "", apperr.Wrap(apperr.CodeCancelled, "oidc login cancelled", ctx.Err())
	case res := <-resCh:
		if res.err != nil {
			return "", res.err
		}
		return res.code, nil
	}
}

type tokenExchangeRequest struct {
	ClientID     string
	Code         string
	RedirectURI  string
	CodeVerifier string
	Resource     string
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

func exchangeAuthorizationCode(ctx context.Context, client *http.Client, tokenEndpoint string, req tokenExchangeRequest) (*tokenResponse, error) {
	if client == nil {
		return nil, apperr.New(apperr.CodeInternal, "token HTTP client is required")
	}
	tokenEndpoint = strings.TrimSpace(tokenEndpoint)
	if tokenEndpoint == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "token_endpoint is required")
	}
	if strings.TrimSpace(req.Code) == "" {
		return nil, apperr.New(apperr.CodeAuthentication, "authorization code is required")
	}
	if strings.TrimSpace(req.CodeVerifier) == "" {
		return nil, apperr.New(apperr.CodeInternal, "code_verifier is required")
	}
	if strings.TrimSpace(req.ClientID) == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "client_id is required")
	}
	if strings.TrimSpace(req.RedirectURI) == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "redirect_uri is required")
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", req.Code)
	form.Set("redirect_uri", req.RedirectURI)
	form.Set("client_id", req.ClientID)
	form.Set("code_verifier", req.CodeVerifier)
	// Public client: no client_secret (must not exist in profile).
	if r := strings.TrimSpace(req.Resource); r != "" {
		form.Set("resource", r)
	}

	// Bound wall time when neither client nor context has a deadline.
	if client.Timeout == 0 {
		if _, ok := ctx.Deadline(); !ok {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, DefaultTokenHTTPTimeout)
			defer cancel()
		}
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "failed to build token request", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, apperr.Wrap(apperr.CodeCancelled, "token exchange cancelled", err)
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, apperr.Wrap(apperr.CodeTimeout, "token exchange timed out", err)
		}
		return nil, apperr.Wrap(apperr.CodeUpstreamProtocol, "token request failed", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxTokenResponseBytes+1))
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeUpstreamProtocol, "failed to read token response", err)
	}
	if len(body) > MaxTokenResponseBytes {
		return nil, apperr.New(apperr.CodeUpstreamProtocol, "token response exceeds size limit")
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		// Do not include body in error (may contain tokens on partial success).
		return nil, apperr.Wrap(apperr.CodeUpstreamProtocol, "token response JSON is invalid", err)
	}
	if tr.Error != "" {
		// Safe short message; never include raw body.
		return nil, apperr.New(apperr.CodeAuthentication,
			fmt.Sprintf("token endpoint error=%s", tr.Error))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, apperr.New(apperr.CodeUpstreamProtocol,
			fmt.Sprintf("token endpoint HTTP %d", resp.StatusCode))
	}
	if strings.TrimSpace(tr.AccessToken) == "" {
		return nil, apperr.New(apperr.CodeAuthentication, "token response missing access_token")
	}
	return &tr, nil
}

func randomURLToken(nBytes int) (string, error) {
	if nBytes < 16 {
		nBytes = 16
	}
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", apperr.Wrap(apperr.CodeInternal, "failed to generate random token", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
