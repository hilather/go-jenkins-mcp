// Package jenkins implements the Jenkins HTTP API client used by the MCP tools.
// It must not import MCP packages (FND-004).
package jenkins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// AuthScheme selects how Client credentials are applied on the wire (OAUTH-005).
type AuthScheme string

const (
	// AuthSchemeBasic sends HTTP Basic with User:Token (personal API token path).
	// Empty AuthScheme is treated as Basic for backward compatibility.
	AuthSchemeBasic AuthScheme = "basic"
	// AuthSchemeBearer sends Authorization: Bearer Token (OIDC Jenkins-audience access token).
	// User is not placed on the wire; it remains a local principal label only.
	AuthSchemeBearer AuthScheme = "bearer"
)

// AuthProvider returns live wire credentials for a single Jenkins HTTP request.
// Used for OIDC mid-serve refresh; leave nil for static api_token sessions.
// Implementations must never put secrets into returned errors.
// scheme may be empty (treated as Basic by applyAuth).
//
// Prefer AuthProviderCtx for per-request multi-user Obtain (HOST multi-user):
// AuthProvider captures a process-bound identity and cannot see request context.
type AuthProvider func() (user, secret string, scheme AuthScheme, err error)

// AuthProviderCtx returns live wire credentials for a single Jenkins HTTP request
// using the request context (HOST multi-user / per-request Obtain).
//
// Used when gateway multi-user mode injects a Caller into ctx. Leave nil for
// single-subject AuthProvider or static api_token sessions.
// Implementations must never put secrets into returned errors.
// scheme may be empty (treated as Basic by applyAuth).
//
// When AuthProviderCtx is set, applyAuth does not write secrets back onto
// Client.User/Token (avoids cross-request races under concurrent multi-user).
type AuthProviderCtx func(ctx context.Context) (user, secret string, scheme AuthScheme, err error)

// Client bundles configuration for jenkins api calls.
//
// Network behavior (NET-002/NET-003):
//   - Prefer constructing API/Logs clients via NewHTTPClients / WithTransport so
//     both share a pooled http.Transport with explicit dial/TLS/header/idle timeouts.
//   - CallJenkins applies origin pin (NET-001), optional retries on GET/HEAD only,
//     body limits on non-log paths, concurrency throttle, and a circuit breaker.
//   - Progressive log paths (closeConn) keep LOG-001 length caps and skip the
//     JSON body hard max.
//
// Auth (OAUTH-005): AuthSchemeBasic (default) uses HTTP Basic; AuthSchemeBearer
// uses Authorization: Bearer with Token as the access token (never log Token).
// Optional AuthProvider refreshes OIDC credentials before each request (wave 14).
// Optional AuthProviderCtx supplies per-request credentials from context
// (gateway multi-user Obtain). AuthProviderCtx wins when both are set.
//
// The package must not import MCP packages (FND-004).
type Client struct {
	mutationGuard MutationGuard // POL-004 optional network PEP

	URL   string
	Auth  string // format: "user:api_token" (kept for backward compatibility)
	User  string
	Token string
	// AuthScheme selects Basic vs Bearer. Empty defaults to Basic (api_token).
	AuthScheme AuthScheme
	// AuthProvider optionally supplies live credentials before each request
	// (OIDC mid-serve refresh / single-subject gateway Obtain). Nil keeps static
	// User/Token/AuthScheme (api_token). On error, CallJenkins fails closed
	// without sending the request. Secrets must never appear in returned errors.
	// Concurrent-safe for single-subject use; multi-user prefers AuthProviderCtx.
	AuthProvider AuthProvider
	// AuthProviderCtx optionally supplies live credentials from request context
	// (per-request multi-user Obtain). When non-nil, takes precedence over
	// AuthProvider and does not write User/Token on the Client (race residual).
	// Concurrent-safe. Secrets must never appear in returned errors.
	AuthProviderCtx AuthProviderCtx
	Client          *http.Client
	LogsClient      *http.Client

	// acceptGzip advertises Accept-Encoding: gzip (opt-in; see TransportConfig).
	acceptGzip bool
	// counters records wire vs decoded bytes when non-nil.
	counters ByteCounters
	// metrics optional OBS-001 HTTP request/byte/error hook (no telemetry import).
	metrics MetricsHook
	// res holds retries, body limits, throttle, and circuit breaker (NET-003).
	// nil uses DefaultResilienceConfig on first use via ensureResilience.
	res     *Resilience
	resOnce sync.Once // race-safe lazy init under concurrent CallJenkins
	// authMu guards User/Token/AuthScheme against concurrent applyAuth
	// write-back (AuthProvider refresh path) racing per-request reads.
	authMu sync.Mutex
	// sharedTransport is the pooled Transport from NewHTTPClients, if any.
	sharedTransport *http.Transport
	// Capability discovery cache (JEN-001).
	capMu         sync.Mutex
	capTTL        time.Duration
	capCache      *CapabilitySet
	capCacheUntil time.Time
	// Shared adaptive wait demux (JEN-004).
	waitOnce      sync.Once
	waitC         *WaitCoordinator
	queuePollSnap map[int]int
	buildPollSnap map[string]int
}

// NewClient builds a Client with enterprise HTTP transport and resilience defaults.
// Default transport settings (system trust, env proxy) always construct successfully.
func NewClient(baseURL, user, token string) *Client {
	c := &Client{
		URL:   baseURL,
		User:  user,
		Token: token,
	}
	if _, err := c.WithTransport(DefaultTransportConfig()); err != nil {
		// Defaults have no custom CA/mTLS files; failure is unexpected.
		// Leave Client nil so callers fail closed on first request rather than
		// silently using http.DefaultClient without origin pin / limits.
		return c.WithResilience(DefaultResilienceConfig())
	}
	return c.WithResilience(DefaultResilienceConfig())
}

// NewClientWithTransport builds a Client with an explicit TransportConfig (NET-004).
// Uses AuthSchemeBasic (personal API token). Returns an error when CA/mTLS files
// are unreadable or proxy URL is invalid.
func NewClientWithTransport(baseURL, user, token string, cfg TransportConfig) (*Client, error) {
	return NewClientWithTransportScheme(baseURL, user, token, AuthSchemeBasic, cfg)
}

// NewClientWithTransportScheme builds a Client with explicit wire auth scheme
// (OAUTH-005). Use AuthSchemeBearer for OIDC access tokens; AuthSchemeBasic for
// api_token. Token material must never be logged.
func NewClientWithTransportScheme(baseURL, user, token string, scheme AuthScheme, cfg TransportConfig) (*Client, error) {
	c := &Client{
		URL:        baseURL,
		User:       user,
		Token:      token,
		AuthScheme: scheme,
	}
	if _, err := c.WithTransport(cfg); err != nil {
		return nil, err
	}
	return c.WithResilience(DefaultResilienceConfig()), nil
}

// applyAuth sets Authorization on req from User/Token/AuthScheme, optionally
// refreshing via AuthProviderCtx (preferred) or AuthProvider first
// (OIDC mid-serve continuity / gateway Obtain).
// Bearer never sets Basic; Basic never sets Bearer.
// On provider failure the request is not authorized and err is returned
// (fail closed; secrets must not appear in err).
func (opts *Client) applyAuth(req *http.Request) error {
	if opts == nil || req == nil {
		return nil
	}
	opts.authMu.Lock()
	user, token, scheme := opts.User, opts.Token, opts.AuthScheme
	opts.authMu.Unlock()
	// Prefer context-scoped provider (multi-user Obtain) so concurrent requests
	// never share a process-bound subject or write secrets onto Client fields.
	if opts.AuthProviderCtx != nil {
		ctx := req.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		u, s, sch, err := opts.AuthProviderCtx(ctx)
		if err != nil {
			return err
		}
		user, token, scheme = u, s, sch
		// Intentionally do not write User/Token/AuthScheme — concurrent multi-user
		// requests would race and could leak another subject's credentials into
		// static fields used by diagnostics or a cleared-provider fallthrough.
	} else if opts.AuthProvider != nil {
		u, s, sch, err := opts.AuthProvider()
		if err != nil {
			return err
		}
		user, token, scheme = u, s, sch
		// Keep static fields in sync for diagnostics / subsequent static reads
		// (single-subject path only). Mutex-guarded: concurrent requests race
		// on these fields otherwise (torn string reads can crash).
		opts.authMu.Lock()
		opts.User = u
		opts.Token = s
		opts.AuthScheme = sch
		opts.authMu.Unlock()
	}
	if scheme == "" {
		scheme = AuthSchemeBasic
	}
	switch scheme {
	case AuthSchemeBearer:
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	default:
		// Basic: personal API token path (and legacy Auth field callers using User/Token).
		if user != "" || token != "" {
			req.SetBasicAuth(user, token)
		}
	}
	return nil
}

// HasLiveAuthProvider reports whether a dynamic credential provider is installed
// (AuthProviderCtx or AuthProvider). Used by gateway session-start whoAmI to
// refuse local static fallthrough when Obtain is expected.
func (opts *Client) HasLiveAuthProvider() bool {
	if opts == nil {
		return false
	}
	return opts.AuthProviderCtx != nil || opts.AuthProvider != nil
}

// WithAuthProvider installs a live credential source (OIDC refresh / single-subject
// gateway Obtain). Nil clears it. Returns the receiver for chaining.
// api_token paths leave AuthProvider nil. Does not clear AuthProviderCtx.
func (opts *Client) WithAuthProvider(p AuthProvider) *Client {
	if opts == nil {
		return nil
	}
	opts.AuthProvider = p
	return opts
}

// WithAuthProviderCtx installs a context-scoped live credential source
// (per-request multi-user Obtain). Nil clears it. Returns the receiver for chaining.
// Does not clear AuthProvider; when both are set, AuthProviderCtx wins in applyAuth.
func (opts *Client) WithAuthProviderCtx(p AuthProviderCtx) *Client {
	if opts == nil {
		return nil
	}
	opts.AuthProviderCtx = p
	return opts
}

// WithTransport installs shared API/Logs http.Clients from cfg (NET-002 / NET-004).
// On error the receiver is unchanged. Returns the receiver for chaining.
// When a MetricsHook is already installed, byte counters fan out to both the
// transport ByteCounters and the hook.
func (opts *Client) WithTransport(cfg TransportConfig) (*Client, error) {
	if opts == nil {
		return nil, errors.New("nil jenkins client")
	}
	hc, err := NewHTTPClients(cfg)
	if err != nil {
		return opts, err
	}
	opts.Client = hc.API
	opts.LogsClient = hc.Logs
	opts.sharedTransport = hc.Transport
	opts.acceptGzip = hc.AcceptGzip
	opts.counters = hc.Counters
	opts.rebindMetricsCounters()
	return opts, nil
}

// WithMetrics installs an optional OBS-001 MetricsHook for request/error/byte
// counters and circuit open events (Wave 27). Nil clears the hook (non-hook
// ByteCounters from TransportConfig are preserved when present). Safe to call
// after WithTransport. Returns the receiver for chaining. Does not import
// internal/telemetry — adapters live in tools/cmd.
func (opts *Client) WithMetrics(h MetricsHook) *Client {
	if opts == nil {
		return nil
	}
	opts.metrics = h
	if h == nil {
		// Drop hook byte sinks; keep any explicit non-hook counters.
		if f, ok := opts.counters.(fanoutByteCounters); ok {
			opts.counters = f.a
		} else if _, ok := opts.counters.(metricsHookByteCounters); ok {
			opts.counters = NopByteCounters{}
		}
		opts.bindCircuitMetrics()
		return opts
	}
	opts.rebindMetricsCounters()
	opts.bindCircuitMetrics()
	return opts
}

// bindCircuitMetrics wires MetricsHook.IncCircuitOpenEvent into Resilience
// without importing telemetry (OBS Wave 27 / NET-003).
// Assignment is mutex-protected so it is safe if called while requests are in flight.
func (opts *Client) bindCircuitMetrics() {
	if opts == nil || opts.res == nil {
		return
	}
	h := opts.metrics
	var hook func()
	if h != nil {
		hook = func() {
			h.IncCircuitOpenEvent()
		}
	}
	opts.res.mu.Lock()
	opts.res.onCircuitOpen = hook
	opts.res.mu.Unlock()
}

// Metrics returns the installed MetricsHook, if any.
func (opts *Client) Metrics() MetricsHook {
	if opts == nil {
		return nil
	}
	return opts.metrics
}

// rebindMetricsCounters merges metrics hook byte sinks with any explicit counters.
func (opts *Client) rebindMetricsCounters() {
	if opts == nil || opts.metrics == nil {
		return
	}
	hookBC := metricsHookByteCounters{h: opts.metrics}
	if isNopByteCounters(opts.counters) {
		opts.counters = hookBC
		return
	}
	// Avoid stacking fanouts if WithMetrics/WithTransport called repeatedly.
	if f, ok := opts.counters.(fanoutByteCounters); ok {
		opts.counters = fanoutByteCounters{a: f.a, b: hookBC}
		return
	}
	if _, ok := opts.counters.(metricsHookByteCounters); ok {
		opts.counters = hookBC
		return
	}
	opts.counters = fanoutByteCounters{a: opts.counters, b: hookBC}
}

// WithResilience installs NET-003 retry/limit/breaker policy. Returns the receiver.
// Rebinds circuit open metrics when a MetricsHook is already installed.
func (opts *Client) WithResilience(cfg ResilienceConfig) *Client {
	if opts == nil {
		return nil
	}
	opts.res = NewResilience(cfg)
	opts.bindCircuitMetrics()
	return opts
}

// CloseIdleConnections closes idle keep-alive connections on the shared transport.
func (opts *Client) CloseIdleConnections() {
	if opts == nil {
		return
	}
	if opts.sharedTransport != nil {
		opts.sharedTransport.CloseIdleConnections()
	}
}

// CircuitState returns the circuit breaker snapshot (NET-003 observability).
func (opts *Client) CircuitState() CircuitState {
	if opts == nil || opts.res == nil {
		return CircuitState{State: "closed", FailureThreshold: defaultCircuitFailures}
	}
	return opts.res.State()
}

func (opts *Client) ensureResilience() *Resilience {
	if opts == nil {
		return NewResilience(DefaultResilienceConfig())
	}
	// Concurrent waiters (queue/build demux) may call CallJenkins before res is set;
	// sync.Once prevents racing NewResilience / bindCircuitMetrics (CI -race).
	opts.resOnce.Do(func() {
		if opts.res == nil {
			opts.res = NewResilience(DefaultResilienceConfig())
			opts.bindCircuitMetrics()
		}
	})
	return opts.res
}

// CallJenkins builds the URL (absolute or relative to the pinned base), attaches
// auth and headers, and executes the request (NET-001/NET-002/NET-003).
//
// Relative paths are joined to the normalized base URL (including any reverse-proxy
// path prefix). Absolute http(s) URLs are accepted only when they match the pinned
// origin (scheme, host, port, path prefix); other origins are rejected so
// credentials are never sent off-origin. Redirects are origin-pinned via
// CheckRedirect.
//
// Non-log responses are hard-capped by MaxJSONBodyBytes (default 32 MiB). GET/HEAD
// may be retried with jittered backoff; POST mutations are never auto-retried.
//
// Default Accept header is application/json unless overridden via headers.

// WithMutationGuard installs an optional POL-004 request guard (read-only / RBAC
// at the Jenkins HTTP boundary). Nil clears the guard. Returns the receiver.
func (opts *Client) WithMutationGuard(g MutationGuard) *Client {
	if opts == nil {
		return nil
	}
	opts.mutationGuard = g
	return opts
}

// MutationGuard returns the installed guard, if any.
func (opts *Client) MutationGuard() MutationGuard {
	if opts == nil {
		return nil
	}
	return opts.mutationGuard
}

func (opts *Client) CallJenkins(
	ctx context.Context,
	client *http.Client,
	method string,
	apiPath string,
	body io.Reader,
	headers map[string]string,
) (*http.Response, error) {
	return opts.callJenkins(ctx, client, method, apiPath, body, headers, false)
}

// callJenkins is the shared request path. When closeConn is true, the request
// sets req.Close so the transport will not keep-alive-slurp an unread body after
// a limited progressiveText read (LOG-001). closeConn also skips the JSON body
// hard max so progressive log paths keep LOG-001 length limits only.
func (opts *Client) callJenkins(
	ctx context.Context,
	client *http.Client,
	method string,
	apiPath string,
	body io.Reader,
	headers map[string]string,
	closeConn bool,
) (*http.Response, error) {
	if client == nil {
		client = opts.Client
	}
	if client == nil {
		return nil, fmt.Errorf("jenkins: nil http.Client")
	}
	fullURL, err := opts.resolveRequestURL(apiPath)
	if err != nil {
		return nil, err
	}

	res := opts.ensureResilience()
	// Network-layer PEP (POL-004): classify + optional MutationGuard before I/O.
	class := ClassifyJenkinsRequest(method, apiPath)
	if opts.mutationGuard != nil {
		if err := opts.mutationGuard.CheckRequest(ctx, class, method, apiPath); err != nil {
			return nil, err
		}
	}
	if err := res.acquire(ctx); err != nil {
		return nil, err
	}
	defer res.release()

	if err := res.allow(); err != nil {
		return nil, err
	}

	// Origin-pinned redirect policy (NET-001): refuse cross-origin redirects.
	client = opts.withPinnedRedirect(client)

	idempotent := isIdempotentMethod(method)
	// Non-idempotent methods (POST build trigger / stop) never auto-retry.
	maxAttempts := 1
	if idempotent {
		maxAttempts = 1 + res.cfg.MaxRetries
	}

	// Body can only be sent once; POST paths do not retry so a single Reader is fine.
	// For GET/HEAD body is typically nil.
	var lastErr error
	var resp *http.Response
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			delay := res.retryBackoff(attempt, resp)
			drainAndClose(resp)
			resp = nil
			if err := res.sleep(ctx, delay); err != nil {
				return nil, err
			}
		}

		req, err := http.NewRequestWithContext(ctx, method, fullURL, body)
		if err != nil {
			return nil, err
		}
		if err := opts.applyAuth(req); err != nil {
			return nil, err
		}
		if closeConn {
			// Do not reuse the TCP connection; avoids Body.Close draining the
			// remainder of a progressiveText response into io.Discard for keep-alive.
			req.Close = true
			req.Header.Set("Connection", "close")
		}
		if headers == nil {
			headers = map[string]string{}
		}
		if _, ok := headers["Accept"]; !ok {
			req.Header.Set("Accept", "application/json")
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		if opts.acceptGzip {
			if _, ok := headers["Accept-Encoding"]; !ok {
				req.Header.Set("Accept-Encoding", "gzip")
			}
		}

		resp, lastErr = client.Do(req)
		if lastErr != nil {
			if errors.Is(lastErr, context.Canceled) {
				// Caller-side cancellation is not a Jenkins health signal:
				// never count it toward the breaker, and release the
				// half-open probe slot if this request was the probe so
				// the circuit cannot wedge half-open. Never retried.
				res.onAbort()
				recordJenkinsHTTPMetrics(opts.metrics, nil, lastErr)
				return nil, lastErr
			}
			res.onFailure()
			recordJenkinsHTTPMetrics(opts.metrics, nil, lastErr)
			if !idempotent || !isRetryableTransportError(lastErr) || attempt+1 >= maxAttempts {
				return nil, lastErr
			}
			continue
		}

		// Retryable upstream statuses for safe reads only.
		if idempotent && classifyRetryStatus(resp.StatusCode) && attempt+1 < maxAttempts {
			if isCircuitFailureStatus(resp.StatusCode) {
				res.onFailure()
			}
			// Count the attempt; caller will retry. Status ≥400 → error counter.
			recordJenkinsHTTPMetrics(opts.metrics, resp, nil)
			lastErr = fmt.Errorf("retryable status %d", resp.StatusCode)
			continue
		}

		if isCircuitFailureStatus(resp.StatusCode) {
			res.onFailure()
		} else if resp.StatusCode < 500 {
			res.onSuccess()
		}

		// Optional gzip decode + wire/decoded counters (NET-002).
		if err := wrapResponseBody(resp, opts.acceptGzip, opts.counters); err != nil {
			// Request reached the wire; body wrap failure is an error outcome.
			recordJenkinsHTTPMetrics(opts.metrics, resp, err)
			drainAndClose(resp)
			return nil, err
		}

		// JSON/API body hard max (NET-003). Log paths keep LOG-001 only.
		if !closeConn && resp.Body != nil {
			resp.Body = newLimitedBody(resp.Body, res.cfg.MaxJSONBodyBytes)
		}

		recordJenkinsHTTPMetrics(opts.metrics, resp, nil)
		return resp, nil
	}
	if resp != nil {
		drainAndClose(resp)
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("jenkins: request failed after retries")
}

// recordJenkinsHTTPMetrics increments request (+ optional error) on MetricsHook.
// Transport errors and HTTP status ≥ 400 count as errors. Nil-safe.
// Does not record when no Do() attempt completed (auth/guard/throttle fail closed first).
func recordJenkinsHTTPMetrics(h MetricsHook, resp *http.Response, err error) {
	if h == nil {
		return
	}
	h.IncRequest()
	if err != nil {
		h.IncError()
		return
	}
	if resp != nil && resp.StatusCode >= 400 {
		h.IncError()
	}
}

// getCrumb fetches Jenkins CSRF crumb and header field name.
func (opts *Client) GetCrumb(ctx context.Context) (field, crumb string, ok bool, err error) {
	resp, err := opts.CallJenkins(ctx, opts.Client, http.MethodGet, "/crumbIssuer/api/json", nil, nil)
	if err != nil {
		return "", "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		// Crumbs disabled
		return "", "", false, nil
	}
	if resp.StatusCode != http.StatusOK {
		// Don't fail build start if crumb endpoint errors; treat as no crumb
		return "", "", false, nil
	}
	var data struct {
		Field string `json:"crumbRequestField"`
		Crumb string `json:"crumb"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", "", false, nil
	}
	if data.Field == "" || data.Crumb == "" {
		return "", "", false, nil
	}
	return data.Field, data.Crumb, true, nil
}
