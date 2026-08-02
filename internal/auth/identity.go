package auth

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
)

// Principal is a verified Jenkins identity (non-secret). Never store tokens here.
type Principal struct {
	// ID is the Jenkins whoAmI "id" (user id).
	ID string
	// FullName is the optional display name from whoAmI.
	FullName string
}

// DefaultIdentityCacheTTL is the short re-verify window used by serve (AUTH-004)
// when identity re-verify TTL is unset or zero.
const DefaultIdentityCacheTTL = 5 * time.Minute

// MinIdentityReverifyTTL is the shortest allowed mid-serve whoAmI re-verify window.
// Below this, invalid configuration fails closed at serve start (AUTH-004 Wave 24).
const MinIdentityReverifyTTL = 10 * time.Second

// MaxIdentityReverifyTTL is the longest allowed mid-serve whoAmI re-verify window.
// Above this, invalid configuration fails closed at serve start (AUTH-004 Wave 24).
const MaxIdentityReverifyTTL = 30 * time.Minute

// EnvIdentityReverifyTTL is the serve env for configurable whoAmI re-verify TTL.
// CLI --identity-reverify-ttl overrides this when set. Empty/zero → DefaultIdentityCacheTTL.
const EnvIdentityReverifyTTL = "JENKINS_MCP_IDENTITY_REVERIFY_TTL"

// DefaultIdentityHTTPTimeout bounds whoAmI latency during login/serve.
const DefaultIdentityHTTPTimeout = 15 * time.Second

// IdentityCache holds a process-local verified principal with a short TTL.
// It is not a secret store; it only caches non-secret identity metadata.
type IdentityCache struct {
	mu         sync.Mutex
	principal  Principal
	verifiedAt time.Time
	ttl        time.Duration
	// nowFn is an optional injectable clock (tests). Nil ⇒ time.Now.
	nowFn func() time.Time
}

// NewIdentityCache builds a cache with the given TTL (0 → DefaultIdentityCacheTTL).
// Callers that accept operator input should use ParseIdentityReverifyTTL first so
// out-of-bounds values fail closed at serve start rather than silently clamping.
func NewIdentityCache(ttl time.Duration) *IdentityCache {
	if ttl <= 0 {
		ttl = DefaultIdentityCacheTTL
	}
	return &IdentityCache{ttl: ttl}
}

// ParseIdentityReverifyTTL resolves the mid-serve whoAmI re-verify window.
// Precedence: flagVal (CLI --identity-reverify-ttl) when non-empty, else envVal
// (JENKINS_MCP_IDENTITY_REVERIFY_TTL), else DefaultIdentityCacheTTL.
//
// Rules (fail closed — never clamp silently):
//   - empty / whitespace → DefaultIdentityCacheTTL
//   - unparseable Go duration → error
//   - zero duration (e.g. "0", "0s") → DefaultIdentityCacheTTL
//   - negative → error
//   - < MinIdentityReverifyTTL (10s) → error
//   - > MaxIdentityReverifyTTL (30m) → error
//
// Residual by design: this is a cache TTL, not continuous every-call whoAmI.
func ParseIdentityReverifyTTL(flagVal, envVal string) (time.Duration, error) {
	raw := strings.TrimSpace(flagVal)
	source := "flag --identity-reverify-ttl"
	if raw == "" {
		raw = strings.TrimSpace(envVal)
		source = "env " + EnvIdentityReverifyTTL
	}
	if raw == "" {
		return DefaultIdentityCacheTTL, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"invalid identity re-verify TTL from "+source+" (use Go duration, e.g. 30s, 1m, 5m): "+raw)
	}
	if d < 0 {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"identity re-verify TTL from "+source+" must not be negative")
	}
	if d == 0 {
		return DefaultIdentityCacheTTL, nil
	}
	if d < MinIdentityReverifyTTL {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"identity re-verify TTL from "+source+" is below minimum "+MinIdentityReverifyTTL.String()+" (got "+d.String()+")")
	}
	if d > MaxIdentityReverifyTTL {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"identity re-verify TTL from "+source+" exceeds maximum "+MaxIdentityReverifyTTL.String()+" (got "+d.String()+")")
	}
	return d, nil
}

// WithNow sets an injectable clock for TTL evaluation (tests). Nil ⇒ time.Now.
// Returns the same cache for chaining. Not safe to call concurrently with Get/Set.
func (c *IdentityCache) WithNow(now func() time.Time) *IdentityCache {
	if c == nil {
		return nil
	}
	c.nowFn = now
	return c
}

func (c *IdentityCache) now() time.Time {
	if c != nil && c.nowFn != nil {
		return c.nowFn()
	}
	return time.Now()
}

// TTL returns the configured cache lifetime.
func (c *IdentityCache) TTL() time.Duration {
	if c == nil {
		return DefaultIdentityCacheTTL
	}
	return c.ttl
}

// Get returns a still-fresh principal when present.
func (c *IdentityCache) Get() (Principal, bool) {
	if c == nil {
		return Principal{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.principal.ID == "" || c.verifiedAt.IsZero() {
		return Principal{}, false
	}
	if c.now().Sub(c.verifiedAt) > c.ttl {
		return Principal{}, false
	}
	return c.principal, true
}

// Set stores a verified principal.
func (c *IdentityCache) Set(p Principal) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.principal = p
	c.verifiedAt = c.now()
}

// Invalidate clears the cached principal (logout / mismatch).
func (c *IdentityCache) Invalidate() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.principal = Principal{}
	c.verifiedAt = time.Time{}
}

// VerifyIdentity calls the approved Jenkins whoAmI endpoint with session credentials.
// It fails closed when:
//   - HTTP / transport fails
//   - the principal is anonymous or missing an id
//   - the principal id does not match the expected profile/session username
//
// Errors never include the API token (AUTH-004 secret canary).
func VerifyIdentity(ctx context.Context, pr Profile, sess Session) (Principal, error) {
	return VerifyIdentityHTTP(ctx, pr, sess, nil)
}

// VerifyIdentityHTTP is like VerifyIdentity but uses hc when non-nil (tests / custom transport).
func VerifyIdentityHTTP(ctx context.Context, pr Profile, sess Session, hc *http.Client) (Principal, error) {
	if err := ctx.Err(); err != nil {
		return Principal{}, apperr.Wrap(apperr.CodeCancelled, "identity verification cancelled", err)
	}
	baseURL := strings.TrimSpace(pr.URL)
	if baseURL == "" {
		return Principal{}, apperr.New(apperr.CodeInvalidArgument, "profile URL is required for identity verification")
	}
	user := strings.TrimSpace(sess.User)
	if user == "" {
		user = strings.TrimSpace(pr.User)
	}
	secret := sess.Secret
	if strings.TrimSpace(secret) == "" {
		return Principal{}, apperr.New(apperr.CodeAuthentication, "missing credentials for identity verification")
	}
	if hc == nil {
		hc = &http.Client{Timeout: DefaultIdentityHTTPTimeout}
	}

	client := &jenkins.Client{
		URL:    baseURL,
		User:   user,
		Token:  secret,
		Client: hc,
	}
	// OAUTH-005: OIDC sessions present Authorization: Bearer; api_token stays Basic.
	if sess.Method == MethodOIDC {
		client.AuthScheme = jenkins.AuthSchemeBearer
		// Bearer does not use the Basic username; keep User only for expected-id binding.
	}
	raw, err := client.WhoAmI(ctx)
	if err != nil {
		return Principal{}, mapWhoAmIError(err, secret)
	}

	p, err := PrincipalFromWhoAmI(raw)
	if err != nil {
		return Principal{}, err
	}

	expected := strings.TrimSpace(pr.User)
	if expected == "" {
		expected = user
	}
	// OIDC: when no profile/session username label is known yet (opaque token
	// path), bind solely to whoAmI principal (AUTH-004 still required).
	if expected != "" && !strings.EqualFold(p.ID, expected) {
		// Identity mismatch: fail closed (session invalid for this process).
		return Principal{}, apperr.New(apperr.CodeAuthentication,
			"jenkins identity does not match expected user for this profile")
	}
	return p, nil
}

// PrincipalFromWhoAmI maps a Jenkins whoAmI payload to Principal with fail-closed rules.
func PrincipalFromWhoAmI(raw jenkins.WhoAmI) (Principal, error) {
	id := strings.TrimSpace(raw.ID)
	if raw.Anonymous || strings.EqualFold(id, "anonymous") || id == "" {
		return Principal{}, apperr.New(apperr.CodeAuthentication,
			"jenkins identity is anonymous; authentication failed closed")
	}
	// Prefer explicit authenticated=false when present in JSON (zero value is false
	// for missing field — only reject when Anonymous or empty id already covered).
	// Some controllers omit authenticated; id + !anonymous is sufficient.
	return Principal{
		ID:       id,
		FullName: strings.TrimSpace(raw.FullName),
	}, nil
}

// VerifyIdentityCached returns a fresh cache hit or re-verifies against Jenkins.
func VerifyIdentityCached(ctx context.Context, pr Profile, sess Session, cache *IdentityCache) (Principal, error) {
	return VerifyIdentityCachedHTTP(ctx, pr, sess, cache, nil)
}

// VerifyIdentityCachedHTTP is like VerifyIdentityCached with an optional HTTP client.
func VerifyIdentityCachedHTTP(ctx context.Context, pr Profile, sess Session, cache *IdentityCache, hc *http.Client) (Principal, error) {
	if cache != nil {
		if p, ok := cache.Get(); ok {
			// Still enforce expected-user binding against cached principal.
			expected := strings.TrimSpace(pr.User)
			if expected == "" {
				expected = strings.TrimSpace(sess.User)
			}
			if expected == "" || strings.EqualFold(p.ID, expected) {
				return p, nil
			}
			cache.Invalidate()
		}
	}
	p, err := VerifyIdentityHTTP(ctx, pr, sess, hc)
	if err != nil {
		if cache != nil {
			cache.Invalidate()
		}
		return Principal{}, err
	}
	if cache != nil {
		cache.Set(p)
	}
	return p, nil
}

// BindPrincipal attaches a verified principal to a session (in-memory only).
func BindPrincipal(sess Session, p Principal) Session {
	sess.Principal = p
	if p.ID != "" {
		// Prefer verified id as the process user label (still non-secret).
		sess.User = p.ID
	}
	return sess
}

// mapWhoAmIError converts transport/API failures into stable apperr codes without secrets.
func mapWhoAmIError(err error, secret string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	// Canary: never surface the token even if a lower layer echoed it.
	if secret != "" && strings.Contains(msg, secret) {
		msg = "identity verification failed"
	}
	code := apperr.CodeAuthentication
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "404") || strings.Contains(lower, "not found"):
		code = apperr.CodeUpstreamProtocol
	case strings.Contains(lower, "cancel"):
		code = apperr.CodeCancelled
	case strings.Contains(lower, "timeout") || strings.Contains(lower, "deadline"):
		code = apperr.CodeTimeout
	case strings.Contains(lower, "transport") || strings.Contains(lower, "connection refused") ||
		strings.Contains(lower, "no such host") || strings.Contains(lower, "protocol"):
		// Connectivity / protocol noise still fails auth path closed for login.
		code = apperr.CodeAuthentication
	}
	// Keep message short and model-safe.
	safe := "identity verification failed"
	if strings.Contains(lower, "anonymous") {
		safe = "jenkins identity is anonymous; authentication failed closed"
	} else if strings.Contains(lower, "401") || strings.Contains(lower, "403") || strings.Contains(lower, "rejected") {
		safe = "jenkins rejected credentials during identity verification"
	} else if strings.Contains(lower, "404") || strings.Contains(lower, "not found") {
		safe = "jenkins identity endpoint is unavailable"
	}
	return apperr.Wrap(code, safe, err)
}
