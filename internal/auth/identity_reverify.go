package auth

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/audit"
)

// Stable reason codes for IdentityReverifyGate audit events (privacy-preserving).
// Never put unexpected principal ids or tokens into free-text fields.
const (
	// ReasonIdentityPrincipalDrift: whoAmI (or cache) principal differs from serve-time bind.
	ReasonIdentityPrincipalDrift = "identity_principal_drift"
	// ReasonIdentityReverifyFail: whoAmI/auth failure during mid-serve re-verify (e.g. 401).
	ReasonIdentityReverifyFail = "identity_reverify_fail"
	// ReasonIdentityUnbound: gate has no BoundPrincipalID (misconfiguration / fail closed).
	ReasonIdentityUnbound = "identity_unbound"
)

// IdentityReverifyConfig configures mid-serve whoAmI re-verification (AUTH-004).
// Secrets are never logged; Session may hold tokens only in memory.
type IdentityReverifyConfig struct {
	// Profile is the non-secret auth profile (URL + expected user label).
	Profile Profile
	// Session returns the current in-memory Session for whoAmI. Called only on
	// cache miss / TTL expiry. Must not log Secret. Required.
	Session func(ctx context.Context) (Session, error)
	// Cache holds the last verified principal. Nil ⇒ a new DefaultIdentityCacheTTL cache.
	// Prefer sharing the serve-start cache (built with ParseIdentityReverifyTTL) so the
	// first Check is a hit and the configured TTL is honored for the serve lifetime.
	Cache *IdentityCache
	// HTTP is optional; nil uses VerifyIdentityHTTP default client.
	HTTP *http.Client
	// BoundPrincipalID is the serve-time whoAmI principal id. Required.
	// Any subsequent whoAmI with a different id fails closed (sticky).
	BoundPrincipalID string
	// Timeout bounds each re-verify whoAmI call (0 → DefaultIdentityHTTPTimeout).
	Timeout time.Duration
	// Now is an optional injectable clock (tests). When set, also applied to Cache.
	Now func() time.Time
	// Audit is an optional privacy-preserving sink for fail-closed re-verify events.
	// Nil ⇒ no emit (same fail-closed auth outcome). Emit is best-effort and never
	// changes Check() success/failure.
	Audit audit.Sink
	// ProfileID is the non-secret connection profile id for audit attribution.
	ProfileID string
}

// IdentityReverifyGate implements tools.AuthGate (Check() error): periodically
// re-runs Jenkins whoAmI and fail-closes when credentials fail, the principal is
// anonymous, or the principal id drifts from the serve-time bound identity.
//
// On Check:
//  1. Sticky failure from a prior identity drift → error
//  2. Cache hit within TTL and principal matches bound id → OK (no network)
//  3. Else load Session and call VerifyIdentityCachedHTTP
//  4. Principal id must EqualFold match BoundPrincipalID
//
// Fail-closed paths emit at most one audit event per reason class for the gate
// lifetime (sticky transition or first network auth fail) so tool-dispatch
// retries do not flood the audit sink. Thread-safe. Holds a mutex across
// re-verify so concurrent tool dispatches single-flight the whoAmI call.
// Never logs tokens; audit PrincipalID is only the serve-time bound id.
type IdentityReverifyGate struct {
	profile    Profile
	session    func(ctx context.Context) (Session, error)
	cache      *IdentityCache
	httpClient *http.Client
	boundID    string
	timeout    time.Duration
	audit      audit.Sink
	profileID  string

	mu                  sync.Mutex
	sticky              error // permanent fail after principal drift (or unbound)
	auditedDrift        bool
	auditedUnbound      bool
	auditedReverifyFail bool
}

// NewIdentityReverifyGate builds a mid-serve whoAmI re-verify gate.
// BoundPrincipalID and Session are required for Check to succeed.
func NewIdentityReverifyGate(cfg IdentityReverifyConfig) *IdentityReverifyGate {
	cache := cfg.Cache
	if cache == nil {
		cache = NewIdentityCache(DefaultIdentityCacheTTL)
	}
	if cfg.Now != nil {
		cache = cache.WithNow(cfg.Now)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultIdentityHTTPTimeout
	}
	return &IdentityReverifyGate{
		profile:    cfg.Profile,
		session:    cfg.Session,
		cache:      cache,
		httpClient: cfg.HTTP,
		boundID:    strings.TrimSpace(cfg.BoundPrincipalID),
		timeout:    timeout,
		audit:      cfg.Audit,
		profileID:  strings.TrimSpace(cfg.ProfileID),
	}
}

// BoundPrincipalID returns the serve-time principal this gate enforces.
func (g *IdentityReverifyGate) BoundPrincipalID() string {
	if g == nil {
		return ""
	}
	return g.boundID
}

// Check implements tools.AuthGate. Nil receiver fails closed.
func (g *IdentityReverifyGate) Check() error {
	if g == nil {
		return apperr.New(apperr.CodeAuthentication, "identity re-verify gate is not configured (fail closed)")
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.sticky != nil {
		return g.sticky
	}
	if g.boundID == "" {
		g.sticky = apperr.New(apperr.CodeAuthentication, "identity re-verify has no bound principal (fail closed)")
		g.emitAuditLocked(ReasonIdentityUnbound, &g.auditedUnbound)
		return g.sticky
	}
	if g.session == nil {
		g.sticky = apperr.New(apperr.CodeInternal, "identity re-verify session source is not configured")
		// Misconfiguration: count as reverify fail (once) without inventing a new code.
		g.emitAuditLocked(ReasonIdentityReverifyFail, &g.auditedReverifyFail)
		return g.sticky
	}

	// Fast path: fresh cache with matching principal — no network.
	if g.cache != nil {
		if p, ok := g.cache.Get(); ok {
			if strings.EqualFold(p.ID, g.boundID) {
				return nil
			}
			// Cache held a different principal than serve-time bind (should not
			// happen in production). Fail sticky closed.
			g.cache.Invalidate()
			g.sticky = principalDriftError()
			g.emitAuditLocked(ReasonIdentityPrincipalDrift, &g.auditedDrift)
			return g.sticky
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), g.timeout)
	defer cancel()

	sess, err := g.session(ctx)
	if err != nil {
		// Do not sticky on session-load failures (e.g. transient OIDC refresh);
		// Live gate / SessionGuard may already be sticky. Preserve upstream codes.
		// Auth-class session load: emit once (avoid spam on every tool call).
		if isAuthClassError(err) {
			g.emitAuditLocked(ReasonIdentityReverifyFail, &g.auditedReverifyFail)
		}
		return err
	}
	// Canary: never include secret in any path we return.
	secret := sess.Secret

	p, err := VerifyIdentityCachedHTTP(ctx, g.profile, sess, g.cache, g.httpClient)
	if err != nil {
		scrubbed := scrubReverifySecret(err, secret)
		// whoAmI 401/anonymous/auth failure: emit once for the gate lifetime so
		// TTL-expiry retries do not flood audit.
		if isAuthClassError(scrubbed) {
			g.emitAuditLocked(ReasonIdentityReverifyFail, &g.auditedReverifyFail)
		}
		return scrubbed
	}
	if !strings.EqualFold(strings.TrimSpace(p.ID), g.boundID) {
		if g.cache != nil {
			g.cache.Invalidate()
		}
		g.sticky = principalDriftError()
		g.emitAuditLocked(ReasonIdentityPrincipalDrift, &g.auditedDrift)
		return g.sticky
	}
	return nil
}

func principalDriftError() error {
	// Stable model-safe message; do not echo unexpected principal ids.
	return apperr.New(apperr.CodeAuthentication,
		"jenkins principal changed during serve; re-authenticate")
}

func scrubReverifySecret(err error, secret string) error {
	if err == nil {
		return nil
	}
	if secret != "" && strings.Contains(err.Error(), secret) {
		return apperr.New(apperr.CodeAuthentication, "identity verification failed")
	}
	return err
}

// isAuthClassError reports whether err is an authentication-class failure
// suitable for identity_reverify_fail audit (vs timeout/cancel noise).
func isAuthClassError(err error) bool {
	if err == nil {
		return false
	}
	switch apperr.CodeOf(err) {
	case apperr.CodeAuthentication, apperr.CodeAuthorization:
		return true
	default:
		return false
	}
}

// emitAuditLocked records a single TypeAuthFail event for reason when *once is false.
// Caller must hold g.mu. Best-effort: audit errors never change auth outcome.
// PrincipalID is only the serve-time bound id (never the unexpected whoAmI id).
func (g *IdentityReverifyGate) emitAuditLocked(reason string, once *bool) {
	if g == nil || once == nil || *once {
		return
	}
	*once = true
	if g.audit == nil {
		return
	}
	_ = audit.Emit(context.Background(), g.audit, audit.Event{
		Time:        time.Now().UTC(),
		Type:        audit.TypeAuthFail,
		ProfileID:   g.profileID,
		PrincipalID: g.boundID, // expected serve-time bind only
		Action:      "identity_reverify",
		Decision:    audit.DecisionFail,
		ReasonCode:  reason,
	})
}
