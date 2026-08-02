package fleetcache

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// DefaultAuthzFreshTTL is the maximum age of a cached allow decision (FLC-018).
const DefaultAuthzFreshTTL = 15 * time.Second

// AuthzProbe is an injectable check against current deny-only policy (and optional Jenkins evidence).
// Must not log secrets. On error, FreshnessGate fails closed (deny).
// allowed=false is a clean policy deny (not an error).
type AuthzProbe func(ctx context.Context, key AuthzKey) (allowed bool, reasonCode string, err error)

// AuthzKey identifies a cache-authorization decision. Opaque subject hash only.
type AuthzKey struct {
	SubjectKeyHash string
	ControllerID   string
	JobFullName    string
	// ToolName is the MCP tool that would consume the cache (e.g. jenkins_get_build_logs).
	ToolName string
	// PolicyEpoch binds the decision to a policy generation (0 = unspecified).
	PolicyEpoch int64
}

// AuthzDecision is the gate outcome (secret-free).
type AuthzDecision struct {
	Allowed    bool
	ReasonCode string
	// FromCache is true when returned from the short TTL cache.
	FromCache bool
	// CacheHitElevation is always false — documented residual honesty (cache never elevates).
	CacheHitElevation bool
}

// Reason codes (stable, non-secret).
const (
	ReasonAuthzOK           = "ok"
	ReasonAuthzPolicyDeny   = "policy_deny"
	ReasonAuthzProbeFail    = "probe_fail_closed"
	ReasonAuthzKeyInvalid   = "authz_key_invalid"
	ReasonAuthzSubjectEmpty = "subject_key_empty"
)

// FreshnessGate caches short-lived allow decisions; denials are not cached as allow.
// Probe failure always fails closed (deny), never elevates on a peer cache hit.
type FreshnessGate struct {
	TTL   time.Duration
	Probe AuthzProbe
	Now   func() time.Time

	mu    sync.Mutex
	cache map[string]freshEntry
}

type freshEntry struct {
	allowed    bool
	reasonCode string
	expires    time.Time
}

// NewFreshnessGate builds a gate. TTL<=0 uses DefaultAuthzFreshTTL. Probe required for Allow.
func NewFreshnessGate(ttl time.Duration, probe AuthzProbe) *FreshnessGate {
	if ttl <= 0 {
		ttl = DefaultAuthzFreshTTL
	}
	return &FreshnessGate{
		TTL:   ttl,
		Probe: probe,
		Now:   func() time.Time { return time.Now().UTC() },
		cache: make(map[string]freshEntry),
	}
}

// Allow checks policy freshness for a prospective cache use (local or peer).
// A prior peer/local cache hit must still call Allow — never skip for elevation.
// Metrics (FLC-061): callers should RecordAuthzDecision(dec) — see AllowObserved.
func (g *FreshnessGate) Allow(ctx context.Context, key AuthzKey) (AuthzDecision, error) {
	if g == nil || g.Probe == nil {
		return AuthzDecision{Allowed: false, ReasonCode: ReasonAuthzProbeFail},
			apperr.New(apperr.CodePolicyDenial, "authz freshness gate not configured")
	}
	if err := normalizeAuthzKey(&key); err != nil {
		return AuthzDecision{Allowed: false, ReasonCode: ReasonAuthzKeyInvalid}, err
	}
	now := g.Now().UTC()
	ck := cacheKey(key)

	g.mu.Lock()
	if e, ok := g.cache[ck]; ok && e.expires.After(now) {
		// Only serve cached *allow*; never promote a stale deny to allow, and never
		// treat missing probe as allow. Cached denials still re-probe after TTL.
		if e.allowed {
			g.mu.Unlock()
			return AuthzDecision{
				Allowed:           true,
				ReasonCode:        ReasonAuthzOK,
				FromCache:         true,
				CacheHitElevation: false,
			}, nil
		}
	}
	// purge expired while holding lock
	for k, e := range g.cache {
		if !e.expires.After(now) {
			delete(g.cache, k)
		}
	}
	g.mu.Unlock()

	allowed, reason, err := g.Probe(ctx, key)
	if err != nil {
		// Fail closed: probe errors deny cache use.
		return AuthzDecision{
			Allowed:           false,
			ReasonCode:        ReasonAuthzProbeFail,
			CacheHitElevation: false,
		}, apperr.Wrap(apperr.CodePolicyDenial, "authz probe failed closed", err)
	}
	if reason == "" {
		if allowed {
			reason = ReasonAuthzOK
		} else {
			reason = ReasonAuthzPolicyDeny
		}
	}
	if !allowed {
		// Do not cache denials as sticky forever; short-cache deny to reduce probe storms.
		g.mu.Lock()
		g.cache[ck] = freshEntry{allowed: false, reasonCode: reason, expires: now.Add(g.TTL)}
		g.mu.Unlock()
		return AuthzDecision{
			Allowed:           false,
			ReasonCode:        reason,
			CacheHitElevation: false,
		}, nil
	}

	g.mu.Lock()
	g.cache[ck] = freshEntry{allowed: true, reasonCode: ReasonAuthzOK, expires: now.Add(g.TTL)}
	g.mu.Unlock()
	return AuthzDecision{
		Allowed:           true,
		ReasonCode:        ReasonAuthzOK,
		FromCache:         false,
		CacheHitElevation: false,
	}, nil
}

// AllowObserved is Allow plus process-local metrics (FLC-061).
func (g *FreshnessGate) AllowObserved(ctx context.Context, key AuthzKey) (AuthzDecision, error) {
	dec, err := g.Allow(ctx, key)
	RecordAuthzDecision(dec)
	return dec, err
}

// InvalidateSubject drops all cached decisions for a subject key hash (policy reload / logout).
func (g *FreshnessGate) InvalidateSubject(subjectKeyHash string) {
	if g == nil {
		return
	}
	subjectKeyHash = strings.TrimSpace(subjectKeyHash)
	g.mu.Lock()
	defer g.mu.Unlock()
	for k := range g.cache {
		if strings.HasPrefix(k, subjectKeyHash+"\x00") {
			delete(g.cache, k)
		}
	}
}

// InvalidateAll clears the decision cache (policy epoch bump).
func (g *FreshnessGate) InvalidateAll() {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.cache = make(map[string]freshEntry)
	g.mu.Unlock()
}

func normalizeAuthzKey(k *AuthzKey) error {
	k.SubjectKeyHash = strings.TrimSpace(k.SubjectKeyHash)
	k.ControllerID = strings.TrimSpace(k.ControllerID)
	k.JobFullName = strings.TrimSpace(k.JobFullName)
	k.ToolName = strings.TrimSpace(k.ToolName)
	if k.SubjectKeyHash == "" {
		return apperr.New(apperr.CodeInvalidArgument, "authz subject_key_hash required")
	}
	// Fail closed on secret-shaped keys (same heuristic as assertions).
	low := strings.ToLower(k.SubjectKeyHash)
	if strings.Contains(low, "bearer ") || strings.Contains(low, "password") ||
		strings.HasPrefix(low, "ghp_") {
		return apperr.New(apperr.CodeInvalidArgument, "authz subject_key_hash looks secret-shaped")
	}
	if k.ControllerID == "" || k.JobFullName == "" {
		return apperr.New(apperr.CodeInvalidArgument, "authz controller and job required")
	}
	if k.ToolName == "" {
		k.ToolName = "jenkins_get_build_logs"
	}
	return nil
}

func cacheKey(k AuthzKey) string {
	return k.SubjectKeyHash + "\x00" + k.ControllerID + "\x00" + k.JobFullName + "\x00" +
		k.ToolName + "\x00" + strconv.FormatInt(k.PolicyEpoch, 10)
}
