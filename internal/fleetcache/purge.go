package fleetcache

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Purge / tombstone constants (FLC-051) — secret-free, low-cardinality.
const (
	// PurgeConfirmToken is the exact confirm string required for destructive purge.
	PurgeConfirmToken = "PURGE"

	// Operator roles permitted to purge (fail closed for all others).
	PurgeRoleOperator    = "operator"
	PurgeRolePolicyAdmin = "policy_admin"

	// Purge plan / result actions (secret-free).
	PurgeActionPurge = "purge"
	PurgeActionDeny  = "deny"
	PurgeActionNoop  = "noop"

	// Purge result status values.
	PurgeStatusPurged  = "purged"
	PurgeStatusDenied  = "denied"
	PurgeStatusNoop    = "noop"
	PurgeStatusPartial = "partial"

	// Residual codes (secret-free).
	PurgeResidualUnauthorizedRole = "unauthorized_role"
	PurgeResidualConfirmRequired  = "confirm_required"
	PurgeResidualEmptyLocator     = "empty_locator"
	PurgeResidualMaxOwners        = "max_owners_bounded"
	PurgeResidualNoOwners         = "no_owners"
	PurgeResidualUnreachable      = "owner_unreachable"
	PurgeResidualDeleteFailed     = "delete_failed"
	PurgeResidualTombstoneBlocked = "tombstone_blocked"
	PurgeResidualTombstoneExpired = "tombstone_expired"
	PurgeResidualIdempotent       = "purge_idempotent"
	PurgeResidualProcessLocalOnly = "process_local_tombstones"
	PurgeResidualNoHTTPPeerProp   = "no_http_peer_purge_prop"

	// DefaultMaxPurgeOwners bounds fan-out of a single purge plan (idempotent + bounded).
	DefaultMaxPurgeOwners = 16
	// AbsoluteMaxPurgeOwners hard ceiling.
	AbsoluteMaxPurgeOwners = 64

	// DefaultTombstoneTTL is how long a process-local tombstone blocks resurrection
	// when ExpiresAt is zero at Put time.
	DefaultTombstoneTTL = 24 * time.Hour
)

// ActiveTombstones is an optional process-local tombstone store (FLC-051).
// Nil = no blocks. Tests and process wiring may assign; multi-member HTTP peer
// purge propagation remains residual (no automatic remote fan-out in this library).
var ActiveTombstones TombstoneStore

// PurgeRequest is a destructive fleet-object purge (FLC-051).
// Origin Jenkins data is never touched by this package.
type PurgeRequest struct {
	// LocatorHash is the sealed object locator (64-hex). Required.
	LocatorHash string
	// ManifestDigest scopes purge to one version; empty = all versions for locator (bounded).
	ManifestDigest string
	// OperatorRole must be operator or policy_admin (fail closed).
	OperatorRole string
	// Confirm must equal PurgeConfirmToken ("PURGE").
	Confirm string
	// MaxOwners bounds planned targets (≤ AbsoluteMaxPurgeOwners).
	MaxOwners int
	// TargetMemberIDs optionally restricts planned owners (intersection with owners arg).
	// Empty = use full owners list (still MaxOwners-bounded).
	TargetMemberIDs []string
	// Reason is a secret-free operator note stored on the tombstone (scrubbed; no tokens).
	Reason string
	// TTL overrides DefaultTombstoneTTL when > 0 (ExpiresAt = now+TTL on Put).
	TTL time.Duration
}

// PurgePlan is a pure auth + bound decision before any delete (secret-free).
type PurgePlan struct {
	// Targets are member IDs to purge (ordered, de-duplicated, MaxOwners-capped).
	Targets []string
	// Residual is secret-free (e.g. unauthorized_role, max_owners_bounded).
	Residual string
	// Action: purge | deny | noop.
	Action string
	// LocatorHash / ManifestDigest echo normalized request fields.
	LocatorHash    string
	ManifestDigest string
	// Truncated is true when MaxOwners dropped planned owners (bounded honesty).
	Truncated bool
}

// Tombstone blocks stale replica resurrection for a locator (+ optional digest)
// during a retention window (FLC-051). Secret-free fields only.
type Tombstone struct {
	LocatorHash    string
	ManifestDigest string // empty = all versions for locator
	ExpiresAt      time.Time
	// Reason is secret-free operator/residual text (never tokens).
	Reason string
}

// TombstoneStore is the process-local (or future durable) tombstone surface.
type TombstoneStore interface {
	Put(ctx context.Context, t Tombstone) error
	// Get returns active tombstones for locator (caller filters expiry).
	Get(ctx context.Context, locatorHash string) ([]Tombstone, error)
	// IsBlocked reports whether locator+digest is currently blocked at now.
	IsBlocked(ctx context.Context, locatorHash, manifestDigest string, now time.Time) (bool, string, error)
}

// MemoryTombstoneStore is an in-process tombstone store for tests and library wiring.
type MemoryTombstoneStore struct {
	mu   sync.Mutex
	byLH map[string][]Tombstone // locator → tombstones (digest-scoped or all)
}

// NewMemoryTombstoneStore returns an empty process-local store.
func NewMemoryTombstoneStore() *MemoryTombstoneStore {
	return &MemoryTombstoneStore{byLH: make(map[string][]Tombstone)}
}

// Put records or refreshes a tombstone (idempotent for same locator+digest).
func (s *MemoryTombstoneStore) Put(_ context.Context, t Tombstone) error {
	if s == nil {
		return apperr.New(apperr.CodeInternal, "tombstone store nil")
	}
	lh := strings.ToLower(strings.TrimSpace(t.LocatorHash))
	if lh == "" {
		return apperr.New(apperr.CodeInvalidArgument, "tombstone locator empty")
	}
	t.LocatorHash = lh
	t.ManifestDigest = strings.ToLower(strings.TrimSpace(t.ManifestDigest))
	t.Reason = scrubPurgeReason(t.Reason)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byLH == nil {
		s.byLH = make(map[string][]Tombstone)
	}
	list := s.byLH[lh]
	// Replace same-scope tombstone (locator + digest) — idempotent refresh.
	out := list[:0]
	replaced := false
	for _, existing := range list {
		if strings.EqualFold(existing.ManifestDigest, t.ManifestDigest) {
			out = append(out, t)
			replaced = true
			continue
		}
		out = append(out, existing)
	}
	if !replaced {
		out = append(out, t)
	}
	// Copy to avoid aliasing caller's slice capacity tricks.
	cp := make([]Tombstone, len(out))
	copy(cp, out)
	s.byLH[lh] = cp
	return nil
}

// Get returns tombstones for locator (including possibly expired; callers filter).
func (s *MemoryTombstoneStore) Get(_ context.Context, locatorHash string) ([]Tombstone, error) {
	if s == nil {
		return nil, nil
	}
	lh := strings.ToLower(strings.TrimSpace(locatorHash))
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.byLH[lh]
	if len(list) == 0 {
		return nil, nil
	}
	out := make([]Tombstone, len(list))
	copy(out, list)
	return out, nil
}

// IsBlocked implements TombstoneStore.
func (s *MemoryTombstoneStore) IsBlocked(ctx context.Context, locatorHash, manifestDigest string, now time.Time) (bool, string, error) {
	list, err := s.Get(ctx, locatorHash)
	if err != nil {
		return false, "", err
	}
	return tombstonesBlock(list, manifestDigest, now)
}

// PurgeSink is the local store surface for destructive fleet object purge.
// Implementations must not call Jenkins. Missing mapping is success (idempotent).
type PurgeSink interface {
	// GetCommitted returns the committed mapping for locator or ok=false.
	GetCommitted(ctx context.Context, locatorHash string) (CommittedMapping, bool, error)
	// DeleteCommitted removes the committed fleet object for locator.
	// When manifestDigest is non-empty, only delete if the committed digest matches
	// (or no mapping → success). Empty digest deletes the committed mapping for locator.
	DeleteCommitted(ctx context.Context, locatorHash, manifestDigest string) error
}

// PurgeResult is the secret-free outcome of ApplyPurge / ApplyPurgeLocal.
type PurgeResult struct {
	Status         string // purged | denied | noop | partial
	LocatorHash    string
	ManifestDigest string
	// PurgedMembers lists members where delete succeeded (or already absent).
	PurgedMembers []string
	// ResidualMembers lists members missing sink or delete failed (not silent success).
	ResidualMembers []string
	// TombstonePut is true when a tombstone was recorded.
	TombstonePut bool
	// Residual aggregate secret-free note.
	Residual string
}

// PlanPurge validates role/confirm and bounds planned owner targets (pure; no disk).
// Fail closed: unauthorized role or wrong confirm → deny. Empty locator → deny.
// owners are planned current/previous owners; optional TargetMemberIDs intersect.
// Truncation under MaxOwners sets Residual max_owners_bounded (honest bound).
func PlanPurge(req PurgeRequest, owners []string) (PurgePlan, error) {
	lh := strings.ToLower(strings.TrimSpace(req.LocatorHash))
	digest := strings.ToLower(strings.TrimSpace(req.ManifestDigest))
	plan := PurgePlan{
		LocatorHash:    lh,
		ManifestDigest: digest,
		Action:         PurgeActionDeny,
	}

	if lh == "" {
		plan.Residual = PurgeResidualEmptyLocator
		return plan, apperr.New(apperr.CodeInvalidArgument, "purge locator empty")
	}
	if !purgeRoleAllowed(req.OperatorRole) {
		plan.Residual = PurgeResidualUnauthorizedRole
		return plan, apperr.New(apperr.CodeAuthorization, "purge requires operator or policy_admin role")
	}
	if strings.TrimSpace(req.Confirm) != PurgeConfirmToken {
		plan.Residual = PurgeResidualConfirmRequired
		return plan, apperr.New(apperr.CodePolicyDenial, "purge requires confirm PURGE")
	}

	max := req.MaxOwners
	if max <= 0 {
		max = DefaultMaxPurgeOwners
	}
	if max > AbsoluteMaxPurgeOwners {
		max = AbsoluteMaxPurgeOwners
	}

	// Intersect optional target filter with owners.
	filter := make(map[string]struct{})
	for _, id := range req.TargetMemberIDs {
		id = strings.TrimSpace(id)
		if id != "" {
			filter[id] = struct{}{}
		}
	}
	seen := make(map[string]struct{})
	var targets []string
	for _, id := range owners {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if len(filter) > 0 {
			if _, ok := filter[id]; !ok {
				continue
			}
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		targets = append(targets, id)
	}

	if len(targets) == 0 {
		// Still a valid authorized purge: tombstone-only / local-only path.
		plan.Action = PurgeActionPurge
		plan.Targets = nil
		plan.Residual = PurgeResidualNoOwners
		return plan, nil
	}

	if len(targets) > max {
		plan.Truncated = true
		plan.Residual = PurgeResidualMaxOwners
		targets = targets[:max]
	}

	plan.Action = PurgeActionPurge
	plan.Targets = targets
	return plan, nil
}

// ApplyPurgeLocal purges one local sink and records a tombstone (idempotent).
// Requires authorized req (role + confirm). Does not touch Jenkins.
func ApplyPurgeLocal(
	ctx context.Context,
	sink PurgeSink,
	req PurgeRequest,
	ts TombstoneStore,
	now time.Time,
) (PurgeResult, error) {
	plan, err := PlanPurge(req, nil)
	if err != nil && plan.Action == PurgeActionDeny {
		return PurgeResult{
			Status: PurgeStatusDenied, LocatorHash: plan.LocatorHash,
			ManifestDigest: plan.ManifestDigest, Residual: plan.Residual,
		}, err
	}
	// Local-only: ignore multi-owner targets; purge this sink.
	return applyPurgeOnSinks(ctx, plan, req, map[string]PurgeSink{"local": sink}, ts, now)
}

// ApplyPurge applies a PlanPurge to member sinks. Missing sinks or delete failures
// are listed in ResidualMembers (not silent success). Always attempts tombstone Put
// when authorized so resurrection is blocked even on partial peer reachability.
// Origin Jenkins is never contacted.
func ApplyPurge(
	ctx context.Context,
	plan PurgePlan,
	req PurgeRequest,
	sinks map[string]PurgeSink,
	ts TombstoneStore,
	now time.Time,
) (PurgeResult, error) {
	// Re-check auth fail-closed (plan may be forged).
	if plan.Action == PurgeActionDeny {
		return PurgeResult{
			Status: PurgeStatusDenied, LocatorHash: plan.LocatorHash,
			ManifestDigest: plan.ManifestDigest, Residual: plan.Residual,
		}, apperr.New(apperr.CodePolicyDenial, "purge plan denied")
	}
	if !purgeRoleAllowed(req.OperatorRole) || strings.TrimSpace(req.Confirm) != PurgeConfirmToken {
		return PurgeResult{
			Status: PurgeStatusDenied, LocatorHash: plan.LocatorHash,
			ManifestDigest: plan.ManifestDigest, Residual: PurgeResidualUnauthorizedRole,
		}, apperr.New(apperr.CodeAuthorization, "purge unauthorized")
	}
	return applyPurgeOnSinks(ctx, plan, req, sinks, ts, now)
}

func applyPurgeOnSinks(
	ctx context.Context,
	plan PurgePlan,
	req PurgeRequest,
	sinks map[string]PurgeSink,
	ts TombstoneStore,
	now time.Time,
) (PurgeResult, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	out := PurgeResult{
		LocatorHash:    plan.LocatorHash,
		ManifestDigest: plan.ManifestDigest,
	}
	if err := ctx.Err(); err != nil {
		out.Status = PurgeStatusDenied
		out.Residual = "cancelled"
		return out, err
	}

	// Determine member list: plan targets, or single "local" if sinks has only local key.
	targets := plan.Targets
	if len(targets) == 0 {
		// Tombstone-only path still walks provided sinks for local cleanup.
		for id := range sinks {
			targets = append(targets, id)
		}
	}

	hadDelete := false
	for _, id := range targets {
		if err := ctx.Err(); err != nil {
			out.Status = PurgeStatusPartial
			out.Residual = "cancelled"
			return out, err
		}
		sink, ok := sinks[id]
		if !ok || sink == nil {
			out.ResidualMembers = append(out.ResidualMembers, id)
			continue
		}
		// Idempotent: delete even if already absent.
		if err := sink.DeleteCommitted(ctx, plan.LocatorHash, plan.ManifestDigest); err != nil {
			out.ResidualMembers = append(out.ResidualMembers, id)
			// Prefer delete_failed residual when any delete fails.
			if out.Residual == "" || out.Residual == PurgeResidualUnreachable {
				out.Residual = PurgeResidualDeleteFailed
			}
			continue
		}
		out.PurgedMembers = append(out.PurgedMembers, id)
		hadDelete = true
	}

	// Record tombstone so repair/import cannot resurrect during retention window.
	if ts != nil {
		ttl := req.TTL
		if ttl <= 0 {
			ttl = DefaultTombstoneTTL
		}
		t := Tombstone{
			LocatorHash:    plan.LocatorHash,
			ManifestDigest: plan.ManifestDigest,
			ExpiresAt:      now.Add(ttl),
			Reason:         scrubPurgeReason(req.Reason),
		}
		if t.Reason == "" {
			t.Reason = PurgeResidualProcessLocalOnly
		}
		if err := ts.Put(ctx, t); err != nil {
			if out.Residual == "" {
				out.Residual = "tombstone_put_failed"
			}
			// Still report partial honesty — deletes may have succeeded.
			if hadDelete && len(out.ResidualMembers) == 0 {
				out.Status = PurgeStatusPartial
			} else if len(out.PurgedMembers) == 0 {
				out.Status = PurgeStatusPartial
			}
			return out, err
		}
		out.TombstonePut = true
	}

	switch {
	case len(out.ResidualMembers) > 0 && len(out.PurgedMembers) > 0:
		out.Status = PurgeStatusPartial
		if out.Residual == "" {
			out.Residual = PurgeResidualUnreachable
		}
	case len(out.ResidualMembers) > 0 && len(out.PurgedMembers) == 0:
		out.Status = PurgeStatusPartial
		if out.Residual == "" {
			out.Residual = PurgeResidualUnreachable
		}
	case !hadDelete && out.TombstonePut:
		// No sinks purged but tombstone recorded (authorized noop cleanup).
		out.Status = PurgeStatusPurged
		out.Residual = PurgeResidualIdempotent
	default:
		out.Status = PurgeStatusPurged
		if plan.Residual == PurgeResidualMaxOwners {
			out.Residual = PurgeResidualMaxOwners
		}
	}
	return out, nil
}

// TombstoneBlocks reports whether Active-style store blocks locator+digest at now.
// Empty residual when not blocked. Residual is always secret-free.
func TombstoneBlocks(ts TombstoneStore, locatorHash, manifestDigest string, now time.Time) (bool, string) {
	if ts == nil {
		return false, ""
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	blocked, residual, err := ts.IsBlocked(context.Background(), locatorHash, manifestDigest, now)
	if err != nil {
		// Fail closed on store error: treat as blocked with stable residual.
		return true, PurgeResidualTombstoneBlocked
	}
	return blocked, residual
}

// tombstonesBlock is the pure filter over a tombstone list.
func tombstonesBlock(list []Tombstone, manifestDigest string, now time.Time) (bool, string, error) {
	digest := strings.ToLower(strings.TrimSpace(manifestDigest))
	for _, t := range list {
		if !t.ExpiresAt.IsZero() && !now.Before(t.ExpiresAt) {
			// Expired — skip (does not block).
			continue
		}
		// Empty digest on tombstone = all versions for locator.
		if t.ManifestDigest == "" {
			return true, PurgeResidualTombstoneBlocked, nil
		}
		// Digest-scoped: block exact match only (or candidate empty treated as all).
		if digest == "" || strings.EqualFold(t.ManifestDigest, digest) {
			return true, PurgeResidualTombstoneBlocked, nil
		}
	}
	return false, "", nil
}

func purgeRoleAllowed(role string) bool {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case PurgeRoleOperator, PurgeRolePolicyAdmin:
		return true
	default:
		return false
	}
}

// scrubPurgeReason keeps residual/reason secret-free (bounded + strip obvious secrets).
func scrubPurgeReason(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// Bound length.
	const maxReason = 128
	if len(s) > maxReason {
		s = s[:maxReason]
	}
	low := strings.ToLower(s)
	for _, bad := range []string{"token=", "bearer ", "password", "authorization:", "cookie", "ghp_", "sk-live"} {
		if strings.Contains(low, bad) {
			return "scrubbed"
		}
	}
	return s
}

// purgeImportTombstoneCheck is used by PlanImport / ReplicateSealed after digest known.
func purgeImportTombstoneCheck(locatorHash, manifestDigest string) (blocked bool, residual string) {
	return TombstoneBlocks(ActiveTombstones, locatorHash, manifestDigest, time.Now().UTC())
}
