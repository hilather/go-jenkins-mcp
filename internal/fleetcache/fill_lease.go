package fleetcache

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Fill-lease defaults (FLC-040). In-memory primary authority; no credentials.
const (
	// DefaultFillLeaseTTL is the producer lease lifetime before takeover is allowed.
	DefaultFillLeaseTTL = 30 * time.Second
	// MinFillLeaseTTL / MaxFillLeaseTTL bound explicit TTLs.
	MinFillLeaseTTL = 5 * time.Second
	MaxFillLeaseTTL = 5 * time.Minute
)

// Fill lease join/status outcomes (low-cardinality, secret-free).
const (
	FillRoleProducer  = "producer"
	FillRoleWaiter    = "waiter"
	FillRoleCompleted = "completed"
	FillRoleNone      = "none"

	FillLeaseActive    = "active"
	FillLeaseCompleted = "completed"
	FillLeaseExpired   = "expired"
)

// FillLease is a secret-free in-memory lease record (no tokens/passwords/subjects).
type FillLease struct {
	LeaseID          string
	LocatorHash      string
	FleetID          string
	ProducerMemberID string
	// Fence is a monotonically increasing token; completion requires exact match.
	Fence uint64
	// IssuedAt / ExpiresAt use the authority clock.
	IssuedAt  time.Time
	ExpiresAt time.Time
	// Completed is true after successful Complete under this fence.
	Completed bool
	// ManifestDigest optional sealed version completed under this lease (64 hex).
	ManifestDigest string
}

// FillJoinResult is returned to Join callers (producer or waiter).
type FillJoinResult struct {
	// Role is producer | waiter | completed.
	Role string
	// Lease is the active or completed lease snapshot (zero when none).
	Lease FillLease
	// Residual is secret-free (empty on happy path).
	Residual string
}

// FillStatus is a secret-free operator/status snapshot for one locator.
type FillStatus struct {
	LocatorHash      string
	State            string // active | completed | expired | none
	LeaseID          string
	Fence            uint64
	ProducerMemberID string
	ExpiresAt        time.Time
	Completed        bool
	ManifestDigest   string
	// Residual documents partition honesty when useful.
	Residual string
}

// FillLeaseAuthority is the primary-side in-memory fill lease authority (FLC-040).
// Clock is injectable for expiry tests. Not durable across process restart
// (restart permits bounded recovery via new Join/takeover — residual honesty).
//
// Partition residual: split primaries may each run an authority and produce
// duplicate origin fills; that is safe only if no credentials are shared and
// sealed publish remains idempotent by digest (no silent elevation).
type FillLeaseAuthority struct {
	mu  sync.Mutex
	ttl time.Duration
	now func() time.Time
	// byLocator maps locator_hash → lease record.
	byLocator map[string]*fillLeaseRec
}

type fillLeaseRec struct {
	lease FillLease
	// nextFence is the next fence value to issue on takeover (monotonic).
	nextFence uint64
}

// NewFillLeaseAuthority builds an authority. ttl<=0 uses DefaultFillLeaseTTL.
func NewFillLeaseAuthority(ttl time.Duration) *FillLeaseAuthority {
	if ttl <= 0 {
		ttl = DefaultFillLeaseTTL
	}
	if ttl < MinFillLeaseTTL {
		ttl = MinFillLeaseTTL
	}
	if ttl > MaxFillLeaseTTL {
		ttl = MaxFillLeaseTTL
	}
	return &FillLeaseAuthority{
		ttl:       ttl,
		now:       func() time.Time { return time.Now().UTC() },
		byLocator: make(map[string]*fillLeaseRec),
	}
}

// SetNow injects a clock (tests). nil restores wall clock.
func (a *FillLeaseAuthority) SetNow(now func() time.Time) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if now == nil {
		a.now = func() time.Time { return time.Now().UTC() }
		return
	}
	a.now = now
}

// Join requests producer role for locator under memberID.
// Concurrent healthy joins yield at most one active producer; others are waiters.
// After expiry (or no lease), a new producer is issued with a higher fence.
func (a *FillLeaseAuthority) Join(fleetID, locatorHash, memberID string) (FillJoinResult, error) {
	if a == nil {
		return FillJoinResult{}, apperr.New(apperr.CodeInternal, "fill lease authority nil")
	}
	fleetID = strings.TrimSpace(fleetID)
	memberID = strings.TrimSpace(memberID)
	locatorHash = strings.ToLower(strings.TrimSpace(locatorHash))
	if fleetID == "" || memberID == "" {
		return FillJoinResult{}, apperr.New(apperr.CodeInvalidArgument, "fill lease fleet/member required")
	}
	if len(locatorHash) != 64 || !isHex(locatorHash) {
		return FillJoinResult{}, apperr.New(apperr.CodeInvalidArgument, "fill lease locator_hash invalid")
	}
	// Reject credential-shaped member IDs (heuristic fail closed).
	if looksSecretShaped(memberID) || looksSecretShaped(fleetID) {
		return FillJoinResult{}, apperr.New(apperr.CodeInvalidArgument, "fill lease identity looks secret-shaped")
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now().UTC()
	rec := a.byLocator[locatorHash]

	if rec != nil && rec.lease.Completed {
		return FillJoinResult{
			Role:  FillRoleCompleted,
			Lease: rec.lease.snapshot(),
		}, nil
	}

	if rec != nil && rec.lease.active(now) {
		// Same producer re-joins: extend heartbeat-style expiry, keep fence/lease ID.
		if rec.lease.ProducerMemberID == memberID && rec.lease.FleetID == fleetID {
			rec.lease.ExpiresAt = now.Add(a.ttl)
			return FillJoinResult{Role: FillRoleProducer, Lease: rec.lease.snapshot()}, nil
		}
		// Waiter: do not become producer.
		return FillJoinResult{
			Role:  FillRoleWaiter,
			Lease: rec.lease.snapshot(),
		}, nil
	}

	// No lease, expired, or wrong fleet residual: issue new producer with higher fence.
	var nextFence uint64 = 1
	if rec != nil {
		if rec.lease.FleetID != "" && rec.lease.FleetID != fleetID && rec.lease.active(now) {
			return FillJoinResult{}, apperr.New(apperr.CodeAuthorization, "fill lease fleet mismatch")
		}
		nextFence = rec.nextFence
		if nextFence < rec.lease.Fence+1 {
			nextFence = rec.lease.Fence + 1
		}
	}
	leaseID, err := newLeaseID()
	if err != nil {
		return FillJoinResult{}, err
	}
	lease := FillLease{
		LeaseID:          leaseID,
		LocatorHash:      locatorHash,
		FleetID:          fleetID,
		ProducerMemberID: memberID,
		Fence:            nextFence,
		IssuedAt:         now,
		ExpiresAt:        now.Add(a.ttl),
		Completed:        false,
	}
	a.byLocator[locatorHash] = &fillLeaseRec{
		lease:     lease,
		nextFence: nextFence + 1,
	}
	residual := ""
	if rec != nil && !rec.lease.Completed && !rec.lease.active(now) {
		residual = "takeover_after_expiry"
	}
	return FillJoinResult{
		Role:     FillRoleProducer,
		Lease:    lease.snapshot(),
		Residual: residual,
	}, nil
}

// Complete marks the fill done under the exact lease ID + fence + producer member.
// Stale fence, wrong member, wrong lease ID, or already-completed-with-newer-fence fail closed.
func (a *FillLeaseAuthority) Complete(fleetID, locatorHash, memberID, leaseID string, fence uint64, manifestDigest string) error {
	if a == nil {
		return apperr.New(apperr.CodeInternal, "fill lease authority nil")
	}
	fleetID = strings.TrimSpace(fleetID)
	memberID = strings.TrimSpace(memberID)
	leaseID = strings.TrimSpace(leaseID)
	locatorHash = strings.ToLower(strings.TrimSpace(locatorHash))
	manifestDigest = strings.ToLower(strings.TrimSpace(manifestDigest))
	if fleetID == "" || memberID == "" || leaseID == "" {
		return apperr.New(apperr.CodeInvalidArgument, "fill complete identity required")
	}
	if len(locatorHash) != 64 || !isHex(locatorHash) {
		return apperr.New(apperr.CodeInvalidArgument, "fill complete locator_hash invalid")
	}
	if manifestDigest != "" && (len(manifestDigest) != 64 || !isHex(manifestDigest)) {
		return apperr.New(apperr.CodeInvalidArgument, "fill complete manifest_digest invalid")
	}
	if looksSecretShaped(memberID) || looksSecretShaped(manifestDigest) {
		return apperr.New(apperr.CodeInvalidArgument, "fill complete field looks secret-shaped")
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now().UTC()
	rec := a.byLocator[locatorHash]
	if rec == nil {
		return apperr.New(apperr.CodeNotFound, "fill lease not found")
	}
	if rec.lease.Completed {
		// Same completion is idempotent; lower fence cannot overwrite.
		if rec.lease.Fence > fence {
			return apperr.New(apperr.CodePolicyDenial, "fill complete stale fence after newer completion")
		}
		if rec.lease.Fence == fence && rec.lease.LeaseID == leaseID &&
			rec.lease.ProducerMemberID == memberID {
			return nil
		}
		if rec.lease.Fence > fence {
			return apperr.New(apperr.CodePolicyDenial, "fill complete stale fence after newer completion")
		}
		// Different producer/lease at same or higher completed fence.
		return apperr.New(apperr.CodePolicyDenial, "fill already completed")
	}
	if rec.lease.FleetID != fleetID {
		return apperr.New(apperr.CodeAuthorization, "fill complete fleet mismatch")
	}
	if rec.lease.ProducerMemberID != memberID {
		return apperr.New(apperr.CodeAuthorization, "fill complete wrong member")
	}
	if rec.lease.LeaseID != leaseID {
		return apperr.New(apperr.CodeAuthorization, "fill complete lease id mismatch")
	}
	if rec.lease.Fence != fence {
		return apperr.New(apperr.CodePolicyDenial, "fill complete fence mismatch")
	}
	// Expired lease cannot complete (must Join takeover first).
	if !rec.lease.active(now) {
		return apperr.New(apperr.CodePolicyDenial, "fill lease expired")
	}
	rec.lease.Completed = true
	rec.lease.ManifestDigest = manifestDigest
	// Keep ExpiresAt as historical; state is completed.
	return nil
}

// Renew extends ExpiresAt for the active producer matching memberID (mid-fill heartbeat).
// Fail closed if not the current active producer (waiter/expired/completed).
// Same fence and lease ID are preserved.
func (a *FillLeaseAuthority) Renew(fleetID, locatorHash, memberID string) (FillLease, error) {
	if a == nil {
		return FillLease{}, apperr.New(apperr.CodeInternal, "fill lease authority nil")
	}
	fleetID = strings.TrimSpace(fleetID)
	memberID = strings.TrimSpace(memberID)
	locatorHash = strings.ToLower(strings.TrimSpace(locatorHash))
	if fleetID == "" || memberID == "" || len(locatorHash) != 64 || !isHex(locatorHash) {
		return FillLease{}, apperr.New(apperr.CodeInvalidArgument, "fill renew identity/locator invalid")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now().UTC()
	rec := a.byLocator[locatorHash]
	if rec == nil || !rec.lease.active(now) {
		return FillLease{}, apperr.New(apperr.CodeNotFound, "fill lease not active")
	}
	if rec.lease.FleetID != fleetID || rec.lease.ProducerMemberID != memberID {
		return FillLease{}, apperr.New(apperr.CodeAuthorization, "fill renew wrong member")
	}
	rec.lease.ExpiresAt = now.Add(a.ttl)
	return rec.lease.snapshot(), nil
}

// TTL returns the configured lease lifetime (for heartbeat sizing).
func (a *FillLeaseAuthority) TTL() time.Duration {
	if a == nil {
		return DefaultFillLeaseTTL
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ttl
}

// Release aborts an active producer lease (origin error / cancel) so the locator
// is not poisoned indefinitely. Matching lease ID + fence + member required.
// After Release, Join can issue a new producer (higher fence). No-op if already
// expired or superseded; fail closed on wrong member/fence when still active.
func (a *FillLeaseAuthority) Release(fleetID, locatorHash, memberID, leaseID string, fence uint64) error {
	if a == nil {
		return apperr.New(apperr.CodeInternal, "fill lease authority nil")
	}
	fleetID = strings.TrimSpace(fleetID)
	memberID = strings.TrimSpace(memberID)
	leaseID = strings.TrimSpace(leaseID)
	locatorHash = strings.ToLower(strings.TrimSpace(locatorHash))
	if fleetID == "" || memberID == "" || leaseID == "" {
		return apperr.New(apperr.CodeInvalidArgument, "fill release identity required")
	}
	if len(locatorHash) != 64 || !isHex(locatorHash) {
		return apperr.New(apperr.CodeInvalidArgument, "fill release locator_hash invalid")
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now().UTC()
	rec := a.byLocator[locatorHash]
	if rec == nil {
		return nil // already gone
	}
	if rec.lease.Completed {
		// Do not un-complete a successful fill.
		return apperr.New(apperr.CodePolicyDenial, "fill already completed")
	}
	if !rec.lease.active(now) {
		// Expired: leave for takeover; release is no-op success.
		return nil
	}
	if rec.lease.FleetID != fleetID || rec.lease.ProducerMemberID != memberID {
		return apperr.New(apperr.CodeAuthorization, "fill release wrong member")
	}
	if rec.lease.LeaseID != leaseID || rec.lease.Fence != fence {
		return apperr.New(apperr.CodePolicyDenial, "fill release lease/fence mismatch")
	}
	// Clear active lease; preserve nextFence for monotonic takeover.
	next := rec.nextFence
	if next <= rec.lease.Fence {
		next = rec.lease.Fence + 1
	}
	a.byLocator[locatorHash] = &fillLeaseRec{
		lease:     FillLease{LocatorHash: locatorHash, FleetID: fleetID, Fence: rec.lease.Fence},
		nextFence: next,
	}
	// Empty LeaseID ⇒ Status reports expired/none path for Join takeover.
	a.byLocator[locatorHash].lease.ExpiresAt = now.Add(-time.Second)
	return nil
}

// Status returns a secret-free snapshot for locator (no credentials).
func (a *FillLeaseAuthority) Status(locatorHash string) FillStatus {
	if a == nil {
		return FillStatus{State: FillRoleNone, Residual: "authority_nil"}
	}
	locatorHash = strings.ToLower(strings.TrimSpace(locatorHash))
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now().UTC()
	rec := a.byLocator[locatorHash]
	if rec == nil {
		return FillStatus{LocatorHash: locatorHash, State: FillRoleNone}
	}
	st := FillStatus{
		LocatorHash:      locatorHash,
		LeaseID:          rec.lease.LeaseID,
		Fence:            rec.lease.Fence,
		ProducerMemberID: rec.lease.ProducerMemberID,
		ExpiresAt:        rec.lease.ExpiresAt,
		Completed:        rec.lease.Completed,
		ManifestDigest:   rec.lease.ManifestDigest,
	}
	switch {
	case rec.lease.Completed:
		st.State = FillLeaseCompleted
	case rec.lease.active(now):
		st.State = FillLeaseActive
	default:
		st.State = FillLeaseExpired
		st.Residual = "expired_takeover_eligible"
	}
	return st
}

// SecretFreeSnapshot returns a single-line residual-safe encoding for canaries.
// Never includes tokens, passwords, or raw subject material by construction.
func (l FillLease) SecretFreeSnapshot() string {
	return fmt.Sprintf("lease_id=%s locator=%s fleet=%s producer=%s fence=%d completed=%v digest=%s",
		l.LeaseID, l.LocatorHash, l.FleetID, l.ProducerMemberID, l.Fence, l.Completed, l.ManifestDigest)
}

func (l FillLease) active(now time.Time) bool {
	if l.Completed || l.LeaseID == "" {
		return false
	}
	return now.Before(l.ExpiresAt)
}

func (l FillLease) snapshot() FillLease {
	return l
}

func newLeaseID() (string, error) {
	var b [18]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", apperr.Wrap(apperr.CodeInternal, "lease id entropy", err)
	}
	return "fl_" + base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func looksSecretShaped(s string) bool {
	low := strings.ToLower(strings.TrimSpace(s))
	if low == "" {
		return false
	}
	if strings.Contains(low, "bearer ") || strings.Contains(low, "password") ||
		strings.HasPrefix(low, "ghp_") || strings.Contains(s, "@") ||
		strings.Contains(low, "authorization:") {
		return true
	}
	// Long high-entropy hex that is not a locator/digest field used intentionally
	// is still allowed for member IDs only if short — member IDs are short labels.
	if len(s) > 128 {
		return true
	}
	return false
}

// PartitionResidualNote is the documented honesty for split-primary duplicate fills.
// Split primaries may each run an authority and produce duplicate origin fills; that is
// safe only if no credentials are shared and sealed publish remains idempotent by digest
// (no silent elevation / no mixed-manifest content). See FLC-045 partition matrix.
const PartitionResidualNote = "partition_may_duplicate_origin_fill_safe_no_credential_share"

// StatusSummaryFill residual field for operator honesty (FLC-040/041/045).
func FillLeaseAuthorityResidual() string {
	return "fill_leases_in_memory+coord; " + PartitionHonestyResidual()
}
