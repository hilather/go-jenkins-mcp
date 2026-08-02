package fleetcache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Fill coordination defaults (FLC-041).
const (
	DefaultFillWaiterPoll = 20 * time.Millisecond
	DefaultFillWaiterMax  = 200 // ~4s at default poll
	// DefaultFillHeartbeat is how often a producer re-Joins to renew TTL while origin runs.
	// Must be well below MinFillLeaseTTL so waiters cannot takeover mid-fill.
	DefaultFillHeartbeat = time.Second
)

// OriginFiller performs the authorized Jenkins progressive mirror on the producer only.
// Must not embed credentials into returned errors beyond apperr codes.
// Implementations typically call logmirror.EnsureMirrored.
type OriginFiller func(ctx context.Context) error

// FillCoordRequest binds a fill wave to a locator without peer credentials.
type FillCoordRequest struct {
	FleetID     string
	MemberID    string
	LocatorHash string
	// Mode off/shadow skips lease I/O and calls Origin immediately (or ModeOff path).
	Mode Mode
	// WaiterPoll / WaiterMax bound waiter backoff (0 → defaults).
	WaiterPoll time.Duration
	WaiterMax  int
	// Heartbeat is producer re-Join interval while OriginFiller runs (0 → DefaultFillHeartbeat).
	// Cap at lease TTL/3 inside CoordinateOriginFill when authority TTL is known.
	Heartbeat time.Duration
}

// FillCoordResult is secret-free residual of a coordinated fill.
type FillCoordResult struct {
	// Role is producer | waiter | completed | none (mode off).
	Role string
	// OriginCalled is true only when this call invoked OriginFiller.
	OriginCalled bool
	// Residual secret-free.
	Residual string
	// Lease snapshot when lease was used.
	Lease FillLease
}

// FillLocatorHash derives a 64-hex fill coordination key from fleet + profile + job + build.
// Secret-free (no tokens); not a Jenkins credential.
func FillLocatorHash(fleetID, profile, job string, build int64) string {
	s := fmt.Sprintf("fill-v1\n%s\n%s\n%s\n%d\n",
		strings.TrimSpace(fleetID), strings.TrimSpace(profile), strings.TrimSpace(job), build)
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// CoordinateOriginFill joins the fill lease then runs Origin only on the producer.
// Waiters poll Status until completed/expired (no Origin call). Mode off/shadow
// skips the authority and calls Origin once (local singleflight remains caller's job).
//
// Credentials: never passed into Join/Complete/Release; OriginFiller closes over
// the entry-node client only.
func CoordinateOriginFill(ctx context.Context, auth *FillLeaseAuthority, req FillCoordRequest, origin OriginFiller) (FillCoordResult, error) {
	if origin == nil {
		return FillCoordResult{}, apperr.New(apperr.CodeInternal, "origin filler nil")
	}
	mode := req.Mode
	if mode == "" {
		mode = ModeOff
	}
	// Mode off/shadow: no lease I/O; direct origin (contract-compatible pre-fill).
	if mode == ModeOff || mode == ModeShadow || auth == nil {
		if err := ctx.Err(); err != nil {
			return FillCoordResult{Role: FillRoleNone, Residual: "cancelled"}, err
		}
		err := origin(ctx)
		return FillCoordResult{Role: FillRoleNone, OriginCalled: true, Residual: "mode_off_or_no_auth"}, err
	}
	if mode != ModeRead && mode != ModeFull {
		return FillCoordResult{}, apperr.New(apperr.CodeInvalidArgument, "fill coord mode invalid")
	}

	fleetID := strings.TrimSpace(req.FleetID)
	memberID := strings.TrimSpace(req.MemberID)
	lh := strings.ToLower(strings.TrimSpace(req.LocatorHash))
	if fleetID == "" || memberID == "" || len(lh) != 64 || !isHex(lh) {
		return FillCoordResult{}, apperr.New(apperr.CodeInvalidArgument, "fill coord identity/locator invalid")
	}
	if looksSecretShaped(memberID) || looksSecretShaped(fleetID) {
		return FillCoordResult{}, apperr.New(apperr.CodeInvalidArgument, "fill coord identity secret-shaped")
	}

	poll := req.WaiterPoll
	if poll <= 0 {
		poll = DefaultFillWaiterPoll
	}
	maxWait := req.WaiterMax
	if maxWait <= 0 {
		maxWait = DefaultFillWaiterMax
	}

	// Join loop: producer fills; waiter waits while lease is active (never origin).
	// WaiterMax bounds polls only when lease is expired/none (takeover attempts),
	// not while a healthy producer is still active (AC1).
	takeoverAttempts := 0
	for {
		if err := ctx.Err(); err != nil {
			return FillCoordResult{Residual: "cancelled"}, err
		}
		join, err := auth.Join(fleetID, lh, memberID)
		if err != nil {
			return FillCoordResult{}, err
		}
		switch join.Role {
		case FillRoleCompleted:
			return FillCoordResult{Role: FillRoleCompleted, Lease: join.Lease, Residual: "already_completed"}, nil
		case FillRoleProducer:
			// Mid-fill Renew heartbeats so waiters cannot takeover while origin runs
			// longer than lease TTL (AC1/AC3).
			hb := req.Heartbeat
			if hb <= 0 {
				hb = DefaultFillHeartbeat
			}
			ttl := auth.TTL()
			if ttl <= 0 {
				ttl = DefaultFillLeaseTTL
			}
			// Heartbeat at most TTL/3 so renew always lands before expiry.
			if maxHB := ttl / 3; hb > maxHB && maxHB > 0 {
				hb = maxHB
			}
			if hb < time.Millisecond {
				hb = time.Millisecond
			}
			lease, err := runOriginWithHeartbeat(ctx, auth, fleetID, lh, memberID, join.Lease, hb, origin)
			if err != nil {
				_ = auth.Release(fleetID, lh, memberID, lease.LeaseID, lease.Fence)
				if ctx.Err() != nil {
					return FillCoordResult{
						Role: FillRoleProducer, OriginCalled: true, Lease: lease, Residual: "producer_cancelled",
					}, ctx.Err()
				}
				return FillCoordResult{
					Role: FillRoleProducer, OriginCalled: true, Lease: lease, Residual: "origin_error_released",
				}, err
			}
			if cerr := auth.Complete(fleetID, lh, memberID, lease.LeaseID, lease.Fence, ""); cerr != nil {
				return FillCoordResult{
					Role: FillRoleProducer, OriginCalled: true, Lease: lease, Residual: "complete_failed",
				}, cerr
			}
			return FillCoordResult{
				Role: FillRoleProducer, OriginCalled: true, Lease: lease,
			}, nil
		case FillRoleWaiter:
			// No origin body while any healthy producer holds the lease (AC1).
			// Poll until completed, expired, or ctx cancel — do not fall through to
			// origin merely because WaiterMax wall-clock elapsed during active lease.
			for {
				if err := ctx.Err(); err != nil {
					return FillCoordResult{Role: FillRoleWaiter, Residual: "waiter_cancelled"}, ctx.Err()
				}
				st := auth.Status(lh)
				if st.Completed || st.State == FillLeaseCompleted {
					return FillCoordResult{Role: FillRoleWaiter, Residual: "waiter_saw_completed"}, nil
				}
				if st.State == FillLeaseExpired || st.State == FillRoleNone || st.State == "" {
					// Lease gone/expired: count a takeover attempt and re-Join.
					takeoverAttempts++
					if takeoverAttempts > maxWait {
						// Repeated expiry/takeover races without a stable producer:
						// degraded availability fallback (not while State=active).
						if err := ctx.Err(); err != nil {
							return FillCoordResult{Role: FillRoleWaiter, Residual: "waiter_budget_cancelled"}, err
						}
						err := origin(ctx)
						return FillCoordResult{
							Role: FillRoleWaiter, OriginCalled: true, Residual: "waiter_takeover_budget_origin_fallback",
						}, err
					}
					break // re-Join outer loop
				}
				// Still active: wait and re-check Status only (never origin).
				t := time.NewTimer(poll)
				select {
				case <-ctx.Done():
					t.Stop()
					return FillCoordResult{Role: FillRoleWaiter, Residual: "waiter_cancelled"}, ctx.Err()
				case <-t.C:
				}
			}
			continue
		default:
			return FillCoordResult{}, apperr.New(apperr.CodeInternal, "fill join role unknown")
		}
	}
}

// runOriginWithHeartbeat invokes origin while periodically Renew-ing the producer
// lease so ExpiresAt stays ahead of waiters (must not use Join takeover path).
// Returns the latest lease snapshot for Complete/Release.
func runOriginWithHeartbeat(
	ctx context.Context,
	auth *FillLeaseAuthority,
	fleetID, locatorHash, memberID string,
	lease FillLease,
	heartbeat time.Duration,
	origin OriginFiller,
) (FillLease, error) {
	type originResult struct{ err error }
	done := make(chan originResult, 1)
	go func() {
		done <- originResult{origin(ctx)}
	}()

	// Immediate renew so the first TTL window is full after Join setup latency.
	if renewed, err := auth.Renew(fleetID, locatorHash, memberID); err == nil {
		lease = renewed
	}

	ticker := time.NewTicker(heartbeat)
	defer ticker.Stop()
	cur := lease
	for {
		select {
		case r := <-done:
			return cur, r.err
		case <-ticker.C:
			renewed, err := auth.Renew(fleetID, locatorHash, memberID)
			if err != nil {
				// Lost producer role or expired — keep origin running for local
				// progress; Complete will fail closed and caller may Release.
				continue
			}
			cur = renewed
		case <-ctx.Done():
			r := <-done
			return cur, r.err
		}
	}
}
