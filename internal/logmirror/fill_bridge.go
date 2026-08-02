package logmirror

import (
	"context"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

// FillBridge wires FLC-040 FillLeaseAuthority into origin EnsureMirrored (FLC-041).
// Nil or Mode off/shadow ⇒ no lease I/O (ResolveAnd* uses plain EnsureMirrored).
//
// Credentials stay on the producer/entry node inside EnsureMirrored; never placed
// on Join/Complete/Release or peer residual.
type FillBridge struct {
	// Auth is the shared primary-side lease authority (process-local or injected).
	Auth *fleetcache.FillLeaseAuthority
	// Mode is fleet-cache mode; only read|full enable lease coordination.
	Mode fleetcache.Mode
	// FleetID / MemberID stamp lease claims (not Jenkins credentials).
	FleetID  string
	MemberID string
	// WaiterPoll / WaiterMax bound waiter backoff (0 → fleetcache defaults).
	WaiterPoll time.Duration
	WaiterMax  int
}

// Active reports whether fill-lease coordination should run.
func (b *FillBridge) Active() bool {
	if b == nil || b.Auth == nil {
		return false
	}
	mode := b.Mode
	if mode == "" {
		mode = fleetcache.ModeOff
	}
	return mode == fleetcache.ModeRead || mode == fleetcache.ModeFull
}

// ensureOriginCoordinated runs EnsureMirrored under a fill lease when Active.
// Waiters do not call EnsureMirrored while a healthy producer holds the lease.
func (a *Access) ensureOriginCoordinated(ctx context.Context, job string, build int64) error {
	if a == nil {
		return apperr.New(apperr.CodeInternal, "log access is not configured")
	}
	if a.Fill == nil || !a.Fill.Active() {
		return a.EnsureMirrored(ctx, job, build)
	}
	b := a.Fill
	lh := fleetcache.FillLocatorHash(b.FleetID, a.Profile, job, build)
	_, err := fleetcache.CoordinateOriginFill(ctx, b.Auth, fleetcache.FillCoordRequest{
		FleetID:     b.FleetID,
		MemberID:    b.MemberID,
		LocatorHash: lh,
		Mode:        b.Mode,
		WaiterPoll:  b.WaiterPoll,
		WaiterMax:   b.WaiterMax,
	}, func(ctx context.Context) error {
		return a.EnsureMirrored(ctx, job, build)
	})
	return err
}
