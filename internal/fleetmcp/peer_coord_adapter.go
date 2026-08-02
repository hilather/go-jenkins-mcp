package fleetmcp

import (
	"context"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
	"github.com/hilather/go-jenkins-mcp/internal/logmirror"
)

// PeerLogCoordinator adapts fleet-cache lookup + decoded read for logmirror (FLC-032).
// Pure adapter: logmirror does not import fleetmcp; wire this from app/serve.
//
// Flow: authz freshness → owner contacts → decoded ReadOwners → typed hit/miss.
// Mode off / shadow → zero peer I/O. Policy deny fails closed before peer/origin.
type PeerLogCoordinator struct {
	Mode       fleetcache.Mode
	FleetID    string
	CachePool  string
	Controller string
	// Freshness optional; when set, Check must Allow before peer I/O.
	Freshness *fleetcache.FreshnessGate
	// FreshSubject opaque subject key for the gate (never log).
	FreshSubject string
	// Owners returns placement-selected owners for a locator (never full roster).
	Owners func(locatorHash string) []fleetcache.OwnerContact
	// Read client (Mode should match Mode field).
	Read *DecodedReadClient
	// LocatorSchemaVersion for ConsoleLogLocator (0 → default).
	LocatorSchemaVersion int
}

// TryRead implements logmirror.PeerCoordinator.
func (c *PeerLogCoordinator) TryRead(ctx context.Context, req logmirror.PeerReadRequest) (logmirror.PeerReadOutcome, bool, error) {
	if c == nil {
		return logmirror.PeerReadOutcome{}, false, nil
	}
	mode := c.Mode
	if mode == "" {
		mode = fleetcache.ModeOff
	}
	if mode == fleetcache.ModeOff || mode == fleetcache.ModeShadow {
		return logmirror.PeerReadOutcome{}, false, nil
	}
	if c.Read == nil || c.Owners == nil {
		return logmirror.PeerReadOutcome{}, false, nil
	}
	// Authz freshness before peer data plane (FLC-018 + FLC-032).
	if c.Freshness != nil {
		dec, err := c.Freshness.Allow(ctx, fleetcache.AuthzKey{
			SubjectKeyHash: c.FreshSubject,
			ControllerID:   c.Controller,
			JobFullName:    req.Job,
			ToolName:       "console_log_read",
		})
		if err != nil || !dec.Allowed {
			return logmirror.PeerReadOutcome{}, false, apperr.New(apperr.CodeAuthorization, "authz freshness denied")
		}
	}

	loc, err := fleetcache.NewConsoleLogLocator(c.FleetID, c.CachePool, c.Controller, req.Job, req.Build)
	if err != nil {
		return logmirror.PeerReadOutcome{}, false, nil
	}
	lh, err := loc.Hash()
	if err != nil {
		return logmirror.PeerReadOutcome{}, false, nil
	}
	owners := c.Owners(lh)
	if len(owners) == 0 {
		return logmirror.PeerReadOutcome{}, false, nil
	}

	dreq := fleetcache.DecodedReadRequest{
		LocatorHash:     lh,
		MaxDecodedBytes: req.MaxDecodedBytes,
	}
	switch req.Kind {
	case logmirror.PeerReadByteRange:
		dreq.Kind = fleetcache.ReadKindByteRange
		dreq.Start = req.Start
		dreq.Length = req.Length
	case logmirror.PeerReadTailBytes:
		dreq.Kind = fleetcache.ReadKindTailBytes
		dreq.TailN = req.TailN
	case logmirror.PeerReadLineRange:
		dreq.Kind = fleetcache.ReadKindLineRange
		dreq.StartLine = req.StartLine
		dreq.LineCount = req.LineCount
	case logmirror.PeerReadTailLines:
		dreq.Kind = fleetcache.ReadKindTailLines
		dreq.TailN = req.TailN
	default:
		dreq.Kind = fleetcache.ReadKindByteRange
		dreq.Start = req.Start
		dreq.Length = req.Length
	}

	// Ensure client mode matches coordinator.
	client := *c.Read
	client.Mode = mode
	res, err := client.ReadOwners(ctx, c.FleetID, dreq, owners, true)
	if err != nil {
		// Invalid request / config: treat as miss for origin fallback unless authz.
		if apperr.CodeOf(err) == apperr.CodeAuthorization || apperr.CodeOf(err) == apperr.CodePolicyDenial {
			return logmirror.PeerReadOutcome{}, false, err
		}
		return logmirror.PeerReadOutcome{}, false, nil
	}
	switch res.Status {
	case fleetcache.DecodedReadOK:
		if res.Result == nil {
			return logmirror.PeerReadOutcome{}, false, nil
		}
		return logmirror.PeerReadOutcome{
			Data:      res.Result.Data,
			Offset:    int(res.Result.RawStart),
			Length:    len(res.Result.Data),
			TotalSize: int(res.Result.RawEnd), // best-effort; may be range end only
			HasMore:   false,
			Sealed:    res.Result.Sealed,
			Source:    "peer",
		}, true, nil
	case fleetcache.DecodedReadScopeDenied:
		return logmirror.PeerReadOutcome{}, false, apperr.New(apperr.CodeAuthorization, "peer assertion scope denied")
	default:
		// miss / unavailable / not materialized / mode_off → origin fallback
		_ = strings.TrimSpace(res.Residual)
		return logmirror.PeerReadOutcome{}, false, nil
	}
}
