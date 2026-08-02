package logmirror

import (
	"context"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// PeerReadKind selects the bounded peer decoded form (FLC-031 wire).
type PeerReadKind string

const (
	PeerReadByteRange PeerReadKind = "byte_range"
	PeerReadTailBytes PeerReadKind = "tail_bytes"
	PeerReadLineRange PeerReadKind = "line_range"
	PeerReadTailLines PeerReadKind = "tail_lines"
)

// PeerReadRequest is a tool-facing peer cache probe (no credentials).
type PeerReadRequest struct {
	Job   string
	Build int64
	Kind  PeerReadKind

	Start  int64
	Length int64

	StartLine int64
	LineCount int64
	TailN     int64

	// MaxDecodedBytes 0 → coordinator/product default ceiling.
	MaxDecodedBytes int64
}

// PeerReadOutcome is a successful peer decoded hit (secret-free metadata).
type PeerReadOutcome struct {
	Data      []byte
	Offset    int
	Length    int
	TotalSize int
	HasMore   bool
	Sealed    bool
	// Source is always "peer" for hits (for accounting/tests).
	Source string
}

// PeerCoordinator is optional fleet peer lookup/read before Jenkins origin (FLC-032).
// Implementations must:
//   - respect fleet-cache mode (off/shadow → hit=false, no peer I/O)
//   - run authz freshness before peer data plane
//   - never broadcast full-roster FanOut
//   - never send Jenkins/OAuth credentials on the peer path
//
// hit=false and err=nil means miss/timeout/unavailable → caller may fall back to origin.
// err != nil for policy/authz denial must fail closed (no origin elevation for that denial path).
type PeerCoordinator interface {
	TryRead(ctx context.Context, req PeerReadRequest) (out PeerReadOutcome, hit bool, err error)
}

// ResolveOptions bounds ResolveAndReadRange / ResolveAndTail.
type ResolveOptions struct {
	// SkipPeer forces origin path even when Peer is set (tests / break-glass).
	SkipPeer bool
	// SkipOrigin when true returns not-found style residual after peer miss (no Jenkins).
	// Default false: fall back to EnsureMirrored.
	SkipOrigin bool
	// MaxDecodedBytes for peer probe (0 → Access/Machine defaults / peer default).
	MaxDecodedBytes int64
}

// ResolveAndReadRange implements local → peer (optional) → origin EnsureMirrored → local.
// With Peer nil or mode-off coordinator, behavior matches EnsureMirrored + ReadRange
// (byte-compatible with pre-FLC tools when Peer is unset).
func (a *Access) ResolveAndReadRange(ctx context.Context, job string, build int64, offset, length int64, opt ResolveOptions) (string, LocalReadMeta, error) {
	if a == nil || a.Machine == nil {
		return "", LocalReadMeta{}, apperr.New(apperr.CodeInternal, "log access is not configured")
	}
	key := LogKey{Profile: a.Profile, Job: job, Build: build}
	if err := key.Validate(); err != nil {
		return "", LocalReadMeta{}, err
	}
	if offset < 0 || length < 0 {
		return "", LocalReadMeta{}, apperr.New(apperr.CodeInvalidArgument, "offset and length must be non-negative")
	}

	// 1) Local durable hit covering the range start.
	if logs, meta, ok, err := a.tryLocalByteRange(ctx, key, job, build, offset, length); err != nil {
		return "", LocalReadMeta{}, err
	} else if ok {
		return logs, meta, nil
	}

	// 2) Peer bounded decoded read (after coordinator-internal authz freshness).
	if !opt.SkipPeer && a.Peer != nil {
		out, hit, err := a.Peer.TryRead(ctx, PeerReadRequest{
			Job: job, Build: build, Kind: PeerReadByteRange,
			Start: offset, Length: length, MaxDecodedBytes: opt.MaxDecodedBytes,
		})
		if err != nil {
			// Policy/authz fail closed — do not fetch origin for this denial.
			return "", LocalReadMeta{}, err
		}
		if hit {
			return peerOutcomeToString(out), peerOutcomeToMeta(out, offset, length), nil
		}
	}

	// 3) Authorized Jenkins origin via EnsureMirrored (optionally under fill lease FLC-041).
	if opt.SkipOrigin {
		return "", LocalReadMeta{}, apperr.New(apperr.CodeNotFound, "log not available locally or via peer")
	}
	if err := a.ensureOriginCoordinated(ctx, job, build); err != nil {
		// Partial mirror may still serve local bytes.
		if logs, meta, ok, lerr := a.tryLocalByteRange(ctx, key, job, build, offset, length); lerr != nil {
			return "", LocalReadMeta{}, lerr
		} else if ok {
			return logs, meta, err // return partial with ensure error residual path: prefer data
		}
		return "", LocalReadMeta{}, err
	}
	return a.ReadRange(ctx, job, build, offset, length)
}

// ResolveAndTail is local → peer tail → origin EnsureMirrored → local Tail.
func (a *Access) ResolveAndTail(ctx context.Context, job string, build int64, maxLen int64, opt ResolveOptions) (string, LocalReadMeta, error) {
	if a == nil || a.Machine == nil {
		return "", LocalReadMeta{}, apperr.New(apperr.CodeInternal, "log access is not configured")
	}
	key := LogKey{Profile: a.Profile, Job: job, Build: build}
	if err := key.Validate(); err != nil {
		return "", LocalReadMeta{}, err
	}
	if maxLen < 0 {
		return "", LocalReadMeta{}, apperr.New(apperr.CodeInvalidArgument, "max_length must be non-negative")
	}

	// Local if sealed or any durable bytes.
	st, err := a.Machine.State(ctx, key)
	if err != nil {
		return "", LocalReadMeta{}, err
	}
	if st.DurableOffset > 0 || st.Sealed {
		return a.Tail(ctx, job, build, maxLen)
	}

	if !opt.SkipPeer && a.Peer != nil {
		out, hit, err := a.Peer.TryRead(ctx, PeerReadRequest{
			Job: job, Build: build, Kind: PeerReadTailBytes,
			TailN: maxLen, MaxDecodedBytes: opt.MaxDecodedBytes,
		})
		if err != nil {
			return "", LocalReadMeta{}, err
		}
		if hit {
			return peerOutcomeToString(out), peerOutcomeToMeta(out, int64(out.Offset), maxLen), nil
		}
	}

	if opt.SkipOrigin {
		return "", LocalReadMeta{}, apperr.New(apperr.CodeNotFound, "log not available locally or via peer")
	}
	if err := a.ensureOriginCoordinated(ctx, job, build); err != nil {
		if st2, serr := a.Machine.State(ctx, key); serr == nil && (st2.DurableOffset > 0 || st2.Sealed) {
			logs, meta, rerr := a.Tail(ctx, job, build, maxLen)
			if rerr == nil {
				return logs, meta, err
			}
		}
		return "", LocalReadMeta{}, err
	}
	return a.Tail(ctx, job, build, maxLen)
}

func (a *Access) tryLocalByteRange(ctx context.Context, key LogKey, job string, build int64, offset, length int64) (string, LocalReadMeta, bool, error) {
	st, err := a.Machine.State(ctx, key)
	if err != nil {
		return "", LocalReadMeta{}, false, err
	}
	// No local materialization yet.
	if st.GenerationID == 0 && st.DurableOffset == 0 && !st.Sealed {
		return "", LocalReadMeta{}, false, nil
	}
	// Range starts beyond durable end and not sealed → not a full local hit; allow peer/origin.
	if !st.Sealed && offset >= st.DurableOffset && st.DurableOffset == 0 {
		return "", LocalReadMeta{}, false, nil
	}
	if st.DurableOffset == 0 && !st.Sealed {
		return "", LocalReadMeta{}, false, nil
	}
	// Prefer local when we have any durable data for this key (including empty sealed).
	logs, meta, err := a.ReadRange(ctx, job, build, offset, length)
	if err != nil {
		// Corrupt/missing frames: fall through to peer/origin rather than hard-fail when empty.
		if st.DurableOffset == 0 {
			return "", LocalReadMeta{}, false, nil
		}
		return "", LocalReadMeta{}, false, err
	}
	// If sealed or we returned data / EOF at durable end, treat as local hit.
	if st.Sealed || len(logs) > 0 || offset >= st.DurableOffset {
		return logs, meta, true, nil
	}
	// Unsealed with empty slice at offset 0 and no durable — not a hit.
	if st.DurableOffset == 0 {
		return "", LocalReadMeta{}, false, nil
	}
	return logs, meta, true, nil
}

func peerOutcomeToString(out PeerReadOutcome) string {
	return string(out.Data)
}

func peerOutcomeToMeta(out PeerReadOutcome, requestedStart, requestedLen int64) LocalReadMeta {
	length := out.Length
	if length == 0 {
		length = len(out.Data)
	}
	offset := out.Offset
	if offset == 0 && requestedStart > 0 && length > 0 {
		offset = int(requestedStart)
	}
	total := out.TotalSize
	if total < offset+length {
		total = offset + length
	}
	return LocalReadMeta{
		Offset:    offset,
		Length:    length,
		TotalSize: total,
		HasMore:   out.HasMore,
		Sealed:    out.Sealed,
	}
}
