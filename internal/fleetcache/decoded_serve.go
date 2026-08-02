package fleetcache

import (
	"context"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// LocalSealedObject is the owner-side resolution of a locator (no file paths on wire).
type LocalSealedObject struct {
	GenerationID int64
	Sealed       bool
	// Materialized is false when L1 is released without readable local frames (v1 residual).
	Materialized   bool
	ManifestDigest string
	FleetID        string
}

// DecodedLogReader is the store LogReader surface used for owner-side reads (FLC-031).
// Implemented by adapters around store.LogReader; fleetcache does not import store.
type DecodedLogReader interface {
	ReadRange(ctx context.Context, generationID int64, start, length int64) (DecodedReadResult, error)
	ReadLineRange(ctx context.Context, generationID int64, startLine, lineCount int64) (DecodedReadResult, error)
	TailBytes(ctx context.Context, generationID int64, n int64) (DecodedReadResult, error)
	TailLines(ctx context.Context, generationID int64, n int64) (DecodedReadResult, error)
}

// SealedObjectResolver maps locator_hash → local sealed object state.
type SealedObjectResolver interface {
	ResolveSealed(locatorHash string) (LocalSealedObject, bool)
}

// ServeDecodedReadOptions configures owner-side authorization + read.
type ServeDecodedReadOptions struct {
	AssertionKey []byte
	Nonces       NonceStore
	Now          time.Time
	FleetID      string
	// MaxDecodedBytes is the server process expected budget (0 → AbsoluteDecodedReadCeiling).
	MaxDecodedBytes int64
	PolicyEpoch     int64
}

// ServeDecodedRead validates assertion + request, resolves local sealed object, and
// calls LogReader under the binding ceiling. Deny paths never invoke the reader.
func ServeDecodedRead(
	ctx context.Context,
	resolver SealedObjectResolver,
	reader DecodedLogReader,
	req DecodedReadRequest,
	assertion Assertion,
	opts ServeDecodedReadOptions,
) (DecodedReadResult, error) {
	if resolver == nil || reader == nil {
		return DecodedReadResult{Status: DecodedReadUnavailable, Residual: "owner backend unavailable"},
			apperr.New(apperr.CodeInternal, "decoded read backend nil")
	}
	if err := ctx.Err(); err != nil {
		return DecodedReadResult{Status: DecodedReadCancelled, Residual: "cancelled"}, err
	}
	req.LocatorHash = strings.ToLower(strings.TrimSpace(req.LocatorHash))
	if err := ValidateDecodedReadRequest(req); err != nil {
		return DecodedReadResult{Status: DecodedReadInvalid, Residual: "invalid request"}, err
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	serverBudget := opts.MaxDecodedBytes
	if serverBudget <= 0 {
		serverBudget = AbsoluteDecodedReadCeiling
	}
	exp := Expected{
		FleetID:         opts.FleetID,
		LocatorHash:     req.LocatorHash,
		Operation:       OpRead,
		MaxDecodedBytes: serverBudget,
		PolicyEpoch:     opts.PolicyEpoch,
	}
	// Verify MAC/time/replay first (authorization), then scope vs request.
	if err := VerifyAssertion(opts.AssertionKey, assertion, now, exp, opts.Nonces); err != nil {
		return DecodedReadResult{Status: DecodedReadScopeDenied, Residual: "assertion denied"}, err
	}
	if err := AuthorizeDecodedReadScope(assertion.Claims, req, exp); err != nil {
		return DecodedReadResult{Status: DecodedReadScopeDenied, Residual: "scope denied"}, err
	}

	obj, ok := resolver.ResolveSealed(req.LocatorHash)
	if !ok {
		return DecodedReadResult{Status: DecodedReadNotFound, Residual: "object not found"}, nil
	}
	if opts.FleetID != "" && obj.FleetID != "" && obj.FleetID != opts.FleetID {
		return DecodedReadResult{Status: DecodedReadNotFound, Residual: "wrong fleet"}, nil
	}
	if !obj.Sealed {
		return DecodedReadResult{Status: DecodedReadNotFound, Residual: "not sealed"}, nil
	}
	if !obj.Materialized {
		// Acceptance: L1-released without materialization is not served incorrectly.
		return DecodedReadResult{Status: DecodedReadNotMaterialized, Residual: "not_materialized"}, nil
	}
	if assertion.Claims.ManifestDigest != "" && obj.ManifestDigest != "" &&
		!strings.EqualFold(assertion.Claims.ManifestDigest, obj.ManifestDigest) {
		return DecodedReadResult{Status: DecodedReadScopeDenied, Residual: "manifest digest mismatch"},
			apperr.New(apperr.CodeAuthorization, "assertion manifest digest mismatch")
	}

	ceiling, err := EffectiveDecodedCeiling(assertion.Claims.MaxDecodedBytes, req.MaxDecodedBytes)
	if err != nil {
		return DecodedReadResult{Status: DecodedReadInvalid, Residual: "ceiling invalid"}, err
	}

	// Cap known-size forms before disk so a 64 KiB request never opens a multi-GB full-object path.
	switch req.Kind {
	case ReadKindByteRange:
		if req.Length > ceiling {
			return DecodedReadResult{Status: DecodedReadOverCeiling, Residual: "over_ceiling"},
				apperr.New(apperr.CodeQuota, "decoded read length exceeds ceiling")
		}
	case ReadKindTailBytes:
		if req.TailN > ceiling {
			return DecodedReadResult{Status: DecodedReadOverCeiling, Residual: "over_ceiling"},
				apperr.New(apperr.CodeQuota, "decoded read tail exceeds ceiling")
		}
	}

	var res DecodedReadResult
	switch req.Kind {
	case ReadKindByteRange:
		res, err = reader.ReadRange(ctx, obj.GenerationID, req.Start, req.Length)
	case ReadKindLineRange:
		res, err = reader.ReadLineRange(ctx, obj.GenerationID, req.StartLine, req.LineCount)
	case ReadKindTailBytes:
		res, err = reader.TailBytes(ctx, obj.GenerationID, req.TailN)
	case ReadKindTailLines:
		res, err = reader.TailLines(ctx, obj.GenerationID, req.TailN)
	default:
		return DecodedReadResult{Status: DecodedReadInvalid, Residual: "kind invalid"},
			apperr.New(apperr.CodeInvalidArgument, "decoded read kind invalid")
	}
	if err != nil {
		if ctx.Err() != nil {
			return DecodedReadResult{Status: DecodedReadCancelled, Residual: "cancelled"}, ctx.Err()
		}
		return DecodedReadResult{Status: DecodedReadUnavailable, Residual: "read failed"}, err
	}
	if err := EnforceDecodedBodyCeiling(int64(len(res.Data)), ceiling); err != nil {
		// Fail closed: do not return oversize body.
		return DecodedReadResult{Status: DecodedReadOverCeiling, Residual: "over_ceiling"}, err
	}
	res.Status = DecodedReadOK
	res.Sealed = true
	res.Residual = ""
	return res, nil
}
