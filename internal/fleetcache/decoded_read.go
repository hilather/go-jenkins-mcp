package fleetcache

import (
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Decoded read forms (FLC-031). Kind is required and exclusive of unused fields.
const (
	ReadKindByteRange = "byte_range"
	ReadKindLineRange = "line_range"
	ReadKindTailBytes = "tail_bytes"
	ReadKindTailLines = "tail_lines"
)

// Decoded peer-read ceilings (product defaults; fail closed above absolute).
const (
	// DefaultDecodedReadCeiling is the default max decoded body for a peer read (64 KiB).
	DefaultDecodedReadCeiling int64 = 64 << 10
	// AbsoluteDecodedReadCeiling is the hard process/peer ceiling (1 MiB).
	// Larger evidence stays on local LogReader / MCP budgets, not peer wire.
	AbsoluteDecodedReadCeiling int64 = 1 << 20
	// MaxLineCount is the max lines in one line_range or tail_lines request.
	MaxLineCount int64 = 10_000
)

// DecodedReadRequest is a scoped bounded decoded read (no local generation/path).
type DecodedReadRequest struct {
	LocatorHash string `json:"locator_hash"`
	Kind        string `json:"kind"`

	// Byte range (ReadKindByteRange).
	Start  int64 `json:"start,omitempty"`
	Length int64 `json:"length,omitempty"`

	// Line range (ReadKindLineRange); 0-based start line.
	StartLine int64 `json:"start_line,omitempty"`
	LineCount int64 `json:"line_count,omitempty"`

	// Tail (ReadKindTailBytes / ReadKindTailLines).
	TailN int64 `json:"tail_n,omitempty"`

	// MaxDecodedBytes is the request ceiling (0 → DefaultDecodedReadCeiling).
	// Cannot exceed AbsoluteDecodedReadCeiling or the assertion claim budget.
	MaxDecodedBytes int64 `json:"max_decoded_bytes,omitempty"`
}

// DecodedReadResult is owner-side decoded body + range metadata (matches LogReader fields used on the wire).
type DecodedReadResult struct {
	Data              []byte
	RawStart          int64
	RawEnd            int64
	LineStart         int64
	LineEnd           int64
	RequestedBytes    int64
	DecompressedBytes int64
	FramesOpened      int
	Sealed            bool
	// Residual is secret-free (e.g. not_materialized); empty on success.
	Residual string
	// Status is a low-cardinality outcome for clients.
	Status DecodedReadStatus
}

// DecodedReadStatus classifies owner/client outcomes (FLC-031).
type DecodedReadStatus string

const (
	DecodedReadOK              DecodedReadStatus = "ok"
	DecodedReadNotFound        DecodedReadStatus = "not_found"
	DecodedReadNotMaterialized DecodedReadStatus = "not_materialized"
	DecodedReadScopeDenied     DecodedReadStatus = "scope_denied"
	DecodedReadOverCeiling     DecodedReadStatus = "over_ceiling"
	DecodedReadModeOff         DecodedReadStatus = "mode_off"
	DecodedReadUnavailable     DecodedReadStatus = "unavailable"
	DecodedReadInvalid         DecodedReadStatus = "invalid"
	DecodedReadCancelled       DecodedReadStatus = "cancelled"
)

// ValidateDecodedReadRequest enforces form bounds without auth or disk I/O.
func ValidateDecodedReadRequest(req DecodedReadRequest) error {
	req.LocatorHash = strings.ToLower(strings.TrimSpace(req.LocatorHash))
	req.Kind = strings.TrimSpace(req.Kind)
	if len(req.LocatorHash) != 64 || !isHex(req.LocatorHash) {
		return apperr.New(apperr.CodeInvalidArgument, "decoded read locator_hash invalid")
	}
	ceiling, err := effectiveRequestCeiling(req.MaxDecodedBytes)
	if err != nil {
		return err
	}
	switch req.Kind {
	case ReadKindByteRange:
		if req.Start < 0 {
			return apperr.New(apperr.CodeInvalidArgument, "decoded read start must be non-negative")
		}
		if req.Length < 0 {
			return apperr.New(apperr.CodeInvalidArgument, "decoded read length must be non-negative")
		}
		if req.Length > ceiling {
			return apperr.New(apperr.CodeInvalidArgument, "decoded read length exceeds ceiling")
		}
		if req.StartLine != 0 || req.LineCount != 0 || req.TailN != 0 {
			return apperr.New(apperr.CodeInvalidArgument, "decoded read byte_range must not set line/tail fields")
		}
	case ReadKindLineRange:
		if req.StartLine < 0 {
			return apperr.New(apperr.CodeInvalidArgument, "decoded read start_line must be non-negative")
		}
		if req.LineCount < 0 {
			return apperr.New(apperr.CodeInvalidArgument, "decoded read line_count must be non-negative")
		}
		if req.LineCount > MaxLineCount {
			return apperr.New(apperr.CodeInvalidArgument, "decoded read line_count exceeds max")
		}
		if req.Start != 0 || req.Length != 0 || req.TailN != 0 {
			return apperr.New(apperr.CodeInvalidArgument, "decoded read line_range must not set byte/tail fields")
		}
	case ReadKindTailBytes:
		if req.TailN < 0 {
			return apperr.New(apperr.CodeInvalidArgument, "decoded read tail_n must be non-negative")
		}
		if req.TailN > ceiling {
			return apperr.New(apperr.CodeInvalidArgument, "decoded read tail_n exceeds ceiling")
		}
		if req.Start != 0 || req.Length != 0 || req.StartLine != 0 || req.LineCount != 0 {
			return apperr.New(apperr.CodeInvalidArgument, "decoded read tail_bytes must not set range fields")
		}
	case ReadKindTailLines:
		if req.TailN < 0 {
			return apperr.New(apperr.CodeInvalidArgument, "decoded read tail_n must be non-negative")
		}
		if req.TailN > MaxLineCount {
			return apperr.New(apperr.CodeInvalidArgument, "decoded read tail_n exceeds max lines")
		}
		if req.Start != 0 || req.Length != 0 || req.StartLine != 0 || req.LineCount != 0 {
			return apperr.New(apperr.CodeInvalidArgument, "decoded read tail_lines must not set range fields")
		}
	default:
		return apperr.New(apperr.CodeInvalidArgument, "decoded read kind invalid")
	}
	return nil
}

// EffectiveDecodedCeiling returns the binding ceiling for a verified claim + request.
// Min of request ceiling, claim MaxDecodedBytes (when >0), and AbsoluteDecodedReadCeiling.
// Claim 0 means "use request/default" (still bounded by absolute).
func EffectiveDecodedCeiling(claimMaxDecoded, requestMaxDecoded int64) (int64, error) {
	reqCeil, err := effectiveRequestCeiling(requestMaxDecoded)
	if err != nil {
		return 0, err
	}
	if claimMaxDecoded < 0 {
		return 0, apperr.New(apperr.CodeInvalidArgument, "assertion max_decoded_bytes negative")
	}
	if claimMaxDecoded > AbsoluteDecodedReadCeiling {
		return 0, apperr.New(apperr.CodeAuthorization, "assertion decoded budget exceeds absolute ceiling")
	}
	if claimMaxDecoded == 0 {
		return reqCeil, nil
	}
	if claimMaxDecoded < reqCeil {
		return claimMaxDecoded, nil
	}
	return reqCeil, nil
}

// AuthorizeDecodedReadScope checks assertion scope against the request before any disk read.
// expected should include fleet, locator, OpRead, and optional MaxDecodedBytes/PolicyEpoch.
// Returns CodeAuthorization on scope deny (fail closed).
func AuthorizeDecodedReadScope(claims AssertionClaims, req DecodedReadRequest, exp Expected) error {
	if err := ValidateDecodedReadRequest(req); err != nil {
		return err
	}
	req.LocatorHash = strings.ToLower(strings.TrimSpace(req.LocatorHash))
	if exp.Operation == "" {
		exp.Operation = OpRead
	}
	if exp.LocatorHash == "" {
		exp.LocatorHash = req.LocatorHash
	}
	if claims.Operation != OpRead {
		return apperr.New(apperr.CodeAuthorization, "assertion operation not read")
	}
	if !strings.EqualFold(claims.LocatorHash, req.LocatorHash) {
		return apperr.New(apperr.CodeAuthorization, "assertion locator out of scope")
	}
	if exp.FleetID != "" && claims.FleetID != exp.FleetID {
		return apperr.New(apperr.CodeAuthorization, "assertion fleet mismatch")
	}
	if exp.LocatorHash != "" && !strings.EqualFold(claims.LocatorHash, exp.LocatorHash) {
		return apperr.New(apperr.CodeAuthorization, "assertion locator mismatch")
	}
	if exp.Operation != "" && claims.Operation != exp.Operation {
		return apperr.New(apperr.CodeAuthorization, "assertion operation mismatch")
	}
	if exp.PolicyEpoch > 0 && claims.PolicyEpoch != exp.PolicyEpoch {
		return apperr.New(apperr.CodeAuthorization, "assertion policy epoch mismatch")
	}
	ceiling, err := EffectiveDecodedCeiling(claims.MaxDecodedBytes, req.MaxDecodedBytes)
	if err != nil {
		return err
	}
	// Claim must not widen beyond expected server/process budget when Expected sets MaxDecodedBytes.
	if exp.MaxDecodedBytes > 0 && claims.MaxDecodedBytes > exp.MaxDecodedBytes {
		return apperr.New(apperr.CodeAuthorization, "assertion decoded budget widened")
	}
	// Known-size forms must fit under the binding ceiling before disk.
	switch strings.TrimSpace(req.Kind) {
	case ReadKindByteRange:
		if req.Length > ceiling {
			return apperr.New(apperr.CodeAuthorization, "decoded read length out of assertion scope")
		}
	case ReadKindTailBytes:
		if req.TailN > ceiling {
			return apperr.New(apperr.CodeAuthorization, "decoded read tail out of assertion scope")
		}
	}
	return nil
}

// EnforceDecodedBodyCeiling fails closed if produced body exceeds the binding ceiling.
// Does not truncate (no partial untrusted success).
func EnforceDecodedBodyCeiling(bodyLen int64, ceiling int64) error {
	if ceiling <= 0 {
		return apperr.New(apperr.CodeInternal, "decoded ceiling unset")
	}
	if bodyLen > ceiling {
		return apperr.New(apperr.CodeQuota, "decoded read exceeds ceiling")
	}
	return nil
}

func effectiveRequestCeiling(requestMaxDecoded int64) (int64, error) {
	if requestMaxDecoded < 0 {
		return 0, apperr.New(apperr.CodeInvalidArgument, "decoded read max_decoded_bytes negative")
	}
	if requestMaxDecoded == 0 {
		return DefaultDecodedReadCeiling, nil
	}
	if requestMaxDecoded > AbsoluteDecodedReadCeiling {
		return 0, apperr.New(apperr.CodeInvalidArgument, "decoded read max_decoded_bytes exceeds absolute ceiling")
	}
	return requestMaxDecoded, nil
}
