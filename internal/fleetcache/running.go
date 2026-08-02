package fleetcache

import (
	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Running-log peer frame planning (FLC-080).
//
// Running builds share only durable, immutable committed frames (ListChunks /
// Flush results). Buffered progressive bytes are never published. Offset
// regression (Jenkins total size behind prior offset) requires a new local
// logical generation. Live multi-host running-log peer stream is residual
// (library + store tests only in this task). Final sealed object without
// recompress of prior frames is FLC-081 (PlanFinalizeFromDurable / FinalizeSealed;
// ExportPureZstd identity after progressive seal is the wire-reuse proof).

// RunningFramePlan describes the durable prefix eligible for peer replicate
// while a local generation still has MoreData=true.
//
// GenerationID is local-only and must never appear on the wire (residual note).
// SealedSeqEnd is the inclusive last durable seq (0-based); -1 means none.
type RunningFramePlan struct {
	// GenerationID is the local SQLite generation row id (not a wire identity).
	GenerationID int64
	// SealedSeqEnd is inclusive last durable frame seq; -1 if no durable frames.
	SealedSeqEnd int
	// FrameCount is SealedSeqEnd+1 when SealedSeqEnd >= 0, else 0.
	FrameCount int
	// Residual is secret-free (e.g. no_durable_frames, durable_prefix_only).
	Residual string
}

// ValidateProgressiveRanges checks WireFrame raw ranges are contiguous with no
// gap or overlap. Seq must be contiguous from 0. Empty is valid (no error).
// Does not require zstd digests so callers can validate local chunk ranges
// before wire export.
func ValidateProgressiveRanges(frames []WireFrame) error {
	if len(frames) == 0 {
		return nil
	}
	if len(frames) > MaxWireFrames {
		return apperr.New(apperr.CodeInvalidArgument, "progressive frames exceed max")
	}
	var rawCursor int64
	for i, f := range frames {
		if f.Seq != i {
			return apperr.New(apperr.CodeInvalidArgument, "progressive frame seq must be contiguous from 0")
		}
		if f.RawStart != rawCursor {
			return apperr.New(apperr.CodeInvalidArgument, "progressive frame raw ranges must be contiguous (no gap/overlap)")
		}
		if f.RawEnd < f.RawStart {
			return apperr.New(apperr.CodeInvalidArgument, "progressive frame raw_end < raw_start")
		}
		if f.DecodedSize > 0 && f.DecodedSize != f.RawEnd-f.RawStart {
			return apperr.New(apperr.CodeInvalidArgument, "progressive frame decoded_size must match raw range")
		}
		rawCursor = f.RawEnd
	}
	return nil
}

// OffsetRegressionNeedsNewGeneration reports whether a new logical generation
// is required because Jenkins reported offset went backward (truncation/rewrite).
//
// Contract: if newOffset < priorOffset → true. Negative newOffset means unknown
// next size and does not force a generation bump (matches logmirror unknown -1).
func OffsetRegressionNeedsNewGeneration(priorOffset, newOffset int64) bool {
	if newOffset < 0 {
		return false
	}
	return newOffset < priorOffset
}

// PlanRunningDurablePrefix builds a RunningFramePlan from already-committed
// durable frames only. Callers must pass ListChunks / sealed-prefix material —
// never in-process buffer bytes (AcceptedEnd beyond DurableEnd).
//
// generationID is local-only residual. Empty durable → SealedSeqEnd=-1.
// Invalid ranges fail closed.
func PlanRunningDurablePrefix(generationID int64, durable []WireFrame) (RunningFramePlan, error) {
	if err := ValidateProgressiveRanges(durable); err != nil {
		return RunningFramePlan{
			GenerationID: generationID,
			SealedSeqEnd: -1,
			Residual:     "invalid_ranges",
		}, err
	}
	if len(durable) == 0 {
		return RunningFramePlan{
			GenerationID: generationID,
			SealedSeqEnd: -1,
			FrameCount:   0,
			Residual:     "no_durable_frames",
		}, nil
	}
	return RunningFramePlan{
		GenerationID: generationID,
		SealedSeqEnd: len(durable) - 1,
		FrameCount:   len(durable),
		// Secret-free: only durable frames are planned; buffered never exported.
		Residual: "durable_prefix_only",
	}, nil
}

// ExportSeqs returns 0..SealedSeqEnd inclusive for peer transfer (nil if none).
func (p RunningFramePlan) ExportSeqs() []int {
	if p.SealedSeqEnd < 0 || p.FrameCount == 0 {
		return nil
	}
	n := p.SealedSeqEnd + 1
	out := make([]int, n)
	for i := 0; i < n; i++ {
		out[i] = i
	}
	return out
}

// SelectRunningExportFrames returns durable frames [0..SealedSeqEnd] for wire
// export. Returns nil when the plan has no durable frames.
func SelectRunningExportFrames(durable []WireFrame, plan RunningFramePlan) []WireFrame {
	if plan.SealedSeqEnd < 0 || len(durable) == 0 {
		return nil
	}
	end := plan.SealedSeqEnd + 1
	if end > len(durable) {
		end = len(durable)
	}
	out := make([]WireFrame, end)
	copy(out, durable[:end])
	return out
}

// ProgressiveChunk is store-like chunk range metadata for progressive planning
// (ValidateProgressiveRanges / PlanRunningDurablePrefix). Wire zstd size/hash
// may be zero until EnsureChunkWireHash / ExportPureZstd.
type ProgressiveChunk struct {
	Seq           int
	RawStart      int64
	RawEnd        int64
	LineStart     int64
	LineEnd       int64
	DecodedSize   int64
	DecodedSHA256 string
	ZstdSize      int64
	ZstdSHA256    string
}

// ProgressiveWireFrames converts progressive chunk metadata to WireFrame slice.
func ProgressiveWireFrames(chunks []ProgressiveChunk) []WireFrame {
	if len(chunks) == 0 {
		return nil
	}
	out := make([]WireFrame, len(chunks))
	for i, c := range chunks {
		decSize := c.DecodedSize
		if decSize == 0 && c.RawEnd >= c.RawStart {
			decSize = c.RawEnd - c.RawStart
		}
		out[i] = WireFrame{
			Seq: c.Seq, RawStart: c.RawStart, RawEnd: c.RawEnd,
			LineStart: c.LineStart, LineEnd: c.LineEnd,
			DecodedSize: decSize, DecodedSHA256: c.DecodedSHA256,
			ZstdSize: c.ZstdSize, ZstdSHA256: c.ZstdSHA256,
		}
	}
	return out
}
