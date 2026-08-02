package fleetcache

import (
	"context"
	"strings"
	"sync"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Finalize running generations into sealed fleet objects without recompression (FLC-081).
//
// PlanFinalizeFromDurable builds a sealed WireManifest from already-known durable
// pure-zstd frame descriptors and bytes. It must never require decoded body bytes
// for prior frames and does not recompress. FinalizeSealed commits via the same
// journaled import path as ReplicateSealed (partial Abort leaves no GetCommitted).
// Live multi-host finalize stream remains residual; mode default off.

// Finalize status / residual tokens (secret-free, low-cardinality).
const (
	// FinalizeStatusCommitted is a successful first sealed publish.
	FinalizeStatusCommitted = ImportStatusCommitted
	// FinalizeStatusIdempotent is a second finalize of the same digest.
	FinalizeStatusIdempotent = ImportStatusIdempotent
	// FinalizeStatusAborted is a crash / mid-write abort (no preferred mapping).
	FinalizeStatusAborted = ImportStatusAborted
	// FinalizeStatusRejected is validation / conflict fail-closed.
	FinalizeStatusRejected = ImportStatusRejected

	// ResidualFinalizeFramesReused documents no-recompress success.
	ResidualFinalizeFramesReused = "frames_reused_no_recompress"
	// ResidualFinalizeIdempotent is same-digest second finalize.
	ResidualFinalizeIdempotent = "idempotent_same_digest"
	// ResidualFinalizePartialAborted documents invisible partial after Abort.
	ResidualFinalizePartialAborted = "partial_aborted_invisible"
	// ResidualFinalizeNoFrames is empty durable set.
	ResidualFinalizeNoFrames = "no_durable_frames"
	// ResidualFinalizeDigestMismatch is pure zstd vs descriptor mismatch.
	ResidualFinalizeDigestMismatch = "frame_digest_mismatch"
	// ResidualFinalizeFenceHeld is concurrent finalize fence conflict.
	ResidualFinalizeFenceHeld = "finalize_fence_held"
	// ResidualFinalizeFenceStale is complete under wrong fence.
	ResidualFinalizeFenceStale = "finalize_fence_stale"
)

// FinalizeHonestyResidual documents offline library vs live multi-host residual.
const FinalizeHonestyResidual = "FLC-081 Done* finalize without recompress library; live multi-host finalize stream residual; mode default off"

// FinalizePlan is the pure decision to seal already-known pure frames (no recompress).
type FinalizePlan struct {
	LocatorHash    string
	ManifestDigest string
	// FrameSeqs is 0..n-1 contiguous for the sealed object.
	FrameSeqs []int
	// Residual is secret-free (e.g. frames_reused_no_recompress).
	Residual string
}

// FinalizeResult is the secret-free outcome of FinalizeSealed.
type FinalizeResult struct {
	Status         string // committed | idempotent | aborted | rejected
	LocatorHash    string
	ManifestDigest string
	// FramesReused equals len(frames) on committed/idempotent success (no recompress).
	// Zero on reject/abort paths that did not reuse a full sealed set.
	FramesReused int
	// GenerationID is local on receiver when committed/idempotent; 0 otherwise.
	GenerationID int64
	// Residual is secret-free.
	Residual string
}

// PlanFinalizeFromDurable builds a sealed WireManifest from existing wire frame
// descriptors and already-exported pure zstd bytes (no recompress, no decode of
// prior frame bodies for planning). Validates progressive ranges and import
// digests; PublishSealed is deterministic/idempotent for the same input.
//
// pure may be nil when every frame already carries verified ZstdSize/ZstdSHA256
// (digest-only plan). When pure is non-empty it must be a complete set matching
// frames (ValidateImportFrames) — used to prove wire identity without recompress.
func PlanFinalizeFromDurable(loc Locator, frames []WireFrame, pure []ImportFrameBytes) (FinalizePlan, WireManifest, error) {
	empty := FinalizePlan{Residual: ResidualFinalizeNoFrames}
	if len(frames) == 0 {
		return empty, WireManifest{}, apperr.New(apperr.CodeInvalidArgument, "finalize requires durable frames")
	}
	if err := ValidateProgressiveRanges(frames); err != nil {
		return FinalizePlan{Residual: "invalid_ranges"}, WireManifest{}, err
	}
	// Every frame must already carry pure-zstd wire identity (no recompress to invent it).
	for i, f := range frames {
		if f.Seq != i {
			return FinalizePlan{Residual: "invalid_seq"}, WireManifest{},
				apperr.New(apperr.CodeInvalidArgument, "finalize frame seq must be contiguous from 0")
		}
		if f.ZstdSize < 1 || strings.TrimSpace(f.ZstdSHA256) == "" {
			return FinalizePlan{Residual: "missing_wire_identity"}, WireManifest{},
				apperr.New(apperr.CodeInvalidArgument, "finalize frame missing pure-zstd wire identity")
		}
		if len(f.DecodedSHA256) != 64 || !isHex(f.DecodedSHA256) {
			return FinalizePlan{Residual: "missing_decoded_digest"}, WireManifest{},
				apperr.New(apperr.CodeInvalidArgument, "finalize frame missing decoded_sha256")
		}
	}

	lh, err := loc.Hash()
	if err != nil {
		return FinalizePlan{Residual: "invalid_locator"}, WireManifest{}, err
	}
	// Job full name for PublishSealed: use normalized locator field.
	fds := make([]FrameDescriptor, len(frames))
	var sumDecoded, lastLine int64
	seqs := make([]int, len(frames))
	for i, f := range frames {
		fds[i] = FrameDescriptor{
			Seq: f.Seq, RawStart: f.RawStart, RawEnd: f.RawEnd,
			LineStart: f.LineStart, LineEnd: f.LineEnd,
			DecodedSize: f.DecodedSize, DecodedSHA256: strings.ToLower(strings.TrimSpace(f.DecodedSHA256)),
			ZstdSize: f.ZstdSize, ZstdSHA256: strings.ToLower(strings.TrimSpace(f.ZstdSHA256)),
		}
		if fds[i].DecodedSize == 0 && f.RawEnd >= f.RawStart {
			fds[i].DecodedSize = f.RawEnd - f.RawStart
		}
		sumDecoded += fds[i].DecodedSize
		if fds[i].LineEnd > lastLine {
			lastLine = fds[i].LineEnd
		}
		seqs[i] = i
	}

	wm, err := PublishSealed(SealedPublishInput{
		FleetID:       loc.FleetID,
		CachePool:     loc.CachePool,
		ControllerID:  loc.ControllerID,
		JobFullName:   loc.JobFullNameNormalized,
		BuildNumber:   loc.BuildNumber,
		Sealed:        true,
		Frames:        fds,
		TotalRawBytes: sumDecoded,
		TotalLines:    lastLine,
	})
	if err != nil {
		return FinalizePlan{LocatorHash: lh, Residual: "publish_rejected"}, WireManifest{}, err
	}
	// Locator hash from publish must match loc (deterministic).
	if !strings.EqualFold(wm.LocatorHash, lh) {
		return FinalizePlan{LocatorHash: lh, Residual: "locator_hash_mismatch"}, WireManifest{},
			apperr.New(apperr.CodeInternal, "finalize locator_hash mismatch")
	}

	// Optional pure-byte proof: no decode/recompress — only size/hash of pure zstd.
	if len(pure) > 0 {
		if err := ValidateImportFrames(wm, pure); err != nil {
			return FinalizePlan{
				LocatorHash: lh, ManifestDigest: wm.ManifestDigest,
				FrameSeqs: seqs, Residual: ResidualFinalizeDigestMismatch,
			}, WireManifest{}, err
		}
	}

	plan := FinalizePlan{
		LocatorHash:    wm.LocatorHash,
		ManifestDigest: wm.ManifestDigest,
		FrameSeqs:      seqs,
		Residual:       ResidualFinalizeFramesReused,
	}
	return plan, wm, nil
}

// FinalizeSealed commits a sealed fleet object from already-known pure-zstd frames
// (no recompress). Uses the journaled import path (ReplicateSealed):
//
//   - Matching committed digest → idempotent; FramesReused == len(frames).
//   - Partial write + Abort → no GetCommitted preferred mapping.
//   - Full commit → exactly one sealed preferred version; second call idempotent.
//
// FramesReused equals len(frames) on committed and idempotent success to document
// that every frame was reused as pure zstd (never recompressed for finalization).
func FinalizeSealed(ctx context.Context, sink ImportSink, m WireManifest, frames []ImportFrameBytes) (FinalizeResult, error) {
	if sink == nil {
		return FinalizeResult{Status: FinalizeStatusRejected, Residual: "sink nil"},
			apperr.New(apperr.CodeInternal, "finalize sink nil")
	}
	if err := ctx.Err(); err != nil {
		return FinalizeResult{Status: FinalizeStatusAborted, Residual: "cancelled"}, err
	}
	// Complete pure set required for atomic finalize (resume of import is ReplicateSealed).
	if err := ValidateImportFrames(m, frames); err != nil {
		return FinalizeResult{Status: FinalizeStatusRejected, Residual: "frame validation failed"}, err
	}
	digest, err := DigestWireManifest(m)
	if err != nil {
		return FinalizeResult{Status: FinalizeStatusRejected, Residual: "invalid manifest"}, err
	}
	m.ManifestDigest = digest
	m.LocatorHash = strings.ToLower(strings.TrimSpace(m.LocatorHash))
	n := len(frames)

	// Fast path: already committed same digest → idempotent, frames reused (no transfer).
	existing, ok, err := sink.GetCommitted(ctx, m.LocatorHash)
	if err != nil {
		return FinalizeResult{Status: FinalizeStatusRejected, Residual: "lookup failed"}, err
	}
	if ok {
		var existingPtr *CommittedMapping
		e := existing
		existingPtr = &e
		outcome := EvaluateManifestConflict(existingPtr, m)
		switch outcome.Action {
		case PartitionActionConverge:
			return FinalizeResult{
				Status: FinalizeStatusIdempotent, LocatorHash: m.LocatorHash,
				ManifestDigest: digest, FramesReused: n, GenerationID: existing.GenerationID,
				Residual: ResidualFinalizeIdempotent,
			}, nil
		case PartitionActionConflict:
			return FinalizeResult{
				Status: FinalizeStatusRejected, LocatorHash: m.LocatorHash,
				ManifestDigest: digest, Residual: PartitionResidualConflictDigest,
			}, apperr.New(apperr.CodePolicyDenial, "conflicting fleet object version")
		}
	}

	// Commit via RF2 import path (journal staging; partial invisible).
	rep, err := ReplicateSealed(ctx, sink, m, frames)
	if err != nil {
		status := rep.Status
		if status == "" {
			status = FinalizeStatusAborted
		}
		residual := rep.Residual
		if residual == "" {
			residual = ResidualFinalizePartialAborted
		}
		return FinalizeResult{
			Status: status, LocatorHash: m.LocatorHash, ManifestDigest: digest,
			GenerationID: rep.GenerationID, Residual: residual,
		}, err
	}
	switch rep.Status {
	case ImportStatusIdempotent:
		return FinalizeResult{
			Status: FinalizeStatusIdempotent, LocatorHash: m.LocatorHash,
			ManifestDigest: digest, FramesReused: n, GenerationID: rep.GenerationID,
			Residual: ResidualFinalizeIdempotent,
		}, nil
	case ImportStatusCommitted:
		return FinalizeResult{
			Status: FinalizeStatusCommitted, LocatorHash: m.LocatorHash,
			ManifestDigest: digest, FramesReused: n, GenerationID: rep.GenerationID,
			Residual: ResidualFinalizeFramesReused,
		}, nil
	default:
		return FinalizeResult{
			Status: rep.Status, LocatorHash: m.LocatorHash, ManifestDigest: digest,
			GenerationID: rep.GenerationID, Residual: rep.Residual,
		}, nil
	}
}

// FinalizeFenceAuthority is an optional process-local single-writer fence for
// concurrent finalize (FLC-081). Not durable across process restart — crash
// recovery is the journaled ImportSink path (partial Abort → GetCommitted false).
// Residual honesty: multi-host fence coordination is residual.
type FinalizeFenceAuthority struct {
	mu   sync.Mutex
	held map[string]uint64 // locator_hash → fence
	next uint64
	// completed digests under fence (optional bookkeeping for tests).
	done map[string]string // locator → manifest_digest
}

// NewFinalizeFenceAuthority builds an empty process-local fence authority.
func NewFinalizeFenceAuthority() *FinalizeFenceAuthority {
	return &FinalizeFenceAuthority{
		held: make(map[string]uint64),
		done: make(map[string]string),
	}
}

// AcquireFinalizeFence tries to acquire the finalize fence for locatorHash.
// Returns fence token on success. Fail-closed if already held (ResidualFinalizeFenceHeld).
func (a *FinalizeFenceAuthority) AcquireFinalizeFence(locatorHash string) (fence uint64, err error) {
	if a == nil {
		return 0, apperr.New(apperr.CodeInternal, "finalize fence authority nil")
	}
	lh := strings.ToLower(strings.TrimSpace(locatorHash))
	if len(lh) != 64 || !isHex(lh) {
		return 0, apperr.New(apperr.CodeInvalidArgument, "finalize fence locator_hash invalid")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.held[lh]; ok {
		return 0, apperr.New(apperr.CodePolicyDenial, ResidualFinalizeFenceHeld)
	}
	a.next++
	fence = a.next
	a.held[lh] = fence
	return fence, nil
}

// ReleaseFinalizeFence drops a held fence (e.g. after Abort). Idempotent if not held.
func (a *FinalizeFenceAuthority) ReleaseFinalizeFence(locatorHash string, fence uint64) {
	if a == nil {
		return
	}
	lh := strings.ToLower(strings.TrimSpace(locatorHash))
	a.mu.Lock()
	defer a.mu.Unlock()
	if cur, ok := a.held[lh]; ok && cur == fence {
		delete(a.held, lh)
	}
}

// CompleteFinalizeFence marks finalize complete under fence and releases hold.
// Stores digest for optional same-digest checks. Stale fence fail-closed.
func (a *FinalizeFenceAuthority) CompleteFinalizeFence(locatorHash, manifestDigest string, fence uint64) error {
	if a == nil {
		return apperr.New(apperr.CodeInternal, "finalize fence authority nil")
	}
	lh := strings.ToLower(strings.TrimSpace(locatorHash))
	md := strings.ToLower(strings.TrimSpace(manifestDigest))
	a.mu.Lock()
	defer a.mu.Unlock()
	cur, ok := a.held[lh]
	if !ok || cur != fence {
		return apperr.New(apperr.CodePolicyDenial, ResidualFinalizeFenceStale)
	}
	if a.done == nil {
		a.done = make(map[string]string)
	}
	a.done[lh] = md
	delete(a.held, lh)
	return nil
}

// IsFinalizeFenceHeld reports whether locator is currently fenced (tests/status).
func (a *FinalizeFenceAuthority) IsFinalizeFenceHeld(locatorHash string) bool {
	if a == nil {
		return false
	}
	lh := strings.ToLower(strings.TrimSpace(locatorHash))
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.held[lh]
	return ok
}
