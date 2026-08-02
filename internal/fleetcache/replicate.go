package fleetcache

import (
	"context"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// ReplicateResult is a secret-free outcome of one RF2 transfer into a sink.
type ReplicateResult struct {
	Status         string // committed | idempotent | aborted | rejected | skipped
	LocatorHash    string
	ManifestDigest string
	// FramesTransferred counts pure-zstd frames written this call (0 on skip/idempotent).
	// On resume (missing_frames), equals the number of still-missing frames written — not total.
	FramesTransferred int
	// GenerationID local on receiver when committed.
	GenerationID int64
	Residual     string
}

// ReplicateSealed transfers pure-zstd frames into sink with atomic commit (FLC-043).
//
// Behaviour:
//   - Matching committed digest → idempotent, FramesTransferred=0.
//   - Open staging import (StagingLookupSink) → write only frames still missing;
//     FramesTransferred equals the missing count actually written this call.
//   - No staging → requires a complete frame set (ValidateImportFrames), Begin+write all.
//
// Wire path: pure zstd only (caller exports via ExportPureZstd); receiver re-wraps locally.
// No FanOut — caller selects a single sink target from PlanRF2Replication.
func ReplicateSealed(ctx context.Context, sink ImportSink, m WireManifest, frames []ImportFrameBytes) (ReplicateResult, error) {
	if sink == nil {
		return ReplicateResult{Status: ImportStatusRejected, Residual: "sink nil"},
			apperr.New(apperr.CodeInternal, "replicate sink nil")
	}
	if err := ctx.Err(); err != nil {
		return ReplicateResult{Status: ImportStatusAborted, Residual: "cancelled"}, err
	}
	if err := ValidateWireManifest(m); err != nil {
		return ReplicateResult{Status: ImportStatusRejected, Residual: "invalid manifest"}, err
	}
	digest, err := DigestWireManifest(m)
	if err != nil {
		return ReplicateResult{Status: ImportStatusRejected}, err
	}
	m.ManifestDigest = digest
	m.LocatorHash = strings.ToLower(strings.TrimSpace(m.LocatorHash))

	// FLC-051: tombstone blocks stale replica resurrection (before converge/resume).
	if blocked, res := purgeImportTombstoneCheck(m.LocatorHash, digest); blocked {
		return ReplicateResult{
			Status: ImportStatusRejected, LocatorHash: m.LocatorHash,
			ManifestDigest: digest, Residual: res,
		}, apperr.New(apperr.CodePolicyDenial, "tombstoned fleet object")
	}

	// Partition matrix (FLC-045): same digest converges (idempotent, 0 frames);
	// different committed digest is conflict residual — never overwrite / never transfer.
	existing, ok, err := sink.GetCommitted(ctx, m.LocatorHash)
	if err != nil {
		return ReplicateResult{Status: ImportStatusRejected, Residual: "lookup failed"}, err
	}
	if ok {
		var existingPtr *CommittedMapping
		e := existing
		existingPtr = &e
		outcome := EvaluateManifestConflict(existingPtr, m)
		switch outcome.Action {
		case PartitionActionConverge:
			return ReplicateResult{
				Status: ImportStatusIdempotent, LocatorHash: m.LocatorHash,
				ManifestDigest: digest, GenerationID: existing.GenerationID,
				FramesTransferred: 0, Residual: PartitionResidualDuplicateConverged,
			}, nil
		case PartitionActionConflict:
			return ReplicateResult{
				Status: ImportStatusRejected, LocatorHash: m.LocatorHash,
				ManifestDigest: digest, Residual: PartitionResidualConflictDigest,
			}, apperr.New(apperr.CodePolicyDenial, "conflicting fleet object version")
		}
	}

	// Resume path: open staging with durable present seqs.
	var (
		importID, genID int64
		present         []int
		resuming        bool
	)
	if sl, ok := sink.(StagingLookupSink); ok {
		id, gen, seqs, found, gerr := sl.GetStaging(ctx, m.LocatorHash, digest)
		if gerr != nil {
			return ReplicateResult{Status: ImportStatusRejected, Residual: "staging lookup failed"}, gerr
		}
		if found {
			importID, genID, present, resuming = id, gen, seqs, true
		}
	}

	missing := MissingFrameSeqs(m, present)
	// Only frames still needed are eligible for transfer this call.
	toWrite := FilterImportFrames(frames, missing)
	if err := ValidateImportFrameSubset(m, toWrite); err != nil {
		return ReplicateResult{
			Status: ImportStatusRejected, LocatorHash: m.LocatorHash,
			ManifestDigest: digest, Residual: "frame validation failed",
		}, err
	}

	// Coverage: every missing seq must be present in the transfer set.
	haveWrite := make(map[int]struct{}, len(toWrite))
	for _, f := range toWrite {
		haveWrite[f.Seq] = struct{}{}
	}
	for _, seq := range missing {
		if _, ok := haveWrite[seq]; !ok {
			// Initial full import without staging still requires the complete set.
			if !resuming {
				return ReplicateResult{
					Status: ImportStatusRejected, LocatorHash: m.LocatorHash,
					ManifestDigest: digest, Residual: "incomplete_frame_set",
				}, apperr.New(apperr.CodeInvalidArgument, "replicate requires full sealed frame set for atomic commit")
			}
			return ReplicateResult{
				Status: ImportStatusRejected, LocatorHash: m.LocatorHash,
				ManifestDigest: digest, Residual: "incomplete_missing_set",
			}, apperr.New(apperr.CodeInvalidArgument, "replicate resume missing frames incomplete")
		}
	}

	if !resuming {
		// Fresh import: Begin then write all missing (= full set when present empty).
		importID, genID, err = sink.Begin(ctx, m)
		if err != nil {
			return ReplicateResult{Status: ImportStatusRejected, Residual: "begin failed"}, err
		}
	}

	// Staging already complete (all frames durable) — commit only, zero transfer.
	if len(missing) == 0 {
		if err := sink.Commit(ctx, importID, genID, m); err != nil {
			_ = sink.Abort(ctx, importID)
			return ReplicateResult{
				Status: ImportStatusAborted, LocatorHash: m.LocatorHash,
				ManifestDigest: digest, GenerationID: genID, Residual: "commit failed",
			}, err
		}
		return ReplicateResult{
			Status: ImportStatusCommitted, LocatorHash: m.LocatorHash,
			ManifestDigest: digest, GenerationID: genID, FramesTransferred: 0,
			Residual: "staging_commit_only",
		}, nil
	}

	bySeq := make(map[int][]byte, len(toWrite))
	for _, f := range toWrite {
		bySeq[f.Seq] = f.PureZstd
	}
	written := 0
	for _, wf := range m.Frames {
		if _, need := haveWrite[wf.Seq]; !need {
			continue
		}
		if err := ctx.Err(); err != nil {
			// Leave staging open for resume (do not Abort) so PresentSeqs remain durable.
			return ReplicateResult{
				Status: ImportStatusAborted, LocatorHash: m.LocatorHash,
				ManifestDigest: digest, GenerationID: genID,
				FramesTransferred: written, Residual: "cancelled",
			}, err
		}
		pure := bySeq[wf.Seq]
		if err := sink.WriteFrame(ctx, importID, genID, wf, pure); err != nil {
			// Leave staging open for honest resume of remaining frames.
			return ReplicateResult{
				Status: ImportStatusAborted, LocatorHash: m.LocatorHash,
				ManifestDigest: digest, GenerationID: genID,
				FramesTransferred: written, Residual: "frame write failed",
			}, err
		}
		written++
	}
	if err := sink.Commit(ctx, importID, genID, m); err != nil {
		return ReplicateResult{
			Status: ImportStatusAborted, LocatorHash: m.LocatorHash,
			ManifestDigest: digest, GenerationID: genID,
			FramesTransferred: written, Residual: "commit failed",
		}, err
	}
	return ReplicateResult{
		Status: ImportStatusCommitted, LocatorHash: m.LocatorHash,
		ManifestDigest: digest, GenerationID: genID, FramesTransferred: written,
		Residual: residualResume(resuming),
	}, nil
}

func residualResume(resuming bool) string {
	if resuming {
		return "resume_missing_frames"
	}
	return ""
}

// ReplicateWave applies a pure plan to multiple sinks (memberID → sink).
// For missing_frames targets, only FilterImportFrames(allFrames, MissingSeqs) is transferred.
// Full import / quarantine targets receive the full frame set.
// Concurrent callers should serialize per locator on the caller side.
func ReplicateWave(
	ctx context.Context,
	plan ReplicatePlan,
	manifest WireManifest,
	allFrames []ImportFrameBytes,
	sinks map[string]ImportSink,
) (map[string]ReplicateResult, error) {
	if plan.LocatorHash == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "replicate plan empty")
	}
	out := make(map[string]ReplicateResult, len(plan.Targets))
	for _, t := range plan.Targets {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if t.Action == ReplicaActionSkipVerified {
			out[t.MemberID] = ReplicateResult{
				Status: "skipped", LocatorHash: plan.LocatorHash,
				ManifestDigest: plan.ManifestDigest, FramesTransferred: 0,
				Residual: t.Residual,
			}
			continue
		}
		sink := sinks[t.MemberID]
		if sink == nil {
			out[t.MemberID] = ReplicateResult{
				Status: ImportStatusRejected, Residual: "sink_missing",
				LocatorHash: plan.LocatorHash, ManifestDigest: plan.ManifestDigest,
			}
			continue
		}
		var transfer []ImportFrameBytes
		switch t.Action {
		case ReplicaActionMissingFrames:
			// Honest resume: send only planned missing sequences.
			transfer = FilterImportFrames(allFrames, t.MissingSeqs)
		default:
			// full_import / quarantined_replace — complete set for atomic first commit.
			transfer = allFrames
		}
		res, err := ReplicateSealed(ctx, sink, manifest, transfer)
		out[t.MemberID] = res
		if err != nil && res.Status != ImportStatusIdempotent {
			// Continue other targets; aggregate error only if all fail is caller's choice.
			continue
		}
	}
	return out, nil
}
