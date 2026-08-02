package fleetcache

import (
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Partition residual codes (FLC-045) — low-cardinality, secret-free.
// Used by pure evaluators and by PlanImport / ReplicateSealed conflict paths.
const (
	// PartitionResidualSameDigest: candidate equals committed sealed version (pre-converge).
	PartitionResidualSameDigest = "partition_same_digest"
	// PartitionResidualConflictDigest: candidate differs from committed; do not overwrite.
	PartitionResidualConflictDigest = "partition_conflict_digest"
	// PartitionResidualStaleFence: fence token does not match expected lease fence.
	PartitionResidualStaleFence = "partition_stale_fence"
	// PartitionResidualStaleEpoch: lease already completed (or superseded); stale completion rejected.
	PartitionResidualStaleEpoch = "partition_stale_epoch"
	// PartitionResidualDuplicateConverged: identical duplicate fill converged (no extra copy).
	PartitionResidualDuplicateConverged = "partition_duplicate_converged"
	// PartitionResidualMixedFramesRejected: frames do not all belong to one wire manifest.
	PartitionResidualMixedFramesRejected = "partition_mixed_frames_rejected"
	// PartitionResidualNoCommitted: no committed mapping yet (safe start).
	PartitionResidualNoCommitted = "partition_no_committed"
)

// Partition decision actions (secret-free).
const (
	// PartitionActionStart — no committed sealed version; import may proceed.
	PartitionActionStart = "start"
	// PartitionActionConverge — same digest; idempotent / no extra persisted copy.
	PartitionActionConverge = "converge"
	// PartitionActionConflict — different digest; reject; keep committed; residual visible.
	PartitionActionConflict = "conflict"
	// PartitionActionReject — fail-closed (stale fence/epoch, mixed frames).
	PartitionActionReject = "reject"
)

// PartitionOutcome is a pure decision for partition / duplicate-fill / conflict (FLC-045).
// Secret-free: digests and residual codes only — never tokens or credentials.
type PartitionOutcome struct {
	Action          string
	Residual        string
	ExistingDigest  string
	CandidateDigest string
}

// EvaluateDuplicateFill compares an existing committed digest with a candidate fill.
// Same digest → converge/idempotent (no silent extra copies). Different → conflict residual
// (do not overwrite). Empty existing → start.
func EvaluateDuplicateFill(existingDigest, candidateDigest string) PartitionOutcome {
	existingDigest = strings.ToLower(strings.TrimSpace(existingDigest))
	candidateDigest = strings.ToLower(strings.TrimSpace(candidateDigest))
	out := PartitionOutcome{
		ExistingDigest:  existingDigest,
		CandidateDigest: candidateDigest,
	}
	if existingDigest == "" {
		out.Action = PartitionActionStart
		out.Residual = PartitionResidualNoCommitted
		return out
	}
	if candidateDigest == "" {
		out.Action = PartitionActionReject
		out.Residual = PartitionResidualConflictDigest
		return out
	}
	if strings.EqualFold(existingDigest, candidateDigest) {
		out.Action = PartitionActionConverge
		out.Residual = PartitionResidualDuplicateConverged
		return out
	}
	out.Action = PartitionActionConflict
	out.Residual = PartitionResidualConflictDigest
	return out
}

// EvaluateStaleFence fails closed when provided fence does not match expected.
// Matching fences return nil. Used by fill-lease Complete semantics and matrix tests.
func EvaluateStaleFence(expected, provided uint64) error {
	if expected != provided {
		return apperr.New(apperr.CodePolicyDenial, PartitionResidualStaleFence)
	}
	return nil
}

// EvaluateStaleEpoch fails closed when a completed lease/epoch rejects a stale completion
// attempt (wrong fence after completion, or completed with a different fence).
// completed=false and matching fence → ok. completed=true with matching fence → idempotent ok.
// completed=true with wrong fence → stale epoch residual.
func EvaluateStaleEpoch(completed bool, completedFence, providedFence uint64) error {
	if !completed {
		return EvaluateStaleFence(completedFence, providedFence)
	}
	if completedFence == providedFence {
		return nil // idempotent same-fence complete
	}
	return apperr.New(apperr.CodePolicyDenial, PartitionResidualStaleEpoch)
}

// EvaluateManifestConflict decides start / converge / conflict for a committed mapping
// vs a candidate wire manifest. Never merges frames across manifests (caller must still
// validate frames against the candidate only via AssertFramesSameManifest / ValidateImportFrames).
func EvaluateManifestConflict(committed *CommittedMapping, candidate WireManifest) PartitionOutcome {
	digest, err := DigestWireManifest(candidate)
	if err != nil {
		// Fall back to declared digest if validation failed (still secret-free residual).
		digest = strings.ToLower(strings.TrimSpace(candidate.ManifestDigest))
		if digest == "" {
			return PartitionOutcome{
				Action:   PartitionActionReject,
				Residual: "invalid manifest",
			}
		}
	}
	digest = strings.ToLower(strings.TrimSpace(digest))
	if committed == nil || !strings.EqualFold(strings.TrimSpace(committed.Status), "committed") {
		return PartitionOutcome{
			Action:          PartitionActionStart,
			Residual:        PartitionResidualNoCommitted,
			CandidateDigest: digest,
		}
	}
	existing := strings.ToLower(strings.TrimSpace(committed.ManifestDigest))
	out := EvaluateDuplicateFill(existing, digest)
	// Normalize same-digest residual for manifest path: same sealed version language.
	if out.Action == PartitionActionConverge {
		out.Residual = PartitionResidualDuplicateConverged
	}
	return out
}

// AssertFramesSameManifest rejects mixed frame sets that do not belong to a single wire
// manifest (hash/seq/size fail closed). Never silently merges frames from different manifests.
// Implementation reuses ValidateImportFrames (complete set) so mixed seq hashes fail closed.
func AssertFramesSameManifest(m WireManifest, frames []ImportFrameBytes) error {
	if err := ValidateImportFrames(m, frames); err != nil {
		return apperr.Wrap(apperr.CodeCorruptCache, PartitionResidualMixedFramesRejected, err)
	}
	return nil
}

// PartitionHonestyResidual documents split-primary duplicate-origin safety (secret-free).
// Split primaries may each fill origin once; sealed publish remains idempotent by digest
// and conflicts never silently overwrite. Metrics catalog emit is residual FLC-061.
func PartitionHonestyResidual() string {
	return PartitionResidualNote + "; FLC-045 partition matrix Done*; metrics residual FLC-061; repair/drain residual FLC-044"
}
