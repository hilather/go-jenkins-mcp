package fleetcache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Import status / actions (FLC-023).
const (
	ImportStatusCommitted  = "committed"
	ImportStatusIdempotent = "idempotent"
	ImportStatusRejected   = "rejected"
	ImportStatusAborted    = "aborted"

	ImportActionStart       = "start"
	ImportActionIdempotent  = "idempotent"
	ImportActionRejectStale = "reject_conflict"
)

// ImportFrameBytes is one pure-zstd frame for import (no paths, no AEAD).
type ImportFrameBytes struct {
	Seq      int
	PureZstd []byte
}

// ImportPlan is the pure decision before any disk I/O.
type ImportPlan struct {
	Action         string
	LocatorHash    string
	ManifestDigest string
	// Residual is secret-free.
	Residual string
}

// CommittedMapping is an existing local fleet object (lookup-visible only when committed).
type CommittedMapping struct {
	LocatorHash    string
	ManifestDigest string
	// GenerationID is local-only (never wire identity).
	GenerationID int64
	Status       string
}

// PlanImport decides start vs idempotent short-circuit vs conflict reject (no disk).
// Partition matrix (FLC-045): same digest converges; different digest is a visible
// conflict residual and never overwrites the committed sealed version.
func PlanImport(existing *CommittedMapping, m WireManifest) (ImportPlan, error) {
	if err := ValidateWireManifest(m); err != nil {
		return ImportPlan{Action: ImportActionRejectStale, Residual: "invalid manifest"}, err
	}
	// Ensure digest is bound.
	inner := m.ToManifestV1()
	digest, err := inner.Digest()
	if err != nil {
		return ImportPlan{}, err
	}
	if m.ManifestDigest != "" && !strings.EqualFold(m.ManifestDigest, digest) {
		return ImportPlan{Action: ImportActionRejectStale, Residual: "manifest digest mismatch"},
			apperr.New(apperr.CodeInvalidArgument, "import manifest_digest does not match content")
	}
	m.ManifestDigest = digest
	lh := strings.ToLower(strings.TrimSpace(m.LocatorHash))
	plan := ImportPlan{LocatorHash: lh, ManifestDigest: digest}

	// FLC-051: process-local tombstones block stale replica resurrection.
	if blocked, res := purgeImportTombstoneCheck(lh, digest); blocked {
		plan.Action = ImportActionRejectStale
		plan.Residual = res
		return plan, apperr.New(apperr.CodePolicyDenial, "tombstoned fleet object")
	}

	// Pure partition decision (FLC-045).
	outcome := EvaluateManifestConflict(existing, m)
	switch outcome.Action {
	case PartitionActionStart:
		plan.Action = ImportActionStart
		return plan, nil
	case PartitionActionConverge:
		plan.Action = ImportActionIdempotent
		plan.Residual = outcome.Residual // partition_duplicate_converged
		return plan, nil
	case PartitionActionConflict:
		plan.Action = ImportActionRejectStale
		plan.Residual = outcome.Residual // partition_conflict_digest
		return plan, apperr.New(apperr.CodePolicyDenial, "conflicting fleet object version")
	default:
		plan.Action = ImportActionRejectStale
		plan.Residual = outcome.Residual
		if plan.Residual == "" {
			plan.Residual = "partition reject"
		}
		return plan, apperr.New(apperr.CodePolicyDenial, "import partition reject")
	}
}

// ValidateImportFrameSubset checks each provided frame against the wire manifest
// (seq/size/hash, pure zstd only). frames may be a proper subset for resume (FLC-043).
// Empty frames is allowed (no-op validation).
func ValidateImportFrameSubset(m WireManifest, frames []ImportFrameBytes) error {
	if err := ValidateWireManifest(m); err != nil {
		return err
	}
	manBySeq := make(map[int]WireFrame, len(m.Frames))
	for _, wf := range m.Frames {
		manBySeq[wf.Seq] = wf
	}
	seen := make(map[int]struct{}, len(frames))
	for _, f := range frames {
		if f.Seq < 0 {
			return apperr.New(apperr.CodeInvalidArgument, "import frame seq negative")
		}
		if _, dup := seen[f.Seq]; dup {
			return apperr.New(apperr.CodeInvalidArgument, "import duplicate frame seq")
		}
		seen[f.Seq] = struct{}{}
		wf, ok := manBySeq[f.Seq]
		if !ok {
			return apperr.New(apperr.CodeInvalidArgument, "import frame seq not in manifest")
		}
		if len(f.PureZstd) == 0 {
			return apperr.New(apperr.CodeInvalidArgument, "import frame empty")
		}
		if int64(len(f.PureZstd)) > MaxZstdFrameBytes {
			return apperr.New(apperr.CodeQuota, "import frame exceeds max zstd size")
		}
		// Reject AEAD magic (JME1) — wire must be pure zstd.
		if len(f.PureZstd) >= 4 && string(f.PureZstd[:4]) == "JME1" {
			return apperr.New(apperr.CodeInvalidArgument, "import frame must not be AEAD envelope")
		}
		if int64(len(f.PureZstd)) != wf.ZstdSize {
			return apperr.New(apperr.CodeCorruptCache, "import zstd size mismatch")
		}
		sum := sha256HexBytes(f.PureZstd)
		if !strings.EqualFold(sum, wf.ZstdSHA256) {
			return apperr.New(apperr.CodeCorruptCache, "import zstd sha256 mismatch")
		}
	}
	return nil
}

// ValidateImportFrames checks frame count/seq/size/hash against the wire manifest
// without decoding (cheap reject). Requires a complete frame set (not resume subset).
// Does not accept peer paths.
func ValidateImportFrames(m WireManifest, frames []ImportFrameBytes) error {
	if err := ValidateWireManifest(m); err != nil {
		return err
	}
	if len(frames) != len(m.Frames) {
		return apperr.New(apperr.CodeInvalidArgument, "import frame count mismatch")
	}
	if err := ValidateImportFrameSubset(m, frames); err != nil {
		return err
	}
	bySeq := make(map[int]struct{}, len(frames))
	for _, f := range frames {
		bySeq[f.Seq] = struct{}{}
	}
	for _, wf := range m.Frames {
		if _, ok := bySeq[wf.Seq]; !ok {
			return apperr.New(apperr.CodeInvalidArgument, "import missing frame seq")
		}
	}
	return nil
}

// ImportSink is implemented by the local store for staged peer import (FLC-023).
// Implementations must not publish lookup-visible mapping until Commit succeeds.
type ImportSink interface {
	// GetCommitted returns the committed mapping for locator or ok=false.
	GetCommitted(ctx context.Context, locatorHash string) (CommittedMapping, bool, error)
	// Begin starts a staging import and allocates a local generation (not sealed).
	Begin(ctx context.Context, m WireManifest) (importID, generationID int64, err error)
	// WriteFrame stages one verified pure-zstd frame into the local generation.
	WriteFrame(ctx context.Context, importID, generationID int64, wf WireFrame, pureZstd []byte) error
	// Commit seals the generation and publishes locator mapping (atomic visibility).
	Commit(ctx context.Context, importID, generationID int64, m WireManifest) error
	// Abort marks the import aborted and leaves no lookup-visible mapping.
	Abort(ctx context.Context, importID int64) error
}

// StagingLookupSink is an optional ImportSink capability for RF2 resume (FLC-043).
// When implemented, ReplicateSealed can continue an interrupted staging import and
// transfer only missing frames (FramesTransferred = missing count only).
type StagingLookupSink interface {
	ImportSink
	// GetStaging returns the latest open staging import for locator+digest.
	// presentSeqs lists durable frame sequences already written (manifest order not required).
	// ok=false means no staging row (caller must Begin a full import).
	GetStaging(ctx context.Context, locatorHash, manifestDigest string) (
		importID, generationID int64, presentSeqs []int, ok bool, err error)
}

// ImportResult is the outcome of RunImport (secret-free).
type ImportResult struct {
	Status         string
	LocatorHash    string
	ManifestDigest string
	// GenerationID is local-only; 0 when not allocated.
	GenerationID int64
	ImportID     int64
	Residual     string
}

// RunImport validates, plans, stages frames, and commits — or aborts on failure.
// Incomplete imports never become lookup hits (sink must enforce).
func RunImport(ctx context.Context, sink ImportSink, m WireManifest, frames []ImportFrameBytes) (ImportResult, error) {
	if sink == nil {
		return ImportResult{Status: ImportStatusRejected, Residual: "import sink nil"},
			apperr.New(apperr.CodeInternal, "import sink nil")
	}
	if err := ctx.Err(); err != nil {
		return ImportResult{Status: ImportStatusAborted, Residual: "cancelled"}, err
	}
	if err := ValidateImportFrames(m, frames); err != nil {
		return ImportResult{Status: ImportStatusRejected, Residual: "frame validation failed"}, err
	}
	// Normalize digest.
	inner := m.ToManifestV1()
	digest, err := inner.Digest()
	if err != nil {
		return ImportResult{Status: ImportStatusRejected}, err
	}
	m.ManifestDigest = digest
	m.LocatorHash = strings.ToLower(strings.TrimSpace(m.LocatorHash))

	existing, ok, err := sink.GetCommitted(ctx, m.LocatorHash)
	if err != nil {
		return ImportResult{Status: ImportStatusRejected, Residual: "mapping lookup failed"}, err
	}
	var existingPtr *CommittedMapping
	if ok {
		existingPtr = &existing
	}
	plan, err := PlanImport(existingPtr, m)
	if err != nil && plan.Action == ImportActionRejectStale {
		return ImportResult{
			Status: ImportStatusRejected, LocatorHash: plan.LocatorHash,
			ManifestDigest: plan.ManifestDigest, Residual: plan.Residual,
		}, err
	}
	if plan.Action == ImportActionIdempotent {
		return ImportResult{
			Status: ImportStatusIdempotent, LocatorHash: plan.LocatorHash,
			ManifestDigest: plan.ManifestDigest, GenerationID: existing.GenerationID,
			Residual: plan.Residual,
		}, nil
	}

	importID, genID, err := sink.Begin(ctx, m)
	if err != nil {
		return ImportResult{Status: ImportStatusRejected, Residual: "begin failed"}, err
	}
	// Ordered by manifest frame sequence.
	bySeq := make(map[int][]byte, len(frames))
	for _, f := range frames {
		bySeq[f.Seq] = f.PureZstd
	}
	for _, wf := range m.Frames {
		if err := ctx.Err(); err != nil {
			_ = sink.Abort(ctx, importID)
			return ImportResult{Status: ImportStatusAborted, ImportID: importID, GenerationID: genID, Residual: "cancelled"}, err
		}
		pure := bySeq[wf.Seq]
		if err := sink.WriteFrame(ctx, importID, genID, wf, pure); err != nil {
			_ = sink.Abort(ctx, importID)
			return ImportResult{
				Status: ImportStatusAborted, ImportID: importID, GenerationID: genID,
				LocatorHash: m.LocatorHash, ManifestDigest: m.ManifestDigest,
				Residual: "frame write failed",
			}, err
		}
	}
	if err := sink.Commit(ctx, importID, genID, m); err != nil {
		_ = sink.Abort(ctx, importID)
		return ImportResult{
			Status: ImportStatusAborted, ImportID: importID, GenerationID: genID,
			LocatorHash: m.LocatorHash, ManifestDigest: m.ManifestDigest,
			Residual: "commit failed",
		}, err
	}
	return ImportResult{
		Status: ImportStatusCommitted, LocatorHash: m.LocatorHash,
		ManifestDigest: m.ManifestDigest, GenerationID: genID, ImportID: importID,
	}, nil
}

// DigestWireManifest returns the sealed manifest digest (helper for tests/callers).
func DigestWireManifest(m WireManifest) (string, error) {
	if err := ValidateWireManifest(m); err != nil {
		return "", err
	}
	return m.ToManifestV1().Digest()
}

// ContentSHA256Hex is lowercase hex SHA-256 of uncompressed content.
func ContentSHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
