package logmirror

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/archive"
	"github.com/simonfxr/go-jenkins-mcp/internal/store"
)

// PackSource loads sealed L1 generation metadata and compressed frame files.
// *store.Meta satisfies ChunkLister; DataDir is the profile data root.
type PackSource interface {
	GetLatestGeneration(ctx context.Context, key store.LogKey) (*store.LogGeneration, error)
	GetGenerationByID(ctx context.Context, id int64) (*store.LogGeneration, error)
	ListChunks(ctx context.Context, generationID int64) ([]store.Chunk, error)
}

// PackMarker records that a generation was published into an L2 pack (ARC-005-lite).
// Optional on PackOptions; *store.Meta implements MarkGenerationPacked.
// Never deletes L1 frames.
type PackMarker interface {
	MarkGenerationPacked(ctx context.Context, generationID int64, packID string) error
}

// PackOptions configures PackCollection / PackGenerations (ARC-005-lite / ARC-011).
type PackOptions struct {
	// PackID optional; generated when empty. For multi-batch packing, used as prefix.
	PackID string
	// AffinityGroup optional catalog metadata on PutPack.
	AffinityGroup string
	// PreferCopy copies L1 .zst frames when valid (default true).
	PreferCopy *bool
	// MemberName formats TAR paths; default logs/<job>/<build>/consoleText.
	MemberName func(key LogKey, gen *store.LogGeneration) string
	// Marker optional; after verify+PutPack, marks generation IDs packed.
	Marker PackMarker
	// Bounds optional rollover limits when packing a collection (ARC-011).
	// Zero ⇒ DefaultPackRolloverBounds when multi-batch planning is used.
	Bounds PackRolloverBounds
	// Domain optional isolation dimensions for collection packing.
	// Profile is taken from Coordinator when packing via PackCollection.
	Domain AffinityDomain
	// DisableRollover packs all sealed members into one pack (tests / forced).
	DisableRollover bool
	// Crypto optional AEAD keys for encrypted L1 frames (ARC-009).
	// When set, encrypted frames are decrypted to pure zstd for zero-recompression
	// copy into L2; L2 pack bodies are not re-encrypted in MVP.
	Crypto *store.FrameCrypto
}

// PackResult is the outcome of publishing one L2 pack.
type PackResult struct {
	PackID        string
	MemberCount   int
	GenerationIDs []int64
	// AffinityGroup is the catalog label applied to the pack.
	AffinityGroup string
	// CopiedFrames is true when at least one member used L1 frame copy.
	CopiedFrames bool
	// UsedRepack is true when compatibility recompression was used for any member.
	UsedRepack bool
	// MarkedPacked is true when Marker successfully marked all generation IDs.
	MarkedPacked bool
}

// PackCollection packs sealed members of a multi-log collection into ArchiveStore.
//
// ARC-011: groups by affinity/isolation domain and rolls over when bounds are
// exceeded (member count, uncompressed bytes, frame count). Never mixes profiles.
//
// ARC-005 journal-lite: build → verify via OpenPack → PutPack (FS: temp+rename) →
// mark generations packed. Source L1 frames are not deleted. Crash mid-way leaves L1 intact.
func (c *Coordinator) PackCollection(
	ctx context.Context,
	collectionID string,
	src PackSource,
	dataDir string,
	dest archive.ArchiveStore,
	opt PackOptions,
) (PackResult, error) {
	results, err := c.PackCollectionBatches(ctx, collectionID, src, dataDir, dest, opt)
	if err != nil {
		return PackResult{}, err
	}
	if len(results) == 0 {
		return PackResult{}, apperr.New(apperr.CodeInvalidArgument, "collection has no sealed members to pack")
	}
	// Backward-compatible single result when one batch; otherwise first batch
	// with MemberCount summed is surprising — return first and document multi API.
	if len(results) == 1 {
		return results[0], nil
	}
	// Multiple packs: return first result; callers needing all should use PackCollectionBatches.
	return results[0], nil
}

// PackCollectionBatches packs sealed collection members with affinity isolation
// and rollover, returning one PackResult per published pack.
func (c *Coordinator) PackCollectionBatches(
	ctx context.Context,
	collectionID string,
	src PackSource,
	dataDir string,
	dest archive.ArchiveStore,
	opt PackOptions,
) ([]PackResult, error) {
	if c == nil {
		return nil, apperr.New(apperr.CodeInternal, "log coordinator is not configured")
	}
	if src == nil || dest == nil {
		return nil, apperr.New(apperr.CodeInvalidArgument, "pack source and archive store are required")
	}
	sealed, err := c.SealedMembers(ctx, collectionID)
	if err != nil {
		return nil, err
	}
	if len(sealed) == 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument, "collection has no sealed members to pack")
	}

	domain := opt.Domain
	if domain.Profile == "" {
		domain.Profile = c.Profile
	}
	if domain.Profile != c.Profile {
		return nil, apperr.New(apperr.CodeInvalidArgument, "cross-profile packing is not allowed")
	}
	if domain.CollectionID == "" {
		domain.CollectionID = collectionID
	}
	if domain.AffinityGroup == "" {
		domain.AffinityGroup = opt.AffinityGroup
	}
	if domain.AffinityGroup == "" {
		domain.AffinityGroup = "collection:" + collectionID
	}

	candidates, err := loadCandidates(ctx, sealed, src, dataDir, domain)
	if err != nil {
		return nil, err
	}

	var batches []PackBatch
	if opt.DisableRollover {
		batches = []PackBatch{{
			Domain:        domain,
			AffinityGroup: domain.AffinityGroup,
			Members:       candidates,
			CollectionID:  collectionID,
		}}
		for _, m := range candidates {
			batches[0].TotalUncompressed += m.UncompressedBytes
			batches[0].TotalFrames += m.FrameCount
		}
	} else {
		batches, err = PlanPackBatches(candidates, opt.Bounds)
		if err != nil {
			return nil, err
		}
	}

	out := make([]PackResult, 0, len(batches))
	baseID := strings.TrimSpace(opt.PackID)
	for i, batch := range batches {
		if err := ctx.Err(); err != nil {
			return out, apperr.Wrap(apperr.CodeCancelled, "context cancelled", err)
		}
		keys := make([]LogKey, 0, len(batch.Members))
		for _, m := range batch.Members {
			keys = append(keys, m.Key)
		}
		batchOpt := opt
		batchOpt.AffinityGroup = batch.AffinityGroup
		if baseID != "" {
			if len(batches) == 1 {
				batchOpt.PackID = baseID
			} else {
				batchOpt.PackID = fmt.Sprintf("%s-p%d", baseID, i)
			}
		} else {
			batchOpt.PackID = ""
		}
		res, err := PackGenerations(ctx, keys, src, dataDir, dest, batchOpt)
		if err != nil {
			return out, err
		}
		out = append(out, res)
	}
	return out, nil
}

// PackGenerations packs the latest sealed generation for each key into dest.
//
// Journal-lite (ARC-005 residual tighten): assemble pack bytes → OpenPack +
// VerifyContentFrames → PutPack → optional MarkGenerationPacked. Never deletes L1.
func PackGenerations(
	ctx context.Context,
	keys []LogKey,
	src PackSource,
	dataDir string,
	dest archive.ArchiveStore,
	opt PackOptions,
) (PackResult, error) {
	if err := ctx.Err(); err != nil {
		return PackResult{}, apperr.Wrap(apperr.CodeCancelled, "context cancelled", err)
	}
	if src == nil || dest == nil {
		return PackResult{}, apperr.New(apperr.CodeInvalidArgument, "pack source and archive store are required")
	}
	if strings.TrimSpace(dataDir) == "" {
		return PackResult{}, apperr.New(apperr.CodeInvalidArgument, "data_dir is required")
	}
	if len(keys) == 0 {
		return PackResult{}, apperr.New(apperr.CodeInvalidArgument, "at least one log key is required")
	}

	// Isolation: all keys must share one profile.
	profile := keys[0].Profile
	for _, key := range keys {
		if key.Profile != profile {
			return PackResult{}, apperr.New(apperr.CodeInvalidArgument,
				"cross-profile packing is not allowed")
		}
	}

	packID := strings.TrimSpace(opt.PackID)
	if packID == "" {
		id, err := newPackID()
		if err != nil {
			return PackResult{}, err
		}
		packID = id
	}

	// ARC-011 lite: catalog affinity from member keys when caller leaves it empty.
	affinity := strings.TrimSpace(opt.AffinityGroup)
	if affinity == "" {
		affinity = AffinityGroupFromKeys(keys)
	}

	nameFn := opt.MemberName
	if nameFn == nil {
		nameFn = defaultMemberName
	}

	var (
		members   []archive.GenerationMember
		genIDs    []int64
		anyCopy   bool
		anyRepack bool
	)

	for _, key := range keys {
		if err := key.Validate(); err != nil {
			return PackResult{}, err
		}
		if err := ctx.Err(); err != nil {
			return PackResult{}, apperr.Wrap(apperr.CodeCancelled, "context cancelled", err)
		}
		g, err := src.GetLatestGeneration(ctx, key)
		if err != nil {
			return PackResult{}, err
		}
		if g == nil {
			return PackResult{}, apperr.New(apperr.CodeNotFound,
				fmt.Sprintf("no generation for %s", key.String()))
		}
		if !g.Sealed {
			return PackResult{}, apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("generation %d for %s is not sealed", g.Generation, key.String()))
		}
		member, usedCopy, err := loadGenerationMember(ctx, src, dataDir, key, g, nameFn, opt.Crypto)
		if err != nil {
			return PackResult{}, err
		}
		members = append(members, member)
		genIDs = append(genIDs, g.ID)
		if usedCopy {
			anyCopy = true
		} else {
			anyRepack = true
		}
	}

	data, st, err := archive.PackFromGenerations(members, archive.PackFromGenerationsOptions{
		PackID:        packID,
		AffinityGroup: affinity,
		PreferCopy:    opt.PreferCopy,
	})
	if err != nil {
		return PackResult{}, err
	}
	_ = st

	// Journal-lite verify before publish (never delete L1; crash here leaves L1).
	if err := ctx.Err(); err != nil {
		return PackResult{}, apperr.Wrap(apperr.CodeCancelled, "context cancelled", err)
	}
	p, err := archive.OpenPack(data)
	if err != nil {
		return PackResult{}, err
	}
	if err := p.VerifyContentFrames(); err != nil {
		p.Close()
		return PackResult{}, err
	}
	p.Close()

	if err := dest.PutPack(ctx, archive.PackDescriptor{
		PackID:        packID,
		SchemaVersion: archive.FormatVersion,
		AffinityGroup: affinity,
		Data:          data,
	}); err != nil {
		// Put failed: L1 still intact, no packed marks.
		return PackResult{}, err
	}

	marked := false
	if opt.Marker != nil {
		marked = true
		for _, id := range genIDs {
			if err := opt.Marker.MarkGenerationPacked(ctx, id, packID); err != nil {
				// Pack is published; mark failure is reported but does not roll back L2.
				// L1 remains; operator can re-mark. Do not delete L1.
				marked = false
				break
			}
		}
	}

	return PackResult{
		PackID:        packID,
		MemberCount:   len(members),
		GenerationIDs: genIDs,
		AffinityGroup: affinity,
		CopiedFrames:  anyCopy,
		UsedRepack:    anyRepack,
		MarkedPacked:  marked,
	}, nil
}

func loadCandidates(
	ctx context.Context,
	keys []LogKey,
	src PackSource,
	dataDir string,
	domain AffinityDomain,
) ([]PackCandidate, error) {
	out := make([]PackCandidate, 0, len(keys))
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return nil, apperr.Wrap(apperr.CodeCancelled, "context cancelled", err)
		}
		g, err := src.GetLatestGeneration(ctx, key)
		if err != nil {
			return nil, err
		}
		if g == nil || !g.Sealed {
			continue
		}
		chunks, err := src.ListChunks(ctx, g.ID)
		if err != nil {
			return nil, err
		}
		var raw int64
		for _, c := range chunks {
			raw += int64(c.UncompressedSize)
		}
		if raw == 0 {
			// Empty sealed log still occupies one member; estimate 0 bytes / 1 frame.
			raw = 0
		}
		fc := len(chunks)
		if fc == 0 {
			fc = 1
		}
		d := domain
		d.Profile = key.Profile
		out = append(out, PackCandidate{
			Key:               key,
			GenerationID:      g.ID,
			UncompressedBytes: raw,
			FrameCount:        fc,
			Domain:            d,
		})
	}
	return out, nil
}

func loadGenerationMember(
	ctx context.Context,
	src PackSource,
	dataDir string,
	key LogKey,
	g *store.LogGeneration,
	nameFn func(LogKey, *store.LogGeneration) string,
	crypto *store.FrameCrypto,
) (archive.GenerationMember, bool, error) {
	chunks, err := src.ListChunks(ctx, g.ID)
	if err != nil {
		return archive.GenerationMember{}, false, err
	}
	if len(chunks) == 0 {
		// Empty sealed log: still a valid empty member.
		return archive.GenerationMember{
			Name:    nameFn(key, g),
			EntryID: fmt.Sprintf("gen:%d", g.ID),
			Mode:    0o644,
			Body:    []byte{},
		}, false, nil
	}

	var (
		body    []byte
		payload [][]byte
	)
	for _, c := range chunks {
		// Pure zstd payload (decrypt AEAD envelope when present — ARC-009).
		comp, err := store.OpenFrameCompressed(dataDir, c, crypto)
		if err != nil {
			return archive.GenerationMember{}, false, apperr.Wrap(apperr.CodeCorruptCache,
				fmt.Sprintf("failed to open L1 frame seq=%d", c.Seq), err)
		}
		raw, err := store.DecompressZstdFrame(comp)
		if err != nil {
			return archive.GenerationMember{}, false, apperr.Wrap(apperr.CodeCorruptCache,
				fmt.Sprintf("failed to decompress L1 frame seq=%d", c.Seq), err)
		}
		// Prefer copy path: keep pure zstd L1 bytes. Integrity is verified by
		// archive.PackFromGenerations (decompress ≡ Body) before publish.
		payload = append(payload, comp)
		body = append(body, raw...)
	}

	return archive.GenerationMember{
		Name:          nameFn(key, g),
		EntryID:       fmt.Sprintf("gen:%d", g.ID),
		Mode:          0o644,
		Body:          body,
		PayloadFrames: payload,
	}, len(payload) > 0, nil
}

func defaultMemberName(key LogKey, _ *store.LogGeneration) string {
	// Stable, path-safe TAR name from job/build (no profile — packs may be shared
	// only within one profile data plane; profile is isolation, not path).
	job := strings.ReplaceAll(key.Job, "/", "_")
	job = strings.ReplaceAll(job, "..", "_")
	return fmt.Sprintf("logs/%s/%d/consoleText", job, key.Build)
}

func newPackID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", apperr.Wrap(apperr.CodeInternal, "failed to allocate pack id", err)
	}
	return "pack-" + hex.EncodeToString(b[:]), nil
}
