package logmirror

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/archive"
	"github.com/simonfxr/go-jenkins-mcp/internal/store"
)

// DefaultFullVerifyMaxPackBytes: packs at or under this size get full VerifyPack
// before L1 release; larger packs get OpenPack + sample member range read.
const DefaultFullVerifyMaxPackBytes int64 = 4 << 20

// PackEntryID returns the TAR entry id used when packing a generation.
func PackEntryID(generationID int64) string {
	return fmt.Sprintf("gen:%d", generationID)
}

// VerifyPackForRelease implements store.PackVerifier using on-disk L2 packs.
// Small packs: full VerifyPackFile. Larger packs: OpenPack + sample ReadMemberRange.
// Never quarantines or deletes packs (safe for release dual-check).
func VerifyPackForRelease(archiveRoot string) store.PackVerifier {
	return func(ctx context.Context, packID string, g *store.LogGeneration) error {
		return verifyPackForRelease(ctx, archiveRoot, packID, g, DefaultFullVerifyMaxPackBytes)
	}
}

func verifyPackForRelease(
	ctx context.Context,
	archiveRoot, packID string,
	g *store.LogGeneration,
	fullMax int64,
) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "pack verify cancelled", err)
	}
	packID = strings.TrimSpace(packID)
	if packID == "" {
		return apperr.New(apperr.CodeInvalidArgument, "pack_id is required")
	}
	root := filepath.Clean(strings.TrimSpace(archiveRoot))
	if root == "" || root == "." {
		return apperr.New(apperr.CodeInternal, "archive root is not configured")
	}
	packPath := filepath.Join(root, packID+".tar.zst")
	st, err := os.Stat(packPath)
	if err != nil {
		if os.IsNotExist(err) {
			return apperr.New(apperr.CodeNotFound, "pack not found")
		}
		return apperr.Wrap(apperr.CodeInternal, "failed to stat pack", err)
	}
	if fullMax <= 0 {
		fullMax = DefaultFullVerifyMaxPackBytes
	}
	if st.Size() <= fullMax {
		// Full verify for small packs (no quarantine on release path).
		rep, verr := archive.VerifyPackFile(ctx, packID, packPath, root, false)
		if verr != nil {
			return verr
		}
		if !rep.PackOK {
			return apperr.New(apperr.CodeCorruptCache, "pack verify did not pass")
		}
		return nil
	}
	// Sample path: open pack + read a small range of the generation member.
	data, err := os.ReadFile(packPath)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to read pack", err)
	}
	p, err := archive.OpenPack(data)
	if err != nil {
		return err
	}
	defer p.Close()
	entryID := PackEntryID(g.ID)
	// Prefer member name fallback if entry id missing (defensive).
	if _, ok := p.SeekTable().FindMember(entryID); !ok {
		name := defaultMemberName(LogKey{Profile: g.Profile, Job: g.Job, Build: g.Build}, g)
		if _, ok2 := p.SeekTable().FindMember(name); ok2 {
			entryID = name
		}
	}
	// Sample first up to 4 KiB (or empty member).
	_, _, _, err = p.ReadMemberRange(ctx, entryID, 0, 4096)
	return err
}

// ReadRangeFromPack reads [start, start+length) of a generation's pack member.
// archiveRoot is the profile archives/ directory.
func ReadRangeFromPack(
	ctx context.Context,
	archiveRoot string,
	g *store.LogGeneration,
	start, length int64,
) (store.ReadResult, error) {
	res := store.ReadResult{
		Generation:     g.Generation,
		GenerationID:   g.ID,
		RequestedBytes: length,
		RawStart:       start,
		Sealed:         g.Sealed,
	}
	if err := ctx.Err(); err != nil {
		return res, apperr.Wrap(apperr.CodeCancelled, "context cancelled", err)
	}
	if g == nil {
		return res, apperr.New(apperr.CodeInvalidArgument, "generation is nil")
	}
	if strings.TrimSpace(g.PackedPackID) == "" {
		return res, apperr.New(apperr.CodeNotFound, "generation has no packed_pack_id")
	}
	if start < 0 || length < 0 {
		return res, apperr.New(apperr.CodeInvalidArgument, "offset and length must be non-negative")
	}
	p, err := openPackFile(archiveRoot, g.PackedPackID)
	if err != nil {
		return res, err
	}
	defer p.Close()

	entryID := PackEntryID(g.ID)
	if _, ok := p.SeekTable().FindMember(entryID); !ok {
		name := defaultMemberName(LogKey{Profile: g.Profile, Job: g.Job, Build: g.Build}, g)
		if _, ok2 := p.SeekTable().FindMember(name); ok2 {
			entryID = name
		}
	}
	data, meta, stats, err := p.ReadMemberRange(ctx, entryID, start, length)
	if err != nil {
		return res, err
	}
	res.Data = data
	res.RawEnd = start + int64(len(data))
	res.DecompressedBytes = stats.DecompressedBytes
	res.FramesOpened = stats.FramesOpened
	if meta.ContentSHA256 != "" {
		res.ContentSHA256 = []string{meta.ContentSHA256}
	}
	return res, nil
}

// TailBytesFromPack returns the last n bytes of the pack member body.
func TailBytesFromPack(
	ctx context.Context,
	archiveRoot string,
	g *store.LogGeneration,
	n int64,
) (store.ReadResult, error) {
	if n < 0 {
		return store.ReadResult{}, apperr.New(apperr.CodeInvalidArgument, "n must be non-negative")
	}
	if g == nil {
		return store.ReadResult{}, apperr.New(apperr.CodeInvalidArgument, "generation is nil")
	}
	p, err := openPackFile(archiveRoot, g.PackedPackID)
	if err != nil {
		return store.ReadResult{}, err
	}
	defer p.Close()
	entryID := PackEntryID(g.ID)
	m, ok := p.SeekTable().FindMember(entryID)
	if !ok {
		name := defaultMemberName(LogKey{Profile: g.Profile, Job: g.Job, Build: g.Build}, g)
		m, ok = p.SeekTable().FindMember(name)
		if ok {
			entryID = name
		}
	}
	if !ok {
		return store.ReadResult{}, apperr.New(apperr.CodeNotFound, "archive entry not found")
	}
	size := m.Size
	if size == 0 || n == 0 {
		return store.ReadResult{
			Generation: g.Generation, GenerationID: g.ID,
			RequestedBytes: n, Sealed: g.Sealed,
		}, nil
	}
	start := size - n
	if start < 0 {
		start = 0
	}
	return ReadRangeFromPack(ctx, archiveRoot, g, start, size-start)
}

func openPackFile(archiveRoot, packID string) (*archive.Pack, error) {
	packID = strings.TrimSpace(packID)
	if packID == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "pack_id is required")
	}
	if strings.Contains(packID, "..") || strings.ContainsAny(packID, `/\`) {
		return nil, apperr.New(apperr.CodeInvalidArgument, "pack_id must be a single path segment")
	}
	root := filepath.Clean(strings.TrimSpace(archiveRoot))
	if root == "" || root == "." {
		return nil, apperr.New(apperr.CodeInternal, "archive root is not configured")
	}
	path := filepath.Join(root, packID+".tar.zst")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, apperr.New(apperr.CodeNotFound, "pack not found")
		}
		return nil, apperr.Wrap(apperr.CodeInternal, "failed to read pack", err)
	}
	return archive.OpenPack(data)
}
