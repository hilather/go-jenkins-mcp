package archive

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// FSStore is a filesystem-backed ArchiveStore for integration-style tests.
// Packs are stored as <root>/<packID>.tar.zst with sibling <packID>.idx.json
// indexes (ARC-006). Paths are never exposed via EntryMetadata or Capabilities.
type FSStore struct {
	mu       sync.Mutex
	root     string
	maxRange int64
	mem      *MemoryStore // catalog + validation reuse after load
}

// NewFSStore creates a store under root (created if needed).
func NewFSStore(root string, opts ...MemoryOption) (*FSStore, error) {
	root = filepath.Clean(strings.TrimSpace(root))
	if root == "" || root == "." {
		return nil, apperr.New(apperr.CodeInvalidArgument, "store root is required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "failed to create archive store dir", err)
	}
	return &FSStore{
		root:     root,
		maxRange: DefaultMaxRangeBytes,
		mem:      NewMemoryStore(opts...),
	}, nil
}

// Root returns the store root directory (for diagnostics/quarantine; not MCP-visible).
func (s *FSStore) Root() string {
	if s == nil {
		return ""
	}
	return s.root
}

// Capabilities implements RangeStore (no path leakage).
func (s *FSStore) Capabilities() Capabilities {
	c := s.mem.Capabilities()
	c.Name = "filesystem"
	return c
}

func (s *FSStore) packPath(packID string) (string, error) {
	id := strings.TrimSpace(packID)
	if id == "" {
		return "", apperr.New(apperr.CodeInvalidArgument, "pack_id is required")
	}
	if strings.Contains(id, "..") || strings.ContainsAny(id, `/\`) {
		return "", apperr.New(apperr.CodeInvalidArgument, "pack_id must be a single path segment")
	}
	return filepath.Join(s.root, id+".tar.zst"), nil
}

// PutPack writes pack bytes to disk after validation, then builds a sibling index.
// Journal-lite: write temp → validate via OpenPack → atomic rename → index.
// Serialized: concurrent PutPack calls share neither the temp path nor the
// catalog update (the temp name is also unpredictable, so even a cross-process
// collision cannot interleave writes).
func (s *FSStore) PutPack(ctx context.Context, pack PackDescriptor) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "context cancelled", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Validate + catalog in memory first (OpenPack + VerifyContentFrames).
	if err := s.mem.PutPack(ctx, pack); err != nil {
		return err
	}
	path, err := s.packPath(pack.PackID)
	if err != nil {
		_ = s.mem.DeletePack(ctx, ArchiveRef{PackID: pack.PackID})
		return err
	}
	tmp, err := os.CreateTemp(s.root, ".pack-*.tmp")
	if err != nil {
		_ = s.mem.DeletePack(ctx, ArchiveRef{PackID: pack.PackID})
		return apperr.Wrap(apperr.CodeInternal, "failed to stage pack", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(pack.Data); err != nil {
		_ = tmp.Close()
		_ = s.mem.DeletePack(ctx, ArchiveRef{PackID: pack.PackID})
		return apperr.Wrap(apperr.CodeInternal, "failed to write pack", err)
	}
	if err := tmp.Close(); err != nil {
		_ = s.mem.DeletePack(ctx, ArchiveRef{PackID: pack.PackID})
		return apperr.Wrap(apperr.CodeInternal, "failed to write pack", err)
	}
	// Re-open from temp before publish (journal-lite verify step).
	p, err := OpenPack(pack.Data)
	if err != nil {
		_ = s.mem.DeletePack(ctx, ArchiveRef{PackID: pack.PackID})
		return err
	}
	if err := p.VerifyContentFrames(); err != nil {
		p.Close()
		_ = s.mem.DeletePack(ctx, ArchiveRef{PackID: pack.PackID})
		return err
	}
	st := p.SeekTable()
	p.Close()

	if err := os.Rename(tmpName, path); err != nil {
		_ = s.mem.DeletePack(ctx, ArchiveRef{PackID: pack.PackID})
		return apperr.Wrap(apperr.CodeInternal, "failed to publish pack", err)
	}

	// Sidecar index off critical path of reads — built at publish time.
	// Failure to write index does not roll back the pack; flag rebuild-needed.
	idx, err := BuildIndexFromPack(pack.PackID, pack.AffinityGroup, pack.Data, st)
	if err == nil {
		if werr := WriteIndexFile(IndexPath(path), idx); werr == nil {
			s.mem.setIndexStatus(pack.PackID, true, false)
		} else {
			s.mem.setIndexStatus(pack.PackID, false, true)
		}
	} else {
		s.mem.setIndexStatus(pack.PackID, false, true)
	}
	return nil
}

// OpenEntry implements ArchiveStore.
func (s *FSStore) OpenEntry(ctx context.Context, ref ArchiveRef) (io.ReadCloser, EntryMetadata, error) {
	if err := s.ensureLoaded(ctx, ref.PackID); err != nil {
		return nil, EntryMetadata{}, err
	}
	return s.mem.OpenEntry(ctx, ref)
}

// OpenRange implements RangeStore.
func (s *FSStore) OpenRange(ctx context.Context, ref ArchiveRef, offset, length int64) (io.ReadCloser, EntryMetadata, error) {
	if err := s.ensureLoaded(ctx, ref.PackID); err != nil {
		return nil, EntryMetadata{}, err
	}
	return s.mem.OpenRange(ctx, ref, offset, length)
}

// Verify implements ArchiveStore.
func (s *FSStore) Verify(ctx context.Context, ref ArchiveRef) error {
	if err := s.ensureLoaded(ctx, ref.PackID); err != nil {
		return err
	}
	return s.mem.Verify(ctx, ref)
}

// DeletePack removes disk file, sibling index, and catalog entry.
func (s *FSStore) DeletePack(ctx context.Context, ref ArchiveRef) error {
	path, err := s.packPath(ref.PackID)
	if err != nil {
		return err
	}
	_ = os.Remove(path)
	_ = os.Remove(IndexPath(path))
	return s.mem.DeletePack(ctx, ref)
}

// ListEntries implements RangeStore.
func (s *FSStore) ListEntries(ctx context.Context, packID string) ([]EntryMetadata, error) {
	if err := s.ensureLoaded(ctx, packID); err != nil {
		return nil, err
	}
	return s.mem.ListEntries(ctx, packID)
}

// PackInfo returns catalog info including index trust flags.
func (s *FSStore) PackInfo(packID string) (PackInfo, bool) {
	return s.mem.PackInfo(packID)
}

// RebuildIndex rebuilds and writes the sibling index for packID (explicit API).
// Not used on MCP read paths.
func (s *FSStore) RebuildIndex(ctx context.Context, packID string) (*PackIndex, error) {
	path, err := s.packPath(packID)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, apperr.New(apperr.CodeNotFound, "pack not found")
		}
		return nil, apperr.Wrap(apperr.CodeInternal, "failed to read pack", err)
	}
	affinity := ""
	if info, ok := s.mem.PackInfo(packID); ok {
		affinity = info.AffinityGroup
	}
	idx, err := RepairIndex(ctx, packID, affinity, path, data)
	if err != nil {
		return nil, err
	}
	// Refresh catalog flags if loaded.
	if _, ok := s.mem.PackInfo(packID); ok {
		s.mem.setIndexStatus(packID, true, false)
	}
	return idx, nil
}

// VerifyAndMaybeQuarantine runs VerifyPackFile and removes the pack from the
// in-memory catalog when quarantined.
func (s *FSStore) VerifyAndMaybeQuarantine(ctx context.Context, packID string, doQuarantine bool) (VerifyReport, error) {
	path, err := s.packPath(packID)
	if err != nil {
		return VerifyReport{}, err
	}
	rep, verr := VerifyPackFile(ctx, packID, path, s.root, doQuarantine)
	if rep.Quarantined {
		_ = s.mem.DeletePack(ctx, ArchiveRef{PackID: packID})
	}
	return rep, verr
}

// ensureLoaded loads pack bytes via native OpenPack. Sidecar index is consulted
// only for trust flags — never trusted when size/checksum/schema mismatch.
// Does not rebuild indexes on the read path (ARC-006).
func (s *FSStore) ensureLoaded(ctx context.Context, packID string) error {
	if info, ok := s.mem.PackInfo(packID); ok && info.SizeBytes > 0 {
		return nil
	}
	path, err := s.packPath(packID)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			if IsQuarantined(s.root, packID) {
				return apperr.New(apperr.CodeCorruptCache, "pack is quarantined")
			}
			return apperr.New(apperr.CodeNotFound, "pack not found")
		}
		return apperr.Wrap(apperr.CodeInternal, "failed to read pack", err)
	}
	// Native bounded open (seek table); no synchronous index rebuild.
	if err := s.mem.PutPack(ctx, PackDescriptor{PackID: packID, Data: data}); err != nil {
		return err
	}
	open := OpenIndexForPack(packID, path, data)
	s.mem.setIndexStatus(packID, open.Trusted, open.RebuildNeeded)
	if open.Trusted && open.Index != nil && open.Index.AffinityGroup != "" {
		s.mem.setAffinity(packID, open.Index.AffinityGroup)
	}
	return nil
}

// Ensure interface compliance.
var (
	_ ArchiveStore = (*FSStore)(nil)
	_ RangeStore   = (*FSStore)(nil)
)
