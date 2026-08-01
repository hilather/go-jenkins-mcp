package archive

import (
	"context"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// MemoryStore is an in-process ArchiveStore for deterministic unit tests (ARC-001).
type MemoryStore struct {
	mu           sync.RWMutex
	packs        map[string]*memPack
	maxRange     int64
	maxPackBytes int64
}

type memPack struct {
	desc  PackDescriptor
	data  []byte
	info  PackInfo
	table *SeekTable
}

// MemoryOption configures MemoryStore.
type MemoryOption func(*MemoryStore)

// WithMaxRangeBytes sets the OpenRange ceiling.
func WithMaxRangeBytes(n int64) MemoryOption {
	return func(s *MemoryStore) {
		if n > 0 {
			s.maxRange = n
		}
	}
}

// NewMemoryStore returns an empty in-memory ArchiveStore.
func NewMemoryStore(opts ...MemoryOption) *MemoryStore {
	s := &MemoryStore{
		packs:        make(map[string]*memPack),
		maxRange:     DefaultMaxRangeBytes,
		maxPackBytes: 256 << 20, // 256 MiB per pack in tests
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Capabilities implements RangeStore.
func (s *MemoryStore) Capabilities() Capabilities {
	return Capabilities{
		Name:               "memory",
		NativeReader:       true,
		RatarmountAdapter:  false,
		MaxRangeBytes:      s.maxRange,
		FUSEMountAvailable: false,
	}
}

// PutPack validates and stores a multi-frame pack.
func (s *MemoryStore) PutPack(ctx context.Context, pack PackDescriptor) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "context cancelled", err)
	}
	id := strings.TrimSpace(pack.PackID)
	if id == "" {
		return apperr.New(apperr.CodeInvalidArgument, "pack_id is required")
	}
	if len(pack.Data) == 0 {
		return apperr.New(apperr.CodeInvalidArgument, "pack data is empty")
	}
	if int64(len(pack.Data)) > s.maxPackBytes {
		return apperr.New(apperr.CodeQuota, "pack exceeds store size limit")
	}
	p, err := OpenPack(pack.Data)
	if err != nil {
		return err
	}
	defer p.Close()
	if p.PackID() != id && p.PackID() != "" {
		// Seek table pack_id should match descriptor when both set.
		if p.table != nil && p.table.PackID != id {
			return apperr.New(apperr.CodeInvalidArgument, "pack_id does not match seek table")
		}
	}
	if err := p.VerifyContentFrames(); err != nil {
		return err
	}
	ver := pack.SchemaVersion
	if ver == 0 {
		ver = FormatVersion
	}
	created := pack.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	sha := pack.SHA256
	if sha == "" && p.table != nil {
		sha = p.table.PackSHA256
	}
	// Copy data for immutability.
	data := append([]byte(nil), pack.Data...)
	mp := &memPack{
		desc: PackDescriptor{
			PackID:        id,
			SchemaVersion: ver,
			AffinityGroup: pack.AffinityGroup,
			SHA256:        sha,
			CreatedAt:     created,
		},
		data:  data,
		table: p.table,
		info: PackInfo{
			PackID:        id,
			SchemaVersion: ver,
			AffinityGroup: pack.AffinityGroup,
			SHA256:        sha,
			SizeBytes:     int64(len(data)),
			MemberCount:   len(p.table.Members),
			FrameCount:    len(p.table.Frames),
			CreatedAt:     created,
			// In-memory put validates the pack; no sidecar yet unless FS writes one.
			IndexTrusted:  false,
			RebuildNeeded: true,
		},
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.packs[id] = mp
	return nil
}

// setIndexStatus updates ARC-006 index trust flags (store-internal).
func (s *MemoryStore) setIndexStatus(packID string, trusted, rebuildNeeded bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	mp, ok := s.packs[packID]
	if !ok {
		return
	}
	mp.info.IndexTrusted = trusted
	mp.info.RebuildNeeded = rebuildNeeded
}

// setAffinity updates affinity group from a trusted index (store-internal).
func (s *MemoryStore) setAffinity(packID, affinity string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	mp, ok := s.packs[packID]
	if !ok {
		return
	}
	if affinity != "" {
		mp.info.AffinityGroup = affinity
		mp.desc.AffinityGroup = affinity
	}
}

// AttachIndex records a trusted in-memory index for tests/diagnostics (no file).
func (s *MemoryStore) AttachIndex(packID string, idx *PackIndex) error {
	if idx == nil {
		return apperr.New(apperr.CodeInvalidArgument, "index is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	mp, ok := s.packs[packID]
	if !ok {
		return apperr.New(apperr.CodeNotFound, "pack not found")
	}
	if err := idx.BindMatches(packID, mp.info.SizeBytes, mp.info.SHA256, sha256Hex(mp.data), mp.info.SchemaVersion); err != nil {
		return err
	}
	mp.info.IndexTrusted = true
	mp.info.RebuildNeeded = false
	if idx.AffinityGroup != "" {
		mp.info.AffinityGroup = idx.AffinityGroup
		mp.desc.AffinityGroup = idx.AffinityGroup
	}
	return nil
}

// OpenEntry returns the full member body as a ReadCloser.
// Entries larger than MaxRangeBytes fail with quota (use OpenRange for partial reads).
func (s *MemoryStore) OpenEntry(ctx context.Context, ref ArchiveRef) (io.ReadCloser, EntryMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, EntryMetadata{}, apperr.Wrap(apperr.CodeCancelled, "context cancelled", err)
	}
	if strings.TrimSpace(ref.PackID) == "" || strings.TrimSpace(ref.EntryID) == "" {
		return nil, EntryMetadata{}, apperr.New(apperr.CodeInvalidArgument, "pack_id and entry_id are required")
	}
	m, ok := s.tableMember(ref)
	if !ok {
		// Pack missing or entry unknown — OpenRange supplies the precise code.
		return s.OpenRange(ctx, ref, 0, 0)
	}
	if m.Size > s.maxRange {
		return nil, EntryMetadata{
			PackID:  ref.PackID,
			EntryID: ref.EntryID,
			Name:    m.Name,
			Size:    m.Size,
		}, apperr.New(apperr.CodeQuota, "entry exceeds store range limit; use OpenRange")
	}
	return s.OpenRange(ctx, ref, 0, m.Size)
}

// OpenRange reads [offset, offset+length) of a member under the store range budget.
func (s *MemoryStore) OpenRange(ctx context.Context, ref ArchiveRef, offset, length int64) (io.ReadCloser, EntryMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, EntryMetadata{}, apperr.Wrap(apperr.CodeCancelled, "context cancelled", err)
	}
	if strings.TrimSpace(ref.PackID) == "" {
		return nil, EntryMetadata{}, apperr.New(apperr.CodeInvalidArgument, "pack_id is required")
	}
	if strings.TrimSpace(ref.EntryID) == "" {
		return nil, EntryMetadata{}, apperr.New(apperr.CodeInvalidArgument, "entry_id is required")
	}
	if offset < 0 || length < 0 {
		return nil, EntryMetadata{}, apperr.New(apperr.CodeInvalidArgument, "offset and length must be non-negative")
	}
	if length > s.maxRange {
		return nil, EntryMetadata{}, apperr.New(apperr.CodeQuota, "range length exceeds store limit")
	}

	s.mu.RLock()
	mp, ok := s.packs[ref.PackID]
	if !ok {
		s.mu.RUnlock()
		return nil, EntryMetadata{}, apperr.New(apperr.CodeNotFound, "pack not found")
	}
	data := mp.data
	s.mu.RUnlock()

	p, err := OpenPack(data)
	if err != nil {
		return nil, EntryMetadata{}, err
	}
	defer p.Close()

	// OpenEntry path uses length=maxRange; clamp to member size inside ReadMemberRange.
	body, meta, _, err := p.ReadMemberRange(ctx, ref.EntryID, offset, length)
	if err != nil {
		return nil, meta, err
	}
	// When OpenEntry asked for maxRange from 0, return full member if within limit.
	return newBytesReadCloser(body), meta, nil
}

// Verify checks pack integrity (and optional entry existence).
func (s *MemoryStore) Verify(ctx context.Context, ref ArchiveRef) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "context cancelled", err)
	}
	if strings.TrimSpace(ref.PackID) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "pack_id is required")
	}
	s.mu.RLock()
	mp, ok := s.packs[ref.PackID]
	if !ok {
		s.mu.RUnlock()
		return apperr.New(apperr.CodeNotFound, "pack not found")
	}
	data := mp.data
	s.mu.RUnlock()

	p, err := OpenPack(data)
	if err != nil {
		return err
	}
	defer p.Close()
	if err := p.VerifyContentFrames(); err != nil {
		return err
	}
	if ref.EntryID != "" {
		if _, ok := p.table.FindMember(ref.EntryID); !ok {
			return apperr.New(apperr.CodeNotFound, "archive entry not found")
		}
	}
	return nil
}

// DeletePack removes a pack. EntryID is ignored (pack-level delete).
func (s *MemoryStore) DeletePack(ctx context.Context, ref ArchiveRef) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "context cancelled", err)
	}
	if strings.TrimSpace(ref.PackID) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "pack_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.packs[ref.PackID]; !ok {
		return apperr.New(apperr.CodeNotFound, "pack not found")
	}
	delete(s.packs, ref.PackID)
	return nil
}

// ListEntries lists members of a pack.
func (s *MemoryStore) ListEntries(ctx context.Context, packID string) ([]EntryMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, apperr.Wrap(apperr.CodeCancelled, "context cancelled", err)
	}
	packID = strings.TrimSpace(packID)
	if packID == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "pack_id is required")
	}
	s.mu.RLock()
	mp, ok := s.packs[packID]
	if !ok {
		s.mu.RUnlock()
		return nil, apperr.New(apperr.CodeNotFound, "pack not found")
	}
	data := mp.data
	s.mu.RUnlock()

	p, err := OpenPack(data)
	if err != nil {
		return nil, err
	}
	defer p.Close()
	return p.ListMembers(), nil
}

// PackInfo returns catalog info if present.
func (s *MemoryStore) PackInfo(packID string) (PackInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	mp, ok := s.packs[packID]
	if !ok {
		return PackInfo{}, false
	}
	return mp.info, true
}

func (s *MemoryStore) tableMember(ref ArchiveRef) (SeekMember, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	mp, ok := s.packs[ref.PackID]
	if !ok || mp.table == nil {
		return SeekMember{}, false
	}
	return mp.table.FindMember(ref.EntryID)
}

// Ensure interface compliance.
var (
	_ ArchiveStore = (*MemoryStore)(nil)
	_ RangeStore   = (*MemoryStore)(nil)
)
