package archive

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// IndexMagic is the sidecar pack-index document magic (ARC-006).
const IndexMagic = "JMCP-IDX-V1"

// IndexSchemaVersion is the sidecar index format version (independent of pack format).
const IndexSchemaVersion = 1

// PackIndex is a derived catalog/index bound to pack checksum, size, and schema.
//
// Sidecar files live beside packs as <packID>.idx.json. A stale or mismatched
// index is never trusted; readers fall back to the native embedded seek table
// (bounded OpenPack) and flag RebuildNeeded. MCP read paths must not rebuild.
type PackIndex struct {
	Magic              string `json:"magic"`
	IndexSchemaVersion int    `json:"index_schema_version"`
	PackID             string `json:"pack_id"`
	PackFormatVersion  int    `json:"pack_format_version"`
	PackSizeBytes      int64  `json:"pack_size_bytes"`
	// PackSHA256 is the content-frames digest (seek table pack_sha256).
	PackSHA256 string `json:"pack_sha256"`
	// FileSHA256 is SHA-256 of the full on-disk pack bytes (content + seek frame).
	FileSHA256    string        `json:"file_sha256"`
	AffinityGroup string        `json:"affinity_group,omitempty"`
	MemberCount   int           `json:"member_count"`
	FrameCount    int           `json:"frame_count"`
	BuiltAt       string        `json:"built_at"`
	Members       []IndexMember `json:"members"`
}

// IndexMember is a lightweight catalog row for one TAR member.
type IndexMember struct {
	EntryID       string `json:"entry_id"`
	Name          string `json:"name"`
	Size          int64  `json:"size"`
	ContentSHA256 string `json:"content_sha256,omitempty"`
}

// IndexOpenResult reports whether a sidecar index was trusted on open.
type IndexOpenResult struct {
	// Trusted is true only when the index binds to pack size/checksum/schema.
	Trusted bool
	// RebuildNeeded is true when index is missing, stale, corrupt, or schema-mismatched.
	// Callers must not rebuild on the interactive MCP path; use RebuildIndex explicitly.
	RebuildNeeded bool
	// Reason is a non-secret diagnostic when !Trusted (empty when trusted).
	Reason string
	// Index is non-nil only when Trusted.
	Index *PackIndex
}

// BuildIndexFromPack constructs a sidecar index from validated pack bytes.
// Prefer calling after OpenPack + VerifyContentFrames (or use RebuildIndex).
func BuildIndexFromPack(packID, affinityGroup string, data []byte, st *SeekTable) (*PackIndex, error) {
	if strings.TrimSpace(packID) == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "pack_id is required")
	}
	if len(data) == 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument, "pack data is empty")
	}
	if st == nil {
		return nil, apperr.New(apperr.CodeInvalidArgument, "seek table is required")
	}
	if err := st.Validate(); err != nil {
		return nil, err
	}
	packSHA := st.PackSHA256
	if packSHA == "" {
		return nil, apperr.New(apperr.CodeCorruptCache, "seek table pack_sha256 is empty")
	}
	members := make([]IndexMember, 0, len(st.Members))
	for _, m := range st.Members {
		id := m.EntryID
		if id == "" {
			id = m.Name
		}
		members = append(members, IndexMember{
			EntryID:       id,
			Name:          m.Name,
			Size:          m.Size,
			ContentSHA256: m.ContentSHA256,
		})
	}
	return &PackIndex{
		Magic:              IndexMagic,
		IndexSchemaVersion: IndexSchemaVersion,
		PackID:             packID,
		PackFormatVersion:  st.FormatVersion,
		PackSizeBytes:      int64(len(data)),
		PackSHA256:         packSHA,
		FileSHA256:         sha256Hex(data),
		AffinityGroup:      strings.TrimSpace(affinityGroup),
		MemberCount:        len(st.Members),
		FrameCount:         len(st.Frames),
		BuiltAt:            time.Now().UTC().Format(time.RFC3339Nano),
		Members:            members,
	}, nil
}

// Validate checks index document shape (not pack binding).
func (idx *PackIndex) Validate() error {
	if idx == nil {
		return apperr.New(apperr.CodeCorruptCache, "pack index is nil")
	}
	if idx.Magic != IndexMagic {
		return apperr.New(apperr.CodeCorruptCache,
			fmt.Sprintf("index magic %q want %q", idx.Magic, IndexMagic))
	}
	if idx.IndexSchemaVersion != IndexSchemaVersion {
		return apperr.New(apperr.CodeCorruptCache,
			fmt.Sprintf("unsupported index_schema_version %d", idx.IndexSchemaVersion))
	}
	if strings.TrimSpace(idx.PackID) == "" {
		return apperr.New(apperr.CodeCorruptCache, "index pack_id is empty")
	}
	if idx.PackFormatVersion != FormatVersion {
		return apperr.New(apperr.CodeCorruptCache,
			fmt.Sprintf("index pack_format_version %d mismatch", idx.PackFormatVersion))
	}
	if idx.PackSizeBytes <= 0 {
		return apperr.New(apperr.CodeCorruptCache, "index pack_size_bytes is invalid")
	}
	if idx.PackSHA256 == "" || idx.FileSHA256 == "" {
		return apperr.New(apperr.CodeCorruptCache, "index checksums are required")
	}
	if idx.MemberCount < 0 || idx.FrameCount < MinContentFrames {
		return apperr.New(apperr.CodeCorruptCache, "index member/frame counts are invalid")
	}
	return nil
}

// BindMatches reports whether idx is bound to the given pack identity fields.
// Wrong checksum, size, schema, or pack id ⇒ not trusted.
func (idx *PackIndex) BindMatches(packID string, packSize int64, packSHA256, fileSHA256 string, packFormatVersion int) error {
	if err := idx.Validate(); err != nil {
		return err
	}
	if idx.PackID != strings.TrimSpace(packID) {
		return apperr.New(apperr.CodeCorruptCache, "index pack_id does not match pack")
	}
	if idx.PackFormatVersion != packFormatVersion {
		return apperr.New(apperr.CodeCorruptCache, "index pack format version mismatch")
	}
	if idx.PackSizeBytes != packSize {
		return apperr.New(apperr.CodeCorruptCache, "index pack size mismatch")
	}
	if !strings.EqualFold(idx.PackSHA256, packSHA256) {
		return apperr.New(apperr.CodeCorruptCache, "index pack_sha256 mismatch")
	}
	if fileSHA256 != "" && !strings.EqualFold(idx.FileSHA256, fileSHA256) {
		return apperr.New(apperr.CodeCorruptCache, "index file_sha256 mismatch")
	}
	return nil
}

// MarshalIndex encodes the index as JSON.
func MarshalIndex(idx *PackIndex) ([]byte, error) {
	if err := idx.Validate(); err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "failed to marshal pack index", err)
	}
	return b, nil
}

// ParseIndex decodes and validates a sidecar index document.
func ParseIndex(data []byte) (*PackIndex, error) {
	if len(data) == 0 {
		return nil, apperr.New(apperr.CodeCorruptCache, "empty pack index")
	}
	var idx PackIndex
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, apperr.Wrap(apperr.CodeCorruptCache, "invalid pack index JSON", err)
	}
	if err := idx.Validate(); err != nil {
		return nil, err
	}
	return &idx, nil
}

// IndexPath returns the sibling index path for a pack file path.
func IndexPath(packPath string) string {
	// pack-foo.tar.zst → pack-foo.idx.json
	ext := filepath.Ext(packPath) // .zst
	base := strings.TrimSuffix(packPath, ext)
	if strings.HasSuffix(base, ".tar") {
		base = strings.TrimSuffix(base, ".tar")
	}
	return base + ".idx.json"
}

// WriteIndexFile writes idx atomically beside the pack (0600).
func WriteIndexFile(path string, idx *PackIndex) error {
	data, err := MarshalIndex(idx)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to create index directory", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to write pack index", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return apperr.Wrap(apperr.CodeInternal, "failed to publish pack index", err)
	}
	return nil
}

// ReadIndexFile loads a sidecar index from disk (does not bind to pack).
func ReadIndexFile(path string) (*PackIndex, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, apperr.New(apperr.CodeNotFound, "pack index not found")
		}
		return nil, apperr.Wrap(apperr.CodeInternal, "failed to read pack index", err)
	}
	return ParseIndex(data)
}

// OpenIndexForPack loads and binds a sibling index to pack bytes.
// Never rebuilds; returns RebuildNeeded when missing/stale/wrong.
func OpenIndexForPack(packID string, packPath string, data []byte) IndexOpenResult {
	res := IndexOpenResult{RebuildNeeded: true}
	if len(data) == 0 {
		res.Reason = "pack data empty"
		return res
	}
	// Bounded native open — seek table at end; not an unbounded full reindex.
	p, err := OpenPack(data)
	if err != nil {
		res.Reason = "native pack open failed"
		return res
	}
	defer p.Close()
	st := p.SeekTable()
	if st == nil {
		res.Reason = "missing seek table"
		return res
	}
	packSHA := st.PackSHA256
	fileSHA := sha256Hex(data)
	idxPath := IndexPath(packPath)
	idx, err := ReadIndexFile(idxPath)
	if err != nil {
		res.Reason = "index missing or unreadable"
		return res
	}
	if err := idx.BindMatches(packID, int64(len(data)), packSHA, fileSHA, st.FormatVersion); err != nil {
		res.Reason = "index binding mismatch"
		return res
	}
	// Optional: member count sanity.
	if idx.MemberCount != len(st.Members) || idx.FrameCount != len(st.Frames) {
		res.Reason = "index catalog counts mismatch seek table"
		return res
	}
	res.Trusted = true
	res.RebuildNeeded = false
	res.Reason = ""
	res.Index = idx
	return res
}

// RebuildIndex builds a fresh index from pack bytes (explicit / off-request-path API).
// Honors ctx cancellation between steps; does not publish — caller writes the file.
func RebuildIndex(ctx context.Context, packID, affinityGroup string, data []byte) (*PackIndex, error) {
	if err := ctx.Err(); err != nil {
		return nil, apperr.Wrap(apperr.CodeCancelled, "index rebuild cancelled", err)
	}
	p, err := OpenPack(data)
	if err != nil {
		return nil, err
	}
	defer p.Close()
	if err := ctx.Err(); err != nil {
		return nil, apperr.Wrap(apperr.CodeCancelled, "index rebuild cancelled", err)
	}
	if err := p.VerifyContentFrames(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, apperr.Wrap(apperr.CodeCancelled, "index rebuild cancelled", err)
	}
	return BuildIndexFromPack(packID, affinityGroup, data, p.SeekTable())
}

// RepairIndex rebuilds and atomically writes the sidecar index when the pack verifies.
// Does not mutate pack bytes. Cancel-safe: partial .tmp is removed on failure.
func RepairIndex(ctx context.Context, packID, affinityGroup, packPath string, data []byte) (*PackIndex, error) {
	idx, err := RebuildIndex(ctx, packID, affinityGroup, data)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, apperr.Wrap(apperr.CodeCancelled, "index repair cancelled", err)
	}
	if err := WriteIndexFile(IndexPath(packPath), idx); err != nil {
		return nil, err
	}
	return idx, nil
}
