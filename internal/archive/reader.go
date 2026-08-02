package archive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Pack holds a parsed multi-frame pack and supports member range reads (ARC-003).
type Pack struct {
	data   []byte
	frames []frameLoc
	table  *SeekTable
	dec    *zstd.Decoder
}

// OpenPack parses and validates a seekable multi-frame .tar.zst buffer.
func OpenPack(data []byte) (*Pack, error) {
	if len(data) == 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument, "pack data is empty")
	}
	locs, err := scanFrames(data)
	if err != nil {
		return nil, err
	}
	if len(locs) < 2 {
		return nil, apperr.New(apperr.CodeCorruptCache,
			"pack must contain multiple frames; single-frame .tar.zst is not random-access")
	}

	// Last skippable frame with seek magic wins; require at least one skippable at end-ish.
	var seekLoc *frameLoc
	contentCount := 0
	for i := range locs {
		if locs[i].Skippable {
			seekLoc = &locs[i]
		} else {
			contentCount++
		}
	}
	if seekLoc == nil {
		return nil, apperr.New(apperr.CodeCorruptCache, "missing seek-table skippable frame")
	}
	// Prefer the last skippable frame.
	for i := len(locs) - 1; i >= 0; i-- {
		if locs[i].Skippable {
			seekLoc = &locs[i]
			break
		}
	}
	if contentCount < MinContentFrames {
		return nil, apperr.New(apperr.CodeCorruptCache,
			fmt.Sprintf("pack has %d content frames; need at least %d (single-frame not allowed)",
				contentCount, MinContentFrames))
	}
	// Content frames must precede the seek table with no trailing content after seek.
	if seekLoc.Offset+seekLoc.Size != int64(len(data)) {
		// Allow only if seek is last frame.
		last := locs[len(locs)-1]
		if !last.Skippable {
			return nil, apperr.New(apperr.CodeCorruptCache, "seek table must be the final frame")
		}
	}

	payload := data[seekLoc.PayloadOffset : seekLoc.PayloadOffset+seekLoc.PayloadSize]
	st, err := ParseSeekTable(payload)
	if err != nil {
		return nil, err
	}

	// Bind seek table compressed offsets to scanned content frames.
	contentLocs := make([]frameLoc, 0, contentCount)
	for _, l := range locs {
		if !l.Skippable {
			contentLocs = append(contentLocs, l)
		}
	}
	if len(contentLocs) != len(st.Frames) {
		return nil, apperr.New(apperr.CodeCorruptCache,
			fmt.Sprintf("content frame count mismatch: file %d seek table %d", len(contentLocs), len(st.Frames)))
	}
	for i, f := range st.Frames {
		loc := contentLocs[i]
		if loc.Offset != f.CompressedOffset || loc.Size != f.CompressedSize {
			return nil, apperr.New(apperr.CodeCorruptCache,
				fmt.Sprintf("frame %d offset/size mismatch seek vs scan", i))
		}
	}

	dec, err := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(MaxDecompressPerOp))
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "failed to create zstd decoder", err)
	}
	return &Pack{data: data, frames: locs, table: st, dec: dec}, nil
}

// Close releases decoder resources.
func (p *Pack) Close() error {
	if p == nil {
		return nil
	}
	if p.dec != nil {
		p.dec.Close()
		p.dec = nil
	}
	return nil
}

// SeekTable returns the parsed seek table (read-only use).
func (p *Pack) SeekTable() *SeekTable {
	if p == nil {
		return nil
	}
	return p.table
}

// PackID returns the pack id from the seek table.
func (p *Pack) PackID() string {
	if p == nil || p.table == nil {
		return ""
	}
	return p.table.PackID
}

// ListMembers returns entry metadata for all TAR members.
func (p *Pack) ListMembers() []EntryMetadata {
	if p == nil || p.table == nil {
		return nil
	}
	out := make([]EntryMetadata, 0, len(p.table.Members))
	for _, m := range p.table.Members {
		id := m.EntryID
		if id == "" {
			id = m.Name
		}
		out = append(out, EntryMetadata{
			PackID:        p.table.PackID,
			EntryID:       id,
			Name:          m.Name,
			Size:          m.Size,
			Mode:          m.Mode,
			ContentSHA256: m.ContentSHA256,
		})
	}
	return out
}

// ReadMemberRange returns [offset, offset+length) within the member body.
// Only intersecting independent frames are decompressed.
func (p *Pack) ReadMemberRange(ctx context.Context, entryID string, offset, length int64) ([]byte, EntryMetadata, ReadStats, error) {
	var stats ReadStats
	meta := EntryMetadata{}
	if p == nil || p.table == nil {
		return nil, meta, stats, apperr.New(apperr.CodeInternal, "pack is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, meta, stats, apperr.Wrap(apperr.CodeCancelled, "context cancelled", err)
	}
	if offset < 0 || length < 0 {
		return nil, meta, stats, apperr.New(apperr.CodeInvalidArgument, "offset and length must be non-negative")
	}
	entryID = strings.TrimSpace(entryID)
	if entryID == "" {
		return nil, meta, stats, apperr.New(apperr.CodeInvalidArgument, "entry_id is required")
	}
	m, ok := p.table.FindMember(entryID)
	if !ok {
		return nil, meta, stats, apperr.New(apperr.CodeNotFound, "archive entry not found")
	}
	id := m.EntryID
	if id == "" {
		id = m.Name
	}
	meta = EntryMetadata{
		PackID:        p.table.PackID,
		EntryID:       id,
		Name:          m.Name,
		Size:          m.Size,
		Mode:          m.Mode,
		ContentSHA256: m.ContentSHA256,
	}
	stats.ContentFrames = len(p.table.Frames)

	if length == 0 || offset >= m.Size {
		return []byte{}, meta, stats, nil
	}
	if offset+length > m.Size {
		length = m.Size - offset
	}
	absStart := m.RawOffset + offset
	absEnd := absStart + length
	frames := p.table.FramesIntersectingRaw(absStart, absEnd)
	if len(frames) == 0 {
		return nil, meta, stats, apperr.New(apperr.CodeCorruptCache, "no frames cover member range")
	}

	var out bytes.Buffer
	var decompressed int64
	for _, f := range frames {
		if err := ctx.Err(); err != nil {
			return nil, meta, stats, apperr.Wrap(apperr.CodeCancelled, "context cancelled", err)
		}
		raw, err := p.decompressFrame(f)
		if err != nil {
			return nil, meta, stats, err
		}
		decompressed += int64(len(raw))
		if decompressed > MaxDecompressPerOp {
			return nil, meta, stats, apperr.New(apperr.CodeQuota, "decompression budget exceeded for range read")
		}
		stats.FramesOpened++
		// Intersection of frame raw range with [absStart, absEnd).
		lo := absStart
		if f.RawOffset > lo {
			lo = f.RawOffset
		}
		hi := absEnd
		if f.RawOffset+f.RawSize < hi {
			hi = f.RawOffset + f.RawSize
		}
		if hi <= lo {
			continue
		}
		from := int(lo - f.RawOffset)
		to := int(hi - f.RawOffset)
		if from < 0 || to > len(raw) || from > to {
			return nil, meta, stats, apperr.New(apperr.CodeCorruptCache,
				fmt.Sprintf("frame %d size mismatch: meta %d decoded %d", f.Index, f.RawSize, len(raw)))
		}
		out.Write(raw[from:to])
	}
	stats.DecompressedBytes = decompressed
	stats.LogicalBytes = int64(out.Len())
	meta.FramesOpened = stats.FramesOpened
	meta.DecompressedBytes = stats.DecompressedBytes
	return out.Bytes(), meta, stats, nil
}

// ReadMember returns the full member body (still frame-bounded, not full-pack when multi-frame).
func (p *Pack) ReadMember(ctx context.Context, entryID string) ([]byte, EntryMetadata, ReadStats, error) {
	m, ok := p.table.FindMember(entryID)
	if !ok {
		return nil, EntryMetadata{}, ReadStats{}, apperr.New(apperr.CodeNotFound, "archive entry not found")
	}
	return p.ReadMemberRange(ctx, entryID, 0, m.Size)
}

// VerifyContentFrames checks frame_sha256 for every content frame and pack_sha256.
func (p *Pack) VerifyContentFrames() error {
	if p == nil || p.table == nil {
		return apperr.New(apperr.CodeInternal, "pack is nil")
	}
	h := sha256.New()
	for _, f := range p.table.Frames {
		if f.CompressedOffset < 0 || f.CompressedOffset+f.CompressedSize > int64(len(p.data)) {
			return apperr.New(apperr.CodeCorruptCache, "frame compressed range out of bounds")
		}
		slice := p.data[f.CompressedOffset : f.CompressedOffset+f.CompressedSize]
		if got := sha256Hex(slice); got != f.FrameSHA256 && f.FrameSHA256 != "" {
			return apperr.New(apperr.CodeCorruptCache,
				fmt.Sprintf("frame %d frame_sha256 mismatch", f.Index))
		}
		_, _ = h.Write(slice)
	}
	if p.table.PackSHA256 != "" && sha256Hex(h.Sum(nil)) != p.table.PackSHA256 {
		return apperr.New(apperr.CodeCorruptCache, "pack_sha256 mismatch")
	}
	return nil
}

// SequentialTAR decompresses all content frames in order (recovery path).
// Does not decompress only for random access; used in tests and repair.
func (p *Pack) SequentialTAR() ([]byte, error) {
	if p == nil || p.table == nil {
		return nil, apperr.New(apperr.CodeInternal, "pack is nil")
	}
	var out bytes.Buffer
	for _, f := range p.table.Frames {
		raw, err := p.decompressFrame(f)
		if err != nil {
			return nil, err
		}
		out.Write(raw)
	}
	return out.Bytes(), nil
}

func (p *Pack) decompressFrame(f SeekFrame) ([]byte, error) {
	if f.CompressedOffset < 0 || f.CompressedOffset+f.CompressedSize > int64(len(p.data)) {
		return nil, apperr.New(apperr.CodeCorruptCache, "frame slice out of bounds")
	}
	slice := p.data[f.CompressedOffset : f.CompressedOffset+f.CompressedSize]
	if f.FrameSHA256 != "" {
		if got := sha256Hex(slice); got != f.FrameSHA256 {
			return nil, apperr.New(apperr.CodeCorruptCache, "frame checksum mismatch before decode")
		}
	}
	raw, err := p.dec.DecodeAll(slice, make([]byte, 0, f.RawSize))
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeCorruptCache, "zstd decompress failed", err)
	}
	if int64(len(raw)) != f.RawSize {
		return nil, apperr.New(apperr.CodeCorruptCache,
			fmt.Sprintf("frame raw size mismatch: got %d want %d", len(raw), f.RawSize))
	}
	if f.ContentSHA256 != "" && sha256Hex(raw) != f.ContentSHA256 {
		return nil, apperr.New(apperr.CodeCorruptCache, "frame content checksum mismatch")
	}
	return raw, nil
}

// bytesReadCloser wraps a buffer as io.ReadCloser.
type bytesReadCloser struct {
	*bytes.Reader
}

func (b bytesReadCloser) Close() error { return nil }

func newBytesReadCloser(b []byte) io.ReadCloser {
	return bytesReadCloser{Reader: bytes.NewReader(b)}
}
