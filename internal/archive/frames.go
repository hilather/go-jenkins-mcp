package archive

import (
	"encoding/binary"
	"fmt"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/klauspost/compress/zstd"
)

// zstd content frame magic (little-endian 0xFD2FB528).
const zstdMagic = 0xFD2FB528

// skippable magic base 0x184D2A50 .. 0x184D2A5F.
const skippableMagicMin = 0x184D2A50
const skippableMagicMax = 0x184D2A5F

// frameLoc is one physical frame in a pack file.
type frameLoc struct {
	Offset    int64
	Size      int64 // compressed size including headers
	Skippable bool
	// PayloadOffset/Size for skippable: user data region.
	PayloadOffset int64
	PayloadSize   int64
}

// scanFrames walks independent Zstd frames (content + skippable) without full decompress.
func scanFrames(data []byte) ([]frameLoc, error) {
	if len(data) == 0 {
		return nil, apperr.New(apperr.CodeCorruptCache, "empty pack")
	}
	var out []frameLoc
	off := 0
	for off < len(data) {
		if off+4 > len(data) {
			return nil, apperr.New(apperr.CodeCorruptCache, "truncated zstd frame magic")
		}
		magic := binary.LittleEndian.Uint32(data[off:])
		if magic >= skippableMagicMin && magic <= skippableMagicMax {
			if off+8 > len(data) {
				return nil, apperr.New(apperr.CodeCorruptCache, "truncated skippable frame header")
			}
			psz := binary.LittleEndian.Uint32(data[off+4:])
			total := 8 + int(psz)
			if off+total > len(data) {
				return nil, apperr.New(apperr.CodeCorruptCache, "truncated skippable frame payload")
			}
			if int(psz) > MaxSeekTableBytes {
				// Only the seek table should be large skippable; still bound —
				// and the bound applies to the FIRST frame too (no exemption).
				return nil, apperr.New(apperr.CodeCorruptCache, "skippable frame exceeds size limit")
			}
			out = append(out, frameLoc{
				Offset:        int64(off),
				Size:          int64(total),
				Skippable:     true,
				PayloadOffset: int64(off + 8),
				PayloadSize:   int64(psz),
			})
			off += total
			continue
		}
		if magic != zstdMagic {
			return nil, apperr.New(apperr.CodeCorruptCache,
				fmt.Sprintf("invalid zstd magic at offset %d", off))
		}
		end, err := contentFrameEnd(data, off)
		if err != nil {
			return nil, err
		}
		out = append(out, frameLoc{
			Offset:    int64(off),
			Size:      int64(end - off),
			Skippable: false,
		})
		off = end
	}
	return out, nil
}

// contentFrameEnd returns the exclusive end offset of a content frame starting at off.
func contentFrameEnd(data []byte, off int) (int, error) {
	var h zstd.Header
	if err := h.Decode(data[off:]); err != nil {
		return 0, apperr.Wrap(apperr.CodeCorruptCache, "invalid zstd frame header", err)
	}
	if h.Skippable {
		// Should have been handled by magic path.
		return off + h.HeaderSize + int(h.SkippableSize), nil
	}
	pos := off + h.HeaderSize
	for {
		if pos+3 > len(data) {
			return 0, apperr.New(apperr.CodeCorruptCache, "truncated zstd block header")
		}
		bheader := uint32(data[pos]) | uint32(data[pos+1])<<8 | uint32(data[pos+2])<<16
		last := bheader & 1
		btype := (bheader >> 1) & 3
		bsize := int(bheader >> 3)
		pos += 3
		switch btype {
		case 0: // raw
			pos += bsize
		case 1: // RLE
			pos++
		case 2: // compressed
			pos += bsize
		default:
			return 0, apperr.New(apperr.CodeCorruptCache, "reserved zstd block type")
		}
		if pos > len(data) {
			return 0, apperr.New(apperr.CodeCorruptCache, "truncated zstd block body")
		}
		if last != 0 {
			break
		}
	}
	if h.HasCheckSum {
		if pos+4 > len(data) {
			return 0, apperr.New(apperr.CodeCorruptCache, "truncated zstd content checksum")
		}
		pos += 4
	}
	return pos, nil
}

// writeSkippableFrame appends a skippable frame with the given payload.
// Uses magic 0x184D2A50 (id 0).
func writeSkippableFrame(payload []byte) ([]byte, error) {
	if len(payload) > MaxSeekTableBytes {
		return nil, apperr.New(apperr.CodeInvalidArgument, "skippable payload exceeds size limit")
	}
	out := make([]byte, 8+len(payload))
	binary.LittleEndian.PutUint32(out[0:4], skippableMagicMin)
	binary.LittleEndian.PutUint32(out[4:8], uint32(len(payload)))
	copy(out[8:], payload)
	return out, nil
}
