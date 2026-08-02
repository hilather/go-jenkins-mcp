package fleetcache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// ManifestCodecZstd is the only v1 codec id for pure independent Zstd frames.
const ManifestCodecZstd = "zstd-independent-v1"

// FrameDescriptor is one sealed frame in a completed log version.
// Digests are lowercase hex SHA-256. Local generation IDs and paths are excluded.
type FrameDescriptor struct {
	Seq           int
	RawStart      int64
	RawEnd        int64 // exclusive end offset in decoded stream
	LineStart     int64
	LineEnd       int64 // exclusive
	DecodedSize   int64
	DecodedSHA256 string // hex
	ZstdSize      int64
	ZstdSHA256    string // pure compressed bytes (pre local AEAD)
}

// ManifestV1 is the sealed-version metadata used for manifest_digest.
type ManifestV1 struct {
	LocatorHash   string
	Sealed        bool
	FormatVersion int
	Codec         string
	Frames        []FrameDescriptor
	TotalRawBytes int64
	TotalLines    int64
}

// CanonicalBytes returns deterministic serialization for hashing.
func (m ManifestV1) CanonicalBytes() ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "locator_hash=%s\n", m.LocatorHash)
	fmt.Fprintf(&b, "sealed=%t\n", m.Sealed)
	fmt.Fprintf(&b, "format_version=%d\n", m.FormatVersion)
	fmt.Fprintf(&b, "codec=%s\n", m.Codec)
	fmt.Fprintf(&b, "total_raw_bytes=%d\n", m.TotalRawBytes)
	fmt.Fprintf(&b, "total_lines=%d\n", m.TotalLines)
	fmt.Fprintf(&b, "frame_count=%d\n", len(m.Frames))
	for _, f := range m.Frames {
		fmt.Fprintf(&b, "frame.seq=%d\n", f.Seq)
		fmt.Fprintf(&b, "frame.raw_start=%d\n", f.RawStart)
		fmt.Fprintf(&b, "frame.raw_end=%d\n", f.RawEnd)
		fmt.Fprintf(&b, "frame.line_start=%d\n", f.LineStart)
		fmt.Fprintf(&b, "frame.line_end=%d\n", f.LineEnd)
		fmt.Fprintf(&b, "frame.decoded_size=%d\n", f.DecodedSize)
		fmt.Fprintf(&b, "frame.decoded_sha256=%s\n", strings.ToLower(f.DecodedSHA256))
		fmt.Fprintf(&b, "frame.zstd_size=%d\n", f.ZstdSize)
		fmt.Fprintf(&b, "frame.zstd_sha256=%s\n", strings.ToLower(f.ZstdSHA256))
	}
	return []byte(b.String()), nil
}

// Digest returns lowercase hex SHA-256 of CanonicalBytes (manifest_digest).
func (m ManifestV1) Digest() (string, error) {
	raw, err := m.CanonicalBytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func (m ManifestV1) validate() error {
	if len(m.LocatorHash) != 64 || !isHex(m.LocatorHash) {
		return apperr.New(apperr.CodeInvalidArgument, "manifest locator_hash must be 64 hex chars")
	}
	if !m.Sealed {
		return apperr.New(apperr.CodeInvalidArgument, "manifest must be sealed for fleet cache v1")
	}
	if m.FormatVersion != 1 {
		return apperr.New(apperr.CodeInvalidArgument, "unsupported manifest format_version")
	}
	if m.Codec != ManifestCodecZstd {
		return apperr.New(apperr.CodeInvalidArgument, "unsupported manifest codec")
	}
	if len(m.Frames) == 0 {
		return apperr.New(apperr.CodeInvalidArgument, "manifest requires at least one frame")
	}
	if m.TotalRawBytes < 0 || m.TotalLines < 0 {
		return apperr.New(apperr.CodeInvalidArgument, "manifest totals must not be negative")
	}
	var expectSeq int
	var rawCursor int64
	var lineCursor int64
	var sumDecoded int64
	for i, f := range m.Frames {
		if f.Seq != expectSeq {
			return apperr.New(apperr.CodeInvalidArgument, "manifest frame seq must be contiguous from 0")
		}
		expectSeq++
		if f.RawStart != rawCursor {
			return apperr.New(apperr.CodeInvalidArgument, "manifest frame raw ranges must be contiguous")
		}
		if f.RawEnd < f.RawStart {
			return apperr.New(apperr.CodeInvalidArgument, "manifest frame raw_end < raw_start")
		}
		if f.LineStart != lineCursor {
			return apperr.New(apperr.CodeInvalidArgument, "manifest frame line ranges must be contiguous")
		}
		if f.LineEnd < f.LineStart {
			return apperr.New(apperr.CodeInvalidArgument, "manifest frame line_end < line_start")
		}
		if f.DecodedSize != f.RawEnd-f.RawStart {
			return apperr.New(apperr.CodeInvalidArgument, "manifest frame decoded_size must match raw range")
		}
		if f.DecodedSize < 0 || f.ZstdSize < 1 {
			return apperr.New(apperr.CodeInvalidArgument, "manifest frame sizes invalid")
		}
		if len(f.DecodedSHA256) != 64 || !isHex(f.DecodedSHA256) {
			return apperr.New(apperr.CodeInvalidArgument, "manifest frame decoded_sha256 invalid")
		}
		if len(f.ZstdSHA256) != 64 || !isHex(f.ZstdSHA256) {
			return apperr.New(apperr.CodeInvalidArgument, "manifest frame zstd_sha256 invalid")
		}
		// Reject fields that look like local paths or generation ids smuggled into digests.
		if strings.Contains(f.DecodedSHA256, "/") || strings.Contains(f.ZstdSHA256, "/") {
			return apperr.New(apperr.CodeInvalidArgument, "manifest digests must be hex only")
		}
		rawCursor = f.RawEnd
		lineCursor = f.LineEnd
		sumDecoded += f.DecodedSize
		_ = i
	}
	if sumDecoded != m.TotalRawBytes {
		return apperr.New(apperr.CodeInvalidArgument, "manifest total_raw_bytes must equal sum of frame decoded sizes")
	}
	if lineCursor != m.TotalLines {
		return apperr.New(apperr.CodeInvalidArgument, "manifest total_lines must equal final line_end")
	}
	return nil
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}
