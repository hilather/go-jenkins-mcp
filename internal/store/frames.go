package store

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// L1 independent Zstandard frame layout (STO-003).
//
// On disk each committed frame file is a single standard Zstandard frame
// (klauspost/compress EncodeAll, no dictionary). There is no cross-frame
// dictionary or history dependency: any frame decompresses alone.
//
// Metadata (ranges, checksums, line indexes, codec) lives in SQLite; the file
// bytes are pure zstd so L2 promotion can copy payload frames without
// recompression (ARC-* later).
//
// Directory layout under a profile data dir:
//
//	frames/<generation_id>/<seq>.zst       immutable once committed
//	frames/<generation_id>/<seq>.zst.tmp   in-progress (recovered by deleting)
//
// Residual: L2 multi-frame seekable .tar.zst packing is ARC-001+; this package
// only owns L1 independent frames.

const (
	// FrameFormatVersion versions SQLite frame metadata semantics.
	FrameFormatVersion = 1

	// DefaultTargetFrameBytes is the initial uncompressed target (~8 MiB).
	DefaultTargetFrameBytes = 8 << 20

	// MinTargetFrameBytes is the smallest allowed configured target (tests).
	MinTargetFrameBytes = 16

	// MaxFrameBytes forces a cut even without a newline (architecture 4–16 MiB).
	MaxFrameBytes = 16 << 20

	// DefaultCodecLevel is klauspost SpeedDefault (~3).
	DefaultCodecLevel = 3

	// FrameFilePerm is owner read/write only.
	FrameFilePerm = 0o600

	// FramesDirName is the subdirectory under the profile data dir.
	FramesDirName = "frames"

	// FrameExt is the committed frame suffix.
	FrameExt = ".zst"

	// FrameTmpExt is the in-progress suffix (STO-004).
	FrameTmpExt = ".zst.tmp"

	// CodecZstd is the only L1 payload codec.
	CodecZstd = "zstd"

	// LineCheckpointInterval samples every N newlines within a frame.
	LineCheckpointInterval = 256

	// NewlineLookback is how far before target we search for a cut newline.
	NewlineLookback = 64 << 10
)

// Chunk is durable metadata for one independent L1 frame.
type Chunk struct {
	ID               int64
	GenerationID     int64
	Seq              int
	RawStart         int64 // inclusive absolute raw offset in generation
	RawEnd           int64 // exclusive
	LineStart        int64 // inclusive 0-based line index of first byte
	LineEnd          int64 // exclusive (line index after last byte's line)
	UncompressedSize int64
	CompressedSize   int64
	ContentSHA256    string // hex SHA-256 of raw uncompressed bytes
	FrameSHA256      string // hex SHA-256 of on-disk frame file (zstd or AEAD envelope)
	// ZstdSize / ZstdSHA256 are pure compressed bytes before local AEAD (FLC-020).
	// Zero/empty means legacy row not yet backfilled; use EnsureChunkWireHash.
	ZstdSize      int64
	ZstdSHA256    string
	Codec         string
	CodecLevel    int
	FormatVersion int
	DictID        string // empty = no dictionary (no cross-frame dependency)
	RelPath       string // relative to profile data dir
	CreatedAt     string
	// EncAlg is empty for plaintext; "aes-256-gcm" when ARC-009 AEAD is applied.
	// Raw key material is never stored here — only key version id.
	EncAlg string
	// EncKeyVersion is 0 for plaintext; N for frames sealed with key version N.
	EncKeyVersion int
}

// LineCheckpoint maps an absolute line number to a raw byte offset.
type LineCheckpoint struct {
	ChunkID   int64
	LineNo    int64
	RawOffset int64
}

// FrameRelPath returns the relative path for a committed frame file.
func FrameRelPath(generationID int64, seq int) string {
	return filepath.ToSlash(filepath.Join(
		FramesDirName,
		fmt.Sprintf("%d", generationID),
		fmt.Sprintf("%d%s", seq, FrameExt),
	))
}

// FrameAbsPath joins dataDir with a frame relative path.
func FrameAbsPath(dataDir, rel string) (string, error) {
	rel = filepath.ToSlash(strings.TrimSpace(rel))
	if rel == "" {
		return "", apperr.New(apperr.CodeInvalidArgument, "frame path is empty")
	}
	if strings.Contains(rel, "..") {
		return "", apperr.New(apperr.CodeInvalidArgument, "frame path must not traverse")
	}
	if !strings.HasPrefix(rel, FramesDirName+"/") {
		return "", apperr.New(apperr.CodeInvalidArgument, "frame path must be under frames/")
	}
	return filepath.Join(dataDir, filepath.FromSlash(rel)), nil
}

// sha256Hex returns lowercase hex SHA-256 of b.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// findNewlineCut returns the exclusive end index for a newline-aware cut.
// Prefer the last '\n' in [minKeep, len(buf)) when len(buf) >= target;
// returns -1 if no cut should be made yet.
func findNewlineCut(buf []byte, target, maxBytes int) int {
	if maxBytes <= 0 {
		maxBytes = MaxFrameBytes
	}
	if target <= 0 {
		target = DefaultTargetFrameBytes
	}
	n := len(buf)
	if n == 0 {
		return -1
	}
	// Hard cap: force cut at maxBytes (may be mid-line).
	if n >= maxBytes {
		return maxBytes
	}
	if n < target {
		return -1
	}
	// Search for last newline in the window [target-lookback, n).
	start := target - NewlineLookback
	if start < 0 {
		start = 0
	}
	// Prefer a cut at or after target when possible.
	cutFrom := target - 1
	if cutFrom < start {
		cutFrom = start
	}
	for i := n - 1; i >= cutFrom; i-- {
		if buf[i] == '\n' {
			return i + 1
		}
	}
	// No newline after target-ish; try any newline from start.
	for i := n - 1; i >= start; i-- {
		if buf[i] == '\n' {
			return i + 1
		}
	}
	// No newline in lookback: if well past target, force mid-line cut at n
	// only when we hit max; otherwise keep buffering.
	if n >= maxBytes {
		return maxBytes
	}
	// Soft: if 2× target with no newline, force cut to bound memory.
	if n >= target*2 {
		return n
	}
	return -1
}
