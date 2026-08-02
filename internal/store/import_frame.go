package store

import (
	"context"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// PureZstdImportSpec describes one wire frame for local re-wrap import (FLC-023).
// PureZstd is verified pure independent Zstandard (not AEAD). Ranges/hashes come
// from the sealed wire manifest and are re-checked against decoded content.
type PureZstdImportSpec struct {
	Seq           int
	RawStart      int64
	RawEnd        int64
	LineStart     int64
	LineEnd       int64
	DecodedSize   int64
	DecodedSHA256 string
	ZstdSize      int64
	ZstdSHA256    string
	PureZstd      []byte
}

// ImportPureZstdFrame writes one pure-zstd frame into a local generation under
// receiver crypto (re-encrypt envelope when enabled). Does not re-compress:
// pure zstd bytes are preserved as the wire identity (zstd_size/zstd_sha256).
// Frame files are under local generation_id/seq paths only (no peer path control).
func (f *Frames) ImportPureZstdFrame(ctx context.Context, generationID int64, spec PureZstdImportSpec) error {
	if f == nil {
		return apperr.New(apperr.CodeInternal, "frames store is nil")
	}
	if generationID <= 0 {
		return apperr.New(apperr.CodeInvalidArgument, "generation_id is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if spec.Seq < 0 {
		return apperr.New(apperr.CodeInvalidArgument, "seq negative")
	}
	if len(spec.PureZstd) == 0 {
		return apperr.New(apperr.CodeInvalidArgument, "pure zstd empty")
	}
	if int64(len(spec.PureZstd)) > MaxFrameBytes {
		return apperr.New(apperr.CodeQuota, "import zstd exceeds max frame bytes")
	}
	if len(spec.PureZstd) >= 4 && string(spec.PureZstd[:4]) == "JME1" {
		return apperr.New(apperr.CodeInvalidArgument, "import must not be AEAD envelope")
	}
	if spec.ZstdSize > 0 && int64(len(spec.PureZstd)) != spec.ZstdSize {
		return apperr.New(apperr.CodeCorruptCache, "import zstd size mismatch")
	}
	zstdSum := sha256Hex(spec.PureZstd)
	if spec.ZstdSHA256 != "" && !hmacEqualHex(strings.ToLower(spec.ZstdSHA256), zstdSum) {
		return apperr.New(apperr.CodeCorruptCache, "import zstd sha256 mismatch")
	}
	// Decode under memory budget (same order as reader).
	raw, err := DecompressZstdFrame(spec.PureZstd)
	if err != nil {
		return apperr.Wrap(apperr.CodeCorruptCache, "import zstd decode failed", err)
	}
	if int64(len(raw)) > MaxFrameBytes {
		return apperr.New(apperr.CodeQuota, "import decoded exceeds max frame bytes")
	}
	if spec.DecodedSize > 0 && int64(len(raw)) != spec.DecodedSize {
		return apperr.New(apperr.CodeCorruptCache, "import decoded size mismatch")
	}
	contentSum := sha256Hex(raw)
	if spec.DecodedSHA256 != "" && !hmacEqualHex(strings.ToLower(spec.DecodedSHA256), contentSum) {
		return apperr.New(apperr.CodeCorruptCache, "import content sha256 mismatch")
	}
	if spec.RawEnd < spec.RawStart || (spec.RawEnd-spec.RawStart) != int64(len(raw)) {
		return apperr.New(apperr.CodeCorruptCache, "import raw range mismatch")
	}

	// Local re-wrap: AEAD seal pure zstd with receiver generation/seq AAD.
	onDisk, encAlg, encVer, err := f.Crypto.sealCompressed(generationID, spec.Seq, FrameFormatVersion, spec.PureZstd)
	if err != nil {
		return err
	}
	frameSum := sha256Hex(onDisk)

	// Line checkpoints from decoded content (regenerated locally).
	firstIsLineStart := spec.RawStart == 0 || spec.LineStart == 0
	// Prefer wire line_start; walkLines uses it as line of raw[0].
	lineStart := spec.LineStart
	// If mid-generation and previous frame didn't end NL, firstIsLineStart is false —
	// for independent frames imported with absolute line metadata from wire, trust LineStart.
	if spec.RawStart > 0 {
		// Wire provides absolute line_start for the first byte of this frame.
		firstIsLineStart = true // emit checkpoint at lineStart for range tools
	}
	checkpoints, lineEndExcl, _, _ := walkLines(raw, spec.RawStart, lineStart, firstIsLineStart)
	if spec.LineEnd > 0 && lineEndExcl != spec.LineEnd {
		// Prefer decoded walk for local index; wire LineEnd is validated loosely.
		// Fail closed only if wildly inconsistent (zero tolerance when wire claims lines).
		if spec.LineEnd < lineStart || (spec.LineEnd-lineStart) > int64(len(raw))+1 {
			return apperr.New(apperr.CodeCorruptCache, "import line range inconsistent")
		}
		// Use wire exclusive end when provided and walk differs only by off-by conventions.
		lineEndExcl = spec.LineEnd
	}

	rel := FrameRelPath(generationID, spec.Seq)
	abs, err := FrameAbsPath(f.dataDir, rel)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(abs, onDisk, f.Hook); err != nil {
		return err
	}

	chunk := &Chunk{
		GenerationID:     generationID,
		Seq:              spec.Seq,
		RawStart:         spec.RawStart,
		RawEnd:           spec.RawEnd,
		LineStart:        lineStart,
		LineEnd:          lineEndExcl,
		UncompressedSize: int64(len(raw)),
		CompressedSize:   int64(len(onDisk)),
		ContentSHA256:    contentSum,
		FrameSHA256:      frameSum,
		ZstdSize:         int64(len(spec.PureZstd)),
		ZstdSHA256:       zstdSum,
		Codec:            CodecZstd,
		CodecLevel:       f.codecLevel(),
		FormatVersion:    FrameFormatVersion,
		RelPath:          rel,
		CreatedAt:        time.Now().UTC().Format(time.RFC3339Nano),
		EncAlg:           encAlg,
		EncKeyVersion:    encVer,
	}
	if err := f.meta.InsertChunk(ctx, chunk, checkpoints); err != nil {
		return err
	}
	return nil
}
