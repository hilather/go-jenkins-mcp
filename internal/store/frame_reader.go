package store

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/klauspost/compress/zstd"
	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// ReadResult is a bounded local read from L1 frames (LOG-003).
//
// UTF-8: ranges are raw byte evidence; multi-byte runes may be split at
// range boundaries. Callers that need valid UTF-8 should expand to rune
// boundaries. Raw bytes remain authoritative for evidence handles.
type ReadResult struct {
	Data []byte

	Generation   int64
	GenerationID int64

	// RawStart/RawEnd are the absolute generation offsets of Data (exclusive end).
	RawStart int64
	RawEnd   int64

	// LineStart/LineEnd describe lines when the read was line-oriented;
	// for pure byte ranges they may be zero if not computed.
	LineStart int64
	LineEnd   int64

	// RequestedBytes is the logical length asked for (before EOF clamp).
	RequestedBytes int64
	// DecompressedBytes is total uncompressed bytes decoded from frames
	// (may exceed len(Data) when only a slice of a frame is returned).
	DecompressedBytes int64
	// FramesOpened is the number of independent frames decompressed.
	FramesOpened int

	// ContentSHA256 lists content checksums of frames opened (evidence).
	ContentSHA256 []string
	// Sealed reports whether the generation is sealed.
	Sealed bool
}

// LogReader serves byte/line range and tail reads from committed frames only
// (uncommitted in-process buffers are invisible — crash-safe view).
type LogReader struct {
	meta    *Meta
	dataDir string
	// crypto optional AEAD keys for encrypted frames (ARC-009).
	crypto *FrameCrypto
}

// NewLogReader builds a reader over the same dataDir/meta as Frames.
func NewLogReader(meta *Meta, dataDir string) (*LogReader, error) {
	if meta == nil {
		return nil, apperr.New(apperr.CodeInvalidArgument, "meta is required")
	}
	dataDir, err := cleanDataPath(dataDir)
	if err != nil {
		return nil, err
	}
	return &LogReader{meta: meta, dataDir: dataDir}, nil
}

// SetCrypto installs optional AEAD keys for reading encrypted frames.
func (r *LogReader) SetCrypto(c *FrameCrypto) {
	if r == nil {
		return
	}
	r.crypto = c
}

// Reader returns a LogReader over this Frames store (inherits Crypto).
func (f *Frames) Reader() (*LogReader, error) {
	if f == nil {
		return nil, apperr.New(apperr.CodeInternal, "frames store is nil")
	}
	r, err := NewLogReader(f.meta, f.dataDir)
	if err != nil {
		return nil, err
	}
	r.crypto = f.Crypto
	return r, nil
}

// ReadRange returns up to length bytes starting at absolute raw offset start
// for the given generation. Only intersecting frames are decompressed.
func (r *LogReader) ReadRange(ctx context.Context, generationID int64, start, length int64) (ReadResult, error) {
	if r == nil {
		return ReadResult{}, apperr.New(apperr.CodeInternal, "log reader is nil")
	}
	if generationID <= 0 {
		return ReadResult{}, apperr.New(apperr.CodeInvalidArgument, "generation_id is required")
	}
	if start < 0 {
		return ReadResult{}, apperr.New(apperr.CodeInvalidArgument, "start must be non-negative")
	}
	if length < 0 {
		return ReadResult{}, apperr.New(apperr.CodeInvalidArgument, "length must be non-negative")
	}
	res := ReadResult{
		GenerationID:   generationID,
		RequestedBytes: length,
		RawStart:       start,
	}
	if length == 0 {
		res.RawEnd = start
		return res, nil
	}
	end := start + length
	chunks, err := r.meta.ChunksIntersectingRaw(ctx, generationID, start, end)
	if err != nil {
		return res, err
	}
	if len(chunks) == 0 {
		// May be past durable end.
		durable, err := r.meta.DurableRawEnd(ctx, generationID)
		if err != nil {
			return res, err
		}
		if start >= durable {
			res.RawEnd = start
			return res, nil
		}
		return res, apperr.New(apperr.CodeCorruptCache, "missing frames for requested range")
	}

	var out bytes.Buffer
	for _, c := range chunks {
		raw, err := r.decompressChunk(ctx, c)
		if err != nil {
			return res, err
		}
		res.DecompressedBytes += int64(len(raw))
		res.FramesOpened++
		res.ContentSHA256 = append(res.ContentSHA256, c.ContentSHA256)

		// Slice intersection of [c.RawStart, c.RawEnd) with [start, end).
		lo := start
		if c.RawStart > lo {
			lo = c.RawStart
		}
		hi := end
		if c.RawEnd < hi {
			hi = c.RawEnd
		}
		if hi <= lo {
			continue
		}
		from := int(lo - c.RawStart)
		to := int(hi - c.RawStart)
		if from < 0 || to > len(raw) || from > to {
			return res, apperr.New(apperr.CodeCorruptCache,
				fmt.Sprintf("frame %d size mismatch: meta %d file %d", c.Seq, c.UncompressedSize, len(raw)))
		}
		out.Write(raw[from:to])
	}
	res.Data = out.Bytes()
	res.RawEnd = start + int64(len(res.Data))
	return res, nil
}

// ReadLineRange returns lines in [startLine, startLine+lineCount) (0-based).
// Line boundaries are '\n'-delimited. The last line of a log may lack a trailing newline.
func (r *LogReader) ReadLineRange(ctx context.Context, generationID int64, startLine, lineCount int64) (ReadResult, error) {
	if r == nil {
		return ReadResult{}, apperr.New(apperr.CodeInternal, "log reader is nil")
	}
	if generationID <= 0 {
		return ReadResult{}, apperr.New(apperr.CodeInvalidArgument, "generation_id is required")
	}
	if startLine < 0 {
		return ReadResult{}, apperr.New(apperr.CodeInvalidArgument, "startLine must be non-negative")
	}
	if lineCount < 0 {
		return ReadResult{}, apperr.New(apperr.CodeInvalidArgument, "lineCount must be non-negative")
	}
	res := ReadResult{
		GenerationID:   generationID,
		LineStart:      startLine,
		RequestedBytes: 0, // filled after extract
	}
	if lineCount == 0 {
		res.LineEnd = startLine
		return res, nil
	}
	endLine := startLine + lineCount
	chunks, err := r.meta.ChunksIntersectingLines(ctx, generationID, startLine, endLine)
	if err != nil {
		return res, err
	}
	if len(chunks) == 0 {
		res.LineEnd = startLine
		return res, nil
	}

	// Decompress intersecting frames and extract lines by absolute line index.
	type seg struct {
		raw      []byte
		rawStart int64
		line0    int64
	}
	var segs []seg
	for _, c := range chunks {
		raw, err := r.decompressChunk(ctx, c)
		if err != nil {
			return res, err
		}
		res.DecompressedBytes += int64(len(raw))
		res.FramesOpened++
		res.ContentSHA256 = append(res.ContentSHA256, c.ContentSHA256)
		segs = append(segs, seg{raw: raw, rawStart: c.RawStart, line0: c.LineStart})
	}

	var (
		out       bytes.Buffer
		curLine   = segs[0].line0
		lineBuf   bytes.Buffer
		emitted   int64
		firstEmit       = true
		rawStart  int64 = -1
		rawEnd    int64
	)
	flushLine := func(absEnd int64) {
		if curLine >= startLine && curLine < endLine {
			if firstEmit {
				rawStart = absEnd - int64(lineBuf.Len())
				firstEmit = false
			}
			out.Write(lineBuf.Bytes())
			rawEnd = absEnd
			emitted++
		}
		lineBuf.Reset()
		curLine++
	}

	for _, s := range segs {
		for i := 0; i < len(s.raw); i++ {
			b := s.raw[i]
			lineBuf.WriteByte(b)
			if b == '\n' {
				flushLine(s.rawStart + int64(i) + 1)
				if curLine >= endLine {
					goto done
				}
			}
		}
	}
	// Final line without trailing newline.
	if lineBuf.Len() > 0 {
		last := segs[len(segs)-1]
		flushLine(last.rawStart + int64(len(last.raw)))
	}
done:
	res.Data = out.Bytes()
	res.LineEnd = startLine + emitted
	res.RequestedBytes = int64(len(res.Data))
	if rawStart >= 0 {
		res.RawStart = rawStart
		res.RawEnd = rawEnd
	}
	return res, nil
}

// TailBytes returns the last n raw bytes of the generation (clamped to durable size).
func (r *LogReader) TailBytes(ctx context.Context, generationID int64, n int64) (ReadResult, error) {
	if n < 0 {
		return ReadResult{}, apperr.New(apperr.CodeInvalidArgument, "n must be non-negative")
	}
	durable, err := r.meta.DurableRawEnd(ctx, generationID)
	if err != nil {
		return ReadResult{}, err
	}
	if durable == 0 || n == 0 {
		return ReadResult{GenerationID: generationID, RequestedBytes: n}, nil
	}
	start := durable - n
	if start < 0 {
		start = 0
	}
	return r.ReadRange(ctx, generationID, start, durable-start)
}

// TailLines returns the last n lines of the generation.
func (r *LogReader) TailLines(ctx context.Context, generationID int64, n int64) (ReadResult, error) {
	if n < 0 {
		return ReadResult{}, apperr.New(apperr.CodeInvalidArgument, "n must be non-negative")
	}
	if n == 0 {
		return ReadResult{GenerationID: generationID}, nil
	}
	chunks, err := r.meta.ListChunks(ctx, generationID)
	if err != nil {
		return ReadResult{}, err
	}
	if len(chunks) == 0 {
		return ReadResult{GenerationID: generationID}, nil
	}
	// Total lines ≈ last.LineEnd (exclusive), but last line without NL still counted.
	last := chunks[len(chunks)-1]
	totalLines := last.LineEnd
	// If last frame does not end mid empty, LineEnd is correct exclusive count.
	startLine := totalLines - n
	if startLine < 0 {
		startLine = 0
	}
	// Only decompress from the first chunk that can contain startLine — already
	// handled by ReadLineRange via ChunksIntersectingLines.
	return r.ReadLineRange(ctx, generationID, startLine, n)
}

func (r *LogReader) decompressChunk(ctx context.Context, c Chunk) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return decompressChunkFile(r.dataDir, c, r.crypto)
}

// OpenFrameCompressed reads, verifies checksum, and decrypts to pure zstd bytes.
// Plaintext frames return the on-disk bytes unchanged. Used by L2 pack copy path.
func OpenFrameCompressed(dataDir string, c Chunk, crypto *FrameCrypto) ([]byte, error) {
	abs, err := FrameAbsPath(dataDir, c.RelPath)
	if err != nil {
		return nil, err
	}
	onDisk, err := os.ReadFile(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, apperr.Wrap(apperr.CodeCorruptCache, "frame file missing", err)
		}
		return nil, apperr.Wrap(apperr.CodeInternal, "failed to read frame file", err)
	}
	if c.FrameSHA256 != "" {
		if got := sha256Hex(onDisk); got != c.FrameSHA256 {
			return nil, apperr.New(apperr.CodeCorruptCache,
				fmt.Sprintf("frame checksum mismatch seq=%d", c.Seq))
		}
	}
	fv := c.FormatVersion
	if fv == 0 {
		fv = FrameFormatVersion
	}
	return crypto.openToCompressed(c.GenerationID, c.Seq, fv, onDisk, c.EncKeyVersion)
}

// decompressChunkFile reads, verifies, decrypts (optional), and decompresses one frame.
func decompressChunkFile(dataDir string, c Chunk, crypto *FrameCrypto) ([]byte, error) {
	zstdBytes, err := OpenFrameCompressed(dataDir, c, crypto)
	if err != nil {
		return nil, err
	}
	dec, err := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(64<<20))
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "failed to create zstd decoder", err)
	}
	defer dec.Close()
	raw, err := dec.DecodeAll(zstdBytes, make([]byte, 0, c.UncompressedSize))
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeCorruptCache, "zstd decompress failed", err)
	}
	if c.UncompressedSize > 0 && int64(len(raw)) != c.UncompressedSize {
		return nil, apperr.New(apperr.CodeCorruptCache,
			fmt.Sprintf("uncompressed size mismatch seq=%d: got %d want %d", c.Seq, len(raw), c.UncompressedSize))
	}
	if c.ContentSHA256 != "" {
		if got := sha256Hex(raw); got != c.ContentSHA256 {
			return nil, apperr.New(apperr.CodeCorruptCache,
				fmt.Sprintf("content checksum mismatch seq=%d", c.Seq))
		}
	}
	return raw, nil
}

// DecompressZstdFrame decodes pure independent zstd frame bytes (no AEAD).
func DecompressZstdFrame(zstdBytes []byte) ([]byte, error) {
	if len(zstdBytes) >= 4 && string(zstdBytes[:4]) == "JME1" {
		return nil, apperr.New(apperr.CodeAuthentication,
			"encrypted frame requires cache key (use OpenFrameCompressed)")
	}
	dec, err := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(64<<20))
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	return dec.DecodeAll(zstdBytes, nil)
}

// DecompressFrameFile is a test/helper that decodes one independent plaintext
// zstd frame file. Encrypted envelopes require OpenFrameCompressed + keys.
func DecompressFrameFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return DecompressZstdFrame(b)
}
