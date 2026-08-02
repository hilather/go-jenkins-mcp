package store

import (
	"context"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Frames is the L1 independent Zstandard frame store for one profile data dir.
// It buffers progressive bytes, cuts newline-aware frames, crash-safely commits
// them (STO-004), and records metadata (STO-003). Bounded reads are on LogReader.
//
// Dictionaries are not used: every frame is independently decodable with no
// cross-frame entropy tables (architecture KD 6–7 / ADR 0005).
//
// Optional ARC-009 AEAD: when Crypto is set, compressed frame bytes are sealed
// before the atomic write; metadata records enc_alg / enc_key_version only.
type Frames struct {
	meta    *Meta
	dataDir string

	// TargetBytes is the uncompressed cut target (default 8 MiB).
	TargetBytes int
	// MaxBytes is the hard uncompressed cap (default MaxFrameBytes).
	MaxBytes int
	// CodecLevel is the zstd level (default DefaultCodecLevel).
	CodecLevel int
	// Hook optional fault-injection for crash tests (STO-004).
	Hook CommitHook
	// Crypto optional AEAD for L1 frames (ARC-009). Nil = plaintext (default).
	Crypto *FrameCrypto

	mu    sync.Mutex
	open  map[int64]*openGen // generation_id → buffer state
	enc   *zstd.Encoder
	encMu sync.Mutex
}

// openGen holds in-process buffer state for one generation.
//
// Line model:
//   - lineAtRawStart = 0-based line index of buf[0] / next byte at rawStart
//   - after each '\n', the following byte starts line+1
//   - Chunk.LineStart = line of first raw byte
//   - Chunk.LineEnd   = line index of last raw byte + 1 (exclusive lines touched)
//   - next frame's lineAtRawStart = line of last raw byte if no trailing '\n',
//     else that + 1 (i.e. the line after the newline)
//
// Cursor after frame (for cold open) is stored as line_end in SQLite using the
// exclusive-touched convention; firstIsLineStart is recovered by reading the
// last byte of the previous frame file only when needed — for the hot path we
// keep prevEndedNL in memory.
type openGen struct {
	generationID   int64
	buf            []byte
	rawStart       int64
	durableEnd     int64
	nextSeq        int
	lineAtRawStart int64
	prevEndedNL    bool // true at generation start or after a frame ending in '\n'
}

// NewFrames builds a Frames store. Call Recover on startup before Append.
func NewFrames(meta *Meta, dataDir string) (*Frames, error) {
	if meta == nil {
		return nil, apperr.New(apperr.CodeInvalidArgument, "meta is required")
	}
	dataDir, err := cleanDataPath(dataDir)
	if err != nil {
		return nil, err
	}
	if err := EnsureDir(dataDir); err != nil {
		return nil, err
	}
	enc, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(DefaultCodecLevel)),
		zstd.WithEncoderCRC(true),
	)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "failed to create zstd encoder", err)
	}
	return &Frames{
		meta:        meta,
		dataDir:     dataDir,
		TargetBytes: DefaultTargetFrameBytes,
		MaxBytes:    MaxFrameBytes,
		CodecLevel:  DefaultCodecLevel,
		open:        make(map[int64]*openGen),
		enc:         enc,
	}, nil
}

// DataDir returns the profile data directory.
func (f *Frames) DataDir() string {
	if f == nil {
		return ""
	}
	return f.dataDir
}

// Close releases encoder resources.
func (f *Frames) Close() error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.enc != nil {
		_ = f.enc.Close()
		f.enc = nil
	}
	f.open = nil
	return nil
}

// AppendResult describes durable progress after Append/Flush.
type AppendResult struct {
	// DurableEnd is the exclusive raw offset of committed frames (files + SQLite).
	DurableEnd int64
	// AcceptedEnd is DurableEnd + uncommitted buffer length (in-process only).
	AcceptedEnd int64
	// FramesCommitted is how many new frames were written in this call.
	FramesCommitted int
}

// Append buffers raw progressive bytes and commits full frames when the target
// is reached. It does not update log_generations offsets; the caller must advance
// jenkins_offset only to DurableEnd (frame → chunk meta → generation offset).
func (f *Frames) Append(ctx context.Context, generationID int64, data []byte) (AppendResult, error) {
	if f == nil {
		return AppendResult{}, apperr.New(apperr.CodeInternal, "frames store is nil")
	}
	if generationID <= 0 {
		return AppendResult{}, apperr.New(apperr.CodeInvalidArgument, "generation_id is required")
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	og, err := f.ensureOpenLocked(ctx, generationID)
	if err != nil {
		return AppendResult{}, err
	}
	if len(data) == 0 {
		return f.resultLocked(og), nil
	}
	og.buf = append(og.buf, data...)
	committed := 0
	for {
		cut := findNewlineCut(og.buf, f.target(), f.max())
		if cut < 0 {
			break
		}
		if err := f.commitSliceLocked(ctx, og, cut); err != nil {
			res := f.resultLocked(og)
			res.FramesCommitted = committed
			return res, err
		}
		committed++
	}
	res := f.resultLocked(og)
	res.FramesCommitted = committed
	return res, nil
}

// Flush commits any buffered bytes as a (possibly small) final frame.
func (f *Frames) Flush(ctx context.Context, generationID int64) (AppendResult, error) {
	if f == nil {
		return AppendResult{}, apperr.New(apperr.CodeInternal, "frames store is nil")
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	og, err := f.ensureOpenLocked(ctx, generationID)
	if err != nil {
		return AppendResult{}, err
	}
	committed := 0
	if len(og.buf) > 0 {
		if err := f.commitSliceLocked(ctx, og, len(og.buf)); err != nil {
			return f.resultLocked(og), err
		}
		committed = 1
	}
	res := f.resultLocked(og)
	res.FramesCommitted = committed
	return res, nil
}

// Forget drops in-process buffer state for a generation (abandon / new gen).
// Does not delete committed frames on disk.
func (f *Frames) Forget(generationID int64) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.open, generationID)
}

// AcceptedEnd returns durable end + buffer length for a generation.
func (f *Frames) AcceptedEnd(ctx context.Context, generationID int64) (int64, error) {
	if f == nil {
		return 0, apperr.New(apperr.CodeInternal, "frames store is nil")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if og, ok := f.open[generationID]; ok {
		return og.rawStart + int64(len(og.buf)), nil
	}
	return f.meta.DurableRawEnd(ctx, generationID)
}

// DurableEnd returns the exclusive end of committed frames.
func (f *Frames) DurableEnd(ctx context.Context, generationID int64) (int64, error) {
	if f == nil {
		return 0, apperr.New(apperr.CodeInternal, "frames store is nil")
	}
	f.mu.Lock()
	if og, ok := f.open[generationID]; ok {
		end := og.durableEnd
		f.mu.Unlock()
		return end, nil
	}
	f.mu.Unlock()
	return f.meta.DurableRawEnd(ctx, generationID)
}

func (f *Frames) target() int {
	t := f.TargetBytes
	if t <= 0 {
		return DefaultTargetFrameBytes
	}
	if t < MinTargetFrameBytes {
		return MinTargetFrameBytes
	}
	return t
}

func (f *Frames) max() int {
	m := f.MaxBytes
	if m <= 0 {
		return MaxFrameBytes
	}
	if m < f.target() {
		return f.target()
	}
	return m
}

func (f *Frames) resultLocked(og *openGen) AppendResult {
	return AppendResult{
		DurableEnd:  og.durableEnd,
		AcceptedEnd: og.rawStart + int64(len(og.buf)),
	}
}

func (f *Frames) ensureOpenLocked(ctx context.Context, generationID int64) (*openGen, error) {
	if og, ok := f.open[generationID]; ok {
		return og, nil
	}
	durable, err := f.meta.DurableRawEnd(ctx, generationID)
	if err != nil {
		return nil, err
	}
	seq, err := f.meta.NextChunkSeq(ctx, generationID)
	if err != nil {
		return nil, err
	}
	og := &openGen{
		generationID: generationID,
		rawStart:     durable,
		durableEnd:   durable,
		nextSeq:      seq,
		prevEndedNL:  true, // empty generation: first byte starts line 0
	}
	if durable > 0 {
		chunks, err := f.meta.ListChunks(ctx, generationID)
		if err != nil {
			return nil, err
		}
		if len(chunks) > 0 {
			last := chunks[len(chunks)-1]
			// Recover line cursor + prevEndedNL from last frame file last byte.
			endedNL, lineOfNext, err := f.lineCursorAfterChunk(ctx, last)
			if err != nil {
				return nil, err
			}
			og.prevEndedNL = endedNL
			og.lineAtRawStart = lineOfNext
		}
	}
	f.open[generationID] = og
	return og, nil
}

// SetCrypto installs optional AEAD configuration (ARC-009). Nil disables.
func (f *Frames) SetCrypto(c *FrameCrypto) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Crypto = c
}

// lineCursorAfterChunk returns whether the chunk ended with '\n' and the line
// index for the next byte after raw_end.
func (f *Frames) lineCursorAfterChunk(ctx context.Context, c Chunk) (endedNL bool, lineOfNext int64, err error) {
	raw, err := decompressChunkFile(f.dataDir, c, f.Crypto)
	if err != nil {
		return false, 0, err
	}
	if len(raw) == 0 {
		return true, c.LineStart, nil
	}
	endedNL = raw[len(raw)-1] == '\n'
	if endedNL {
		return true, c.LineEnd, nil
	}
	return false, c.LineEnd - 1, nil
}

func (f *Frames) commitSliceLocked(ctx context.Context, og *openGen, n int) error {
	if n <= 0 || n > len(og.buf) {
		return apperr.New(apperr.CodeInternal, "invalid frame cut")
	}
	raw := make([]byte, n)
	copy(raw, og.buf[:n])

	lineStart := og.lineAtRawStart
	firstIsLineStart := og.prevEndedNL || og.rawStart == 0
	checkpoints, lineEndExcl, nextLineAt, endedNL := walkLines(raw, og.rawStart, lineStart, firstIsLineStart)

	contentSum := sha256Hex(raw)
	compressed, err := f.compress(raw)
	if err != nil {
		return err
	}
	// ARC-009: optionally seal compressed bytes; FrameSHA256 covers on-disk envelope.
	onDisk, encAlg, encVer, err := f.Crypto.sealCompressed(og.generationID, og.nextSeq, FrameFormatVersion, compressed)
	if err != nil {
		return err
	}
	frameSum := sha256Hex(onDisk)

	rel := FrameRelPath(og.generationID, og.nextSeq)
	abs, err := FrameAbsPath(f.dataDir, rel)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(abs, onDisk, f.Hook); err != nil {
		return err
	}

	chunk := &Chunk{
		GenerationID:     og.generationID,
		Seq:              og.nextSeq,
		RawStart:         og.rawStart,
		RawEnd:           og.rawStart + int64(n),
		LineStart:        lineStart,
		LineEnd:          lineEndExcl,
		UncompressedSize: int64(n),
		CompressedSize:   int64(len(onDisk)),
		ContentSHA256:    contentSum,
		FrameSHA256:      frameSum,
		Codec:            CodecZstd,
		CodecLevel:       f.codecLevel(),
		FormatVersion:    FrameFormatVersion,
		RelPath:          rel,
		CreatedAt:        time.Now().UTC().Format(time.RFC3339Nano),
		EncAlg:           encAlg,
		EncKeyVersion:    encVer,
	}
	if err := f.meta.InsertChunk(ctx, chunk, checkpoints); err != nil {
		// Frame file durable; meta missing → Recover reclaims orphan file.
		return err
	}

	og.buf = og.buf[n:]
	og.rawStart += int64(n)
	og.durableEnd = og.rawStart
	og.nextSeq++
	og.lineAtRawStart = nextLineAt
	og.prevEndedNL = endedNL
	return nil
}

func (f *Frames) codecLevel() int {
	if f.CodecLevel == 0 {
		return DefaultCodecLevel
	}
	return f.CodecLevel
}

func (f *Frames) compress(raw []byte) ([]byte, error) {
	f.encMu.Lock()
	defer f.encMu.Unlock()
	if f.enc == nil {
		enc, err := zstd.NewWriter(nil,
			zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(f.codecLevel())),
			zstd.WithEncoderCRC(true),
		)
		if err != nil {
			return nil, apperr.Wrap(apperr.CodeInternal, "failed to create zstd encoder", err)
		}
		f.enc = enc
	}
	return f.enc.EncodeAll(raw, make([]byte, 0, len(raw)/2)), nil
}

// walkLines assigns line numbers to raw bytes.
//
// lineStart = line index of raw[0].
// firstIsLineStart = raw[0] begins a line (emit checkpoint).
//
// Returns:
//   - checkpoints (absolute)
//   - lineEndExcl = max line touched + 1
//   - nextLineAt = line index for the byte after raw
//   - endedNL = raw ends with '\n'
func walkLines(raw []byte, rawStart, lineStart int64, firstIsLineStart bool) (
	cps []LineCheckpoint, lineEndExcl, nextLineAt int64, endedNL bool,
) {
	if len(raw) == 0 {
		return nil, lineStart, lineStart, true
	}
	line := lineStart
	maxLine := lineStart
	if firstIsLineStart {
		cps = append(cps, LineCheckpoint{LineNo: line, RawOffset: rawStart})
	}
	newlines := 0
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\n' {
			if line > maxLine {
				maxLine = line
			}
			continue
		}
		// newline completes current line; next byte starts line+1
		if line > maxLine {
			maxLine = line
		}
		newlines++
		line++
		if i+1 < len(raw) {
			// checkpoint at start of new line inside this frame
			if newlines == 1 || line%int64(LineCheckpointInterval) == 0 {
				cps = append(cps, LineCheckpoint{
					LineNo:    line,
					RawOffset: rawStart + int64(i) + 1,
				})
			}
		}
	}
	endedNL = raw[len(raw)-1] == '\n'
	if endedNL {
		// last byte was '\n'; maxLine is the line that ended; nextLineAt = line
		// (already incremented past the completed line)
		nextLineAt = line
		lineEndExcl = line // exclusive: lines [lineStart, line)
	} else {
		nextLineAt = line
		if line > maxLine {
			maxLine = line
		}
		lineEndExcl = maxLine + 1
	}
	// Ensure lineEndExcl covers lineStart even for single-byte non-nl frames.
	if lineEndExcl <= lineStart {
		lineEndExcl = lineStart + 1
	}
	return cps, lineEndExcl, nextLineAt, endedNL
}
