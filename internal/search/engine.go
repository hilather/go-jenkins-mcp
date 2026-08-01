package search

import (
	"bytes"
	"context"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/store"
)

// Engine runs bounded literal/regex search over L1 frames for one profile data dir.
type Engine struct {
	meta   *store.Meta
	reader *store.LogReader
}

// New builds an Engine over the same Meta/dataDir as the frames store.
func New(meta *store.Meta, dataDir string) (*Engine, error) {
	if meta == nil {
		return nil, apperr.New(apperr.CodeInvalidArgument, "meta is required")
	}
	reader, err := store.NewLogReader(meta, dataDir)
	if err != nil {
		return nil, err
	}
	return &Engine{meta: meta, reader: reader}, nil
}

// NewWithReader builds an Engine with a pre-built LogReader (e.g. from Frames.Reader).
func NewWithReader(meta *store.Meta, reader *store.LogReader) (*Engine, error) {
	if meta == nil {
		return nil, apperr.New(apperr.CodeInvalidArgument, "meta is required")
	}
	if reader == nil {
		return nil, apperr.New(apperr.CodeInvalidArgument, "log reader is required")
	}
	return &Engine{meta: meta, reader: reader}, nil
}

// Resolve maps a Query to its generation Scope without opening L1 frames.
// generation_id wins over profile/job/build. Callers (jenkins_search_logs)
// use this to re-evaluate deny_job_prefixes before scanning.
func (e *Engine) Resolve(ctx context.Context, q Query) (Scope, error) {
	if e == nil || e.meta == nil {
		return Scope{}, apperr.New(apperr.CodeInternal, "search engine is not configured")
	}
	if err := ctx.Err(); err != nil {
		return Scope{}, mapCtxErr(err)
	}
	gen, err := e.resolveGeneration(ctx, q)
	if err != nil {
		return Scope{}, err
	}
	if gen == nil {
		return Scope{}, apperr.New(apperr.CodeNotFound, "log generation not found")
	}
	return Scope{
		GenerationID: gen.ID,
		Generation:   gen.Generation,
		Profile:      gen.Profile,
		Job:          gen.Job,
		Build:        gen.Build,
		Sealed:       gen.Sealed,
	}, nil
}

// Search executes a bounded line-oriented search. Only frames belonging to the
// resolved generation are opened, in seq order. Cancellation is checked between
// frames and every cancelCheckEveryNLines lines.
func (e *Engine) Search(ctx context.Context, q Query) (Result, error) {
	if e == nil || e.meta == nil || e.reader == nil {
		return Result{}, apperr.New(apperr.CodeInternal, "search engine is not configured")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, mapCtxErr(err)
	}

	q = normalizeQuery(q)
	gen, err := e.resolveGeneration(ctx, q)
	if err != nil {
		return Result{}, err
	}
	if gen == nil {
		return Result{}, apperr.New(apperr.CodeNotFound, "log generation not found")
	}

	m, err := buildMatcher(q)
	if err != nil {
		return Result{}, err
	}

	res := Result{
		GenerationID:    gen.ID,
		Generation:      gen.Generation,
		Profile:         gen.Profile,
		Job:             gen.Job,
		Build:           gen.Build,
		Sealed:          gen.Sealed,
		BytesScannedCap: q.MaxBytesScanned,
		MaxMatches:      q.MaxMatches,
	}

	chunks, err := e.meta.ListChunks(ctx, gen.ID)
	if err != nil {
		return res, err
	}

	var (
		beforeRing = newLineRing(q.Before)
		// pending matches waiting for After lines
		pending []openMatch
		// carry incomplete last line across frames
		carry       []byte
		carryStart  int64 // absolute raw offset of carry start
		carryFrame  store.Chunk
		haveCarry   bool
		lineNo      int64
		linesInLoop int
		stop        bool
	)

	flushPendingAfter := func(line string) {
		still := pending[:0]
		for i := range pending {
			om := &pending[i]
			if om.needAfter > 0 {
				om.match.After = append(om.match.After, truncateSnippet(line))
				om.needAfter--
			}
			if om.needAfter > 0 {
				still = append(still, *om)
			} else {
				res.Matches = append(res.Matches, om.match)
			}
		}
		pending = still
	}

	processLine := func(line []byte, lineStart int64, frame store.Chunk) error {
		linesInLoop++
		if linesInLoop%cancelCheckEveryNLines == 0 {
			if err := ctx.Err(); err != nil {
				return mapCtxErr(err)
			}
		}
		// Strip trailing '\r' for CRLF logs (match on visual line content).
		content := bytes.TrimSuffix(line, []byte{'\r'})

		// Feed after-context for open matches before evaluating this line as a
		// new hit so a match does not appear in its own After.
		if len(pending) > 0 {
			flushPendingAfter(string(content))
		}

		// Stop accepting new matches once cap hit; still drain after-context.
		if len(res.Matches)+len(pending) < q.MaxMatches {
			if start, end, ok := m.find(content); ok {
				match := Match{
					Line:           lineNo,
					LineByteStart:  lineStart,
					MatchByteStart: lineStart + int64(start),
					MatchByteEnd:   lineStart + int64(end),
					LineText:       truncateSnippet(string(content)),
					Before:         beforeRing.snapshot(),
					FrameSeq:       frame.Seq,
					ContentSHA256:  frame.ContentSHA256,
				}
				if q.After > 0 {
					pending = append(pending, openMatch{match: match, needAfter: q.After})
				} else {
					res.Matches = append(res.Matches, match)
				}
				if len(res.Matches)+len(pending) >= q.MaxMatches {
					res.Truncated = true
				}
			}
		} else {
			res.Truncated = true
		}

		beforeRing.push(string(content))
		lineNo++
		return nil
	}

	for _, c := range chunks {
		if err := ctx.Err(); err != nil {
			return res, mapCtxErr(err)
		}
		if stop {
			break
		}
		// Budget is in uncompressed frame bytes. LogReader decompresses whole
		// independent frames (no partial zstd decode), so skip frames that would
		// exceed the remaining cap once we have already opened something.
		frameSize := c.UncompressedSize
		if frameSize <= 0 {
			frameSize = c.RawEnd - c.RawStart
		}
		if res.BytesScanned >= q.MaxBytesScanned {
			res.Incomplete = true
			stop = true
			break
		}
		if res.BytesScanned > 0 && res.BytesScanned+frameSize > q.MaxBytesScanned {
			res.Incomplete = true
			stop = true
			break
		}

		rr, err := e.reader.ReadRange(ctx, gen.ID, c.RawStart, frameSize)
		if err != nil {
			return res, err
		}
		res.FramesOpened++
		// Count full frame cost (decompress work), not only returned slice length.
		if rr.DecompressedBytes > 0 {
			res.BytesScanned += rr.DecompressedBytes
		} else {
			res.BytesScanned += int64(len(rr.Data))
		}

		raw := rr.Data
		// Prepend carry from previous frame (mid-line split).
		if haveCarry {
			buf := make([]byte, 0, len(carry)+len(raw))
			buf = append(buf, carry...)
			buf = append(buf, raw...)
			raw = buf
		}

		// Walk lines in raw.
		baseOffset := c.RawStart
		if haveCarry {
			baseOffset = carryStart
			haveCarry = false
			carry = nil
		}
		pos := 0
		for pos < len(raw) {
			if err := ctx.Err(); err != nil {
				return res, mapCtxErr(err)
			}
			nl := bytes.IndexByte(raw[pos:], '\n')
			if nl < 0 {
				// Incomplete line — carry to next frame.
				break
			}
			lineBytes := raw[pos : pos+nl] // without '\n'
			lineStart := baseOffset + int64(pos)
			if err := processLine(lineBytes, lineStart, c); err != nil {
				return res, err
			}
			pos += nl + 1
			// If match cap hit and no pending after, we can stop early.
			if res.Truncated && len(pending) == 0 {
				stop = true
				break
			}
		}
		if stop {
			break
		}
		if pos < len(raw) {
			// Carry trailing partial line to next frame.
			carry = append(carry[:0], raw[pos:]...)
			carryStart = baseOffset + int64(pos)
			carryFrame = c
			haveCarry = true
		}
	}

	// Final carry after last frame.
	if haveCarry && !stop {
		if err := processLine(carry, carryStart, carryFrame); err != nil {
			return res, err
		}
	}

	// Drain pending after-context (EOF → fewer after lines than requested).
	for _, om := range pending {
		res.Matches = append(res.Matches, om.match)
	}
	pending = nil

	// Deterministic order: already ascending by discovery order (line order).
	return res, nil
}

type openMatch struct {
	match     Match
	needAfter int
}

func (e *Engine) resolveGeneration(ctx context.Context, q Query) (*store.LogGeneration, error) {
	if q.GenerationID > 0 {
		g, err := e.meta.GetGenerationByID(ctx, q.GenerationID)
		if err != nil {
			return nil, err
		}
		return g, nil
	}
	key := store.LogKey{Profile: strings.TrimSpace(q.Profile), Job: strings.TrimSpace(q.Job), Build: q.Build}
	if err := key.Validate(); err != nil {
		return nil, err
	}
	if q.Generation > 0 {
		return e.meta.GetGeneration(ctx, key, q.Generation)
	}
	return e.meta.GetLatestGeneration(ctx, key)
}

func normalizeQuery(q Query) Query {
	if q.MaxMatches <= 0 {
		q.MaxMatches = DefaultMaxMatches
	}
	if q.MaxMatches > HardMaxMatches {
		q.MaxMatches = HardMaxMatches
	}
	if q.MaxBytesScanned <= 0 {
		q.MaxBytesScanned = DefaultMaxBytesScanned
	}
	if q.MaxBytesScanned > HardMaxBytesScanned {
		q.MaxBytesScanned = HardMaxBytesScanned
	}
	if q.Before < 0 {
		q.Before = 0
	}
	if q.After < 0 {
		q.After = 0
	}
	if q.Before > HardMaxContextLines {
		q.Before = HardMaxContextLines
	}
	if q.After > HardMaxContextLines {
		q.After = HardMaxContextLines
	}
	return q
}

func mapCtxErr(err error) error {
	if err == nil {
		return nil
	}
	if apperr.IsTimeout(err) {
		return apperr.Wrap(apperr.CodeTimeout, "search timed out", err)
	}
	// ctx.Err() is Cancelled or DeadlineExceeded; treat other values as cancel.
	return apperr.Wrap(apperr.CodeCancelled, "search cancelled", err)
}

func truncateSnippet(s string) string {
	if len(s) <= MaxSnippetBytes {
		return s
	}
	// Truncate on UTF-8 boundary when possible.
	cut := MaxSnippetBytes
	for cut > 0 && !utf8SafePrefix(s, cut) {
		cut--
	}
	return s[:cut] + "…"
}

func utf8SafePrefix(s string, n int) bool {
	if n >= len(s) {
		return true
	}
	// Valid if we are not mid-rune: top bits not 10xxxxxx.
	return s[n]&0xC0 != 0x80
}

// lineRing is a fixed-capacity FIFO of recent lines for before-context.
type lineRing struct {
	buf  []string
	cap  int
	head int
	len  int
}

func newLineRing(n int) *lineRing {
	if n <= 0 {
		return &lineRing{}
	}
	return &lineRing{buf: make([]string, n), cap: n}
}

func (r *lineRing) push(line string) {
	if r == nil || r.cap == 0 {
		return
	}
	if r.len < r.cap {
		r.buf[(r.head+r.len)%r.cap] = truncateSnippet(line)
		r.len++
		return
	}
	r.buf[r.head] = truncateSnippet(line)
	r.head = (r.head + 1) % r.cap
}

func (r *lineRing) snapshot() []string {
	if r == nil || r.len == 0 {
		return nil
	}
	out := make([]string, r.len)
	for i := 0; i < r.len; i++ {
		out[i] = r.buf[(r.head+i)%r.cap]
	}
	return out
}
