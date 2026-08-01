package redact

import (
	"bytes"
	"io"
	"os"
	"sync"
)

// maxPendingLineDefault is the maximum incomplete line held across Writes
// before a forced redacted flush (no '\n'). Log lines are far smaller; the cap
// bounds memory if a non-line-oriented caller streams without newlines.
const maxPendingLineDefault = 256 << 10 // 256 KiB

// forceFlushCarry is the trailing window kept unflushed when force-flushing
// pending without a newline (Wave 34 / KD-004 residual). A secret that straddles
// the size boundary can rejoin on the next Write when the carry is prepended.
// Typical API tokens fit well under this window. Residual: secrets longer than
// the carry window may still false-negative if repeated force-flushes without
// '\n' slice them into sub-threshold fragments.
const forceFlushCarry = 256

// Writer is an io.Writer that applies RedactText to complete lines before
// forwarding to the underlying writer. Use as:
//
//	log.SetOutput(redact.NewWriter(os.Stderr))
//
// so accidental token prints via the standard library logger are scrubbed (KD-004).
//
// Line buffering (Wave 33 / KD-004 residual): incomplete data after the last
// '\n' is held until a later Write completes the line, or until Flush/Close.
// Complete lines (including the terminating '\n') are redacted with RedactText
// (labeled detectors + bare high-entropy) before the underlying write.
//
// Force-flush carry (Wave 34 / KD-004 residual): when pending without '\n'
// exceeds the pending cap (default 256 KiB), the Writer redacts and writes the
// prefix but keeps the last forceFlushCarry bytes so a secret straddling that
// boundary can rejoin on a subsequent Write. Flush/Close still redacts the
// entire remainder (including any carry). Total pending stays ≤ cap.
//
// Concurrency: Writer is safe for concurrent use. Write, Flush, and Close share
// a mutex so line reassembly and the underlying write are serialized. Callers
// still need the underlying writer to tolerate sequential writes from one
// goroutine at a time (guaranteed by the mutex).
//
// On success Write always returns n == len(p) (standard Writer contract) even
// when part or all of p is only buffered. Close flushes any remainder and marks
// the Writer closed; it does not close the underlying writer (stderr must stay
// open for process lifetime).
type Writer struct {
	mu      sync.Mutex
	w       io.Writer
	pending []byte // incomplete line (no trailing '\n'); may include force-flush carry
	closed  bool

	// maxPending overrides maxPendingLineDefault when > 0 (tests only via export_test).
	maxPending int
}

// NewWriter returns a redacting Writer wrapping w. When w is nil, os.Stderr is used.
func NewWriter(w io.Writer) *Writer {
	if w == nil {
		w = os.Stderr
	}
	return &Writer{w: w}
}

// pendingLimit returns the force-flush threshold for incomplete lines.
func (rw *Writer) pendingLimit() int {
	if rw != nil && rw.maxPending > 0 {
		return rw.maxPending
	}
	return maxPendingLineDefault
}

// Write buffers p with any incomplete prior line, redacts and forwards every
// complete line (through the last '\n'), and keeps any trailing partial line.
// On success it returns len(p) so callers such as log.Logger treat the write as
// complete even when redaction shortens the payload or data remains buffered.
func (rw *Writer) Write(p []byte) (int, error) {
	if rw == nil {
		return 0, io.ErrClosedPipe
	}
	rw.mu.Lock()
	defer rw.mu.Unlock()
	if rw.closed || rw.w == nil {
		return 0, io.ErrClosedPipe
	}
	if len(p) == 0 {
		return 0, nil
	}

	// Build combined view without mutating pending until the underlying write
	// succeeds (so a failed Write leaves the Writer retryable with the same p).
	combinedLen := len(rw.pending) + len(p)
	combined := make([]byte, combinedLen)
	copy(combined, rw.pending)
	copy(combined[len(rw.pending):], p)

	limit := rw.pendingLimit()
	lastNL := bytes.LastIndexByte(combined, '\n')
	if lastNL < 0 {
		// No complete line. Cap incomplete growth for non-line-oriented streams.
		if len(combined) > limit {
			if err := rw.forceFlushCombinedLocked(combined, limit); err != nil {
				return 0, err
			}
			return len(p), nil
		}
		rw.pending = append(rw.pending[:0], combined...)
		return len(p), nil
	}

	complete := combined[:lastNL+1]
	rest := combined[lastNL+1:]
	out := RedactText(string(complete))
	if _, err := io.WriteString(rw.w, out); err != nil {
		return 0, err
	}

	if len(rest) == 0 {
		rw.pending = rw.pending[:0]
	} else {
		rw.pending = append(rw.pending[:0], rest...)
	}

	// Bound remainder after a successful complete-line write (carry window).
	if len(rw.pending) > limit {
		if err := rw.forceFlushPendingLocked(limit); err != nil {
			// Complete lines already left; remainder still in pending if flush
			// failed to write (forceFlushPendingLocked only updates on success).
			return 0, err
		}
	}
	return len(p), nil
}

// Flush redacts and writes any incomplete line held in the buffer (full flush,
// including any force-flush carry — end of stream has no further rejoin).
// Safe for concurrent use with Write/Close.
func (rw *Writer) Flush() error {
	if rw == nil {
		return io.ErrClosedPipe
	}
	rw.mu.Lock()
	defer rw.mu.Unlock()
	if rw.closed || rw.w == nil {
		return io.ErrClosedPipe
	}
	return rw.flushPendingLocked()
}

// Close flushes any buffered remainder and marks the Writer closed.
// Further Write/Flush calls return io.ErrClosedPipe.
// Close does not close the underlying writer (e.g. os.Stderr).
func (rw *Writer) Close() error {
	if rw == nil {
		return io.ErrClosedPipe
	}
	rw.mu.Lock()
	defer rw.mu.Unlock()
	if rw.closed {
		return nil
	}
	if err := rw.flushPendingLocked(); err != nil {
		// Leave open so Close can be retried; pending still holds the remainder.
		return err
	}
	rw.closed = true
	return nil
}

// flushPendingLocked redacts and writes the entire pending buffer without
// requiring a newline. Clears pending only after a successful write.
// Used by Flush/Close (no carry retained). Caller must hold rw.mu.
func (rw *Writer) flushPendingLocked() error {
	if len(rw.pending) == 0 {
		return nil
	}
	out := RedactText(string(rw.pending))
	if _, err := io.WriteString(rw.w, out); err != nil {
		return err
	}
	rw.pending = rw.pending[:0]
	return nil
}

// forceFlushPendingLocked force-flushes rw.pending with a carry tail when
// len(pending) > limit. Caller must hold rw.mu.
func (rw *Writer) forceFlushPendingLocked(limit int) error {
	if len(rw.pending) <= limit {
		return nil
	}
	return rw.forceFlushCombinedLocked(rw.pending, limit)
}

// forceFlushCombinedLocked redacts and writes the prefix of buf, keeping a
// trailing carry window in rw.pending so secrets straddling the size boundary
// can rejoin on the next Write. Always makes progress (at least one byte
// flushed when buf is non-empty). Caller must hold rw.mu.
func (rw *Writer) forceFlushCombinedLocked(buf []byte, limit int) error {
	if len(buf) == 0 {
		rw.pending = rw.pending[:0]
		return nil
	}
	prefix, carry := forceFlushSplit(buf, limit)
	if len(prefix) > 0 {
		out := RedactText(string(prefix))
		if _, err := io.WriteString(rw.w, out); err != nil {
			return err
		}
	}
	rw.pending = append(rw.pending[:0], carry...)
	return nil
}

// forceFlushSplit returns the prefix to redact+write and the carry tail to keep.
// keep is min(forceFlushCarry, limit, len(buf)-1) so we always flush at least
// one byte when buf is non-empty and pending after is ≤ limit.
func forceFlushSplit(buf []byte, limit int) (prefix, carry []byte) {
	if len(buf) == 0 {
		return nil, nil
	}
	if limit <= 0 {
		limit = maxPendingLineDefault
	}
	keep := forceFlushCarry
	if keep > limit {
		keep = limit
	}
	if keep >= len(buf) {
		// Must make progress under the size cap.
		keep = len(buf) - 1
	}
	if keep < 0 {
		keep = 0
	}
	return buf[:len(buf)-keep], buf[len(buf)-keep:]
}
