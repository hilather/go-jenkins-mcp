package redact

// Test-only exports for white-box Writer force-flush / carry-window tests.
// Available to external tests as redact.MaxPendingLineDefault etc. (export_test
// is compiled only with package tests).

// MaxPendingLineDefault is the production force-flush pending cap (bytes).
const MaxPendingLineDefault = maxPendingLineDefault

// ForceFlushCarry is the trailing carry window kept on size force-flush.
const ForceFlushCarry = forceFlushCarry

// SetMaxPendingLineForTest sets a per-Writer pending cap for force-flush tests.
// When n <= 0, the production default is restored for that Writer.
// Safe under t.Parallel: only the given Writer is affected.
func SetMaxPendingLineForTest(w *Writer, n int) {
	if w == nil {
		return
	}
	w.mu.Lock()
	w.maxPending = n
	w.mu.Unlock()
}

// PendingLenForTest returns the current pending buffer length (under lock).
func PendingLenForTest(w *Writer) int {
	if w == nil {
		return 0
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.pending)
}

// ForceFlushSplitForTest exposes forceFlushSplit for unit tests of the split.
func ForceFlushSplitForTest(buf []byte, limit int) (prefix, carry []byte) {
	return forceFlushSplit(buf, limit)
}
