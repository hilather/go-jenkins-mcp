package redact_test

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/redact"
)

func TestWriterRedactsBearerAndAPIToken(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w := redact.NewWriter(&buf)

	const bearerCanary = "kd004-bearer-canary-token-value-xyz"
	const apiCanary = "kd004-api-token-canary-value-abc"

	n, err := w.Write([]byte("Authorization: Bearer " + bearerCanary + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if n != len("Authorization: Bearer "+bearerCanary+"\n") {
		t.Fatalf("Write returned %d, want input length", n)
	}
	_, err = w.Write([]byte("config api_token=" + apiCanary + " ok\n"))
	if err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	if strings.Contains(out, bearerCanary) {
		t.Fatalf("bearer canary leaked: %q", out)
	}
	if strings.Contains(out, apiCanary) {
		t.Fatalf("api_token canary leaked: %q", out)
	}
	if !strings.Contains(out, redact.Replacement) {
		t.Fatalf("expected redaction marker: %q", out)
	}
	// Non-secret diagnostic text preserved.
	if !strings.Contains(out, "config ") || !strings.Contains(out, " ok") {
		t.Fatalf("over-redacted: %q", out)
	}
}

func TestWriterNilUnderlyingUsesStderr(t *testing.T) {
	t.Parallel()
	w := redact.NewWriter(nil)
	if w == nil {
		t.Fatal("NewWriter(nil) must not return nil")
	}
	// Empty write is a no-op success.
	n, err := w.Write(nil)
	if err != nil || n != 0 {
		t.Fatalf("empty Write: n=%d err=%v", n, err)
	}
}

func TestWriterPreservesUsername(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w := redact.NewWriter(&buf)
	line := "Using Jenkins auth for user: alice.ops\n"
	if _, err := w.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != line {
		t.Fatalf("username line mutated: %q", got)
	}
}

// Regression KD-004: unlabeled high-entropy token on the serve log Writer path.
func TestWriterScrubsBareHighEntropyToken(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w := redact.NewWriter(&buf)
	const bare = "a1b2c3d4e5f6789012345678abcdef12deadbeef" // 40 hex
	if _, err := w.Write([]byte("debug token=" + bare + "\n")); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, bare) {
		t.Fatalf("Regression KD-004: bare hex canary in Writer output: %q", out)
	}
	if !strings.Contains(out, redact.Replacement) {
		t.Fatalf("expected marker: %q", out)
	}
}

// Regression KD-004 residual (Wave 33): secret split across two Writes must
// still be redacted after line reassembly (not per-chunk independently).
func TestWriterRedactsSecretSplitAcrossWrites(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w := redact.NewWriter(&buf)

	const bare = "a1b2c3d4e5f6789012345678abcdef12deadbeef" // 40 hex
	// First chunk: incomplete line, secret only half-present (below bare threshold).
	part1 := []byte("accidental dump " + bare[:20])
	n1, err := w.Write(part1)
	if err != nil {
		t.Fatal(err)
	}
	if n1 != len(part1) {
		t.Fatalf("Write part1 returned %d, want %d", n1, len(part1))
	}
	// Nothing should reach the underlying writer yet (no newline).
	if buf.Len() != 0 {
		t.Fatalf("expected no forward before newline; got %q", buf.String())
	}

	// Second chunk: remainder of secret + newline completes the line.
	part2 := []byte(bare[20:] + " end\n")
	n2, err := w.Write(part2)
	if err != nil {
		t.Fatal(err)
	}
	if n2 != len(part2) {
		t.Fatalf("Write part2 returned %d, want %d", n2, len(part2))
	}

	out := buf.String()
	if strings.Contains(out, bare) {
		t.Fatalf("Regression KD-004 split-chunk: bare hex canary leaked: %q", out)
	}
	if strings.Contains(out, bare[:20]) || strings.Contains(out, bare[20:]) {
		t.Fatalf("Regression KD-004 split-chunk: partial canary leaked: %q", out)
	}
	if !strings.Contains(out, redact.Replacement) {
		t.Fatalf("expected redaction marker after split Write: %q", out)
	}
	if !strings.Contains(out, "accidental dump ") || !strings.Contains(out, " end") {
		t.Fatalf("over-redacted split line: %q", out)
	}
}

// Regression KD-004 residual: labeled Bearer token split across Writes.
func TestWriterRedactsBearerSplitAcrossWrites(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w := redact.NewWriter(&buf)

	const canary = "kd004-split-bearer-canary-token-xyz"
	p1 := []byte("Authorization: Bearer " + canary[:12])
	p2 := []byte(canary[12:] + "\n")
	if n, err := w.Write(p1); err != nil || n != len(p1) {
		t.Fatalf("part1: n=%d err=%v", n, err)
	}
	if buf.Len() != 0 {
		t.Fatalf("buffered before newline: %q", buf.String())
	}
	if n, err := w.Write(p2); err != nil || n != len(p2) {
		t.Fatalf("part2: n=%d err=%v", n, err)
	}
	out := buf.String()
	if strings.Contains(out, canary) {
		t.Fatalf("split Bearer canary leaked: %q", out)
	}
	if !strings.Contains(out, redact.Replacement) {
		t.Fatalf("expected marker: %q", out)
	}
}

// Flush/Close must redact and emit the incomplete remainder (no trailing '\n').
func TestWriterFlushAndCloseRedactRemainder(t *testing.T) {
	t.Parallel()
	const bare = "a1b2c3d4e5f6789012345678abcdef12deadbeef" // 40 hex

	t.Run("Flush", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		w := redact.NewWriter(&buf)
		chunk := []byte("no-newline dump " + bare)
		if n, err := w.Write(chunk); err != nil || n != len(chunk) {
			t.Fatalf("Write: n=%d err=%v", n, err)
		}
		if buf.Len() != 0 {
			t.Fatalf("should buffer without newline: %q", buf.String())
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
		out := buf.String()
		if strings.Contains(out, bare) {
			t.Fatalf("Flush left bare canary: %q", out)
		}
		if !strings.Contains(out, redact.Replacement) {
			t.Fatalf("expected marker after Flush: %q", out)
		}
		// Second flush is a no-op.
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Close", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		w := redact.NewWriter(&buf)
		chunk := []byte("close dump " + bare)
		if _, err := w.Write(chunk); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		out := buf.String()
		if strings.Contains(out, bare) {
			t.Fatalf("Close left bare canary: %q", out)
		}
		if !strings.Contains(out, redact.Replacement) {
			t.Fatalf("expected marker after Close: %q", out)
		}
		// Further writes fail closed.
		if _, err := w.Write([]byte("after\n")); err != io.ErrClosedPipe {
			t.Fatalf("Write after Close: err=%v", err)
		}
		if err := w.Flush(); err != io.ErrClosedPipe {
			t.Fatalf("Flush after Close: err=%v", err)
		}
		// Close is idempotent.
		if err := w.Close(); err != nil {
			t.Fatalf("second Close: %v", err)
		}
	})
}

// Concurrent Writes are documented as safe; exercise interleaving of complete lines.
func TestWriterConcurrentWrites(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w := redact.NewWriter(&buf)

	const bare = "a1b2c3d4e5f6789012345678abcdef12deadbeef" // 40 hex
	const nG = 32
	const nPer = 20

	var wg sync.WaitGroup
	errCh := make(chan error, nG)
	wg.Add(nG)
	for g := 0; g < nG; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < nPer; i++ {
				// Each Write is a full line (typical log.Logger pattern).
				line := []byte(fmt.Sprintf("g=%d i=%d token=%s\n", id, i, bare))
				if n, err := w.Write(line); err != nil || n != len(line) {
					errCh <- fmt.Errorf("concurrent Write: n=%d err=%v", n, err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, bare) {
		snip := out
		if len(snip) > 200 {
			snip = snip[:200]
		}
		t.Fatalf("concurrent path leaked bare canary: %q", snip)
	}
	// Expect many redaction markers (one per line).
	if c := strings.Count(out, redact.Replacement); c < nG*nPer {
		t.Fatalf("expected >= %d markers, got %d", nG*nPer, c)
	}
}

// Multi-line single Write still redacts each line; trailing partial stays buffered.
func TestWriterMultiLineAndPartial(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w := redact.NewWriter(&buf)

	const bare = "a1b2c3d4e5f6789012345678abcdef12deadbeef"
	payload := "line1 " + bare + "\nline2 ok\npartial " + bare[:10]
	if n, err := w.Write([]byte(payload)); err != nil || n != len(payload) {
		t.Fatalf("Write: n=%d err=%v", n, err)
	}
	out := buf.String()
	if strings.Contains(out, bare) {
		t.Fatalf("complete-line canary leaked: %q", out)
	}
	if !strings.Contains(out, "line2 ok\n") {
		t.Fatalf("expected line2 preserved: %q", out)
	}
	if strings.Contains(out, "partial") {
		t.Fatalf("partial should still be buffered: %q", out)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	// After flush, partial prefix may appear (short hex half is not a secret alone).
	if !strings.Contains(buf.String(), "partial ") {
		t.Fatalf("expected flushed partial prefix: %q", buf.String())
	}
}

// forceFlushSplit always makes progress and bounds carry to min(carry, limit).
func TestForceFlushSplit(t *testing.T) {
	t.Parallel()
	// Production defaults: large buffer keeps last ForceFlushCarry bytes.
	buf := bytes.Repeat([]byte("x"), redact.MaxPendingLineDefault+10)
	prefix, carry := redact.ForceFlushSplitForTest(buf, redact.MaxPendingLineDefault)
	if len(carry) != redact.ForceFlushCarry {
		t.Fatalf("carry len=%d want %d", len(carry), redact.ForceFlushCarry)
	}
	if len(prefix)+len(carry) != len(buf) {
		t.Fatalf("split lost bytes: prefix=%d carry=%d buf=%d", len(prefix), len(carry), len(buf))
	}
	if len(prefix) == 0 {
		t.Fatal("expected non-empty prefix for oversize buffer")
	}

	// Small test limit: carry capped to limit, still progress.
	small := []byte("0123456789abcdefghij") // 20
	prefix, carry = redact.ForceFlushSplitForTest(small, 8)
	if len(carry) != 8 {
		t.Fatalf("carry len=%d want 8 (min of forceFlushCarry and limit)", len(carry))
	}
	if string(carry) != "cdefghij" {
		t.Fatalf("carry=%q", carry)
	}
	if string(prefix) != "0123456789ab" {
		t.Fatalf("prefix=%q", prefix)
	}

	// keep >= len(buf): must flush at least one byte.
	tiny := []byte("abc")
	prefix, carry = redact.ForceFlushSplitForTest(tiny, 100)
	if len(prefix) != 1 || string(prefix) != "a" {
		t.Fatalf("progress prefix=%q", prefix)
	}
	if string(carry) != "bc" {
		t.Fatalf("carry=%q", carry)
	}
}

// Regression KD-004 residual (Wave 34): force-flush of pending without '\n'
// must forward a redacted prefix and retain a carry tail (≤ forceFlushCarry /
// pending limit) so memory stays bounded.
func TestWriterForceFlushKeepsCarry(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w := redact.NewWriter(&buf)

	const limit = 48
	redact.SetMaxPendingLineForTest(w, limit)

	// No secret: pure padding past the limit. Force-flush should emit something
	// and leave pending ≤ limit (carry).
	payload := bytes.Repeat([]byte("p"), limit+20) // 68 bytes, no newline
	if n, err := w.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write: n=%d err=%v", n, err)
	}
	// Prefix was force-flushed (redact of padding is a no-op).
	if buf.Len() == 0 {
		t.Fatal("expected force-flushed prefix to reach underlying writer")
	}
	pending := redact.PendingLenForTest(w)
	if pending == 0 {
		t.Fatal("expected carry tail retained after force-flush")
	}
	if pending > limit {
		t.Fatalf("pending %d exceeds limit %d", pending, limit)
	}
	// Carry is last min(ForceFlushCarry, limit) of payload.
	wantCarry := redact.ForceFlushCarry
	if wantCarry > limit {
		wantCarry = limit
	}
	if pending != wantCarry {
		t.Fatalf("pending=%d want carry=%d", pending, wantCarry)
	}
	// Flushed text must not include the full payload (carry still held).
	if buf.Len()+pending != len(payload) {
		// RedactText of pure 'p' is identity; lengths must add up.
		t.Fatalf("flushed=%d pending=%d payload=%d", buf.Len(), pending, len(payload))
	}
}

// Regression KD-004 residual (Wave 34): secret split across the force-flush
// boundary (no '\n' in the first oversized Write) must still be redacted when a
// later Write completes the line and rejoins the carry tail.
func TestWriterForceFlushCarryRejoinsSecret(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w := redact.NewWriter(&buf)

	// Small pending cap so a single log-sized Write hits force-flush without
	// needing multi-megabyte fixtures. Carry defaults to ForceFlushCarry (256)
	// but is capped to the pending limit.
	const limit = 48
	redact.SetMaxPendingLineForTest(w, limit)

	const bare = "a1b2c3d4e5f6789012345678abcdef12deadbeef" // 40 hex (≥ bareMinLenHex)
	// Craft first Write: pad + first half of secret, total > limit, no newline.
	// After force-flush, carry (last `limit` bytes) includes the secret prefix
	// so the second Write can complete the token.
	const secretHead = 30
	padLen := limit + 10 - secretHead // total = limit+10
	if padLen < 1 {
		t.Fatal("padLen math")
	}
	part1 := append(bytes.Repeat([]byte("."), padLen), bare[:secretHead]...)
	if len(part1) <= limit {
		t.Fatalf("part1 len %d must exceed limit %d to force-flush", len(part1), limit)
	}
	if n, err := w.Write(part1); err != nil || n != len(part1) {
		t.Fatalf("Write part1: n=%d err=%v", n, err)
	}
	// Force-flush happened: some prefix left, carry retained.
	if buf.Len() == 0 {
		t.Fatal("expected force-flushed prefix before secret rejoin")
	}
	pending := redact.PendingLenForTest(w)
	if pending == 0 {
		t.Fatal("expected carry after force-flush")
	}
	// Full secret must not appear in the force-flushed prefix alone
	// (head alone is 30 hex < bareMinLenHex=40 — if it leaked as full bare, fail).
	if strings.Contains(buf.String(), bare) {
		t.Fatalf("full bare canary in force-flushed prefix: %q", buf.String())
	}

	// Second Write: remainder of secret + diagnostic + newline completes the line.
	part2 := []byte(bare[secretHead:] + " end\n")
	if n, err := w.Write(part2); err != nil || n != len(part2) {
		t.Fatalf("Write part2: n=%d err=%v", n, err)
	}

	out := buf.String()
	if strings.Contains(out, bare) {
		t.Fatalf("Regression KD-004 force-flush carry: bare canary leaked: %q", out)
	}
	// Partial halves must not leak either (rejoin + RedactText on complete line).
	if strings.Contains(out, bare[:secretHead]) || strings.Contains(out, bare[secretHead:]) {
		t.Fatalf("Regression KD-004 force-flush carry: partial canary leaked: %q", out)
	}
	if !strings.Contains(out, redact.Replacement) {
		t.Fatalf("expected redaction marker after carry rejoin: %q", out)
	}
	if !strings.Contains(out, " end") {
		t.Fatalf("over-redacted rejoin line: %q", out)
	}
}

// Flush after force-flush still redacts the retained carry (full remainder).
func TestWriterFlushAfterForceFlushRedactsCarry(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w := redact.NewWriter(&buf)
	// limit must be ≥ bare length so the carry tail can hold the full token.
	const limit = 64
	redact.SetMaxPendingLineForTest(w, limit)

	const bare = "a1b2c3d4e5f6789012345678abcdef12deadbeef" // 40 hex
	// Oversized write: pad then secret without newline. Carry (last `limit`
	// bytes) includes the full bare token so Flush redacts it.
	part := append(bytes.Repeat([]byte("z"), limit+5), []byte(bare)...)
	if _, err := w.Write(part); err != nil {
		t.Fatal(err)
	}
	if redact.PendingLenForTest(w) == 0 {
		t.Fatal("expected carry pending")
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, bare) {
		t.Fatalf("Flush after force-flush left bare canary: %q", out)
	}
	if !strings.Contains(out, redact.Replacement) {
		t.Fatalf("expected marker after Flush of carry: %q", out)
	}
	if redact.PendingLenForTest(w) != 0 {
		t.Fatalf("pending not cleared after Flush: %d", redact.PendingLenForTest(w))
	}
}
