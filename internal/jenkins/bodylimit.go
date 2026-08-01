package jenkins

import (
	"fmt"
	"io"
)

// Default progressive log over-read slack is zero: we hard-cap application
// buffers at the requested length (LOG-001). Residual: Jenkins may still
// generate more on the wire until the client closes the body.
const progressiveReadSlack = 0

// readLimited reads at most limit bytes from r into a new buffer.
// It does not drain the remainder; callers should Close the underlying body
// promptly so the transport can abandon the connection if needed (LOG-001).
func readLimited(r io.Reader, limit int) ([]byte, error) {
	if limit < 0 {
		limit = 0
	}
	if limit == 0 {
		return []byte{}, nil
	}
	lr := io.LimitReader(r, int64(limit))
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// readLimitedErrBody reads an error response body with a hard cap so status
// error paths cannot allocate unbounded memory.
func readLimitedErrBody(r io.Reader) string {
	const maxErrBody = 64 << 10 // 64 KiB is enough for diagnostics
	data, err := readLimited(r, maxErrBody)
	if err != nil {
		return ""
	}
	return string(data)
}

// progressiveLimit returns the hard read cap for a progressiveText body given
// the caller-requested length.
func progressiveLimit(length int) int {
	if length < 0 {
		return 0
	}
	if progressiveReadSlack <= 0 {
		return length
	}
	// Overflow-safe add of small slack.
	if length > (1<<31-1)-progressiveReadSlack {
		return length
	}
	return length + progressiveReadSlack
}

// validateNonNegativeOffsetLength normalizes offset/length for log tools.
func validateNonNegativeOffsetLength(offset, length int) (int, int, error) {
	if offset < 0 {
		return 0, 0, fmt.Errorf("offset must be >= 0")
	}
	if length < 0 {
		return 0, 0, fmt.Errorf("length must be >= 0")
	}
	return offset, length, nil
}

// limitedBody enforces a hard max on API response bodies (NET-003).
// Reads past max return ErrBodyTooLarge without allocating the excess.
// Log/progressive paths must not use this wrapper; they keep LOG-001 caps.
type limitedBody struct {
	r      io.ReadCloser
	remain int64
	hit    bool // true once ErrBodyTooLarge has been returned
}

// newLimitedBody wraps rc with a hard max byte limit. max <= 0 means DefaultMaxJSONBodyBytes.
func newLimitedBody(rc io.ReadCloser, max int64) io.ReadCloser {
	if rc == nil {
		return nil
	}
	if max <= 0 {
		max = DefaultMaxJSONBodyBytes
	}
	return &limitedBody{r: rc, remain: max}
}

func (l *limitedBody) Read(p []byte) (int, error) {
	if l.hit {
		return 0, ErrBodyTooLarge
	}
	if l.remain <= 0 {
		// Budget exhausted: detect whether more data exists without large alloc.
		var b [1]byte
		n, err := l.r.Read(b[:])
		if n > 0 {
			l.hit = true
			return 0, ErrBodyTooLarge
		}
		if err != nil {
			return 0, err
		}
		l.hit = true
		return 0, ErrBodyTooLarge
	}
	if int64(len(p)) > l.remain {
		p = p[:l.remain]
	}
	n, err := l.r.Read(p)
	l.remain -= int64(n)
	if err == io.EOF {
		return n, err
	}
	if err != nil {
		return n, err
	}
	// If we exactly filled the budget, peek once so a subsequent Read fails fast.
	if l.remain == 0 {
		var b [1]byte
		m, e := l.r.Read(b[:])
		if m > 0 {
			l.hit = true
			// Deliver the last allowed bytes; next Read returns ErrBodyTooLarge.
			// For streaming JSON that ends exactly at max this is fine.
			// For bodies larger than max, the next Read (or this EOF path) errors.
			_ = e
			// Signal overflow on this read if the caller might stop early:
			// prefer fail-closed on known excess.
			return n, ErrBodyTooLarge
		}
	}
	return n, err
}

func (l *limitedBody) Close() error {
	if l.r != nil {
		return l.r.Close()
	}
	return nil
}
