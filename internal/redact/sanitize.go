package redact

import (
	"strings"
	"unicode/utf8"
)

// StripControlSequences removes terminal/control sequences that can manipulate
// clients or agents (SEC-003):
//   - ANSI CSI sequences (ESC [ … final, single-byte CSI 0x9B, UTF-8 U+009B)
//   - OSC sequences including hyperlinks (ESC ] … BEL/ST, single-byte/UTF-8 OSC)
//   - Other ESC-introduced sequences (charset, two-byte forms)
//   - C0 controls other than \t \n \r
//   - DEL (0x7F)
//   - Unicode C1 controls U+0080–U+009F (including UTF-8 C2 80–C2 9F form)
//   - Unicode bidi format controls that reorder visible text
//
// Incomplete/truncated escape sequences at end-of-string are dropped.
// The function is deterministic for a given input.
func StripControlSequences(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		c := s[i]

		// ESC-introduced sequences.
		if c == 0x1b {
			i = skipESC(s, i)
			continue
		}
		// 8-bit C1 controls that start CSI / OSC / PM / APC.
		if c == 0x9b { // CSI
			i = skipCSI(s, i+1)
			continue
		}
		if c == 0x9d { // OSC
			i = skipOSC(s, i+1)
			continue
		}
		if c == 0x90 || c == 0x9e || c == 0x9f { // DCS / PM / APC
			i = skipStringTerm(s, i+1)
			continue
		}

		// C0 controls except tab/LF/CR.
		if c < 0x20 {
			if c == '\t' || c == '\n' || c == '\r' {
				b.WriteByte(c)
			}
			i++
			continue
		}
		if c == 0x7f { // DEL
			i++
			continue
		}

		// Multi-byte UTF-8: strip bidi / C1 controls (including UTF-8-encoded
		// U+0080–U+009F, which are two-byte sequences C2 80–C2 9F — not the
		// single-byte C1 path above). Regression: lone U+009D / U+009B.
		if c >= utf8.RuneSelf {
			r, size := utf8.DecodeRuneInString(s[i:])
			if r == utf8.RuneError && size == 1 {
				// Invalid byte: drop (do not pass through as control vehicle).
				i++
				continue
			}
			// UTF-8 C1 introducers start CSI/OSC/DCS/PM/APC payloads.
			switch r {
			case 0x9b: // CSI
				i = skipCSI(s, i+size)
				continue
			case 0x9d: // OSC
				i = skipOSC(s, i+size)
				continue
			case 0x90, 0x9e, 0x9f: // DCS / PM / APC
				i = skipStringTerm(s, i+size)
				continue
			}
			if isC1Control(r) || isBidiOrDangerousFormat(r) {
				i += size
				continue
			}
			b.WriteString(s[i : i+size])
			i += size
			continue
		}

		b.WriteByte(c)
		i++
	}
	return b.String()
}

// skipESC consumes an ESC-introduced sequence starting at index i (s[i]==ESC).
// Returns the index after the sequence (or end of string).
func skipESC(s string, i int) int {
	// i points at ESC.
	i++
	if i >= len(s) {
		return i
	}
	switch s[i] {
	case '[': // CSI
		return skipCSI(s, i+1)
	case ']': // OSC (hyperlinks, titles, …)
		return skipOSC(s, i+1)
	case 'P': // DCS
		return skipStringTerm(s, i+1)
	case '^', '_': // PM, APC
		return skipStringTerm(s, i+1)
	case '(':
		// Charset designation: ESC ( X
		if i+1 < len(s) {
			return i + 2
		}
		return len(s)
	case ')', '*', '+', '-', '.', '/':
		if i+1 < len(s) {
			return i + 2
		}
		return len(s)
	default:
		// Two-byte ESC Fe / simple forms: consume one more byte if present.
		return i + 1
	}
}

// skipCSI consumes CSI parameter/intermediate bytes until a final byte (@–~).
func skipCSI(s string, i int) int {
	for i < len(s) {
		c := s[i]
		i++
		// Final byte of CSI is 0x40–0x7E (@–~).
		if c >= 0x40 && c <= 0x7e {
			return i
		}
		// Abort on unexpected C0 (except we already strip them elsewhere).
		if c < 0x20 && c != 0x1b {
			// Malformed; stop before this control so outer loop handles it.
			return i - 1
		}
	}
	return i
}

// skipOSC consumes OSC payload until BEL, ST (ESC \), or end.
func skipOSC(s string, i int) int {
	for i < len(s) {
		c := s[i]
		if c == 0x07 { // BEL
			return i + 1
		}
		if c == 0x1b {
			// ST = ESC \
			if i+1 < len(s) && s[i+1] == '\\' {
				return i + 2
			}
			// Nested ESC: end OSC and let outer handle.
			return i
		}
		// 8-bit ST
		if c == 0x9c {
			return i + 1
		}
		i++
	}
	return i
}

// skipStringTerm is like OSC termination for DCS/PM/APC (BEL or ST).
func skipStringTerm(s string, i int) int {
	return skipOSC(s, i)
}

// isC1Control reports Unicode C1 controls U+0080–U+009F (including UTF-8 form).
func isC1Control(r rune) bool {
	return r >= 0x80 && r <= 0x9f
}

// isBidiOrDangerousFormat reports Unicode bidi / isolate controls.
func isBidiOrDangerousFormat(r rune) bool {
	switch r {
	case '\u202A', // LRE
		'\u202B', // RLE
		'\u202C', // PDF
		'\u202D', // LRO
		'\u202E', // RLO
		'\u2066', // LRI
		'\u2067', // RLI
		'\u2068', // FSI
		'\u2069': // PDI
		return true
	default:
		return false
	}
}

// SanitizeForModel strips control sequences then applies layered secret redaction.
// Use this for any build log / artifact text returned to the model.
func SanitizeForModel(s string) string {
	out, _ := SanitizeForModelReport(s)
	return out
}

// SanitizeForModelReport is like SanitizeForModel with redaction category counts.
func SanitizeForModelReport(s string) (string, Report) {
	s = StripControlSequences(s)
	return RedactTextReport(s)
}
