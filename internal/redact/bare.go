package redact

import "strings"

// CategoryBareToken labels unlabeled high-entropy hex / base64url material
// caught by the bare-token heuristic (Wave 25 / KD-004 residual).
const CategoryBareToken = "bare_token"

// Bare high-entropy thresholds (SEC-003 / KD-004).
// Prefer missing a short secret over redacting useful diagnostics.
//
// Heuristic rules (documented residual FP notes below):
//
//  1. Candidates are maximal runs of [A-Za-z0-9_+\-=] only.
//     '/' is intentionally excluded so Jenkins job paths (folder/job) and
//     URL path segments do not merge into one run.
//  2. key=value runs (mid-string '=', not trailing base64 padding) evaluate
//     and redact only the value side so labels like trace_id= stay visible
//     and do not inflate entropy.
//  3. Pure hex (0-9a-fA-F):
//     - Single-case (all lower or all upper): length ≥ bareMinLenHex (40).
//     Catches random-looking 40-char hex; full git SHA-1 (40) / SHA-256
//     (64) may false-positive — residual FP. Short SHAs (7–12) stay visible.
//     - Mixed case (both upper and lower present): length ≥ 32 with diversity.
//     Avoids redacting all-lowercase W3C trace_id (exactly 32 hex) while
//     still catching mixed-case Jenkins-style API token material.
//  4. Mixed base64url-like: length ≥ bareMinLenMixed (32) with ≥2 char
//     classes and unique-char floor; or length ≥ bareMinLenStrong (24)
//     with ≥3 classes and higher uniqueness (true random short secrets).
//  5. Reject pure lowercase letter runs (optional -_), i.e. "words" and
//     hyphenated job/service names without digits/upper.
//  6. Reject low-diversity repeats (e.g. aaaaaaaaa…, deadbeefdeadbeef…).
//
// Residual false negatives: secrets shorter than thresholds, single-case
// 32–39 hex (incl. some historical Jenkins tokens when unlabeled — use
// SetKnownSecrets / labeled api_token=), secrets longer than
// redact.Writer's force-flush carry window (256 B) when repeated size
// force-flushes without '\n' slice them into sub-threshold fragments
// (line reassembly + carry cover normal multi-Write log lines and
// typical API tokens straddling the 256 KiB pending cap), characters
// outside the alphabet (e.g. '.'), pure base64 with '/' only.
// Residual false positives: full git commit SHAs, long random build IDs,
// high-entropy artifact digests embedded in plain text.
const (
	bareMinLenStrong   = 24
	bareMinLenHex      = 40 // single-case pure hex
	bareMinLenHexMixed = 32 // mixed-case pure hex (not W3C trace_id shape)
	bareMinLenMixed    = 32
	bareMaxLen         = 512
)

func isBareTokenByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z':
		return true
	case c >= 'A' && c <= 'Z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '_', c == '-', c == '+', c == '=':
		return true
	default:
		return false
	}
}

// bareValueOffset returns the index of the value after a mid-string '='
// (key=value). Trailing base64 padding '=' does not count. Returns 0 when
// the whole token should be scored.
func bareValueOffset(tok string) int {
	end := len(tok)
	for end > 0 && tok[end-1] == '=' {
		end--
	}
	if end == 0 {
		return 0
	}
	body := tok[:end]
	j := strings.IndexByte(body, '=')
	if j < 0 || j+1 >= end {
		return 0
	}
	return j + 1
}

// isHighEntropyBareToken reports whether tok looks like an unlabeled secret.
// For key=value alphabet runs, only the value is scored (see apply).
func isHighEntropyBareToken(tok string) bool {
	if off := bareValueOffset(tok); off > 0 {
		return isHighEntropyBareTokenCore(tok[off:])
	}
	return isHighEntropyBareTokenCore(tok)
}

func isHighEntropyBareTokenCore(tok string) bool {
	n := len(tok)
	if n < bareMinLenStrong || n > bareMaxLen {
		return false
	}
	// Avoid re-touching our own marker if it ever grows into the alphabet.
	if strings.Contains(tok, "REDACTED") {
		return false
	}

	var lower, upper, digit, special int
	var seen [128]bool
	unique := 0
	hexOnly := true

	for i := 0; i < n; i++ {
		c := tok[i]
		if c >= 128 || !isBareTokenByte(c) {
			return false
		}
		if !seen[c] {
			seen[c] = true
			unique++
		}
		switch {
		case c >= 'a' && c <= 'z':
			lower++
			if c > 'f' {
				hexOnly = false
			}
		case c >= 'A' && c <= 'Z':
			upper++
			if c > 'F' {
				hexOnly = false
			}
		case c >= '0' && c <= '9':
			digit++
		default:
			// _ - + =
			special++
			hexOnly = false
		}
	}

	// Pure words / hyphenated job names (no digits, no uppercase).
	if upper == 0 && digit == 0 {
		return false
	}

	classes := 0
	if lower > 0 {
		classes++
	}
	if upper > 0 {
		classes++
	}
	if digit > 0 {
		classes++
	}
	if special > 0 {
		classes++
	}

	// Pure hex: long single-case (≥40) or mixed-case (≥32). W3C trace_id is
	// exactly 32 lowercase hex — preserved by the single-case floor of 40.
	if hexOnly && special == 0 && digit > 0 && (lower > 0 || upper > 0) {
		mixedCase := lower > 0 && upper > 0
		if mixedCase {
			if n < bareMinLenHexMixed {
				return false
			}
			return unique >= 12
		}
		if n < bareMinLenHex {
			return false
		}
		return unique >= 12
	}

	// Mixed base64url / alnum secrets (common for modern opaque tokens).
	if n >= bareMinLenMixed && classes >= 2 && unique >= 12 {
		// Hyphenated lowercase + sparse digits often = long service names
		// with versions (deploy-service-v2-pipeline-…); require more unique.
		if upper == 0 && special > 0 && digit > 0 && digit*4 < n && unique < 16 {
			return false
		}
		return true
	}

	// Shorter mixed (24–31): need three classes and high uniqueness.
	if n >= bareMinLenStrong && classes >= 3 && unique >= 14 {
		return true
	}
	return false
}

// applyBareHighEntropyTokens redacts unlabeled high-entropy candidates.
// Order: run after labeled detectors so Bearer/api_token= keep their categories.
// For key=value alphabet runs only the value span is replaced.
func applyBareHighEntropyTokens(s string, rep *Report) string {
	if len(s) < bareMinLenStrong {
		return s
	}

	type span struct{ start, end int }
	var spans []span
	for i := 0; i < len(s); {
		if !isBareTokenByte(s[i]) {
			i++
			continue
		}
		j := i + 1
		for j < len(s) && isBareTokenByte(s[j]) {
			j++
		}
		cand := s[i:j]
		if off := bareValueOffset(cand); off > 0 {
			if isHighEntropyBareTokenCore(cand[off:]) {
				spans = append(spans, span{i + off, j})
			}
		} else if isHighEntropyBareTokenCore(cand) {
			spans = append(spans, span{i, j})
		}
		i = j
	}
	if len(spans) == 0 {
		return s
	}
	rep.add(CategoryBareToken, len(spans))

	var b strings.Builder
	b.Grow(len(s))
	prev := 0
	for _, sp := range spans {
		b.WriteString(s[prev:sp.start])
		b.WriteString(Replacement)
		prev = sp.end
	}
	b.WriteString(s[prev:])
	return b.String()
}
