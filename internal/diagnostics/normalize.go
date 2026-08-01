package diagnostics

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// SignatureHexLen is the number of hex characters kept from SHA-256 (64-bit prefix).
const SignatureHexLen = 16

// Documented normalization rules (DIAG-001):
//  1. Strip CR; trim trailing whitespace.
//  2. Replace ISO-8601 / common log timestamps with <ts>.
//  3. Replace UUID forms with <uuid>.
//  4. Replace Windows drive paths with their basename only (C:\a\b\c.go → c.go).
//  5. Replace long hex hashes (≥8 hex digits) with <hex>.
//  6. Replace digit runs with <n> (line numbers, ports, exit codes, versions digits).
//  7. Collapse horizontal whitespace to a single space.
//  8. Lowercase ASCII letters for stable signature preimage.
//
// Residual: Unix absolute paths and UNC shares are not reduced to basenames.
// Only the rules above run; there is no silent extra mutation.

var (
	reISOTimestamp = regexp.MustCompile(
		`\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b`,
	)
	reCommonTime = regexp.MustCompile(
		`\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b`,
	)
	reUUID = regexp.MustCompile(
		`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`,
	)
	reLongHex = regexp.MustCompile(`\b[0-9a-fA-F]{8,}\b`)
	// Windows drive path: C:\dir\file or C:/dir/file (stop at whitespace / quotes).
	reWinDrivePath = regexp.MustCompile(`(?i)\b[a-z]:(?:[\\/][^\s"'<>|:\\/]+)+`)
	reDigits       = regexp.MustCompile(`\d+`)
)

// NormalizeLine applies documented volatile-token normalization for signatures.
func NormalizeLine(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.TrimRightFunc(s, unicode.IsSpace)
	if s == "" {
		return ""
	}
	s = reISOTimestamp.ReplaceAllString(s, "<ts>")
	s = reCommonTime.ReplaceAllString(s, "<ts>")
	s = reUUID.ReplaceAllString(s, "<uuid>")
	// Cheap Windows path → basename only (before hex/digit so path segments stay intact).
	s = reWinDrivePath.ReplaceAllStringFunc(s, winPathBasename)
	s = reLongHex.ReplaceAllString(s, "<hex>")
	s = reDigits.ReplaceAllString(s, "<n>")
	// Collapse horizontal whitespace.
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := false
	for _, r := range s {
		if r == ' ' || r == '\t' {
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		prevSpace = false
		if r < utf8.RuneSelf && r >= 'A' && r <= 'Z' {
			b.WriteByte(byte(r + ('a' - 'A')))
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// winPathBasename returns the final path segment of a Windows drive path.
func winPathBasename(p string) string {
	i := strings.LastIndexAny(p, `\/`)
	if i < 0 || i+1 >= len(p) {
		return p
	}
	return p[i+1:]
}

// Signature returns the short hex digest of a normalized line.
// Empty input yields an empty signature.
func Signature(normalized string) string {
	if normalized == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])[:SignatureHexLen]
}

// truncateBytes returns s truncated to max bytes on a UTF-8 boundary, with "…" when cut.
func truncateBytes(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	// Leave room for ellipsis.
	cut := max - len("…")
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	if cut <= 0 {
		return "…"
	}
	return s[:cut] + "…"
}
