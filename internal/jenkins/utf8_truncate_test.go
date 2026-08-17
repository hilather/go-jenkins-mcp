package jenkins

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Regression: byte-wise truncation split multi-byte runes in model-facing
// strings (nodes.go sanitizeNodeText, stagelog.go, client_logs.go), producing
// invalid UTF-8 tails (encoding/json later substitutes U+FFFD — silently
// mangled output). All three now truncate on rune boundaries via the existing
// truncateBytes helper.
func TestRuneSafeTruncation(t *testing.T) {
	t.Parallel()
	// 4-byte rune (emoji) straddling the 512-byte cut point in
	// sanitizeNodeText (bytes 510-513; cut at 512 splits it).
	s := strings.Repeat("a", 510) + "🚀" + strings.Repeat("b", 100)
	if got := sanitizeNodeText(s); !utf8.ValidString(got) {
		t.Fatalf("sanitizeNodeText split a rune: %q", got[len(got)-8:])
	}
	if got, _ := truncateBytes(s, 512); !utf8.ValidString(got) {
		t.Fatalf("truncateBytes split a rune: %q", got[len(got)-8:])
	}

	// fetchProgressiveRange-level: logs[:length] path. Build via the public
	// helper used by GetBuildLogs truncation semantics.
	logs := strings.Repeat("x", 100) + "🚀" + strings.Repeat("y", 100)
	cut, _ := truncateBytes(logs, 102) // cut lands inside the 4-byte rune
	if !utf8.ValidString(cut) {
		t.Fatalf("log truncation split a rune: %q", cut[len(cut)-8:])
	}
	if len(cut) > 102 {
		t.Fatalf("truncateBytes exceeded cap: %d", len(cut))
	}
}
