package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// HashOpaque returns a short, non-reversible hex digest of s for high-cardinality
// labels (job names, etc.). Empty input yields empty output.
//
// Prefer this over storing raw job names when cardinality or privacy is a concern.
func HashOpaque(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	// 16 hex chars (64 bits) is enough for correlation without full SHA-256.
	return hex.EncodeToString(sum[:8])
}
