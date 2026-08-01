package update

import (
	"strconv"
	"strings"
)

// CompareVersions returns "newer" if remote > current, "older" if remote < current,
// "same" if equal after normalization, "unknown" if not comparable.
// Supports dotted numeric versions (optionally with leading v) and ignores
// git-describe suffixes after the first '-' (e.g. v1.2.3-4-gabcdef → 1.2.3).
func CompareVersions(current, remote string) string {
	c := versionCore(current)
	r := versionCore(remote)
	if c == "" || r == "" {
		if normalizeVersion(current) == normalizeVersion(remote) {
			return "same"
		}
		return "unknown"
	}
	if c == r {
		return "same"
	}
	cp := splitVersionParts(c)
	rp := splitVersionParts(r)
	n := len(cp)
	if len(rp) > n {
		n = len(rp)
	}
	for i := 0; i < n; i++ {
		var a, b int
		if i < len(cp) {
			a = cp[i]
		}
		if i < len(rp) {
			b = rp[i]
		}
		if b > a {
			return "newer"
		}
		if b < a {
			return "older"
		}
	}
	return "same"
}

func normalizeVersion(v string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(v), "v")))
}

// versionCore returns the dotted numeric prefix (without leading v), or empty if none.
func versionCore(v string) string {
	s := normalizeVersion(v)
	if s == "" || s == "dev" || s == "unknown" {
		return ""
	}
	if i := strings.IndexAny(s, "-+_"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) == 0 {
		return ""
	}
	for _, p := range parts {
		if p == "" {
			return ""
		}
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				return ""
			}
		}
	}
	return s
}

func splitVersionParts(core string) []int {
	parts := strings.Split(core, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	return out
}
