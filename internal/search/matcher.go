package search

import (
	"bytes"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// matcher finds the first match within a single line (bytes, no trailing '\n').
type matcher interface {
	// find returns [start, end) relative to line, or ok=false.
	find(line []byte) (start, end int, ok bool)
}

func buildMatcher(q Query) (matcher, error) {
	pat := q.Pattern
	if pat == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "pattern is required")
	}
	if len(pat) > MaxPatternBytes {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			"pattern exceeds maximum size")
	}
	switch q.Mode {
	case ModeLiteral:
		return newLiteralMatcher([]byte(pat), q.CaseSensitive), nil
	case ModeRegex:
		return newRegexMatcher(pat, q.CaseSensitive)
	default:
		return nil, apperr.New(apperr.CodeInvalidArgument, "unknown search mode")
	}
}

type literalMatcher struct {
	pat           []byte
	caseSensitive bool
	lowerPat      []byte // set when !caseSensitive
}

func newLiteralMatcher(pat []byte, caseSensitive bool) *literalMatcher {
	m := &literalMatcher{pat: append([]byte(nil), pat...), caseSensitive: caseSensitive}
	if !caseSensitive {
		m.lowerPat = bytes.ToLower(pat)
	}
	return m
}

func (m *literalMatcher) find(line []byte) (int, int, bool) {
	if len(m.pat) == 0 {
		return 0, 0, false
	}
	if m.caseSensitive {
		i := bytes.Index(line, m.pat)
		if i < 0 {
			return 0, 0, false
		}
		return i, i + len(m.pat), true
	}
	// Case-insensitive: ASCII fast path; otherwise strings.ToLower.
	if isASCII(line) && isASCII(m.pat) {
		lower := bytes.ToLower(line)
		i := bytes.Index(lower, m.lowerPat)
		if i < 0 {
			return 0, 0, false
		}
		return i, i + len(m.pat), true
	}
	// Unicode: map ToLower string index back carefully. When ToLower preserves
	// UTF-8 length (common), byte index aligns; otherwise EqualFold scan.
	ls := strings.ToLower(string(line))
	ps := strings.ToLower(string(m.pat))
	i := strings.Index(ls, ps)
	if i < 0 {
		return 0, 0, false
	}
	if len(ls) == len(line) && len(ps) == len(m.pat) {
		return i, i + len(m.pat), true
	}
	return findEqualFold(line, m.pat)
}

// findEqualFold finds the first substring of line that EqualFolds with pat.
func findEqualFold(line, pat []byte) (int, int, bool) {
	if len(pat) == 0 {
		return 0, 0, false
	}
	for i := 0; i < len(line); {
		if end, ok := equalFoldAt(line[i:], pat); ok {
			return i, i + end, true
		}
		_, size := utf8.DecodeRune(line[i:])
		if size <= 0 {
			size = 1
		}
		i += size
	}
	return 0, 0, false
}

func equalFoldAt(line, pat []byte) (end int, ok bool) {
	// Find shortest line prefix EqualFold-equal to pat.
	maxN := len(pat) * 4
	if maxN < len(pat) {
		maxN = len(pat)
	}
	if maxN > len(line) {
		maxN = len(line)
	}
	for n := 1; n <= maxN; n++ {
		// Only try at rune boundaries for n>1.
		if n < len(line) && line[n]&0xC0 == 0x80 {
			continue
		}
		if strings.EqualFold(string(line[:n]), string(pat)) {
			return n, true
		}
	}
	return 0, false
}

func isASCII(b []byte) bool {
	for _, c := range b {
		if c >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

type regexMatcher struct {
	re *regexp.Regexp
}

func newRegexMatcher(pattern string, caseSensitive bool) (*regexMatcher, error) {
	if err := guardRegexPattern(pattern); err != nil {
		return nil, err
	}
	p := pattern
	if !caseSensitive {
		// Case-insensitive unless the pattern already sets inline flags.
		if !strings.Contains(p, "(?i") {
			p = "(?i:" + p + ")"
		}
	}
	re, err := regexp.Compile(p)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInvalidArgument, "invalid regular expression", err)
	}
	return &regexMatcher{re: re}, nil
}

func (m *regexMatcher) find(line []byte) (int, int, bool) {
	loc := m.re.FindIndex(line)
	if loc == nil {
		return 0, 0, false
	}
	return loc[0], loc[1], true
}

// guardRegexPattern rejects oversized patterns and extreme nesting (optional
// complexity guard). Go's RE2 engine already prevents catastrophic backtracking.
func guardRegexPattern(pattern string) error {
	if len(pattern) > MaxPatternBytes {
		return apperr.New(apperr.CodeInvalidArgument, "pattern exceeds maximum size")
	}
	depth := 0
	maxDepth := 0
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '(':
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		case ')':
			if depth > 0 {
				depth--
			}
		}
	}
	const maxGroupDepth = 32
	if maxDepth > maxGroupDepth {
		return apperr.New(apperr.CodeInvalidArgument,
			"regular expression nesting depth exceeds limit")
	}
	return nil
}
