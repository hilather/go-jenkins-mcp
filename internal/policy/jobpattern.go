package policy

import (
	"errors"
	"fmt"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// deny_job_prefixes pattern language (POL-002 Wave 26 glob-lite + Wave 29 mid-path **/
// + Wave 30 limited brace expansion {a,b,c} + Wave 31 character classes […]
// + Wave 32 bounded nested braces).
//
// Grammar (fail closed at overlay Validate):
//
//	pattern     := brace-pat | plain-pat
//	brace-pat   := pattern with one or more {alt1,alt2[,…]} groups (nesting ≤
//	               MaxDenyJobBraceNestDepth); expands to the cartesian product
//	               of alternatives (bounded). Nested groups use matching-depth
//	               `}` and top-level commas only (commas inside nested `{…}`
//	               do not split the outer group).
//	plain-pat   := segment ("/" segment)* [ "/**" ]
//	segment     := literal-seg | star-seg | class-seg | "**"
//	literal-seg := non-empty path segment without * / ? [ \ { }
//	star-seg    := path segment with one or more single-segment *
//	class-seg   := path segment with one or more […] classes (may mix with * / literals)
//	*           := zero or more non-slash chars within one segment
//	**          := zero or more full path segments (whole segment only)
//	/**         := trailing only after strip for matching; ≡ base folder + descendants
//	{a,b}       := alternatives are path-segment-safe (may include * and […] and
//	               nested braces; no / or empty; each group ≥2 top-level alts)
//	[abc]       := exactly one path character from the set (match-time; not expanded)
//	[a-z]       := inclusive byte range (fail closed if lo > hi)
//	[^…]        := negation: exactly one character not in the set
//
// Matching (MatchDenyJobPattern):
//
//  1. Expand braces (if any); job is denied if **any** expanded plain pattern matches.
//  2. Normalize: strip a single trailing "/**" (folder + descendants ≡ base).
//  3. Pattern matches if it matches some path-prefix of the job (segment-wise),
//     so children under a matching prefix are also denied (classic deny prefix).
//  4. Mid-path "**" consumes zero or more job segments (DP, O(p·j)).
//  5. Single-segment "*" never crosses "/".
//  6. Character classes match exactly one byte within a segment (match-time set/range).
//
// Rejected at load (overly broad / unsafe):
//   "*", "**", "/**", empty, absolute ("/..."), ".." segments, empty segments,
//   trailing "/", metacharacters "?", "\", "**" embedded in a non-**
//   segment (e.g. "a**b"), patterns longer than MaxDenyJobPatternSegments,
//   invalid braces (unclosed, empty/single alt, nesting > max, explosion),
//   invalid classes (empty [], unclosed [, inverted range z-a, "/" in class),
//   any expanded form that is itself invalid or overly broad.
//
// Residual: no cross-segment single "*" (multi-segment span requires "**").
// Bare string prefixes are never used ("secret-folder" does not match
// "secret-folder-other").

// MaxDenyJobPatternSegments bounds pattern path depth at Validate (fail closed).
// Jenkins full names are shallow; this caps DP size for MatchDenyJobPattern
// (O(pattern·job) segment DP — no catastrophic backtracking).
const MaxDenyJobPatternSegments = 64

// MaxDenyJobBraceAlternatives caps alternatives inside one `{a,b,…}` group
// (top-level commas within that group only).
const MaxDenyJobBraceAlternatives = 8

// MaxDenyJobBraceExpanded caps the cartesian product size after brace expansion.
const MaxDenyJobBraceExpanded = 32

// MaxDenyJobBraceNestDepth caps structural brace nesting (`{` inside a group).
// Depth 1 = non-nested `{a,b}`; depth 2 = `{a,{b,c}}`. Fail closed deeper.
const MaxDenyJobBraceNestDepth = 4

// MatchDenyJobPattern reports whether job is denied by a deny_job_prefixes entry.
// Empty pattern or job → false. Invalid patterns never panic; they do not match
// (production loads call ValidateDenyJobPattern first).
//
// Job paths are normalized like Jenkins BuildJobPath: empty segments and leading
// "/" are collapsed so `prod//secret` and `/secret` still match `**/secret`
// (fail closed — Wave 29 regression vs skip-on-malformed early-out).
//
// Job path length is not truncated: truncating could fail open (miss a deny) on
// deep names. Cost stays bounded by pattern segment cap (≤64) and brace product
// (≤ MaxDenyJobBraceExpanded).
func MatchDenyJobPattern(pattern, job string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	// Defense in depth: never treat absolute / traversal patterns as a match.
	if strings.Contains(pattern, "..") || strings.HasPrefix(pattern, "/") {
		return false
	}

	jobNorm, ok := NormalizeJobFullName(job)
	if !ok || jobNorm == "" {
		return false
	}

	expanded, err := ExpandDenyJobBraces(pattern)
	if err != nil || len(expanded) == 0 {
		return false
	}
	for _, p := range expanded {
		if matchDenyJobPatternPlain(p, jobNorm) {
			return true
		}
	}
	return false
}

// matchDenyJobPatternPlain matches one brace-expanded (plain) pattern against a
// already-normalized job full name.
func matchDenyJobPatternPlain(pattern, jobNorm string) bool {
	base, ok := normalizeDenyJobPattern(pattern)
	if !ok {
		return false
	}

	// No wildcards or classes: exact or folder-child (classic + explicit /**).
	if !strings.ContainsAny(base, "*[") {
		return jobNorm == base || strings.HasPrefix(jobNorm, base+"/")
	}

	jSegs := strings.Split(jobNorm, "/")
	pSegs := strings.Split(base, "/")
	if len(pSegs) > MaxDenyJobPatternSegments {
		return false
	}
	return matchPatternPrefix(pSegs, jSegs)
}

// NormalizeJobFullName collapses empty segments and strips leading/trailing
// slashes so deny matching aligns with jenkins.BuildJobPath (which skips empty
// segments). Returns ok=false on path traversal ("..").
func NormalizeJobFullName(job string) (string, bool) {
	job = strings.TrimSpace(job)
	if job == "" {
		return "", false
	}
	if strings.Contains(job, "..") {
		return "", false
	}
	raw := strings.Split(job, "/")
	segs := make([]string, 0, len(raw))
	for _, s := range raw {
		if s == "" {
			continue // same as BuildJobPath — collapse // and leading /
		}
		if s == ".." {
			return "", false
		}
		segs = append(segs, s)
	}
	if len(segs) == 0 {
		return "", false
	}
	return strings.Join(segs, "/"), true
}

// ValidateDenyJobPattern fails closed on empty, traversal, overly broad,
// unsupported glob syntax, invalid braces, or invalid character classes.
// Used by Overlay.Validate for each deny_job_prefixes entry.
func ValidateDenyJobPattern(pattern string) error {
	p := strings.TrimSpace(pattern)
	if p == "" {
		return apperr.New(apperr.CodeInvalidArgument, "deny_job_prefixes entry is empty")
	}
	if strings.HasPrefix(p, "/") {
		return apperr.New(apperr.CodeInvalidArgument,
			"deny_job_prefixes entry must be a relative job path (not absolute)")
	}
	if strings.Contains(p, "..") {
		return apperr.New(apperr.CodeInvalidArgument,
			"deny_job_prefixes entry must not contain path traversal")
	}
	// Unsupported metacharacters (keep language minimal and deterministic).
	// Character classes […] are Wave 31; still reject ? and \.
	if strings.ContainsAny(p, "?\\") {
		return apperr.New(apperr.CodeInvalidArgument,
			"deny_job_prefixes entry has unsupported metacharacters (only * **/ {a,b} and […])")
	}

	expanded, err := ExpandDenyJobBraces(p)
	if err != nil {
		return err
	}
	for _, one := range expanded {
		if err := validateDenyJobPatternPlain(one); err != nil {
			return err
		}
	}
	return nil
}

// validateDenyJobPatternPlain validates one brace-expanded pattern (no '{' / '}').
func validateDenyJobPatternPlain(p string) error {
	if strings.ContainsAny(p, "{}") {
		// Should not happen after ExpandDenyJobBraces; defense in depth.
		return apperr.New(apperr.CodeInvalidArgument,
			"deny_job_prefixes entry has invalid brace syntax")
	}
	// Overly broad: alone or root recursive.
	switch p {
	case "*", "**", "/**":
		return apperr.New(apperr.CodeInvalidArgument,
			"deny_job_prefixes entry is overly broad (reject bare * or **)")
	}
	// Strip one trailing /** (folder + descendants sugar); remainder is the
	// match base and may still contain mid-path ** segments.
	if strings.HasSuffix(p, "/**") {
		base := strings.TrimSuffix(p, "/**")
		if base == "" {
			return apperr.New(apperr.CodeInvalidArgument,
				"deny_job_prefixes entry is overly broad (/** alone)")
		}
		// **/** collapses to bare ** (overly broad). Note: */** → base "*" is
		// intentional multi-seg sugar (any top-level folder + descendants) and
		// remains valid as in Wave 26; only bare "*" alone is rejected above.
		if base == "**" {
			return apperr.New(apperr.CodeInvalidArgument,
				"deny_job_prefixes entry is overly broad (reject bare * or **)")
		}
		p = base
	}

	// Reject trailing slash (except already handled /**).
	if strings.HasSuffix(p, "/") {
		return apperr.New(apperr.CodeInvalidArgument,
			"deny_job_prefixes entry must not end with / (use trailing /** for descendants)")
	}

	segs := strings.Split(p, "/")
	if len(segs) > MaxDenyJobPatternSegments {
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("deny_job_prefixes entry exceeds max path segments (%d)", MaxDenyJobPatternSegments))
	}
	for _, seg := range segs {
		if seg == "" {
			return apperr.New(apperr.CodeInvalidArgument,
				"deny_job_prefixes entry has empty path segment")
		}
		// ** is only valid as a whole segment (mid-path or after other segs).
		if seg == "**" {
			continue
		}
		if strings.Contains(seg, "**") {
			return apperr.New(apperr.CodeInvalidArgument,
				"deny_job_prefixes entry: ** must be a whole path segment (use **/ for mid-path)")
		}
		if err := validateSegmentCharClasses(seg); err != nil {
			return err
		}
	}
	return nil
}

// ExpandDenyJobBraces expands `{a,b[,…]}` groups (including bounded nesting) to
// the cartesian product of alternatives. Patterns without braces return a
// single-element slice. Fail closed on unclosed/empty braces, empty or single
// alternatives, nesting deeper than MaxDenyJobBraceNestDepth, path-unsafe
// alternatives, or expansion past MaxDenyJobBraceExpanded.
//
// Exported for tests and for callers that want the expanded set without matching.
func ExpandDenyJobBraces(pattern string) ([]string, error) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "deny_job_prefixes entry is empty")
	}
	// Fast path: no braces.
	if !strings.ContainsAny(pattern, "{}") {
		return []string{pattern}, nil
	}
	// Structural nest-depth check before product expansion (fail closed).
	if depth, err := braceNestDepth(pattern); err != nil {
		return nil, err
	} else if depth > MaxDenyJobBraceNestDepth {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("deny_job_prefixes entry brace nesting exceeds max depth (%d)", MaxDenyJobBraceNestDepth))
	}
	out, err := expandBracesOnce(pattern, MaxDenyJobBraceExpanded)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			"deny_job_prefixes entry brace expansion produced no patterns")
	}
	if len(out) > MaxDenyJobBraceExpanded {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("deny_job_prefixes entry brace expansion exceeds max patterns (%d)", MaxDenyJobBraceExpanded))
	}
	return out, nil
}

// braceNestDepth returns the maximum structural brace nesting depth of pattern
// (1 = non-nested `{a,b}`, 2 = `{a,{b,c}}`). Also fails closed on unmatched
// braces so ExpandDenyJobBraces can reject bad structure before product work.
func braceNestDepth(pattern string) (int, error) {
	depth := 0
	maxDepth := 0
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '{':
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		case '}':
			depth--
			if depth < 0 {
				return 0, apperr.New(apperr.CodeInvalidArgument,
					"deny_job_prefixes entry has unmatched '}'")
			}
		}
	}
	if depth != 0 {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"deny_job_prefixes entry has unclosed '{'")
	}
	return maxDepth, nil
}

// findMatchingBrace returns the index of the `}` that matches pattern[start]
// (`{`), tracking nesting depth. Fail closed if unclosed.
func findMatchingBrace(pattern string, start int) (int, error) {
	if start < 0 || start >= len(pattern) || pattern[start] != '{' {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"deny_job_prefixes entry has invalid brace syntax")
	}
	depth := 0
	for i := start; i < len(pattern); i++ {
		switch pattern[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i, nil
			}
		}
	}
	return 0, apperr.New(apperr.CodeInvalidArgument,
		"deny_job_prefixes entry has unclosed '{'")
}

// splitBraceAlternatives splits a brace group's interior on top-level commas
// only (commas inside nested `{…}` do not split). Empty interior is invalid.
func splitBraceAlternatives(inner string) ([]string, error) {
	if inner == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			"deny_job_prefixes entry has empty brace group {}")
	}
	var alts []string
	depth := 0
	start := 0
	for i := 0; i < len(inner); i++ {
		switch inner[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth < 0 {
				return nil, apperr.New(apperr.CodeInvalidArgument,
					"deny_job_prefixes entry has unmatched '}'")
			}
		case ',':
			if depth == 0 {
				alts = append(alts, inner[start:i])
				start = i + 1
			}
		}
	}
	if depth != 0 {
		// Should not happen after findMatchingBrace; defense in depth.
		return nil, apperr.New(apperr.CodeInvalidArgument,
			"deny_job_prefixes entry has unclosed '{'")
	}
	alts = append(alts, inner[start:])
	return alts, nil
}

// expandBracesOnce expands the leftmost brace group (matching-depth close),
// then recursively expands remaining braces in each alternative product.
// maxOut is the remaining budget for the full product (fail closed on explosion).
func expandBracesOnce(pattern string, maxOut int) ([]string, error) {
	if maxOut < 1 {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("deny_job_prefixes entry brace expansion exceeds max patterns (%d)", MaxDenyJobBraceExpanded))
	}
	start := strings.IndexByte(pattern, '{')
	if start < 0 {
		// No more opens; any stray } is invalid.
		if strings.IndexByte(pattern, '}') >= 0 {
			return nil, apperr.New(apperr.CodeInvalidArgument,
				"deny_job_prefixes entry has unmatched '}'")
		}
		return []string{pattern}, nil
	}
	// Unmatched } before first { is invalid.
	if closeBefore := strings.IndexByte(pattern[:start], '}'); closeBefore >= 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			"deny_job_prefixes entry has unmatched '}'")
	}
	end, err := findMatchingBrace(pattern, start)
	if err != nil {
		return nil, err
	}
	inner := pattern[start+1 : end]
	alts, err := splitBraceAlternatives(inner)
	if err != nil {
		return nil, err
	}
	if len(alts) < 2 {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			"deny_job_prefixes entry brace group needs at least two alternatives")
	}
	if len(alts) > MaxDenyJobBraceAlternatives {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("deny_job_prefixes entry brace group exceeds max alternatives (%d)", MaxDenyJobBraceAlternatives))
	}
	for _, alt := range alts {
		if err := validateBraceAlternative(alt); err != nil {
			return nil, err
		}
	}

	prefix := pattern[:start]
	suffix := pattern[end+1:]
	// Product budget: each alt fans out; remaining suffix / nested alts may
	// expand further. Cap partial products early so we never allocate more than
	// maxOut leaves (and fail closed rather than truncate, which would fail open).
	out := make([]string, 0, len(alts))
	for _, alt := range alts {
		candidate := prefix + alt + suffix
		// Recurse on remaining braces (nested alts and sequential groups).
		partial, err := expandBracesOnce(candidate, maxOut-len(out))
		if err != nil {
			return nil, err
		}
		if len(out)+len(partial) > maxOut {
			return nil, apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("deny_job_prefixes entry brace expansion exceeds max patterns (%d)", MaxDenyJobBraceExpanded))
		}
		out = append(out, partial...)
	}
	return out, nil
}

// validateBraceAlternative enforces path-segment-safe alternatives: non-empty,
// no '/'. Nested braces are allowed (expanded recursively). Leaf alternatives
// may include single-segment '*' and character classes […]. Character class
// structure is re-checked on each expanded plain pattern.
func validateBraceAlternative(alt string) error {
	if alt == "" {
		return apperr.New(apperr.CodeInvalidArgument,
			"deny_job_prefixes entry has empty brace alternative")
	}
	if strings.Contains(alt, "/") {
		return apperr.New(apperr.CodeInvalidArgument,
			"deny_job_prefixes entry brace alternative must be path-segment-safe (no /)")
	}
	if strings.ContainsAny(alt, "?\\") {
		return apperr.New(apperr.CodeInvalidArgument,
			"deny_job_prefixes entry brace alternative has unsupported metacharacters")
	}
	// Nested brace content is expanded recursively; only validate leaf shape.
	if strings.ContainsAny(alt, "{}") {
		// Reject empty nested group fragments early when obvious; full structure
		// is checked by findMatchingBrace / splitBraceAlternatives on recurse.
		return nil
	}
	// ** as a whole alternative is only safe inside a multi-segment pattern after
	// expand; bare product elements are re-validated. Embedded ** in a segment
	// (e.g. a**b) is rejected later by plain validate. Allow ** as alt here so
	// folder/{a,**} → folder/** is expressible (trailing /** sugar after expand).
	if alt != "**" && strings.Contains(alt, "**") {
		return apperr.New(apperr.CodeInvalidArgument,
			"deny_job_prefixes entry brace alternative: ** must be the whole alternative")
	}
	// Classes in alts are validated after expand (and lightly here for fail-closed
	// early errors on obviously broken alts).
	if strings.Contains(alt, "[") {
		if err := validateSegmentCharClasses(alt); err != nil {
			return err
		}
	}
	return nil
}

// normalizeDenyJobPattern strips a trailing /** and reports whether the pattern
// form is structurally usable (not a full Validate — that is stricter).
// Trailing /** is semantically equivalent to the base literal/glob for matching.
// Base may contain mid-path ** whole segments.
func normalizeDenyJobPattern(pattern string) (base string, ok bool) {
	if pattern == "*" || pattern == "**" || pattern == "/**" {
		return "", false
	}
	if strings.HasSuffix(pattern, "/**") {
		base = strings.TrimSuffix(pattern, "/**")
		// /** alone or **/** (bare **) are unusable; */** → "*" is OK.
		if base == "" || base == "**" {
			return "", false
		}
		// Remaining may contain mid-path **; validate structure lightly.
		if !structurallyOKDenyBase(base) {
			return "", false
		}
		return base, true
	}
	if !structurallyOKDenyBase(pattern) {
		return "", false
	}
	return pattern, true
}

// structurallyOKDenyBase rejects embedded ** in non-** segments and empty segs.
// Invalid character classes make the base unusable (match fails closed).
func structurallyOKDenyBase(base string) bool {
	if base == "" || strings.HasSuffix(base, "/") {
		return false
	}
	// Brace patterns must be expanded before structural checks.
	if strings.ContainsAny(base, "{}") {
		return false
	}
	segs := strings.Split(base, "/")
	if len(segs) > MaxDenyJobPatternSegments {
		return false
	}
	for _, seg := range segs {
		if seg == "" {
			return false
		}
		if seg == "**" {
			continue
		}
		if strings.Contains(seg, "**") {
			return false
		}
		if strings.Contains(seg, "[") {
			if err := validateSegmentCharClasses(seg); err != nil {
				return false
			}
		}
	}
	return true
}

// matchPatternPrefix reports whether patternSegs matches some path-prefix of
// jobSegs (exact job or job under a matching prefix). Segment "**" matches zero
// or more job segments. Complexity O(len(pattern)·len(job)) via DP — no
// catastrophic backtracking.
func matchPatternPrefix(patternSegs, jobSegs []string) bool {
	np, nj := len(patternSegs), len(jobSegs)
	// dp[i][j] = patternSegs[:i] matches jobSegs[:j] exactly.
	// Success if dp[np][j] for any j in 0..nj (leftover job = children).
	dp := make([][]bool, np+1)
	for i := range dp {
		dp[i] = make([]bool, nj+1)
	}
	dp[0][0] = true

	for i := 1; i <= np; i++ {
		ps := patternSegs[i-1]
		if ps == "**" {
			// ** matches empty prefix of remaining job.
			dp[i][0] = dp[i-1][0]
		}
		for j := 1; j <= nj; j++ {
			if ps == "**" {
				// empty (from pattern without this job seg) or extend ** by one seg
				dp[i][j] = dp[i-1][j] || dp[i][j-1]
			} else {
				dp[i][j] = dp[i-1][j-1] && segmentMatchStar(ps, jobSegs[j-1])
			}
		}
	}
	for j := 0; j <= nj; j++ {
		if dp[np][j] {
			return true
		}
	}
	return false
}

// segmentMatchStar matches a single path segment against a pattern that may
// contain '*' and/or character classes […]. Callers must not pass pat == "**"
// here (handled at segment-list level).
func segmentMatchStar(pat, seg string) bool {
	if pat == "**" {
		return false
	}
	if !strings.ContainsAny(pat, "*[") {
		return pat == seg
	}
	return matchSegmentGlob(pat, seg)
}

// matchSegmentGlob implements shell-style * and […] matching within one path
// segment (no '/'). Character classes match exactly one byte at match time
// (not expanded to alternative patterns). Invalid classes → no match.
func matchSegmentGlob(pat, s string) bool {
	tokens, ok := tokenizeSegmentPattern(pat)
	if !ok {
		return false
	}
	return matchSegmentTokens(tokens, s)
}

// segTok is one atom in a path-segment pattern: literal byte, '*', or class.
type segTok struct {
	kind     byte // '*', 'l' (literal), 'c' (class)
	lit      byte
	neg      bool
	interior string // class interior (between [ and ], excluding leading ^)
}

// tokenizeSegmentPattern splits a segment pattern into atoms. Returns ok=false
// on unclosed/invalid character classes.
func tokenizeSegmentPattern(pat string) ([]segTok, bool) {
	out := make([]segTok, 0, len(pat))
	for i := 0; i < len(pat); {
		switch {
		case pat[i] == '*':
			// Collapse consecutive * (same as one *).
			out = append(out, segTok{kind: '*'})
			for i < len(pat) && pat[i] == '*' {
				i++
			}
		case pat[i] == '[':
			end, neg, interior, err := parseCharClass(pat, i)
			if err != nil {
				return nil, false
			}
			out = append(out, segTok{kind: 'c', neg: neg, interior: interior})
			i = end
		default:
			out = append(out, segTok{kind: 'l', lit: pat[i]})
			i++
		}
	}
	return out, true
}

// matchSegmentTokens DP-matches tokenized segment pattern against s.
// Complexity O(tokens·len(s)); segments are short path components.
func matchSegmentTokens(toks []segTok, s string) bool {
	n, m := len(toks), len(s)
	prev := make([]bool, m+1)
	cur := make([]bool, m+1)
	prev[0] = true
	for i := 1; i <= n; i++ {
		tk := toks[i-1]
		switch tk.kind {
		case '*':
			cur[0] = prev[0]
			for j := 1; j <= m; j++ {
				// * matches empty (prev[j]) or one more char (cur[j-1]).
				cur[j] = prev[j] || cur[j-1]
			}
		case 'l':
			cur[0] = false
			for j := 1; j <= m; j++ {
				cur[j] = prev[j-1] && tk.lit == s[j-1]
			}
		case 'c':
			cur[0] = false
			for j := 1; j <= m; j++ {
				cur[j] = prev[j-1] && charClassMatches(tk.neg, tk.interior, s[j-1])
			}
		default:
			return false
		}
		prev, cur = cur, prev
		for j := range cur {
			cur[j] = false
		}
	}
	return prev[m]
}

// matchStars is retained for tests/callers that only need * (no classes).
// Prefer matchSegmentGlob for full segment patterns.
func matchStars(pat, s string) bool {
	return matchSegmentGlob(pat, s)
}

// ---------------------------------------------------------------------------
// Character classes (Wave 31)
// ---------------------------------------------------------------------------

// validateSegmentCharClasses walks pat for […] groups and fails closed on
// empty [], unclosed [, inverted ranges, or "/" inside a class.
func validateSegmentCharClasses(seg string) error {
	for i := 0; i < len(seg); {
		if seg[i] != '[' {
			i++
			continue
		}
		end, _, _, err := parseCharClass(seg, i)
		if err != nil {
			return err
		}
		i = end
	}
	return nil
}

// parseCharClass parses seg[start:] which must begin with '['.
// Returns exclusive end index (after the closing ']'), negation flag, and the
// class interior (characters/ranges between brackets, excluding a leading '^').
//
// Rules (fail closed):
//   - unclosed '[' → error
//   - empty class "[]" (or only "^" with no members) → error
//   - inverted range (lo > hi) → error
//   - '/' inside class → error (classes cannot span path segments)
//   - first content char may be ']' (literal member); needs a later closer
//   - '-' at start/end of interior is literal; mid "a-z" is inclusive range
func parseCharClass(seg string, start int) (end int, neg bool, interior string, err error) {
	if start >= len(seg) || seg[start] != '[' {
		return 0, false, "", apperr.New(apperr.CodeInvalidArgument,
			"deny_job_prefixes entry has invalid character class")
	}
	i := start + 1
	if i >= len(seg) {
		return 0, false, "", apperr.New(apperr.CodeInvalidArgument,
			"deny_job_prefixes entry has unclosed character class '['")
	}
	if seg[i] == '^' {
		neg = true
		i++
		if i >= len(seg) {
			return 0, false, "", apperr.New(apperr.CodeInvalidArgument,
				"deny_job_prefixes entry has unclosed character class '['")
		}
	}
	contentStart := i
	// Optional literal ']' as the first content character (POSIX-style).
	if seg[i] == ']' {
		i++
	}
	for i < len(seg) && seg[i] != ']' {
		i++
	}
	if i >= len(seg) {
		return 0, false, "", apperr.New(apperr.CodeInvalidArgument,
			"deny_job_prefixes entry has unclosed character class '['")
	}
	interior = seg[contentStart:i]
	if interior == "" {
		return 0, false, "", apperr.New(apperr.CodeInvalidArgument,
			"deny_job_prefixes entry has empty character class []")
	}
	if err := validateClassInterior(interior); err != nil {
		return 0, false, "", err
	}
	return i + 1, neg, interior, nil
}

// validateClassInterior checks ranges and rejects "/" (segment boundary).
func validateClassInterior(interior string) error {
	if strings.Contains(interior, "/") {
		return apperr.New(apperr.CodeInvalidArgument,
			"deny_job_prefixes entry character class must not contain '/'")
	}
	i := 0
	for i < len(interior) {
		// Range: lo-hi when '-' is mid and both ends exist.
		if i+2 < len(interior) && interior[i+1] == '-' {
			lo, hi := interior[i], interior[i+2]
			if lo > hi {
				return apperr.New(apperr.CodeInvalidArgument,
					"deny_job_prefixes entry has inverted character class range")
			}
			i += 3
			continue
		}
		i++
	}
	return nil
}

// charClassMatches reports whether byte c is accepted by a class with the given
// negation and interior. Match-time set/range checks — never expands [a-z].
func charClassMatches(neg bool, interior string, c byte) bool {
	in := classInteriorContains(interior, c)
	if neg {
		return !in
	}
	return in
}

// classInteriorContains reports whether c is in the positive set described by
// interior (literals and inclusive lo-hi ranges).
func classInteriorContains(interior string, c byte) bool {
	i := 0
	for i < len(interior) {
		if i+2 < len(interior) && interior[i+1] == '-' {
			lo, hi := interior[i], interior[i+2]
			if c >= lo && c <= hi {
				return true
			}
			i += 3
			continue
		}
		if interior[i] == c {
			return true
		}
		i++
	}
	return false
}

// validateDenyJobPatternIndex wraps ValidateDenyJobPattern with a field index for
// Overlay.Validate error messages (job prefixes field).
func validateDenyJobPatternIndex(i int, pattern string) error {
	return validateDenyPatternIndex("deny_job_prefixes", i, pattern)
}

// validateDenyPatternIndex wraps ValidateDenyJobPattern with a JSON field name
// and index for Overlay.Validate (deny_job_prefixes / deny_node_names /
// deny_view_names / deny_artifact_paths / deny_branch_names share the same
// pattern language).
func validateDenyPatternIndex(field string, i int, pattern string) error {
	if err := ValidateDenyJobPattern(pattern); err != nil {
		msg := err.Error()
		var ae *apperr.Error
		if errors.As(err, &ae) && ae != nil && ae.Message != "" {
			msg = ae.Message
		}
		return apperr.New(apperr.CodeOf(err), fmt.Sprintf("%s[%d]: %s", field, i, msg))
	}
	return nil
}
