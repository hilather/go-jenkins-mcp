package diagnostics

import (
	"sort"
	"strings"
)

// patternRule is a conservative literal failure marker.
type patternRule struct {
	id         string
	confidence float64
	// match reports whether line matches; line is original (not normalized).
	match func(line string) bool
}

// rules are ordered; first match wins for Pattern/Confidence on a line.
// Keep parsers pluggable and conservative — only strong failure markers.
// Higher-confidence / more-specific adapters come first to avoid generic
// fallbacks (error_prefix, failed_marker) claiming specialized lines.
var rules = []patternRule{
	{
		id:         "build_failure",
		confidence: 0.95,
		match:      containsFold("BUILD FAILURE"),
	},
	{
		// Gradle: exact banner phrase (not bare "FAILURE").
		id:         "gradle_failure",
		confidence: 0.95,
		match:      containsFold("FAILURE: Build failed with an exception"),
	},
	{
		// Maven Surefire / JUnit console markers.
		id:         "junit_surefire",
		confidence: 0.93,
		match:      matchJUnitSurefire,
	},
	{
		// Go testing: "--- FAIL: TestX" and package summary "FAIL\tpkg".
		id:         "go_test_fail",
		confidence: 0.92,
		match:      matchGoTestFail,
	},
	{
		// npm / node lifecycle failures.
		id:         "npm_error",
		confidence: 0.91,
		match: func(line string) bool {
			return strings.Contains(line, "npm ERR!") ||
				strings.Contains(line, "ELIFECYCLE")
		},
	},
	{
		id:         "maven_error_header",
		confidence: 0.9,
		match:      containsFold("### Error"),
	},
	{
		id:         "panic",
		confidence: 0.9,
		match: func(line string) bool {
			return strings.Contains(line, "panic:")
		},
	},
	{
		// OOM: Java + Linux killer line. Bare "Killed" is intentionally not matched.
		id:         "oom",
		confidence: 0.9,
		match:      matchOOM,
	},
	{
		// Docker CLI/API failure line.
		id:         "docker_daemon",
		confidence: 0.89,
		match:      containsFold("Error response from daemon"),
	},
	{
		// Kubernetes pod restart loop.
		id:         "k8s_crashloop",
		confidence: 0.89,
		match: func(line string) bool {
			return strings.Contains(line, "CrashLoopBackOff")
		},
	},
	{
		id:         "fatal",
		confidence: 0.88,
		match: func(line string) bool {
			t := strings.TrimSpace(line)
			return hasWordPrefixFold(t, "FATAL") || strings.Contains(line, "FATAL:")
		},
	},
	{
		id:         "exception",
		confidence: 0.85,
		match: func(line string) bool {
			if strings.Contains(line, "Exception") || strings.Contains(line, "exception:") {
				return true
			}
			return strings.Contains(line, "Traceback (most recent call last)")
		},
	},
	{
		id:         "assertion",
		confidence: 0.8,
		match: func(line string) bool {
			if strings.Contains(line, "AssertionError") {
				return true
			}
			return strings.Contains(line, "assert ") && strings.Contains(strings.ToLower(line), "failed")
		},
	},
	{
		// GCC/Clang style: "file:line:col: error: msg" — requires ": error: " mid-line.
		// Avoids bare "error:" prose spam.
		id:         "clang_error",
		confidence: 0.78,
		match: func(line string) bool {
			return strings.Contains(line, ": error: ")
		},
	},
	{
		id:         "error_prefix",
		confidence: 0.75,
		match: func(line string) bool {
			t := strings.TrimSpace(line)
			if strings.HasPrefix(t, "Error:") || strings.HasPrefix(t, "ERROR:") {
				return true
			}
			return hasWordPrefixFold(t, "ERROR") || strings.Contains(line, " Error:")
		},
	},
	{
		id:         "exit_nonzero",
		confidence: 0.7,
		match: func(line string) bool {
			low := strings.ToLower(line)
			return strings.Contains(low, "exit code") ||
				strings.Contains(low, "exited with") ||
				strings.Contains(low, "process completed with exit") ||
				strings.Contains(low, "command failed")
		},
	},
	{
		id:         "failed_marker",
		confidence: 0.6,
		match: func(line string) bool {
			t := strings.TrimSpace(line)
			if strings.Contains(t, "FAILED") {
				return true
			}
			low := strings.ToLower(t)
			if strings.HasPrefix(low, "failed ") || strings.HasPrefix(low, "failed:") {
				return true
			}
			return strings.Contains(t, "*** Failed") || strings.Contains(t, "failures=")
		},
	},
}

func containsFold(sub string) func(string) bool {
	return func(line string) bool {
		return strings.Contains(strings.ToLower(line), strings.ToLower(sub))
	}
}

// matchJUnitSurefire matches Surefire/JUnit strong failure markers only.
func matchJUnitSurefire(line string) bool {
	if strings.Contains(line, "<<< FAILURE!") || strings.Contains(line, "<<< ERROR!") {
		return true
	}
	if strings.Contains(strings.ToLower(line), "there are test failures") {
		return true
	}
	// Surefire summary: "Tests run: N, Failures: X, Errors: Y, ..."
	// Only when Failures or Errors is a nonzero integer (avoids clean summaries).
	if !strings.Contains(line, "Tests run:") {
		return false
	}
	return hasNonzeroLabeledInt(line, "Failures:") || hasNonzeroLabeledInt(line, "Errors:")
}

// hasNonzeroLabeledInt reports whether line contains label followed by an
// integer that is not all zeros (e.g. "Failures: 2", "Errors: 10").
func hasNonzeroLabeledInt(line, label string) bool {
	idx := strings.Index(line, label)
	if idx < 0 {
		return false
	}
	rest := strings.TrimSpace(line[idx+len(label):])
	if rest == "" || rest[0] < '0' || rest[0] > '9' {
		return false
	}
	nonzero := false
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if c < '0' || c > '9' {
			break
		}
		if c != '0' {
			nonzero = true
		}
	}
	return nonzero
}

// matchGoTestFail matches go test failure markers without bare "FAIL" spam.
func matchGoTestFail(line string) bool {
	if strings.Contains(line, "--- FAIL:") {
		return true
	}
	t := strings.TrimSpace(line)
	// Package summary: "FAIL\tpackage/path" (go test default) or "FAIL  package".
	if strings.HasPrefix(t, "FAIL\t") {
		return true
	}
	if strings.HasPrefix(t, "FAIL  ") && len(t) > 6 {
		// Require a non-space package token after two spaces.
		rest := strings.TrimSpace(t[4:])
		return rest != "" && !strings.HasPrefix(rest, "-")
	}
	return false
}

// matchOOM matches high-confidence out-of-memory markers only.
// Bare "Killed" is excluded (too many false positives in CI chatter).
func matchOOM(line string) bool {
	if strings.Contains(line, "OutOfMemoryError") {
		return true
	}
	// Linux OOM killer classic line.
	if strings.Contains(line, "Out of memory: Killed process") {
		return true
	}
	return strings.Contains(strings.ToLower(line), "cannot allocate memory")
}

// hasWordPrefixFold reports whether line starts with word (case-insensitive)
// as a leading token (optional [LEVEL] brackets handled).
func hasWordPrefixFold(line, word string) bool {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "[") {
		if i := strings.Index(line, "]"); i > 0 {
			inner := line[1:i]
			if strings.EqualFold(inner, word) {
				return true
			}
			line = strings.TrimSpace(line[i+1:])
		}
	}
	if len(line) < len(word) {
		return false
	}
	if !strings.EqualFold(line[:len(word)], word) {
		return false
	}
	if len(line) == len(word) {
		return true
	}
	r := line[len(word)]
	return r == ' ' || r == '\t' || r == ':' || r == ',' || r == '|'
}

func normalizeOptions(opts Options) Options {
	if opts.MaxFindings <= 0 {
		opts.MaxFindings = DefaultMaxFindings
	}
	if opts.MaxFindings > HardMaxFindings {
		opts.MaxFindings = HardMaxFindings
	}
	if opts.MaxEvidenceLines <= 0 {
		opts.MaxEvidenceLines = DefaultMaxEvidenceLines
	}
	if opts.MaxEvidenceLines > HardMaxEvidenceLines {
		opts.MaxEvidenceLines = HardMaxEvidenceLines
	}
	return opts
}

// matchLine returns the first matching rule for line, or ok=false.
func matchLine(line string) (rule patternRule, ok bool) {
	for _, r := range rules {
		if r.match != nil && r.match(line) {
			return r, true
		}
	}
	return patternRule{}, false
}

// lineAgg accumulates matches for one signature.
type lineAgg struct {
	rule       patternRule
	firstMsg   string
	norm       string
	sig        string
	lineStart  int64
	lineEnd    int64
	count      int
	evidence   []EvidenceLine
	confidence float64
}

// ExtractCandidates scans log text line-by-line and returns bounded findings.
// Empty input yields an empty Result (not an error).
//
// Every returned Finding maps to exact source line numbers within text.
// Matching uses conservative literal rules; non-matching lines are ignored.
func ExtractCandidates(logText string, opts Options) Result {
	opts = normalizeOptions(opts)
	if logText == "" {
		return Result{}
	}
	lines := splitLines(logText)
	return extractLines(lines, opts, false)
}

// ExtractFromHits converts search hits into findings using the same rules.
// Hits with Line <= 0 are assigned sequential 1-based numbers in order.
// Hits that do not match failure rules are kept as pattern "search_hit" so
// SEARCH-driven diagnose does not drop data (parser fallback).
func ExtractFromHits(hits []SearchHit, opts Options) Result {
	opts = normalizeOptions(opts)
	if len(hits) == 0 {
		return Result{}
	}
	lines := make([]numberedLine, 0, len(hits))
	seq := int64(1)
	for _, h := range hits {
		ln := h.Line
		if ln <= 0 {
			ln = seq
			seq++
		} else if ln >= seq {
			seq = ln + 1
		}
		lines = append(lines, numberedLine{line: ln, text: h.Text})
	}
	return extractNumbered(lines, opts, true)
}

type numberedLine struct {
	line int64
	text string
}

func extractLines(lines []string, opts Options, keepUnmatched bool) Result {
	numbered := make([]numberedLine, len(lines))
	for i, raw := range lines {
		numbered[i] = numberedLine{line: int64(i) + 1, text: raw}
	}
	return extractNumbered(numbered, opts, keepUnmatched)
}

func extractNumbered(lines []numberedLine, opts Options, keepUnmatched bool) Result {
	bySig := make(map[string]*lineAgg)
	order := make([]string, 0)
	var firstErr, lastErr int64
	const highConf = 0.7

	for _, it := range lines {
		text := strings.TrimRight(it.text, "\r\n")
		if text == "" {
			continue
		}
		rule, ok := matchLine(text)
		if !ok {
			if !keepUnmatched {
				continue
			}
			rule = patternRule{id: "search_hit", confidence: 0.4}
		}
		norm := NormalizeLine(text)
		sig := Signature(norm)
		if sig == "" {
			sig = Signature(rule.id + "|empty")
			norm = rule.id
		}
		a, exists := bySig[sig]
		if !exists {
			a = &lineAgg{
				rule:       rule,
				firstMsg:   truncateBytes(text, MaxMessageBytes),
				norm:       norm,
				sig:        sig,
				lineStart:  it.line,
				lineEnd:    it.line,
				count:      1,
				confidence: rule.confidence,
				evidence: []EvidenceLine{{
					Line: it.line,
					Text: truncateBytes(text, MaxMessageBytes),
				}},
			}
			bySig[sig] = a
			order = append(order, sig)
		} else {
			a.count++
			if it.line < a.lineStart {
				a.lineStart = it.line
			}
			if it.line > a.lineEnd {
				a.lineEnd = it.line
			}
			if rule.confidence > a.confidence {
				a.confidence = rule.confidence
				a.rule = rule
			}
			if len(a.evidence) < opts.MaxEvidenceLines {
				a.evidence = append(a.evidence, EvidenceLine{
					Line: it.line,
					Text: truncateBytes(text, MaxMessageBytes),
				})
			}
		}
		if rule.confidence >= highConf {
			if firstErr == 0 || it.line < firstErr {
				firstErr = it.line
			}
			if it.line > lastErr {
				lastErr = it.line
			}
		}
	}

	return finalizeFromMap(bySig, order, opts, len(lines), firstErr, lastErr)
}

func finalizeFromMap(bySig map[string]*lineAgg, order []string, opts Options, linesScanned int, firstErr, lastErr int64) Result {
	type ranked struct {
		a *lineAgg
	}
	items := make([]ranked, 0, len(order))
	for _, sig := range order {
		a := bySig[sig]
		if a == nil {
			continue
		}
		items = append(items, ranked{a: a})
	}
	sort.SliceStable(items, func(i, j int) bool {
		ai, aj := items[i].a, items[j].a
		if ai.confidence != aj.confidence {
			return ai.confidence > aj.confidence
		}
		if ai.count != aj.count {
			return ai.count > aj.count
		}
		return ai.lineStart < aj.lineStart
	})

	truncated := false
	if len(items) > opts.MaxFindings {
		truncated = true
		items = items[:opts.MaxFindings]
	}

	findings := make([]Finding, 0, len(items))
	for _, it := range items {
		a := it.a
		f := Finding{
			Signature:  a.sig,
			Pattern:    a.rule.id,
			Message:    a.firstMsg,
			Confidence: a.confidence,
			LineStart:  a.lineStart,
			LineEnd:    a.lineEnd,
			Count:      a.count,
			Evidence:   a.evidence,
		}
		if opts.IncludeNormalized {
			f.Normalized = a.norm
		}
		findings = append(findings, f)
	}
	return Result{
		Findings:       findings,
		LinesScanned:   linesScanned,
		Truncated:      truncated,
		FirstErrorLine: firstErr,
		LastErrorLine:  lastErr,
	}
}

func splitLines(text string) []string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	if text == "" {
		return nil
	}
	parts := strings.Split(text, "\n")
	if len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}
