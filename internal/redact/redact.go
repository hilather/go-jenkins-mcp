package redact

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Replacement is the opaque marker substituted for secret material.
// Never include the original value in reports or logs.
const Replacement = "[REDACTED]"

// ContentKindBuildLog is the structured content_kind for build log excerpts.
const ContentKindBuildLog = "build_log_excerpt"

// Category names for Report counts (stable, value-free).
const (
	CategoryKnownSecret   = "known_secret"
	CategoryStructuredKey = "structured_key"
	CategoryAuthorization = "authorization"
	CategoryBearer        = "bearer"
	CategoryBasicAuth     = "basic_auth"
	CategoryCookie        = "cookie"
	CategoryPassword      = "password"
	CategoryAPIToken      = "api_token"
	CategoryAWSKey        = "aws_key"
	CategoryAWSSecret     = "aws_secret"
	CategoryPEMPrivateKey = "pem_private_key"
	CategoryJWT           = "jwt"
	CategoryGitHubToken   = "github_token"
	CategoryGitLabToken   = "gitlab_token"
	CategoryConnString    = "connection_string"
	CategoryEnterprise    = "enterprise"
	// CategoryBareToken is defined in bare.go (unlabeled high-entropy).
)

// Report holds redaction category counts without revealing matched values.
type Report struct {
	// Counts maps category name → number of replacements applied.
	Counts map[string]int `json:"counts,omitempty"`
}

// Total returns the sum of all category counts.
func (r Report) Total() int {
	n := 0
	for _, c := range r.Counts {
		n += c
	}
	return n
}

// add increments a category (lazy-init).
func (r *Report) add(cat string, n int) {
	if n <= 0 {
		return
	}
	if r.Counts == nil {
		r.Counts = make(map[string]int)
	}
	r.Counts[cat] += n
}

// NamedPattern is a named detector for enterprise (or built-in) lists.
// Prefer two capture groups: group 1 = kept prefix, group 2 = secret to redact.
// With zero or one group, the entire match is replaced by Replacement.
type NamedPattern struct {
	Category string
	RE       *regexp.Regexp
}

// EnterprisePatterns is the config hook for enterprise pattern lists (SEC-002).
// Implementations must be safe for concurrent use after construction.
// Compile regexes at load time; do not recompile per call.
type EnterprisePatterns interface {
	NamedPatterns() []NamedPattern
}

// CompileEnterprisePatterns builds NamedPatterns from config name/expression pairs.
// Invalid expressions fail the whole list (fail closed for that config load).
// Error messages include the pattern name only — not match samples or secrets.
func CompileEnterprisePatterns(items []struct{ Name, Expr string }) ([]NamedPattern, error) {
	out := make([]NamedPattern, 0, len(items))
	for _, it := range items {
		name := strings.TrimSpace(it.Name)
		if name == "" {
			name = CategoryEnterprise
		}
		expr := strings.TrimSpace(it.Expr)
		if expr == "" {
			continue
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("pattern %q: %w", name, err)
		}
		out = append(out, NamedPattern{Category: name, RE: re})
	}
	return out, nil
}

// staticPatterns is a simple EnterprisePatterns from a slice.
type staticPatterns []NamedPattern

func (s staticPatterns) NamedPatterns() []NamedPattern { return s }

// StaticEnterprise wraps a precompiled list as EnterprisePatterns.
func StaticEnterprise(patterns []NamedPattern) EnterprisePatterns {
	if len(patterns) == 0 {
		return nil
	}
	cp := make([]NamedPattern, len(patterns))
	copy(cp, patterns)
	return staticPatterns(cp)
}

// built-in detectors. Order matters for overlapping matches: more specific first.
// Patterns are deliberately conservative: prefer false positives over leaks.
type detector struct {
	category string
	re       *regexp.Regexp
	// prefixGroup: if true, keep submatch 1 and replace the rest of the match
	// with Replacement (classic "key=secret" forms). If false, replace whole match.
	prefixGroup bool
}

var builtinDetectors = []detector{
	// PEM private keys (multiline).
	{CategoryPEMPrivateKey, regexp.MustCompile(`(?s)-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----`), false},
	// Authorization headers (Bearer, Basic, raw schemes).
	{CategoryAuthorization, regexp.MustCompile(`(?i)(authorization\s*:\s*)(\S+(?:\s+\S+)?)`), true},
	{CategoryBearer, regexp.MustCompile(`(?i)(\bbearer\s+)([a-z0-9._\-+/=]+)`), true},
	{CategoryBasicAuth, regexp.MustCompile(`(?i)(\bbasic\s+)([a-z0-9+/=\s]+)`), true},
	// Cookies / session ids.
	{CategoryCookie, regexp.MustCompile(`(?i)(cookie\s*:\s*)([^\n\r]+)`), true},
	{CategoryCookie, regexp.MustCompile(`(?i)(jsessionid\s*=\s*)([^;\s\n\r]+)`), true},
	// Common secret parameter forms.
	{CategoryAPIToken, regexp.MustCompile(`(?i)(api[_-]?token\s*[=:]\s*)(\S+)`), true},
	{CategoryAPIToken, regexp.MustCompile(`(?i)(access[_-]?token\s*[=:]\s*)(\S+)`), true},
	{CategoryAPIToken, regexp.MustCompile(`(?i)(refresh[_-]?token\s*[=:]\s*)(\S+)`), true},
	{CategoryAPIToken, regexp.MustCompile(`(?i)(client[_-]?secret\s*[=:]\s*)(\S+)`), true},
	{CategoryPassword, regexp.MustCompile(`(?i)(password\s*[=:]\s*)(\S+)`), true},
	{CategoryAPIToken, regexp.MustCompile(`(?i)(x-api-key\s*[=:]\s*)(\S+)`), true},
	// AWS access key IDs (AKIA…).
	{CategoryAWSKey, regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`), false},
	// AWS secret access key labeled forms.
	{CategoryAWSSecret, regexp.MustCompile(`(?i)(aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*)([A-Za-z0-9/+=]{40})`), true},
	// JWT-like (header.payload.signature, base64url).
	{CategoryJWT, regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b`), false},
	// GitHub tokens.
	{CategoryGitHubToken, regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{36,})\b`), false},
	{CategoryGitHubToken, regexp.MustCompile(`\b(github_pat_[A-Za-z0-9_]{20,})\b`), false},
	// GitLab personal access tokens.
	{CategoryGitLabToken, regexp.MustCompile(`\b(glpat-[A-Za-z0-9\-_]{20,})\b`), false},
	// Connection strings with embedded user:password@ (keep scheme://user: … @host).
	// Applied via applyConnString (custom groups).
}

// Legacy alias used by older call sites; same marker.
const replacement = Replacement

// Package-level state for known secrets and enterprise patterns.
var (
	stateMu    sync.RWMutex
	knownList  []string // longest-first for overlapping exact matches
	enterprise EnterprisePatterns
)

// SetKnownSecrets installs exact-match secrets (e.g. session tokens) for the
// process. Values are never logged. Empty strings are ignored. Longest match
// first so overlapping tokens redact fully. Pass nil or empty to clear.
func SetKnownSecrets(secrets []string) {
	cleaned := make([]string, 0, len(secrets))
	seen := make(map[string]struct{}, len(secrets))
	for _, s := range secrets {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		cleaned = append(cleaned, s)
	}
	sort.Slice(cleaned, func(i, j int) bool {
		return len(cleaned[i]) > len(cleaned[j])
	})
	stateMu.Lock()
	knownList = cleaned
	stateMu.Unlock()
}

// ClearKnownSecrets removes all exact known-secret matchers.
func ClearKnownSecrets() { SetKnownSecrets(nil) }

// SetEnterprisePatterns installs the enterprise pattern list hook.
// Pass nil to clear. Safe for concurrent RedactText after return.
func SetEnterprisePatterns(p EnterprisePatterns) {
	stateMu.Lock()
	enterprise = p
	stateMu.Unlock()
}

// snapshot copies package state for a single redaction pass.
func snapshot() (known []string, ent []NamedPattern) {
	stateMu.RLock()
	defer stateMu.RUnlock()
	if len(knownList) > 0 {
		known = make([]string, len(knownList))
		copy(known, knownList)
	}
	if enterprise != nil {
		// Copy slice so callers cannot mutate concurrent state.
		raw := enterprise.NamedPatterns()
		if len(raw) > 0 {
			ent = make([]NamedPattern, len(raw))
			copy(ent, raw)
		}
	}
	return known, ent
}

// Secrets returns s with credential-like material replaced by [REDACTED].
// Empty input is returned unchanged. Equivalent to RedactText for callers that
// predate SEC-002 (apperr, diagnostics). Prefer RedactText / SanitizeForModel
// for new model-facing paths.
func Secrets(s string) string {
	return RedactText(s)
}

// RedactText applies layered secret redaction to plain text.
// Order: exact known secrets → built-in detectors → enterprise patterns →
// bare high-entropy tokens (CategoryBareToken).
func RedactText(s string) string {
	out, _ := RedactTextReport(s)
	return out
}

// RedactTextReport is like RedactText but also returns category counts
// (values are never included in the report).
func RedactTextReport(s string) (string, Report) {
	var rep Report
	if s == "" {
		return s, rep
	}
	known, ent := snapshot()
	out := s

	// 1. Exact known secrets (non-reversible matchers).
	for _, k := range known {
		if k == "" || !strings.Contains(out, k) {
			continue
		}
		n := strings.Count(out, k)
		out = strings.ReplaceAll(out, k, Replacement)
		rep.add(CategoryKnownSecret, n)
	}

	// 2. Built-in detectors.
	for _, d := range builtinDetectors {
		out = applyDetector(out, d, &rep)
	}
	out = applyConnString(out, &rep)

	// 3. Enterprise patterns.
	for _, p := range ent {
		if p.RE == nil {
			continue
		}
		cat := p.Category
		if cat == "" {
			cat = CategoryEnterprise
		}
		out = applyNamed(out, p.RE, cat, &rep)
	}

	// 4. Unlabeled high-entropy hex / base64url (KD-004 residual / Wave 25).
	// After labeled detectors so Bearer / api_token= keep specific categories.
	out = applyBareHighEntropyTokens(out, &rep)

	return out, rep
}

func applyDetector(s string, d detector, rep *Report) string {
	if d.re == nil {
		return s
	}
	if d.prefixGroup {
		// Count matches, replace group2 with marker keeping group1.
		matches := d.re.FindAllStringSubmatchIndex(s, -1)
		if len(matches) == 0 {
			return s
		}
		rep.add(d.category, len(matches))
		return d.re.ReplaceAllString(s, "${1}"+Replacement)
	}
	return applyNamed(s, d.re, d.category, rep)
}

func applyNamed(s string, re *regexp.Regexp, cat string, rep *Report) string {
	matches := re.FindAllStringIndex(s, -1)
	if len(matches) == 0 {
		return s
	}
	rep.add(cat, len(matches))
	// If two+ groups, keep first as prefix when present.
	if re.NumSubexp() >= 2 {
		return re.ReplaceAllString(s, "${1}"+Replacement)
	}
	return re.ReplaceAllString(s, Replacement)
}

// IsSensitiveFieldName reports whether a map/JSON key name should have its
// value fully redacted (structured parameter redaction).
func IsSensitiveFieldName(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(name)
	n = strings.ReplaceAll(n, "-", "_")
	// Normalize common separators.
	switch {
	case n == "password", n == "passwd", n == "secret", n == "token",
		n == "api_key", n == "apikey", n == "private_key", n == "access_key",
		n == "client_secret", n == "authorization", n == "cookie",
		n == "credentials", n == "credential", n == "jsessionid",
		n == "auth", n == "auth_token", n == "access_token", n == "refresh_token":
		return true
	}
	// Substring match for Jenkins-style Parameter names.
	for _, frag := range []string{
		"password", "passwd", "secret", "token", "api_key", "apikey",
		"private_key", "access_key", "client_secret", "credential",
		"authorization", "jsessionid",
	} {
		if strings.Contains(n, frag) {
			return true
		}
	}
	return false
}

// RedactJSON deep-redacts a JSON-shaped value (maps, slices, strings).
// Non-string leaves are left unchanged. Sensitive map keys have their entire
// value replaced with Replacement. String values also pass through RedactText.
// Returns a new structure (does not mutate the input when it is a map/slice
// produced via encoding/json); for arbitrary Go values, a JSON round-trip is used.
func RedactJSON(v any) any {
	out, _ := RedactJSONReport(v)
	return out
}

// RedactJSONReport is like RedactJSON with category counts.
func RedactJSONReport(v any) (any, Report) {
	var rep Report
	if v == nil {
		return nil, rep
	}
	// Normalize via JSON so structs become map[string]any.
	raw, err := json.Marshal(v)
	if err != nil {
		// Fallback: string form only.
		s, r := RedactTextReport(stringify(v))
		return s, r
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		s, r := RedactTextReport(string(raw))
		return s, r
	}
	return redactAny(generic, &rep), rep
}

func stringify(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

func redactAny(v any, rep *Report) any {
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		s, r := RedactTextReport(x)
		for cat, n := range r.Counts {
			rep.add(cat, n)
		}
		return s
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if IsSensitiveFieldName(k) {
				out[k] = Replacement
				rep.add(CategoryStructuredKey, 1)
				continue
			}
			out[k] = redactAny(val, rep)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = redactAny(val, rep)
		}
		return out
	case float64, bool:
		return x
	default:
		// encoding/json only yields the types above for generic decode.
		return x
	}
}

// ContainsSecretHint reports whether s still looks like it may hold a secret
// after redaction (for tests and fail-closed checks). Heuristic only.
func ContainsSecretHint(s string) bool {
	if s == "" {
		return false
	}
	// Common unredacted forms.
	if regexp.MustCompile(`(?i)bearer\s+[a-z0-9._\-+/=]{12,}`).MatchString(s) {
		return true
	}
	if regexp.MustCompile(`(?i)authorization\s*:\s*(?:basic|bearer)\s+[^\s\[]+`).MatchString(s) {
		return true
	}
	if regexp.MustCompile(`(?i)jsessionid\s*=\s*[^;\s\[]+`).MatchString(s) {
		return true
	}
	if regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`).MatchString(s) {
		return true
	}
	if regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`).MatchString(s) {
		return true
	}
	if regexp.MustCompile(`\bglpat-[A-Za-z0-9\-_]{20,}\b`).MatchString(s) {
		return true
	}
	if regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----`).MatchString(s) {
		return true
	}
	// Long JWT-like still present.
	if regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`).MatchString(s) {
		return true
	}
	// Unlabeled high-entropy bare token residual (same heuristic as RedactText).
	for i := 0; i < len(s); {
		if !isBareTokenByte(s[i]) {
			i++
			continue
		}
		j := i + 1
		for j < len(s) && isBareTokenByte(s[j]) {
			j++
		}
		if isHighEntropyBareToken(s[i:j]) {
			return true
		}
		i = j
	}
	return false
}

// UntrustedExcerpt is a structured wrapper for model-facing log/build text
// (SEC-003). Evidence handles (job, build, offset, ranges) stay outside this
// object so forensic raw retrieval is not broken.
type UntrustedExcerpt struct {
	// Untrusted is always true for build/log model content.
	Untrusted bool `json:"untrusted"`
	// ContentKind labels the excerpt type (e.g. build_log_excerpt).
	ContentKind string `json:"content_kind"`
	// Text is control-stripped and secret-redacted.
	Text string `json:"text"`
	// Redaction holds category counts when any redaction occurred (no values).
	Redaction map[string]int `json:"redaction,omitempty"`
}

// NewUntrustedExcerpt sanitizes s for the model and wraps it with untrusted metadata.
func NewUntrustedExcerpt(s, contentKind string) UntrustedExcerpt {
	if contentKind == "" {
		contentKind = ContentKindBuildLog
	}
	text, rep := SanitizeForModelReport(s)
	ex := UntrustedExcerpt{
		Untrusted:   true,
		ContentKind: contentKind,
		Text:        text,
	}
	if rep.Total() > 0 {
		ex.Redaction = rep.Counts
	}
	return ex
}

// connStringRE matches scheme://user:password@ and redacts the password.
var connStringRE = regexp.MustCompile(`(?i)\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?|mssql|sqlserver)://[^/\s:@]+:)([^@\s/]+)(@)`)

func applyConnString(s string, rep *Report) string {
	matches := connStringRE.FindAllStringSubmatchIndex(s, -1)
	if len(matches) == 0 {
		return s
	}
	rep.add(CategoryConnString, len(matches))
	return connStringRE.ReplaceAllString(s, "${1}"+Replacement+"${3}")
}
