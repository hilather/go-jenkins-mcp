package correlate

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// Bounds for correlation extraction (INT-004).
const (
	// DefaultMaxItems is the default cap on WorkItem entries returned.
	DefaultMaxItems = 32
	// HardMaxItems is the absolute ceiling.
	HardMaxItems = 64
	// maxScanTextBytes bounds each text field scanned for patterns.
	maxScanTextBytes = 4096
	// maxValueLen rejects oversized parameter values before scan.
	maxValueLen = 2048
	// maxURLLen bounds returned URL strings.
	maxURLLen = 512
)

// Kind classifies a correlated object.
const (
	KindJiraKey      = "jira_key"
	KindGitHubIssue  = "github_issue"
	KindGitHubPR     = "github_pull"
	KindCommitSHA    = "commit_sha"
	KindSCMHost      = "scm_host"
	KindGitLabIssue  = "gitlab_issue"
	KindGitLabMR     = "gitlab_merge_request"
	KindBitbucketPR  = "bitbucket_pull"
	KindGenericIssue = "issue_url"
)

// Evidence / source labels.
const (
	EvidenceSourceBuildMetadata = "jenkins_build_metadata"
	EvidenceSourceSCM           = "jenkins_scm"
	SourceBuildParameter        = "build_parameter"
	SourceCommitMessage         = "commit_message"
	SourceCommitID              = "commit_id"
	SourceRepoURL               = "repo_url"
	SourceCause                 = "cause"
	SourceFreeText              = "text"
)

// WorkItem is a bounded, non-secret correlation reference for model/operator use.
// It is not a remote ticket fetch; EvidenceSource is Jenkins metadata/SCM in MVP.
type WorkItem struct {
	// Kind is jira_key, github_issue, commit_sha, scm_host, …
	Kind string `json:"kind"`
	// ID is the normalized identifier (e.g. PROJ-123, owner/repo#42, full SHA).
	ID string `json:"id"`
	// URL is a sanitized https URL when the identifier was extracted as a URL.
	URL string `json:"url,omitempty"`
	// Host is the SCM/issue host when known (e.g. github.com).
	Host string `json:"host,omitempty"`
	// SourceKey is the original parameter key when from parameters.
	SourceKey string `json:"source_key,omitempty"`
	// Source is where the value was found.
	Source string `json:"source"`
	// EvidenceSource labels the evidence origin.
	EvidenceSource string `json:"evidence_source"`
	// Note carries residual guidance (never secrets).
	Note string `json:"note,omitempty"`
}

// ExtractOptions configures extraction caps.
type ExtractOptions struct {
	// MaxItems caps returned items (0 ⇒ DefaultMaxItems; hard-capped).
	MaxItems int
}

// ExtractResult is the bounded extraction outcome.
type ExtractResult struct {
	Items     []WorkItem
	Truncated bool
	// Scanned is the number of text/param fields considered.
	Scanned int
	// MaxItems is the effective cap applied.
	MaxItems int
}

// SCMCommitInput is a minimal commit shape for extraction (avoids jenkins import).
type SCMCommitInput struct {
	ID      string
	Message string
}

// SCMChangeSetInput is a minimal changeSet shape for extraction.
type SCMChangeSetInput struct {
	Kind     string
	RepoURLs []string
	Commits  []SCMCommitInput
}

// ExtractFromParams extracts work-item / issue identifiers from build parameters.
// Sensitive-looking keys are never read.
func ExtractFromParams(params map[string]string, opts ExtractOptions) ExtractResult {
	max := effectiveMax(opts.MaxItems)
	out := ExtractResult{MaxItems: max, Items: []WorkItem{}}
	if len(params) == 0 {
		return out
	}
	// Sorted key order: map iteration order is random, and both output order
	// and the over-cap truncation set must be reproducible for evidence.
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := params[k]
		if k == "" || isSensitiveKey(k) {
			continue
		}
		if len(v) > maxValueLen {
			v = v[:maxValueLen]
		}
		out.Scanned++
		addFromText(&out, v, SourceBuildParameter, EvidenceSourceBuildMetadata, k, max)
		if out.Truncated && len(out.Items) >= max {
			break
		}
	}
	return out
}

// ExtractFromText scans free text (cause description, etc.) for identifiers.
func ExtractFromText(text, source string, opts ExtractOptions) ExtractResult {
	max := effectiveMax(opts.MaxItems)
	out := ExtractResult{MaxItems: max, Items: []WorkItem{}}
	if strings.TrimSpace(text) == "" {
		return out
	}
	if source == "" {
		source = SourceFreeText
	}
	out.Scanned = 1
	addFromText(&out, text, source, EvidenceSourceBuildMetadata, "", max)
	return out
}

// ExtractFromChangeSets extracts commit SHAs, issue keys from messages, and SCM hosts.
func ExtractFromChangeSets(sets []SCMChangeSetInput, opts ExtractOptions) ExtractResult {
	max := effectiveMax(opts.MaxItems)
	out := ExtractResult{MaxItems: max, Items: []WorkItem{}}
	for _, cs := range sets {
		for _, ru := range cs.RepoURLs {
			out.Scanned++
			addRepoURL(&out, ru, max)
			if out.Truncated && len(out.Items) >= max {
				return out
			}
		}
		for _, c := range cs.Commits {
			out.Scanned++
			if sha, ok := normalizeSHA(c.ID); ok {
				addItem(&out, WorkItem{
					Kind:           KindCommitSHA,
					ID:             sha,
					Source:         SourceCommitID,
					EvidenceSource: EvidenceSourceSCM,
					Note:           "commit id from Jenkins SCM changeSet; no remote ticket fetch",
				}, max)
			}
			if c.Message != "" {
				addFromText(&out, c.Message, SourceCommitMessage, EvidenceSourceSCM, "", max)
			}
			if out.Truncated && len(out.Items) >= max {
				return out
			}
		}
	}
	return out
}

// MergeResults concatenates multiple ExtractResults under a single cap.
func MergeResults(opts ExtractOptions, parts ...ExtractResult) ExtractResult {
	max := effectiveMax(opts.MaxItems)
	out := ExtractResult{MaxItems: max, Items: []WorkItem{}}
	for _, p := range parts {
		out.Scanned += p.Scanned
		if p.Truncated {
			out.Truncated = true
		}
		for _, it := range p.Items {
			addItem(&out, it, max)
			if out.Truncated && len(out.Items) >= max {
				return out
			}
		}
	}
	return out
}

func effectiveMax(n int) int {
	if n <= 0 {
		n = DefaultMaxItems
	}
	if n > HardMaxItems {
		n = HardMaxItems
	}
	return n
}

func addFromText(out *ExtractResult, text, source, evidence, sourceKey string, max int) {
	if text == "" {
		return
	}
	if len(text) > maxScanTextBytes {
		text = text[:maxScanTextBytes]
	}

	// JIRA-like keys: PROJECT-123 (project starts with letter, 2+ alnum).
	for _, m := range jiraKeyRE.FindAllString(text, HardMaxItems) {
		addItem(out, WorkItem{
			Kind:           KindJiraKey,
			ID:             m,
			Source:         source,
			SourceKey:      sourceKey,
			EvidenceSource: evidence,
			Note:           "JIRA-like key from Jenkins metadata; no ticket API call",
		}, max)
	}

	// GitHub issue/PR URLs.
	// Groups: 1=owner 2=repo 3=issues|pull 4=num
	for _, m := range githubIssueRE.FindAllStringSubmatch(text, HardMaxItems) {
		if len(m) < 5 {
			continue
		}
		owner, repo, kindPart, num := m[1], m[2], m[3], m[4]
		kind := KindGitHubIssue
		if strings.EqualFold(kindPart, "pull") {
			kind = KindGitHubPR
		}
		id := owner + "/" + repo + "#" + num
		u := sanitizeHTTPSURL(m[0])
		addItem(out, WorkItem{
			Kind:           kind,
			ID:             id,
			URL:            u,
			Host:           "github.com",
			Source:         source,
			SourceKey:      sourceKey,
			EvidenceSource: evidence,
			Note:           "GitHub issue/PR URL from Jenkins metadata; no API call",
		}, max)
	}

	// GitLab issue/MR URLs (gitlab.com and self-hosted path patterns).
	// Groups: 1=host 2=path 3=issues|merge_requests 4=num
	for _, m := range gitlabIssueRE.FindAllStringSubmatch(text, HardMaxItems) {
		if len(m) < 5 {
			continue
		}
		host, path, kindPart, num := m[1], m[2], m[3], m[4]
		kind := KindGitLabIssue
		if kindPart == "merge_requests" {
			kind = KindGitLabMR
		}
		id := path + "#" + num
		u := sanitizeHTTPSURL(m[0])
		addItem(out, WorkItem{
			Kind:           kind,
			ID:             id,
			URL:            u,
			Host:           strings.ToLower(host),
			Source:         source,
			SourceKey:      sourceKey,
			EvidenceSource: evidence,
			Note:           "GitLab issue/MR URL from Jenkins metadata; no API call",
		}, max)
	}

	// Bitbucket PR URLs.
	// Groups: 1=workspace 2=repo 3=num
	for _, m := range bitbucketPRRE.FindAllStringSubmatch(text, HardMaxItems) {
		if len(m) < 4 {
			continue
		}
		ws, repo, num := m[1], m[2], m[3]
		id := ws + "/" + repo + "#" + num
		u := sanitizeHTTPSURL(m[0])
		addItem(out, WorkItem{
			Kind:           KindBitbucketPR,
			ID:             id,
			URL:            u,
			Host:           "bitbucket.org",
			Source:         source,
			SourceKey:      sourceKey,
			EvidenceSource: evidence,
			Note:           "Bitbucket PR URL from Jenkins metadata; no API call",
		}, max)
	}
}

func addRepoURL(out *ExtractResult, raw string, max int) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	// Credentials should already be stripped by SCM layer; strip again fail-closed.
	raw = stripUserinfo(raw)
	host, path := parseRepoHostPath(raw)
	if host == "" {
		return
	}
	id := host
	if path != "" {
		id = host + "/" + path
	}
	u := ""
	if strings.HasPrefix(strings.ToLower(raw), "https://") {
		u = sanitizeHTTPSURL(raw)
	}
	addItem(out, WorkItem{
		Kind:           KindSCMHost,
		ID:             id,
		URL:            u,
		Host:           host,
		Source:         SourceRepoURL,
		EvidenceSource: EvidenceSourceSCM,
		Note:           "SCM host/path from changeSet repo URL; correlation only",
	}, max)
}

func addItem(out *ExtractResult, it WorkItem, max int) {
	if it.ID == "" || it.Kind == "" {
		return
	}
	// Dedupe kind+id+source.
	for _, existing := range out.Items {
		if existing.Kind == it.Kind && existing.ID == it.ID && existing.Source == it.Source {
			return
		}
	}
	if len(out.Items) >= max {
		out.Truncated = true
		return
	}
	if it.EvidenceSource == "" {
		it.EvidenceSource = EvidenceSourceBuildMetadata
	}
	out.Items = append(out.Items, it)
}

// --- patterns ---

// JIRA-like: ABC-123, MYPROJ-9 (avoid matching SHAs / pure numbers).
var jiraKeyRE = regexp.MustCompile(`\b([A-Z][A-Z0-9]{1,15}-\d{1,8})\b`)

// github.com/owner/repo/issues|pull/N
var githubIssueRE = regexp.MustCompile(`(?i)https?://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/(issues|pull)/(\d{1,8})`)

// host/group/project/-/issues|merge_requests/N (GitLab)
var gitlabIssueRE = regexp.MustCompile(`(?i)https?://([A-Za-z0-9._:-]+)/([A-Za-z0-9_./-]+)/-/(issues|merge_requests)/(\d{1,8})`)

// bitbucket.org/workspace/repo/pull-requests/N
var bitbucketPRRE = regexp.MustCompile(`(?i)https?://(?:www\.)?bitbucket\.org/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/pull-requests?/(\d{1,8})`)

func normalizeSHA(id string) (string, bool) {
	id = strings.TrimSpace(strings.ToLower(id))
	if len(id) != 7 && len(id) != 8 && len(id) != 12 && len(id) != 40 {
		// Accept common short and full git SHAs only.
		if len(id) < 7 || len(id) > 40 {
			return "", false
		}
		// Allow other lengths 7–40 if all hex.
	}
	if len(id) < 7 || len(id) > 40 {
		return "", false
	}
	for _, r := range id {
		if !unicode.Is(unicode.ASCII_Hex_Digit, r) {
			return "", false
		}
	}
	// Reject pure decimal that looks like a short number (e.g. "1234567").
	allDigit := true
	for _, r := range id {
		if r < '0' || r > '9' {
			allDigit = false
			break
		}
	}
	if allDigit && len(id) < 12 {
		return "", false
	}
	return id, true
}

func sanitizeHTTPSURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) > maxURLLen {
		raw = raw[:maxURLLen]
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
		return ""
	}
	// Prefer https form without userinfo.
	u.User = nil
	u.Fragment = ""
	u.RawFragment = ""
	// Drop query (may hold tokens).
	u.RawQuery = ""
	u.ForceQuery = false
	if strings.EqualFold(u.Scheme, "http") {
		u.Scheme = "https"
	}
	s := u.String()
	if len(s) > maxURLLen {
		return s[:maxURLLen]
	}
	return s
}

func stripUserinfo(raw string) string {
	// git@host:path → leave for parseRepoHostPath
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err == nil && u.User != nil {
			u.User = nil
			return u.String()
		}
	}
	return raw
}

func parseRepoHostPath(raw string) (host, path string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	// SSH: git@github.com:org/repo.git
	if strings.HasPrefix(raw, "git@") {
		rest := strings.TrimPrefix(raw, "git@")
		parts := strings.SplitN(rest, ":", 2)
		if len(parts) == 2 {
			host = strings.ToLower(parts[0])
			path = strings.TrimSuffix(strings.Trim(parts[1], "/"), ".git")
			return host, path
		}
	}
	// scp-like without git@ already handled; try URL.
	u, err := url.Parse(raw)
	if err != nil {
		return "", ""
	}
	if u.Host != "" {
		host = strings.ToLower(u.Host)
		// strip default ports noise
		path = strings.TrimSuffix(strings.Trim(u.Path, "/"), ".git")
		return host, path
	}
	return "", ""
}

// isSensitiveKey rejects parameter names that must never be read for correlation.
func isSensitiveKey(name string) bool {
	if name == "" {
		return false
	}
	n := normalizeKey(name)
	switch n {
	case "password", "passwd", "secret", "token", "api_key", "apikey",
		"private_key", "access_key", "client_secret", "authorization",
		"cookie", "credentials", "credential", "auth", "auth_token",
		"access_token", "refresh_token", "api_token", "jsessionid":
		return true
	}
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

func normalizeKey(k string) string {
	k = strings.TrimSpace(k)
	k = strings.ToLower(k)
	k = strings.ReplaceAll(k, "-", "_")
	k = strings.ReplaceAll(k, ".", "_")
	return k
}
