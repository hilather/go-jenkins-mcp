package jenkins

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// Bounds for SCM change extraction (SCM-001).
const (
	DefaultMaxSCMCommits      = 50
	MaxSCMCommitsHardCap      = 200
	DefaultMaxSCMFiles        = 50
	MaxSCMFilesHardCap        = 200
	DefaultMaxSCMMessageBytes = 512
	MaxSCMMessageBytesHardCap = 2048
	DefaultMaxSCMScanBuilds   = 20
	MaxSCMScanBuildsHardCap   = 50
	maxSCMBodyBytes           = 4 << 20 // 4 MiB per build JSON
)

// SCMCommit is one changeset item (bounded message + file list).
type SCMCommit struct {
	// ID is the commit/revision id (SHA or SCM-specific).
	ID string `json:"id,omitempty"`
	// Message is truncated commit subject/body.
	Message string `json:"message,omitempty"`
	// Author is the Jenkins-reported author display name.
	Author string `json:"author,omitempty"`
	// Timestamp is epoch millis when provided by Jenkins.
	Timestamp int64 `json:"timestamp,omitempty"`
	// AffectedPaths is a bounded modified-file summary.
	AffectedPaths []string `json:"affectedPaths,omitempty"`
	// PathsTruncated is true when more files exist than returned.
	PathsTruncated bool `json:"pathsTruncated,omitempty"`
	// MessageTruncated is true when the message was cut by bounds.
	MessageTruncated bool `json:"messageTruncated,omitempty"`
	// BuildNumber is the build this commit was reported on (range aggregate).
	BuildNumber int `json:"buildNumber,omitempty"`
}

// SCMRevision is a branch/revision tip from BuildData (or similar).
type SCMRevision struct {
	// Branch is e.g. "refs/heads/main" or "main".
	Branch string `json:"branch,omitempty"`
	// SHA is the revision id.
	SHA string `json:"sha,omitempty"`
}

// SCMCulprit is a Jenkins-reported culprit (correlation, not proof of cause).
type SCMCulprit struct {
	// FullName is the Jenkins user display name.
	FullName string `json:"fullName,omitempty"`
	// Note labels the field as correlation only.
	Note string `json:"note,omitempty"`
}

// SCMChangeSet is one SCM contribution (one repo / changeSet kind).
type SCMChangeSet struct {
	// Kind is Jenkins changeSet.kind (e.g. "git") when present.
	Kind string `json:"kind,omitempty"`
	// RepoURLs are credential-stripped remote URLs.
	RepoURLs []string `json:"repoUrls,omitempty"`
	// Revisions are last-built / branch tips from BuildData when available.
	Revisions []SCMRevision `json:"revisions,omitempty"`
	// Commits are bounded changeset items for this SCM.
	Commits []SCMCommit `json:"commits,omitempty"`
	// CommitsTotal is the number of commits seen for this set before commit offset/limit.
	CommitsTotal int `json:"commitsTotal"`
	// CommitsTruncated is true when more commits exist than returned for this set.
	CommitsTruncated bool `json:"commitsTruncated,omitempty"`
}

// BuildChanges is the bounded SCM change result (SCM-001).
type BuildChanges struct {
	JobName       string `json:"jobName"`
	BuildNumber   int    `json:"buildNumber"`
	BaselineBuild int    `json:"baselineBuild,omitempty"`
	// ChangeSets are explicit multi-SCM contributions (never merged into one list).
	ChangeSets []SCMChangeSet `json:"changeSets"`
	// Culprits are Jenkins-reported correlation only (not proof).
	Culprits []SCMCulprit `json:"culprits,omitempty"`
	// CommitOffset / CommitLimit describe pagination over the flattened commit stream
	// used for page selection (per-set commits still carry their own truncation flags).
	CommitOffset int `json:"commitOffset"`
	CommitLimit  int `json:"commitLimit"`
	// CommitsReturned is the number of commits in this page (all sets).
	CommitsReturned int `json:"commitsReturned"`
	// CommitsTotal is commits seen across scanned builds (pre-pagination).
	CommitsTotal int `json:"commitsTotal"`
	// Truncated is true when commit or build scan bounds cut data.
	Truncated bool `json:"truncated,omitempty"`
	// BuildsScanned is how many build API responses were read (range mode).
	BuildsScanned int `json:"buildsScanned,omitempty"`
	// Residuals explain missing data without inventing changes.
	Residuals []string `json:"residuals,omitempty"`
	// Message is a short human status (e.g. no change data).
	Message string `json:"message,omitempty"`
}

// GetBuildChangesToolArgs are arguments for jenkins_get_build_changes (SCM-001).
type GetBuildChangesToolArgs struct {
	JobName     string `json:"job_name" jsonschema:"Name/path of the Jenkins job (supports folders)"`
	BuildNumber int    `json:"build_number" jsonschema:"Build number to inspect (typically the failing build)"`
	// BaselineBuild when >0 aggregates changes from (baseline, build] inclusive of build.
	// When 0, only the single build's changeSet is returned.
	BaselineBuild int `json:"baseline_build,omitempty" jsonschema:"Optional baseline build number; changes are aggregated for builds after baseline through build_number"`
	// MaxCommits caps commits returned after offset (default 50, max 200).
	MaxCommits int `json:"max_commits,omitempty" jsonschema:"Maximum commits to return after offset (default: 50, max: 200)" default:"50"`
	// CommitOffset skips this many commits for pagination (default 0).
	CommitOffset int `json:"commit_offset,omitempty" jsonschema:"Number of commits to skip for pagination (default: 0)" default:"0"`
	// MaxFiles caps affected paths per commit (default 50, max 200).
	MaxFiles int `json:"max_files,omitempty" jsonschema:"Maximum affected paths per commit (default: 50, max: 200)" default:"50"`
	// MaxMessageBytes caps commit message length (default 512, max 2048).
	MaxMessageBytes int `json:"max_message_bytes,omitempty" jsonschema:"Maximum commit message bytes (default: 512, max: 2048)" default:"512"`
	// MaxScanBuilds caps how many builds are fetched when aggregating a range (default 20, max 50).
	MaxScanBuilds int `json:"max_scan_builds,omitempty" jsonschema:"Maximum builds to scan in baseline range (default: 20, max: 50)" default:"20"`
}

// GetBuildChangesToolResponse is returned by jenkins_get_build_changes.
type GetBuildChangesToolResponse = BuildChanges

// scmTree is the Jenkins tree selector for change/SCM fields.
const scmTree = "number,result,building," +
	"changeSet[kind,items[commitId,msg,message,author[fullName],timestamp,affectedPaths,date]]," +
	"changeSets[kind,items[commitId,msg,message,author[fullName],timestamp,affectedPaths,date]]," +
	"culprits[fullName]," +
	"actions[_class,remoteUrls,lastBuiltRevision[SHA1,branch[name,SHA1]]]"

// GetBuildChanges returns bounded SCM changes for a build, optionally aggregated
// since a baseline build (SCM-001). Missing change data yields empty sets + residual notes.
func (opts *Client) GetBuildChanges(ctx context.Context, args GetBuildChangesToolArgs) (*BuildChanges, error) {
	if opts == nil {
		return nil, fmt.Errorf("jenkins client is nil")
	}
	jobName := strings.TrimSpace(args.JobName)
	if jobName == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "job_name is required")
	}
	if strings.Contains(jobName, "://") {
		return nil, apperr.New(apperr.CodeInvalidArgument, "job_name must be a typed path, not a URL")
	}
	if args.BuildNumber <= 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument, "build_number must be positive")
	}
	if args.BaselineBuild < 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument, "baseline_build must be non-negative")
	}
	if args.BaselineBuild > 0 && args.BaselineBuild >= args.BuildNumber {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			"baseline_build must be less than build_number")
	}

	maxCommits := args.MaxCommits
	if maxCommits <= 0 {
		maxCommits = DefaultMaxSCMCommits
	}
	if maxCommits > MaxSCMCommitsHardCap {
		maxCommits = MaxSCMCommitsHardCap
	}
	maxFiles := args.MaxFiles
	if maxFiles <= 0 {
		maxFiles = DefaultMaxSCMFiles
	}
	if maxFiles > MaxSCMFilesHardCap {
		maxFiles = MaxSCMFilesHardCap
	}
	maxMsg := args.MaxMessageBytes
	if maxMsg <= 0 {
		maxMsg = DefaultMaxSCMMessageBytes
	}
	if maxMsg > MaxSCMMessageBytesHardCap {
		maxMsg = MaxSCMMessageBytesHardCap
	}
	offset := args.CommitOffset
	if offset < 0 {
		offset = 0
	}
	maxScan := args.MaxScanBuilds
	if maxScan <= 0 {
		maxScan = DefaultMaxSCMScanBuilds
	}
	if maxScan > MaxSCMScanBuildsHardCap {
		maxScan = MaxSCMScanBuildsHardCap
	}

	// Determine build numbers to scan (oldest → newest for stable ordering).
	var numbers []int
	if args.BaselineBuild > 0 {
		start := args.BaselineBuild + 1
		// Cap scan from the high end if the range is larger than maxScan.
		if args.BuildNumber-args.BaselineBuild > maxScan {
			start = args.BuildNumber - maxScan + 1
			if start <= args.BaselineBuild {
				start = args.BaselineBuild + 1
			}
		}
		for n := start; n <= args.BuildNumber; n++ {
			numbers = append(numbers, n)
		}
	} else {
		numbers = []int{args.BuildNumber}
	}

	out := &BuildChanges{
		JobName:       jobName,
		BuildNumber:   args.BuildNumber,
		BaselineBuild: args.BaselineBuild,
		CommitOffset:  offset,
		CommitLimit:   maxCommits,
		ChangeSets:    nil,
	}

	// Key change sets by kind+first repo URL for multi-build merge.
	setOrder := make([]scmSetKey, 0)
	setMap := make(map[scmSetKey]*SCMChangeSet)
	var allCommits []scmCommitRef // ordered for pagination
	var residuals []string
	scanned := 0
	rangeTruncated := args.BaselineBuild > 0 && (args.BuildNumber-args.BaselineBuild) > maxScan

	for _, n := range numbers {
		raw, err := opts.fetchSCMBuildJSON(ctx, jobName, n)
		if err != nil {
			// Fail closed on target build; degrade on intermediate.
			if n == args.BuildNumber {
				return nil, err
			}
			residuals = append(residuals,
				fmt.Sprintf("build #%d change data unavailable: %s", n, safeSCMErr(err)))
			continue
		}
		scanned++
		parsed := parseSCMBuildJSON(raw, n, maxFiles, maxMsg)
		if len(parsed.residuals) > 0 {
			residuals = append(residuals, parsed.residuals...)
		}
		for _, cs := range parsed.sets {
			key := scmSetKey{kind: cs.Kind, repo: firstRepo(cs.RepoURLs)}
			existing, ok := setMap[key]
			if !ok {
				cp := cs
				cp.Commits = nil // commits collected via allCommits + reassembly
				setMap[key] = &cp
				setOrder = append(setOrder, key)
				existing = setMap[key]
			} else {
				// Merge repo URLs and revisions (dedupe).
				existing.RepoURLs = mergeUniqueStrings(existing.RepoURLs, cs.RepoURLs)
				existing.Revisions = mergeRevisions(existing.Revisions, cs.Revisions)
				if existing.Kind == "" {
					existing.Kind = cs.Kind
				}
			}
			for _, c := range cs.Commits {
				allCommits = append(allCommits, scmCommitRef{key: key, commit: c})
			}
		}
		// Culprits only from the target build (Jenkins labels them on the failing build).
		if n == args.BuildNumber {
			out.Culprits = parsed.culprits
		}
	}

	out.BuildsScanned = scanned
	out.CommitsTotal = len(allCommits)

	// Paginate flattened commits then re-bucket into change sets.
	page := allCommits
	if offset > 0 {
		if offset >= len(page) {
			page = nil
		} else {
			page = page[offset:]
		}
	}
	if len(page) > maxCommits {
		page = page[:maxCommits]
		out.Truncated = true
	}
	if rangeTruncated {
		out.Truncated = true
		residuals = append(residuals,
			fmt.Sprintf("baseline range exceeded max_scan_builds=%d; only newest %d builds scanned",
				maxScan, scanned))
	}

	// Rebuild per-set commit lists for the page only.
	for _, ref := range page {
		cs := setMap[ref.key]
		if cs == nil {
			continue
		}
		cs.Commits = append(cs.Commits, ref.commit)
	}
	// Totals / truncation per set (relative to full allCommits for that set).
	setTotals := make(map[scmSetKey]int)
	for _, ref := range allCommits {
		setTotals[ref.key]++
	}
	out.ChangeSets = make([]SCMChangeSet, 0, len(setOrder))
	for _, key := range setOrder {
		cs := setMap[key]
		if cs == nil {
			continue
		}
		cs.CommitsTotal = setTotals[key]
		// Truncated if not all of this set's commits appear in the page.
		if len(cs.Commits) < cs.CommitsTotal {
			// Only mark truncated when some of this set fell outside the page window
			// or global max — always true when total > returned for set.
			cs.CommitsTruncated = true
			out.Truncated = true
		}
		out.ChangeSets = append(out.ChangeSets, *cs)
	}
	out.CommitsReturned = len(page)

	// Deduplicate residuals and add missing-data note when empty.
	out.Residuals = uniqueNonEmpty(residuals)
	if len(out.ChangeSets) == 0 {
		out.ChangeSets = []SCMChangeSet{}
		out.Message = "no SCM change data reported by Jenkins for this build"
		out.Residuals = append(out.Residuals,
			"missing changeSet/changeSets/BuildData; nothing invented")
	} else if out.CommitsTotal == 0 {
		out.Message = "SCM identity present but no commits in range"
	}

	return out, nil
}

type scmSetKey struct {
	kind string
	repo string
}

type scmCommitRef struct {
	key    scmSetKey
	commit SCMCommit
}

type scmParsedBuild struct {
	sets      []SCMChangeSet
	culprits  []SCMCulprit
	residuals []string
}

// scmBuildData is the subset of hudson.plugins.git.util.BuildData we consume.
type scmBuildData struct {
	Class             string   `json:"_class"`
	RemoteURLs        []string `json:"remoteUrls"`
	LastBuiltRevision *struct {
		SHA1   string `json:"SHA1"`
		Branch []struct {
			Name string `json:"name"`
			SHA1 string `json:"SHA1"`
		} `json:"branch"`
	} `json:"lastBuiltRevision"`
}

func (opts *Client) fetchSCMBuildJSON(ctx context.Context, jobName string, buildNumber int) ([]byte, error) {
	jobPath := BuildJobPath(jobName)
	apiPath := fmt.Sprintf("%s/%d/api/json?tree=%s", jobPath, buildNumber, url.QueryEscape(scmTree))
	resp, err := opts.CallJenkins(ctx, opts.Client, http.MethodGet, apiPath, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch build SCM data: %w", err)
	}
	body, err := readLimited(resp.Body, maxSCMBodyBytes)
	_ = resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to read build SCM data: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return body, nil
	case http.StatusNotFound:
		return nil, apperr.New(apperr.CodeNotFound,
			fmt.Sprintf("build not found for job %q build #%d", jobName, buildNumber))
	case http.StatusUnauthorized:
		return nil, apperr.New(apperr.CodeAuthentication, "not authenticated for build SCM data")
	case http.StatusForbidden:
		return nil, apperr.New(apperr.CodeAuthorization, "not authorized for build SCM data")
	default:
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, truncateForErr(string(body)))
	}
}

// parseSCMBuildJSON extracts changeSets, BuildData, and culprits without inventing data.
func parseSCMBuildJSON(body []byte, buildNumber, maxFiles, maxMsg int) scmParsedBuild {
	var raw struct {
		Number    int `json:"number"`
		ChangeSet *struct {
			Kind  string            `json:"kind"`
			Items []json.RawMessage `json:"items"`
		} `json:"changeSet"`
		ChangeSets []struct {
			Kind  string            `json:"kind"`
			Items []json.RawMessage `json:"items"`
		} `json:"changeSets"`
		Culprits []struct {
			FullName string `json:"fullName"`
		} `json:"culprits"`
		Actions []json.RawMessage `json:"actions"`
	}
	var out scmParsedBuild
	if err := json.Unmarshal(body, &raw); err != nil {
		out.residuals = append(out.residuals, "invalid build SCM JSON")
		return out
	}

	// BuildData actions → repo URLs + revisions (multi-SCM = multiple BuildData).
	var dataList []scmBuildData
	for _, a := range raw.Actions {
		var bd scmBuildData
		if err := json.Unmarshal(a, &bd); err != nil {
			continue
		}
		if !isBuildDataClass(bd.Class) {
			// Still accept remoteUrls if present (plugin variants).
			if len(bd.RemoteURLs) == 0 && bd.LastBuiltRevision == nil {
				continue
			}
		}
		if len(bd.RemoteURLs) == 0 && bd.LastBuiltRevision == nil {
			continue
		}
		dataList = append(dataList, bd)
	}

	// Prefer multi changeSets when present; else single changeSet.
	type rawSet struct {
		kind  string
		items []json.RawMessage
	}
	var sets []rawSet
	if len(raw.ChangeSets) > 0 {
		for _, cs := range raw.ChangeSets {
			sets = append(sets, rawSet{kind: cs.Kind, items: cs.Items})
		}
	} else if raw.ChangeSet != nil && (raw.ChangeSet.Kind != "" || len(raw.ChangeSet.Items) > 0) {
		sets = append(sets, rawSet{kind: raw.ChangeSet.Kind, items: raw.ChangeSet.Items})
	}

	// Pair change sets with BuildData by index when counts match; else attach all
	// BuildData as separate sets when there are no changeSets, or merge by index.
	if len(sets) == 0 && len(dataList) > 0 {
		// Identity only (no commits).
		for _, bd := range dataList {
			cs := SCMChangeSet{
				Kind:      kindFromBuildData(bd.Class),
				RepoURLs:  stripRepoURLList(bd.RemoteURLs),
				Revisions: revisionsFromBuildData(bd),
			}
			out.sets = append(out.sets, cs)
		}
	} else {
		for i, s := range sets {
			cs := SCMChangeSet{Kind: s.kind}
			if i < len(dataList) {
				cs.RepoURLs = stripRepoURLList(dataList[i].RemoteURLs)
				cs.Revisions = revisionsFromBuildData(dataList[i])
				if cs.Kind == "" {
					cs.Kind = kindFromBuildData(dataList[i].Class)
				}
			} else if len(dataList) == 1 {
				// Single BuildData for multi empty-kind sets: attach once.
				cs.RepoURLs = stripRepoURLList(dataList[0].RemoteURLs)
				cs.Revisions = revisionsFromBuildData(dataList[0])
			}
			for _, item := range s.items {
				c, ok := parseSCMItem(item, buildNumber, maxFiles, maxMsg)
				if ok {
					cs.Commits = append(cs.Commits, c)
				}
			}
			cs.CommitsTotal = len(cs.Commits)
			out.sets = append(out.sets, cs)
		}
		// Extra BuildData beyond changeSet count → explicit multi-SCM identity rows.
		if len(dataList) > len(sets) {
			for i := len(sets); i < len(dataList); i++ {
				bd := dataList[i]
				out.sets = append(out.sets, SCMChangeSet{
					Kind:      kindFromBuildData(bd.Class),
					RepoURLs:  stripRepoURLList(bd.RemoteURLs),
					Revisions: revisionsFromBuildData(bd),
				})
			}
		}
	}

	for _, c := range raw.Culprits {
		name := strings.TrimSpace(c.FullName)
		if name == "" {
			continue
		}
		out.culprits = append(out.culprits, SCMCulprit{
			FullName: name,
			Note:     "Jenkins-reported correlation, not proof of cause",
		})
	}
	if len(out.sets) == 0 && len(out.culprits) == 0 {
		out.residuals = append(out.residuals,
			fmt.Sprintf("build #%d has no changeSet/changeSets/BuildData", buildNumber))
	}
	return out
}

func parseSCMItem(raw json.RawMessage, buildNumber, maxFiles, maxMsg int) (SCMCommit, bool) {
	var item struct {
		CommitID      string   `json:"commitId"`
		Msg           string   `json:"msg"`
		Message       string   `json:"message"`
		Timestamp     int64    `json:"timestamp"`
		AffectedPaths []string `json:"affectedPaths"`
		Author        *struct {
			FullName string `json:"fullName"`
		} `json:"author"`
	}
	if err := json.Unmarshal(raw, &item); err != nil {
		return SCMCommit{}, false
	}
	msg := item.Msg
	if msg == "" {
		msg = item.Message
	}
	msg, msgTrunc := truncateBytes(msg, maxMsg)
	paths := item.AffectedPaths
	pathsTrunc := false
	if maxFiles > 0 && len(paths) > maxFiles {
		paths = paths[:maxFiles]
		pathsTrunc = true
	}
	author := ""
	if item.Author != nil {
		author = strings.TrimSpace(item.Author.FullName)
	}
	id := strings.TrimSpace(item.CommitID)
	// Skip completely empty items.
	if id == "" && msg == "" && len(paths) == 0 && author == "" {
		return SCMCommit{}, false
	}
	return SCMCommit{
		ID:               id,
		Message:          msg,
		Author:           author,
		Timestamp:        item.Timestamp,
		AffectedPaths:    paths,
		PathsTruncated:   pathsTrunc,
		MessageTruncated: msgTrunc,
		BuildNumber:      buildNumber,
	}, true
}

func isBuildDataClass(class string) bool {
	class = strings.ToLower(class)
	return strings.Contains(class, "builddata") ||
		strings.Contains(class, "git.util") ||
		strings.Contains(class, "subversion") ||
		strings.Contains(class, "mercurial")
}

func kindFromBuildData(class string) string {
	c := strings.ToLower(class)
	switch {
	case strings.Contains(c, "git"):
		return "git"
	case strings.Contains(c, "subversion"), strings.Contains(c, "svn"):
		return "svn"
	case strings.Contains(c, "mercurial"), strings.Contains(c, "hg"):
		return "hg"
	default:
		return ""
	}
}

func revisionsFromBuildData(bd scmBuildData) []SCMRevision {
	if bd.LastBuiltRevision == nil {
		return nil
	}
	var out []SCMRevision
	if len(bd.LastBuiltRevision.Branch) > 0 {
		for _, b := range bd.LastBuiltRevision.Branch {
			sha := b.SHA1
			if sha == "" {
				sha = bd.LastBuiltRevision.SHA1
			}
			out = append(out, SCMRevision{Branch: b.Name, SHA: sha})
		}
		return out
	}
	if bd.LastBuiltRevision.SHA1 != "" {
		out = append(out, SCMRevision{SHA: bd.LastBuiltRevision.SHA1})
	}
	return out
}

// StripRepoURLCredentials removes userinfo and common token query params from a repo URL.
// Exported for tests and diagnostics.
func StripRepoURLCredentials(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// git@host:path form — no userinfo credentials beyond SSH user (keep as-is).
	if strings.HasPrefix(raw, "git@") || strings.HasPrefix(raw, "ssh://git@") {
		return raw
	}
	// user:pass@host without scheme (common in misconfigured remotes)
	if !strings.Contains(raw, "://") {
		if at := strings.Index(raw, "@"); at > 0 && strings.Contains(raw[:at], ":") {
			return raw[at+1:]
		}
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		// Best-effort strip user:pass@
		return stripUserinfoHeuristic(raw)
	}
	u.User = nil
	if u.RawQuery != "" {
		q := u.Query()
		for _, k := range []string{
			"token", "access_token", "private_token", "auth", "password",
			"api_key", "apikey", "secret", "jwt", "bearer",
		} {
			q.Del(k)
		}
		u.RawQuery = q.Encode()
	}
	// url.URL.String may re-encode; acceptable.
	out := u.String()
	// Avoid trailing "?" with empty query.
	out = strings.TrimSuffix(out, "?")
	return out
}

func stripUserinfoHeuristic(raw string) string {
	// scheme://user:pass@host/...
	schemeIdx := strings.Index(raw, "://")
	if schemeIdx < 0 {
		return raw
	}
	rest := raw[schemeIdx+3:]
	at := strings.Index(rest, "@")
	if at <= 0 {
		return raw
	}
	return raw[:schemeIdx+3] + rest[at+1:]
}

func stripRepoURLList(urls []string) []string {
	if len(urls) == 0 {
		return nil
	}
	out := make([]string, 0, len(urls))
	seen := make(map[string]struct{}, len(urls))
	for _, u := range urls {
		s := StripRepoURLCredentials(u)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func truncateBytes(s string, max int) (string, bool) {
	if max <= 0 || len(s) <= max {
		return s, false
	}
	// Avoid splitting mid-rune.
	for max > 0 && !utf8.ValidString(s[:max]) {
		max--
	}
	return s[:max], true
}

func firstRepo(urls []string) string {
	if len(urls) == 0 {
		return ""
	}
	return urls[0]
}

func mergeUniqueStrings(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, s := range b {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func mergeRevisions(a, b []SCMRevision) []SCMRevision {
	if len(b) == 0 {
		return a
	}
	type key struct{ branch, sha string }
	seen := make(map[key]struct{}, len(a)+len(b))
	out := make([]SCMRevision, 0, len(a)+len(b))
	for _, r := range a {
		k := key{r.Branch, r.SHA}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, r)
	}
	for _, r := range b {
		k := key{r.Branch, r.SHA}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, r)
	}
	return out
}

func uniqueNonEmpty(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func safeSCMErr(err error) string {
	if err == nil {
		return ""
	}
	// Prefer stable codes over free-form (may still contain job names).
	if c := apperr.CodeOf(err); c != "" {
		return string(c)
	}
	s := err.Error()
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}
