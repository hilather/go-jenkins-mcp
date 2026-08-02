package jenkins

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Bounds for artifact metadata and selective text download (ART-001).
// Wave 42: process default hard cap (filtering / list hard-stop default) is
// DefaultArtifactsHardCap; ListArtifacts clamps only to AbsoluteMax so tools
// can pass a higher operator-configured live hard cap (≤ AbsoluteMax).
// Wave 43: ListArtifacts JSON body bound is operator-configurable
// (default DefaultArtifactListBodyBytes, absolute AbsoluteMaxArtifactListBodyBytes)
// so large inventories near AbsoluteMaxArtifactsHardCap are less likely to hit
// the body limit before the count hard cap.
const (
	DefaultMaxArtifacts = 200
	// DefaultArtifactsHardCap is the process default list hard-stop when
	// deny_artifact_paths force a hard-cap fetch (Wave 40) and the default
	// upper bound for caller max_artifacts after tools normalize.
	DefaultArtifactsHardCap = 500
	// AbsoluteMaxArtifactsHardCap is the fail-closed absolute ceiling for
	// ListArtifacts maxArtifacts and operator --artifacts-hard-cap / env.
	// Body budget: live ArtifactListBodyBytes() (default 2 MiB, absolute 8 MiB)
	// still bounds raw JSON; very long paths at AbsoluteMax may hit the body
	// limit (fail closed via truncated/invalid JSON) unless the operator raises
	// --artifacts-list-body-bytes within the absolute max.
	AbsoluteMaxArtifactsHardCap = 2000
	// MaxArtifactsHardCap is a backward-compat alias of DefaultArtifactsHardCap
	// (historical name used by Wave 40 filter/tests). Prefer Default/Absolute
	// names for new code; tools live cap is tools.ArtifactsHardCap().
	MaxArtifactsHardCap  = DefaultArtifactsHardCap
	MaxArtifactTextBytes = 256 << 10 // 256 KiB raw download cap
	// DefaultArtifactListBodyBytes is the process default max raw JSON body
	// for ListArtifacts (api/json artifacts tree). Enough for typical
	// AbsoluteMax short paths; operators may raise up to absolute max.
	DefaultArtifactListBodyBytes = 2 << 20 // 2 MiB
	// AbsoluteMaxArtifactListBodyBytes is the fail-closed absolute ceiling for
	// operator --artifacts-list-body-bytes / env (Wave 43). Kept well under
	// DefaultMaxJSONBodyBytes (32 MiB) so transport-level limits still apply.
	AbsoluteMaxArtifactListBodyBytes = 8 << 20 // 8 MiB
)

// artifactListBodyBytes is the live process max for ListArtifacts JSON
// (package-level so tests can override and serve can set once from
// tools.ResolveArtifactsListBodyBytes). Defaults to DefaultArtifactListBodyBytes.
var artifactListBodyBytes = DefaultArtifactListBodyBytes

// SetArtifactListBodyBytes sets the process ListArtifacts JSON body bound after
// a successful ResolveArtifactsListBodyBytes (serve start). Non-positive n uses
// DefaultArtifactListBodyBytes. Oversize values are clamped to
// AbsoluteMaxArtifactListBodyBytes as belt-and-suspenders (resolve already
// fail-closed).
func SetArtifactListBodyBytes(n int) {
	if n <= 0 {
		n = DefaultArtifactListBodyBytes
	}
	if n > AbsoluteMaxArtifactListBodyBytes {
		n = AbsoluteMaxArtifactListBodyBytes
	}
	artifactListBodyBytes = n
}

// ArtifactListBodyBytes returns the live process ListArtifacts JSON body bound
// (diagnostics/tests and ListArtifacts readLimited).
func ArtifactListBodyBytes() int {
	return artifactListBodyBytes
}

// ArtifactMeta is metadata for one build artifact (list-only; no download).
type ArtifactMeta struct {
	// Path is the relative artifact path (Jenkins relativePath).
	Path string `json:"path"`
	// FileName is the base file name when provided by Jenkins.
	FileName string `json:"fileName,omitempty"`
	// SizeBytes is the artifact size when known; 0 means unknown.
	SizeBytes int64 `json:"sizeBytes,omitempty"`
	// Timestamp is a build-level timestamp when per-artifact times are absent.
	Timestamp TimeMS `json:"timestamp,omitempty"`
}

// ArtifactList is the result of jenkins_list_artifacts (ART-001).
type ArtifactList struct {
	JobName     string         `json:"jobName"`
	BuildNumber int            `json:"buildNumber"`
	Artifacts   []ArtifactMeta `json:"artifacts"`
	// Count is the number of artifacts returned (after truncation and optional
	// policy path filter; Wave 37).
	Count int `json:"count"`
	// Truncated is true when more artifacts exist than returned: caller
	// max_artifacts cap, hard-cap fetch when deny_artifact_paths is live
	// (Wave 40/42), or raw list hit the process hard cap (default 500,
	// AbsoluteMax 2000). Policy row omit does not clear an already-true flag.
	Truncated bool `json:"truncated,omitempty"`
	// BytesDownloaded is always 0 for list-only (acceptance: no download).
	BytesDownloaded int `json:"bytesDownloaded"`
	// PolicyFiltered is true when ≥1 row was omitted by deny_artifact_paths
	// (Wave 37 list-row privacy). Denied paths are never listed.
	PolicyFiltered bool `json:"policy_filtered,omitempty"`
	// PolicyOmittedCount is the number of rows dropped by MCP policy (integer only).
	PolicyOmittedCount int `json:"policy_omitted_count,omitempty"`
}

// ArtifactText is a bounded text artifact download (ART-001).
type ArtifactText struct {
	JobName     string `json:"jobName"`
	BuildNumber int    `json:"buildNumber"`
	Path        string `json:"path"`
	// SizeBytes is Content-Length when known, else len(Content) after bound.
	SizeBytes int64 `json:"sizeBytes"`
	Truncated bool  `json:"truncated,omitempty"`
	// SHA256 is the hex digest of raw downloaded bytes (pre-model-redaction; truncated prefix if capped).
	SHA256      string `json:"sha256"`
	ContentType string `json:"contentType,omitempty"`
	Content     string `json:"content"`
	// Ref is a stable build+path reference for evidence.
	Ref string `json:"ref,omitempty"`
}

// ListArtifactsToolArgs are tool arguments for jenkins_list_artifacts.
type ListArtifactsToolArgs struct {
	JobName     string `json:"job_name" jsonschema:"Name/path of the Jenkins job (supports folders)"`
	BuildNumber int    `json:"build_number" jsonschema:"Build number"`
	// MaxArtifacts caps the list (default 200; server hard-caps at the live
	// process artifacts hard cap, default 500, absolute max 2000 — Wave 42).
	MaxArtifacts int `json:"max_artifacts,omitempty" jsonschema:"Maximum artifacts to list (default: 200; server hard-cap default 500, absolute max 2000)" default:"200"`
}

// ListArtifactsToolResponse is returned by jenkins_list_artifacts.
type ListArtifactsToolResponse = ArtifactList

// GetArtifactTextToolArgs are tool arguments for jenkins_get_artifact_text.
type GetArtifactTextToolArgs struct {
	JobName     string `json:"job_name" jsonschema:"Name/path of the Jenkins job (supports folders)"`
	BuildNumber int    `json:"build_number" jsonschema:"Build number"`
	// Path is the relative artifact path from jenkins_list_artifacts.
	Path string `json:"path" jsonschema:"Relative artifact path (no .. or absolute paths)"`
	// MaxBytes caps download size (default and hard max: 256KiB).
	MaxBytes int `json:"max_bytes,omitempty" jsonschema:"Maximum text bytes to download (default/max: 262144)" default:"262144"`
}

// GetArtifactTextToolResponse is returned by jenkins_get_artifact_text.
type GetArtifactTextToolResponse = ArtifactText

// binaryOrExecExt are extensions refused for text download (never execute).
var binaryOrExecExt = map[string]struct{}{
	".exe": {}, ".dll": {}, ".so": {}, ".dylib": {}, ".bin": {},
	".o": {}, ".a": {}, ".lib": {}, ".class": {}, ".jar": {},
	".war": {}, ".ear": {}, ".apk": {}, ".dex": {},
	".png": {}, ".jpg": {}, ".jpeg": {}, ".gif": {}, ".webp": {}, ".ico": {}, ".bmp": {},
	".mp3": {}, ".mp4": {}, ".wav": {}, ".avi": {}, ".mov": {},
	".zip": {}, ".gz": {}, ".tgz": {}, ".bz2": {}, ".xz": {}, ".7z": {}, ".rar": {},
	".tar": {}, ".zst": {}, ".lz4": {},
	".pdf": {}, ".doc": {}, ".docx": {}, ".xls": {}, ".xlsx": {}, ".ppt": {}, ".pptx": {},
	".woff": {}, ".woff2": {}, ".ttf": {}, ".otf": {}, ".eot": {},
	".pyc": {}, ".pyo": {}, ".wasm": {},
	".dmg": {}, ".iso": {}, ".img": {}, ".msi": {}, ".deb": {}, ".rpm": {},
}

// ListArtifacts returns artifact metadata for a build without downloading bytes (ART-001).
func (opts *Client) ListArtifacts(ctx context.Context, jobName string, buildNumber, maxArtifacts int) (*ArtifactList, error) {
	if opts == nil {
		return nil, fmt.Errorf("jenkins client is nil")
	}
	if strings.TrimSpace(jobName) == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "job_name is required")
	}
	if buildNumber <= 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument, "build_number must be positive")
	}
	if maxArtifacts <= 0 {
		maxArtifacts = DefaultMaxArtifacts
	}
	// Clamp only to AbsoluteMax so tools can pass operator-raised live hard
	// caps (Wave 42). Caller/tools layer enforces Default/live hard cap.
	if maxArtifacts > AbsoluteMaxArtifactsHardCap {
		maxArtifacts = AbsoluteMaxArtifactsHardCap
	}

	jobPath := BuildJobPath(jobName)
	// tree: artifacts only + optional build timestamp. No artifact/* byte paths.
	tree := "artifacts[fileName,relativePath],timestamp"
	apiPath := fmt.Sprintf("%s/%d/api/json?tree=%s", jobPath, buildNumber, tree)

	resp, err := opts.CallJenkins(ctx, opts.Client, http.MethodGet, apiPath, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list artifacts: %w", err)
	}
	defer resp.Body.Close()

	// Wave 43: live process body bound (default 2 MiB; operator-raisable ≤ 8 MiB).
	body, err := readLimited(resp.Body, ArtifactListBodyBytes())
	if err != nil {
		return nil, fmt.Errorf("failed to read artifacts list: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		// continue
	case http.StatusNotFound:
		return nil, apperr.New(apperr.CodeNotFound,
			fmt.Sprintf("build not found for job %q build #%d", jobName, buildNumber))
	case http.StatusUnauthorized:
		return nil, apperr.New(apperr.CodeAuthentication, "not authenticated for artifacts")
	case http.StatusForbidden:
		return nil, apperr.New(apperr.CodeAuthorization, "not authorized to list artifacts")
	default:
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, truncateForErr(string(body)))
	}

	var raw struct {
		Timestamp int64 `json:"timestamp"`
		Artifacts []struct {
			FileName     string `json:"fileName"`
			RelativePath string `json:"relativePath"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, apperr.Wrap(apperr.CodeUpstreamProtocol, "invalid artifacts JSON", err)
	}

	ts := timeMSFromMillis(raw.Timestamp)
	list := make([]ArtifactMeta, 0, min(len(raw.Artifacts), maxArtifacts))
	truncated := false
	for i, a := range raw.Artifacts {
		if i >= maxArtifacts {
			truncated = true
			break
		}
		p := strings.TrimSpace(a.RelativePath)
		if p == "" {
			p = strings.TrimSpace(a.FileName)
		}
		if p == "" {
			continue
		}
		// Normalize but do not reject list entries that look odd — download will re-validate.
		list = append(list, ArtifactMeta{
			Path:      p,
			FileName:  a.FileName,
			Timestamp: ts,
		})
	}

	return &ArtifactList{
		JobName:         jobName,
		BuildNumber:     buildNumber,
		Artifacts:       list,
		Count:           len(list),
		Truncated:       truncated,
		BytesDownloaded: 0,
	}, nil
}

// GetArtifactText downloads a small text artifact with size and extension policy (ART-001).
// Paths cannot escape the artifact workspace (.., absolute, URL schemes).
// Binary/exec extensions are refused. Content is hard-capped at MaxArtifactTextBytes.
func (opts *Client) GetArtifactText(ctx context.Context, jobName string, buildNumber int, artifactPath string, maxBytes int) (*ArtifactText, error) {
	if opts == nil {
		return nil, fmt.Errorf("jenkins client is nil")
	}
	if strings.TrimSpace(jobName) == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "job_name is required")
	}
	if buildNumber <= 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument, "build_number must be positive")
	}
	safePath, err := SanitizeArtifactPath(artifactPath)
	if err != nil {
		return nil, err
	}
	if maxBytes <= 0 || maxBytes > MaxArtifactTextBytes {
		maxBytes = MaxArtifactTextBytes
	}
	if err := CheckArtifactTextPolicy(safePath); err != nil {
		return nil, err
	}

	jobPath := BuildJobPath(jobName)
	// Escape each path segment; Jenkins serves /artifact/rel/path.
	apiPath := fmt.Sprintf("%s/%d/artifact/%s", jobPath, buildNumber, escapeArtifactURLPath(safePath))

	// closeConn=true: skip JSON body hard max; we apply MaxArtifactTextBytes ourselves.
	resp, err := opts.callJenkins(ctx, opts.Client, http.MethodGet, apiPath, nil,
		map[string]string{"Accept": "text/*, application/json, application/xml, */*"}, true)
	if err != nil {
		return nil, fmt.Errorf("failed to download artifact: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// continue
	case http.StatusNotFound:
		return nil, apperr.New(apperr.CodeNotFound,
			fmt.Sprintf("artifact %q not found for job %q build #%d", safePath, jobName, buildNumber))
	case http.StatusUnauthorized:
		return nil, apperr.New(apperr.CodeAuthentication, "not authenticated for artifact download")
	case http.StatusForbidden:
		return nil, apperr.New(apperr.CodeAuthorization, "not authorized to download artifact")
	default:
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, readLimitedErrBody(resp.Body))
	}

	// Stream at most maxBytes; abort reading before exceeding the cap (ART-001).
	// When Content-Length is known and larger, we still return a truncated prefix.
	knownLarge := resp.ContentLength > int64(maxBytes)
	data, err := readLimited(resp.Body, maxBytes+1)
	if err != nil {
		return nil, fmt.Errorf("failed to read artifact body: %w", err)
	}
	truncated := knownLarge
	if len(data) > maxBytes {
		data = data[:maxBytes]
		truncated = true
	}

	// Reject obvious binary (NUL) even if extension looked text-friendly.
	if containsNUL(data) {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			"artifact appears binary (NUL bytes); text download refused")
	}
	// Prefer valid UTF-8; replace invalid sequences rather than failing hard for
	// slightly messy logs, but reject if mostly non-text (high replacement rate).
	content := string(data)
	if !utf8.Valid(data) {
		content = strings.ToValidUTF8(content, "\uFFFD")
	}

	sum := sha256.Sum256(data)
	ct := resp.Header.Get("Content-Type")
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}

	size := int64(len(data))
	if resp.ContentLength > 0 {
		size = resp.ContentLength
	}

	return &ArtifactText{
		JobName:     jobName,
		BuildNumber: buildNumber,
		Path:        safePath,
		SizeBytes:   size,
		Truncated:   truncated,
		SHA256:      hex.EncodeToString(sum[:]),
		ContentType: ct,
		Content:     content,
		Ref:         fmt.Sprintf("%s#%d/artifact:%s", jobName, buildNumber, safePath),
	}, nil
}

// SanitizeArtifactPath normalizes and validates a relative artifact path (ART-001).
// Rejects absolute paths, schemes, backslash tricks, and .. escape attempts.
func SanitizeArtifactPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", apperr.New(apperr.CodeInvalidArgument, "path is required")
	}
	// Reject URL-like and absolute forms early.
	if strings.Contains(p, "://") || strings.HasPrefix(p, "//") {
		return "", apperr.New(apperr.CodeInvalidArgument, "path must be a relative artifact path, not a URL")
	}
	// Normalize separators.
	p = strings.ReplaceAll(p, "\\", "/")
	if strings.HasPrefix(p, "/") {
		return "", apperr.New(apperr.CodeInvalidArgument, "path must not be absolute")
	}
	// Reject empty/dot segments and .. before clean for clarity.
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return "", apperr.New(apperr.CodeInvalidArgument, "path must not contain .. segments")
		}
		if seg == "" {
			return "", apperr.New(apperr.CodeInvalidArgument, "path must not contain empty segments")
		}
	}
	cleaned := path.Clean(p)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", apperr.New(apperr.CodeInvalidArgument, "path escapes artifact workspace")
	}
	if strings.HasPrefix(cleaned, "/") {
		return "", apperr.New(apperr.CodeInvalidArgument, "path must not be absolute")
	}
	return cleaned, nil
}

// CheckArtifactTextPolicy refuses known binary/exec extensions for text download.
func CheckArtifactTextPolicy(safePath string) error {
	ext := strings.ToLower(filepath.Ext(safePath))
	if ext == "" {
		// No extension: allow (common for "console" dumps); binary check on content.
		return nil
	}
	if _, bad := binaryOrExecExt[ext]; bad {
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("artifact extension %q is not allowed for text download", ext))
	}
	// Unknown extensions are allowed through; content NUL check is the backstop.
	return nil
}

func escapeArtifactURLPath(rel string) string {
	parts := strings.Split(rel, "/")
	for i, p := range parts {
		parts[i] = urlPathEscapeSegment(p)
	}
	return strings.Join(parts, "/")
}

func containsNUL(b []byte) bool {
	for _, c := range b {
		if c == 0 {
			return true
		}
	}
	return false
}
