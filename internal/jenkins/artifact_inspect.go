package jenkins

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// Inspect kinds (ART-002).
const (
	InspectKindText    = "text"
	InspectKindJSON    = "json"
	InspectKindXML     = "xml"
	InspectKindArchive = "archive"
	InspectKindBinary  = "binary_refused"
)

// InspectArtifactToolArgs are arguments for jenkins_inspect_artifact (ART-002).
type InspectArtifactToolArgs struct {
	JobName     string `json:"job_name" jsonschema:"Name/path of the Jenkins job (supports folders)"`
	BuildNumber int    `json:"build_number" jsonschema:"Build number"`
	// Path is the relative artifact path from jenkins_list_artifacts.
	Path string `json:"path" jsonschema:"Relative artifact path (no .. or absolute paths)"`
	// MaxBytes caps download size for text/json/xml/archive (default/max depend on kind).
	MaxBytes int `json:"max_bytes,omitempty" jsonschema:"Maximum bytes to download (text default 256KiB; archive default 4MiB)"`
	// MaxMembers caps archive inventory rows (default 200, max 1000).
	MaxMembers int `json:"max_members,omitempty" jsonschema:"Maximum archive members to list (default: 200, max: 1000)" default:"200"`
}

// ArtifactInspection is the result of jenkins_inspect_artifact.
type ArtifactInspection struct {
	JobName     string `json:"jobName"`
	BuildNumber int    `json:"buildNumber"`
	Path        string `json:"path"`
	// Kind is text|json|xml|archive|binary_refused.
	Kind string `json:"kind"`
	// SizeBytes is Content-Length when known, else downloaded length.
	SizeBytes int64 `json:"sizeBytes"`
	// SHA256 of downloaded (possibly truncated) bytes.
	SHA256      string `json:"sha256,omitempty"`
	ContentType string `json:"contentType,omitempty"`
	// Truncated is true when download hit max_bytes.
	Truncated bool `json:"truncated,omitempty"`
	// Text is a bounded snippet for text/json/xml (pre-model-redaction).
	Text string `json:"text,omitempty"`
	// JSONValid / XMLValid report structural parse success when kind is json/xml.
	JSONValid bool `json:"jsonValid,omitempty"`
	XMLValid  bool `json:"xmlValid,omitempty"`
	// ParseError is a safe parse failure message (no secrets).
	ParseError string `json:"parseError,omitempty"`
	// Archive is inventory-only when kind=archive.
	Archive *ArchiveInventory `json:"archive,omitempty"`
	// Ref is a stable build+path reference.
	Ref string `json:"ref,omitempty"`
	// Residuals note deferred capabilities (e.g. random member read).
	Residuals []string `json:"residuals,omitempty"`
	// Message is a short status for refused/empty cases.
	Message string `json:"message,omitempty"`
}

// InspectArtifactToolResponse is returned by jenkins_inspect_artifact.
type InspectArtifactToolResponse = ArtifactInspection

// InspectArtifact downloads a bounded artifact and inspects text/JSON/XML or
// inventories zip/tar without extraction (ART-002). Never executes content.
func (opts *Client) InspectArtifact(ctx context.Context, jobName string, buildNumber int, artifactPath string, maxBytes, maxMembers int) (*ArtifactInspection, error) {
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

	kind := classifyInspectKind(safePath)
	if kind == InspectKindBinary {
		return &ArtifactInspection{
			JobName:     jobName,
			BuildNumber: buildNumber,
			Path:        safePath,
			Kind:        InspectKindBinary,
			Message:     "binary/exec extension refused for inspection (never execute)",
			Ref:         fmt.Sprintf("%s#%d/artifact:%s", jobName, buildNumber, safePath),
			Residuals:   []string{"use jenkins_list_artifacts for metadata only"},
		}, nil
	}

	// Bounds: archive allows larger download than text.
	if kind == InspectKindArchive {
		if maxBytes <= 0 {
			maxBytes = DefaultMaxArchiveDownloadBytes
		}
		if maxBytes > MaxArchiveDownloadBytesHardCap {
			maxBytes = MaxArchiveDownloadBytesHardCap
		}
	} else {
		if maxBytes <= 0 || maxBytes > MaxArtifactTextBytes {
			maxBytes = MaxArtifactTextBytes
		}
	}
	if maxMembers <= 0 {
		maxMembers = DefaultMaxArchiveMembers
	}
	if maxMembers > MaxArchiveMembersHardCap {
		maxMembers = MaxArchiveMembersHardCap
	}

	jobPath := BuildJobPath(jobName)
	apiPath := fmt.Sprintf("%s/%d/artifact/%s", jobPath, buildNumber, escapeArtifactURLPath(safePath))

	resp, err := opts.callJenkins(ctx, opts.Client, http.MethodGet, apiPath, nil,
		map[string]string{"Accept": "application/octet-stream, text/*, application/json, application/xml, */*"}, true)
	if err != nil {
		return nil, fmt.Errorf("failed to download artifact for inspect: %w", err)
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

	sum := sha256.Sum256(data)
	ct := resp.Header.Get("Content-Type")
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	size := int64(len(data))
	if resp.ContentLength > 0 {
		size = resp.ContentLength
	}

	out := &ArtifactInspection{
		JobName:     jobName,
		BuildNumber: buildNumber,
		Path:        safePath,
		Kind:        kind,
		SizeBytes:   size,
		SHA256:      hex.EncodeToString(sum[:]),
		ContentType: ct,
		Truncated:   truncated,
		Ref:         fmt.Sprintf("%s#%d/artifact:%s", jobName, buildNumber, safePath),
	}

	switch kind {
	case InspectKindArchive:
		lim := ArchiveInventoryLimits{
			MaxMembers: maxMembers,
			Deadline:   time.Now().Add(DefaultArchiveInventoryTimeout),
		}
		inv, ierr := InventoryArchiveBytes(data, safePath, lim)
		if ierr != nil {
			// Surface block as structured result when inventory detected bomb/slip.
			if inv != nil && inv.Blocked {
				out.Archive = inv
				out.Message = inv.BlockReason
				return out, nil
			}
			// Pure parse errors become invalid_argument.
			if apperr.IsCode(ierr, apperr.CodeInvalidArgument) || apperr.IsCode(ierr, apperr.CodeQuota) ||
				apperr.IsCode(ierr, apperr.CodeTimeout) {
				out.Message = ierr.Error()
				if inv != nil {
					out.Archive = inv
				}
				return out, nil
			}
			return nil, ierr
		}
		out.Archive = inv
		out.Residuals = []string{
			"archive member random-read not implemented (inventory only)",
			"no extraction, no execution, no dynamic library load",
		}
		return out, nil

	case InspectKindJSON:
		if containsNUL(data) {
			return nil, apperr.New(apperr.CodeInvalidArgument, "artifact appears binary (NUL bytes)")
		}
		text := bytesToText(data)
		out.Text = text
		if truncated {
			out.ParseError = "download truncated; JSON parse skipped"
			out.Residuals = []string{"full structured walk residual when truncated"}
			return out, nil
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		// Safe: no custom unmarshaler execution; standard library only.
		var v any
		if err := dec.Decode(&v); err != nil {
			out.JSONValid = false
			out.ParseError = "JSON parse failed: " + truncateForErr(err.Error())
		} else {
			out.JSONValid = true
			// Reject trailing garbage lightly.
			if err := dec.Decode(&struct{}{}); err == nil {
				out.ParseError = "JSON has trailing values"
				out.JSONValid = false
			}
		}
		return out, nil

	case InspectKindXML:
		if containsNUL(data) {
			return nil, apperr.New(apperr.CodeInvalidArgument, "artifact appears binary (NUL bytes)")
		}
		text := bytesToText(data)
		out.Text = text
		if truncated {
			out.ParseError = "download truncated; XML parse skipped"
			return out, nil
		}
		// encoding/xml does not resolve external entities / DTD by default (no XXE).
		dec := xml.NewDecoder(bytes.NewReader(data))
		dec.Strict = true
		dec.Entity = map[string]string{} // no custom entity expansion
		// Bound token walk (element count) without building a full DOM.
		const maxXMLTokens = 10_000
		tokens := 0
		for {
			tok, err := dec.Token()
			if err == io.EOF {
				out.XMLValid = tokens > 0
				if tokens == 0 {
					out.ParseError = "empty XML"
				}
				break
			}
			if err != nil {
				out.XMLValid = false
				out.ParseError = "XML parse failed: " + truncateForErr(err.Error())
				break
			}
			if tok == nil {
				break
			}
			tokens++
			if tokens > maxXMLTokens {
				out.XMLValid = false
				out.ParseError = "XML token budget exceeded"
				out.Truncated = true
				break
			}
		}
		return out, nil

	default: // text
		if containsNUL(data) {
			return nil, apperr.New(apperr.CodeInvalidArgument, "artifact appears binary (NUL bytes)")
		}
		out.Text = bytesToText(data)
		return out, nil
	}
}

func classifyInspectKind(safePath string) string {
	ext := strings.ToLower(filepath.Ext(safePath))
	base := strings.ToLower(safePath)
	switch {
	case ext == ".zip" || ext == ".tar" || strings.HasSuffix(base, ".tar.gz") || strings.HasSuffix(base, ".tgz"):
		return InspectKindArchive
	case ext == ".json":
		return InspectKindJSON
	case ext == ".xml" || ext == ".xsl" || ext == ".xsd":
		return InspectKindXML
	case ext == "":
		return InspectKindText
	default:
		if _, bad := binaryOrExecExt[ext]; bad {
			// Archives already handled; remaining binary/exec refused.
			// Note: .zip/.tar are in binaryOrExecExt for text download — archive kind above wins.
			if ext == ".zip" || ext == ".tar" || ext == ".gz" || ext == ".tgz" ||
				ext == ".bz2" || ext == ".xz" || ext == ".7z" || ext == ".rar" ||
				ext == ".zst" || ext == ".lz4" {
				// Non-inventory archives (gz alone, 7z, …) refused.
				return InspectKindBinary
			}
			return InspectKindBinary
		}
		return InspectKindText
	}
}

func bytesToText(data []byte) string {
	content := string(data)
	if !utf8.Valid(data) {
		content = strings.ToValidUTF8(content, "\uFFFD")
	}
	return content
}
