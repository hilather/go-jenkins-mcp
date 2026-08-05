package resourcecache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/contracts"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
)

// KeySchemaVersion is the ResourceKey encoding version.
const KeySchemaVersion = 1

// ResourceKey is the canonical local identity for a cacheable resource.
// Never includes secrets, tokens, arbitrary URLs, or filesystem paths.
type ResourceKey struct {
	SchemaVersion int
	ProfileID     string
	ControllerID  string // non-secret controller fingerprint (often origin hash)
	Kind          ResourceKind
	JobFullName   string
	BuildNumber   int64
	// Selector is kind-specific (artifact path, stage id, empty for build-scoped).
	Selector string
	// Variant is schema/canonical variant (e.g. "v1", "max_failed=50"), not caller display caps.
	Variant string
}

// Normalize returns a validated, normalized key.
func (k ResourceKey) Normalize() (ResourceKey, error) {
	out := k
	if out.SchemaVersion == 0 {
		out.SchemaVersion = KeySchemaVersion
	}
	if out.SchemaVersion != KeySchemaVersion {
		return ResourceKey{}, apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("unsupported resource key schema %d", out.SchemaVersion))
	}
	out.ProfileID = strings.TrimSpace(out.ProfileID)
	if out.ProfileID == "" {
		return ResourceKey{}, apperr.New(apperr.CodeInvalidArgument, "profile id is required")
	}
	out.ControllerID = strings.TrimSpace(out.ControllerID)
	if out.ControllerID == "" {
		out.ControllerID = "default"
	}
	if !out.Kind.Valid() {
		return ResourceKey{}, apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("unknown resource kind %q", out.Kind))
	}
	job, err := contracts.ParseJobFullName("job_name", out.JobFullName)
	if err != nil {
		return ResourceKey{}, err
	}
	out.JobFullName = job.FullName
	if out.BuildNumber < 1 {
		return ResourceKey{}, apperr.New(apperr.CodeInvalidArgument, "build number must be >= 1")
	}
	out.Selector = strings.TrimSpace(out.Selector)
	out.Variant = strings.TrimSpace(out.Variant)
	if out.Variant == "" {
		out.Variant = "v1"
	}

	switch out.Kind {
	case KindArtifactBlob, KindArtifactText, KindArtifactInspection:
		if out.Selector == "" {
			return ResourceKey{}, apperr.New(apperr.CodeInvalidArgument, "artifact path selector required")
		}
		safe, err := jenkins.SanitizeArtifactPath(out.Selector)
		if err != nil {
			return ResourceKey{}, err
		}
		out.Selector = safe
	case KindStageLog:
		if out.Selector == "" {
			return ResourceKey{}, apperr.New(apperr.CodeInvalidArgument, "stage id selector required")
		}
		// Stage IDs are opaque flow-node ids; reject path separators.
		if strings.ContainsAny(out.Selector, "/\\") {
			return ResourceKey{}, apperr.New(apperr.CodeInvalidArgument, "invalid stage id selector")
		}
	case KindArtifactCatalog, KindTestReport, KindPipelineStages, KindBuildChanges:
		// build-scoped; selector optional (e.g. baseline for changes)
	}
	return out, nil
}

// Digest returns a stable hex SHA-256 of the canonical key encoding.
func (k ResourceKey) Digest() (string, error) {
	nk, err := k.Normalize()
	if err != nil {
		return "", err
	}
	// Canonical encoding: versioned field order, no secrets.
	raw := strings.Join([]string{
		"v" + strconv.Itoa(nk.SchemaVersion),
		nk.ProfileID,
		nk.ControllerID,
		string(nk.Kind),
		nk.JobFullName,
		strconv.FormatInt(nk.BuildNumber, 10),
		nk.Selector,
		nk.Variant,
	}, "\x1f")
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:]), nil
}

// MustDigest panics only in tests; production code should use Digest.
func (k ResourceKey) String() string {
	d, err := k.Digest()
	if err != nil {
		return fmt.Sprintf("invalid-key(%v)", err)
	}
	return string(k.Kind) + ":" + d[:16]
}

// ControllerIDFromURL returns a non-secret controller fingerprint from a base URL.
func ControllerIDFromURL(baseURL string) string {
	baseURL = strings.TrimSpace(strings.TrimRight(baseURL, "/"))
	if baseURL == "" {
		return "default"
	}
	sum := sha256.Sum256([]byte(strings.ToLower(baseURL)))
	return hex.EncodeToString(sum[:8])
}
