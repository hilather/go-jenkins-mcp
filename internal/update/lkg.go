package update

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/config"
)

// LKG schema version for the on-disk last-known-good record.
const LKGSchemaVersion = 1

// EnvUpdateLKGPath overrides the default LKG JSON path under XDG data.
// Empty ⇒ $XDG_DATA_HOME/jenkins-mcp/update/last_known_good.json
const EnvUpdateLKGPath = "JENKINS_MCP_UPDATE_LKG_PATH"

// LKGRecord is a secret-free last-known-good record written after a successful
// verified download. It never stores URLs (credential-bearing or otherwise),
// full paths that may embed secrets, private keys, or signature material.
type LKGRecord struct {
	// SchemaVersion is the LKG record format version (not the manifest schema).
	SchemaVersion int `json:"schema_version"`
	// Version is the manifest / artifact version that was downloaded.
	Version string `json:"version"`
	// Channel is the release channel (stable|beta).
	Channel string `json:"channel"`
	// ArtifactSHA256 is the lowercase hex content hash of the verified artifact.
	ArtifactSHA256 string `json:"artifact_sha256"`
	// PathBasename is only the file basename of the staged artifact (no directory).
	PathBasename string `json:"path_basename"`
	// Timestamp is when LKG was written (RFC3339 UTC).
	Timestamp string `json:"timestamp"`
	// SignatureKeyIDs are public key ids that verified the manifest (not key material).
	SignatureKeyIDs []string `json:"signature_key_ids,omitempty"`
	// Platform is GOOS/GOARCH of the downloaded artifact when known.
	Platform string `json:"platform,omitempty"`
}

// DefaultLKGPath returns the resolved LKG file path (env override or XDG data).
func DefaultLKGPath(paths *config.Paths) (string, error) {
	if p := strings.TrimSpace(os.Getenv(EnvUpdateLKGPath)); p != "" {
		return p, nil
	}
	var resolved config.Paths
	if paths != nil {
		resolved = *paths
	} else {
		r, err := config.Resolve()
		if err != nil {
			return "", apperr.Wrap(apperr.CodeInternal, "resolve config paths for update LKG", err)
		}
		resolved = r
	}
	return resolved.UpdateLKGFile(), nil
}

// LoadLKG loads an LKG record from path. Missing file returns (nil, nil).
// Corrupt JSON fails closed (operator must repair or remove).
func LoadLKG(path string) (*LKGRecord, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, apperr.Wrap(apperr.CodePolicyDenial,
			fmt.Sprintf("update LKG unreadable: %s", sanitizePath(path)), err)
	}
	var rec LKGRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, apperr.Wrap(apperr.CodePolicyDenial,
			"update LKG is corrupt (fail closed; remove to re-bootstrap)", err)
	}
	if err := rec.Validate(); err != nil {
		return nil, err
	}
	return &rec, nil
}

// LoadLKGFromEnviron resolves the default path and loads LKG when present.
func LoadLKGFromEnviron(paths *config.Paths) (*LKGRecord, string, error) {
	path, err := DefaultLKGPath(paths)
	if err != nil {
		return nil, "", err
	}
	rec, err := LoadLKG(path)
	if err != nil {
		return nil, path, err
	}
	return rec, path, nil
}

// Validate checks required secret-free fields on an LKG record.
func (r *LKGRecord) Validate() error {
	if r == nil {
		return apperr.New(apperr.CodeInvalidArgument, "update LKG is nil")
	}
	if strings.TrimSpace(r.Version) == "" {
		return apperr.New(apperr.CodePolicyDenial, "update LKG version is empty")
	}
	sum := strings.ToLower(strings.TrimSpace(r.ArtifactSHA256))
	if sum == "" {
		return apperr.New(apperr.CodePolicyDenial, "update LKG artifact_sha256 is empty")
	}
	if len(sum) != 64 || !isHex(sum) {
		return apperr.New(apperr.CodePolicyDenial, "update LKG artifact_sha256 must be 64 hex chars")
	}
	// Hard fail if someone smuggled a URL or absolute path into basename.
	base := strings.TrimSpace(r.PathBasename)
	if base != "" {
		if strings.Contains(base, "://") || strings.Contains(base, string(filepath.Separator)) {
			return apperr.New(apperr.CodePolicyDenial,
				"update LKG path_basename must be a bare filename (no URL or directory)")
		}
		if base != filepath.Base(base) {
			return apperr.New(apperr.CodePolicyDenial, "update LKG path_basename is invalid")
		}
	}
	return nil
}

// LKGWriteOptions builds an LKG record after a successful verified download.
type LKGWriteOptions struct {
	// Path is the destination JSON file. Empty skips write.
	Path string
	// Version / Channel from the verified manifest.
	Version string
	Channel string
	// ArtifactSHA256 is the verified content hash (required).
	ArtifactSHA256 string
	// ArtifactPath is the local staged path; only basename is stored.
	ArtifactPath string
	// SignatureKeyIDs are public key ids used for verification (not material).
	SignatureKeyIDs []string
	// Platform is GOOS/GOARCH when known.
	Platform string
	// Now overrides time.Now for tests. Nil ⇒ time.Now().UTC.
	Now func() time.Time
}

// StoreLKG writes a secret-free LKG record atomically. Never stores URLs or keys.
func StoreLKG(opts LKGWriteOptions) (*LKGRecord, error) {
	path := strings.TrimSpace(opts.Path)
	if path == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "update LKG path is empty")
	}
	sum := strings.ToLower(strings.TrimSpace(opts.ArtifactSHA256))
	ver := strings.TrimSpace(opts.Version)
	if ver == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "update LKG version is required")
	}
	if sum == "" || len(sum) != 64 || !isHex(sum) {
		return nil, apperr.New(apperr.CodeInvalidArgument, "update LKG artifact_sha256 must be 64 hex chars")
	}

	base := filepath.Base(strings.TrimSpace(opts.ArtifactPath))
	if base == "." || base == string(filepath.Separator) || base == "" {
		base = ""
	}
	// Refuse storing URL-shaped basenames (defense in depth).
	if strings.Contains(base, "://") {
		base = ""
	}

	now := time.Now().UTC()
	if opts.Now != nil {
		now = opts.Now().UTC()
	}

	keyIDs := uniqueSortedNonEmpty(opts.SignatureKeyIDs)
	rec := &LKGRecord{
		SchemaVersion:   LKGSchemaVersion,
		Version:         ver,
		Channel:         strings.TrimSpace(opts.Channel),
		ArtifactSHA256:  sum,
		PathBasename:    base,
		Timestamp:       now.Format(time.RFC3339),
		SignatureKeyIDs: keyIDs,
		Platform:        strings.TrimSpace(opts.Platform),
	}
	if err := rec.Validate(); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "create update LKG dir", err)
	}
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "encode update LKG", err)
	}
	// Sanity: never persist obvious secrets / private key PEM / credentials.
	if err := assertSecretFreeLKGJSON(raw); err != nil {
		return nil, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "write update LKG temp", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return nil, apperr.Wrap(apperr.CodeInternal, "commit update LKG", err)
	}
	return rec, nil
}

// SignatureKeyIDsFromManifest returns public key_id values from signature entries.
// Does not include signature material or private keys.
func SignatureKeyIDsFromManifest(m *Manifest) []string {
	if m == nil {
		return nil
	}
	ids := make([]string, 0, len(m.Signatures))
	for _, s := range m.Signatures {
		if id := strings.TrimSpace(s.KeyID); id != "" {
			ids = append(ids, id)
		}
	}
	return uniqueSortedNonEmpty(ids)
}

func uniqueSortedNonEmpty(in []string) []string {
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
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

// assertSecretFreeLKGJSON rejects LKG payloads that look like they contain secrets.
func assertSecretFreeLKGJSON(raw []byte) error {
	lower := strings.ToLower(string(raw))
	// Private key PEM / JWT-ish / basic-auth URL patterns must never land in LKG.
	for _, bad := range []string{
		"-----begin private",
		"-----begin rsa private",
		"-----begin openssh private",
		"private_key",
		"client_secret",
		"password",
		"authorization",
		"://", // no URLs (credential-bearing or otherwise)
	} {
		if strings.Contains(lower, bad) {
			return apperr.New(apperr.CodePolicyDenial,
				"update LKG refused: payload is not secret-free")
		}
	}
	return nil
}
