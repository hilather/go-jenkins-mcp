package update

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// Schema versions.
const (
	// SchemaV1 is the lite metadata-only shape (no signatures / artifacts).
	SchemaV1 = 1
	// SchemaV2 is the signed update manifest with per-platform artifacts.
	SchemaV2 = 2
	// CurrentSchemaVersion is the preferred publisher schema.
	CurrentSchemaVersion = SchemaV2
	// ClientMinSchema is the oldest schema this client can parse.
	ClientMinSchema = SchemaV1
)

// AlgEd25519 is the only supported signature algorithm for MVP.
const AlgEd25519 = "ed25519"

// Signature state tokens (non-secret; CLI / doctor).
const (
	SigStateAbsent          = "absent"
	SigStateUnverifiedPilot = "unverified_pilot"
	SigStateVerified        = "verified"
	SigStateRejected        = "rejected"
)

// Channels.
const (
	ChannelStable = "stable"
	ChannelBeta   = "beta"
)

// Artifact is one platform binary (or package) referenced by a v2 manifest.
// Secret-free: public HTTPS URL + content hash only.
type Artifact struct {
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`             // lowercase hex of raw artifact bytes
	Size     int64  `json:"size,omitempty"`     // optional; used for preflight when > 0
	Filename string `json:"filename,omitempty"` // suggested local name
}

// ManifestSignature is one Ed25519 signature over CanonicalSigningBytes.
type ManifestSignature struct {
	Alg       string `json:"alg"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"` // base64 raw 64-byte Ed25519 signature
}

// Manifest is the unified in-memory release manifest (v1 or v2).
//
// Schema v2 example:
//
//	{
//	  "schema_version": 2,
//	  "channel": "stable",
//	  "version": "1.2.3",
//	  "commit": "abc1234",
//	  "changelog_url": "https://example.corp/changelog/1.2.3",
//	  "issued_at": "2026-08-01T00:00:00Z",
//	  "not_after": "2027-08-01T00:00:00Z",
//	  "min_schema": 2,
//	  "min_app_version": "1.0.0",
//	  "artifacts": {
//	    "linux/amd64": {
//	      "url": "https://example.corp/jenkins-mcp_1.2.3_linux_amd64.tar.gz",
//	      "sha256": "…",
//	      "filename": "jenkins-mcp_1.2.3_linux_amd64.tar.gz"
//	    }
//	  },
//	  "signatures": [
//	    {"alg":"ed25519","key_id":"corp-update-2026","signature":"…"}
//	  ]
//	}
//
// Schema v1 (lite, unsigned pilot only) uses nested latest:
//
//	{"schema_version":1,"channel":"stable","latest":{"version":"1.2.3",…}}
type Manifest struct {
	SchemaVersion int                 `json:"schema_version"`
	Channel       string              `json:"channel"`
	Version       string              `json:"version,omitempty"`
	Commit        string              `json:"commit,omitempty"`
	ChangelogURL  string              `json:"changelog_url,omitempty"`
	IssuedAt      string              `json:"issued_at,omitempty"`  // RFC3339
	NotAfter      string              `json:"not_after,omitempty"`  // RFC3339; empty = no expiry
	MinSchema     int                 `json:"min_schema,omitempty"` // min client schema
	MinAppVersion string              `json:"min_app_version,omitempty"`
	Artifacts     map[string]Artifact `json:"artifacts,omitempty"` // key = "GOOS/GOARCH"
	Notes         string              `json:"notes,omitempty"`
	Signatures    []ManifestSignature `json:"signatures,omitempty"`
	// Latest is v1-only nested shape; normalized into Version/Commit/… on parse.
	Latest *legacyLatest `json:"latest,omitempty"`
}

// legacyLatest is the v1 nested latest object (not part of v2 signing body).
type legacyLatest struct {
	Version      string `json:"version"`
	Commit       string `json:"commit,omitempty"`
	ChangelogURL string `json:"changelog_url,omitempty"`
	PublishedAt  string `json:"published_at,omitempty"`
}

// signingBody is the deterministic JSON payload that is signed/verified.
// Field order is fixed by the Go struct layout (encoding/json).
// Signatures and legacy Latest are never included.
type signingBody struct {
	SchemaVersion int                 `json:"schema_version"`
	Channel       string              `json:"channel"`
	Version       string              `json:"version"`
	Commit        string              `json:"commit,omitempty"`
	ChangelogURL  string              `json:"changelog_url,omitempty"`
	IssuedAt      string              `json:"issued_at,omitempty"`
	NotAfter      string              `json:"not_after,omitempty"`
	MinSchema     int                 `json:"min_schema,omitempty"`
	MinAppVersion string              `json:"min_app_version,omitempty"`
	Artifacts     map[string]Artifact `json:"artifacts,omitempty"`
	Notes         string              `json:"notes,omitempty"`
}

// ParseManifest unmarshals raw JSON and normalizes v1 → flat fields.
func ParseManifest(raw []byte) (*Manifest, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, apperr.New(apperr.CodeUpstreamProtocol, "update manifest is empty")
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, apperr.Wrap(apperr.CodeUpstreamProtocol, "update manifest JSON parse failed", err)
	}
	if err := m.normalize(); err != nil {
		return nil, err
	}
	return &m, nil
}

func (m *Manifest) normalize() error {
	if m == nil {
		return apperr.New(apperr.CodeInvalidArgument, "update manifest is nil")
	}
	// Default missing schema to v1 for lite pilot documents.
	if m.SchemaVersion == 0 {
		m.SchemaVersion = SchemaV1
	}
	if m.SchemaVersion != SchemaV1 && m.SchemaVersion != SchemaV2 {
		return apperr.New(apperr.CodeUpstreamProtocol,
			fmt.Sprintf("unsupported update manifest schema_version %d (want %d or %d)",
				m.SchemaVersion, SchemaV1, SchemaV2))
	}
	// Lift v1 latest into flat fields when needed.
	if m.Latest != nil {
		if strings.TrimSpace(m.Version) == "" {
			m.Version = strings.TrimSpace(m.Latest.Version)
		}
		if strings.TrimSpace(m.Commit) == "" {
			m.Commit = strings.TrimSpace(m.Latest.Commit)
		}
		if strings.TrimSpace(m.ChangelogURL) == "" {
			m.ChangelogURL = strings.TrimSpace(m.Latest.ChangelogURL)
		}
		if strings.TrimSpace(m.IssuedAt) == "" {
			m.IssuedAt = strings.TrimSpace(m.Latest.PublishedAt)
		}
	}
	// Do not rewrite signed fields (channel/version/artifacts/…) beyond v1 lift:
	// CanonicalSigningBytes re-marshals the struct; mutating values here would
	// invalidate legitimate signatures. Lookup helpers normalize case at read time.
	if strings.TrimSpace(m.Version) == "" {
		return apperr.New(apperr.CodeUpstreamProtocol, "update manifest version is empty")
	}
	return nil
}

// HasSignatures reports whether any signature entries are present.
func (m *Manifest) HasSignatures() bool {
	if m == nil {
		return false
	}
	for _, s := range m.Signatures {
		if strings.TrimSpace(s.Signature) != "" {
			return true
		}
	}
	return false
}

// PlatformKey returns "goos/goarch" for artifact lookup.
func PlatformKey(goos, goarch string) string {
	return strings.ToLower(strings.TrimSpace(goos)) + "/" + strings.ToLower(strings.TrimSpace(goarch))
}

// ArtifactFor returns the artifact for goos/goarch when present.
// Matching is case-insensitive on the platform key.
func (m *Manifest) ArtifactFor(goos, goarch string) (Artifact, bool) {
	if m == nil || len(m.Artifacts) == 0 {
		return Artifact{}, false
	}
	want := PlatformKey(goos, goarch)
	if a, ok := m.Artifacts[want]; ok {
		return a, true
	}
	for k, a := range m.Artifacts {
		if strings.ToLower(strings.TrimSpace(k)) == want {
			return a, true
		}
	}
	return Artifact{}, false
}

// ValidateStructure checks non-crypto field constraints for the schema version.
func (m *Manifest) ValidateStructure() error {
	if m == nil {
		return apperr.New(apperr.CodeInvalidArgument, "update manifest is nil")
	}
	if m.SchemaVersion != SchemaV1 && m.SchemaVersion != SchemaV2 {
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("unsupported update manifest schema_version %d", m.SchemaVersion))
	}
	if m.Version == "" {
		return apperr.New(apperr.CodeInvalidArgument, "update manifest version is required")
	}
	if m.SchemaVersion == SchemaV2 {
		if m.Channel == "" {
			return apperr.New(apperr.CodeInvalidArgument, "update manifest channel is required for schema v2")
		}
		if len(m.Artifacts) == 0 {
			return apperr.New(apperr.CodeInvalidArgument, "update manifest artifacts are required for schema v2")
		}
		for plat, a := range m.Artifacts {
			url := strings.TrimSpace(a.URL)
			sum := strings.ToLower(strings.TrimSpace(a.SHA256))
			if url == "" {
				return apperr.New(apperr.CodeInvalidArgument,
					fmt.Sprintf("update manifest artifact %q url is empty", plat))
			}
			if sum == "" {
				return apperr.New(apperr.CodeInvalidArgument,
					fmt.Sprintf("update manifest artifact %q sha256 is empty", plat))
			}
			if len(sum) != 64 || !isHex(sum) {
				return apperr.New(apperr.CodeInvalidArgument,
					fmt.Sprintf("update manifest artifact %q sha256 must be 64 hex chars", plat))
			}
			if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
				return apperr.New(apperr.CodeInvalidArgument,
					fmt.Sprintf("update manifest artifact %q url must be http(s)", plat))
			}
		}
	}
	if m.NotAfter != "" {
		if _, err := time.Parse(time.RFC3339, m.NotAfter); err != nil {
			return apperr.Wrap(apperr.CodeInvalidArgument, "update manifest not_after must be RFC3339", err)
		}
	}
	if m.IssuedAt != "" {
		if _, err := time.Parse(time.RFC3339, m.IssuedAt); err != nil {
			return apperr.Wrap(apperr.CodeInvalidArgument, "update manifest issued_at must be RFC3339", err)
		}
	}
	return nil
}

// ParseNotAfter parses not_after when set. ok=false means no expiry constraint.
func (m *Manifest) ParseNotAfter() (t time.Time, ok bool, err error) {
	s := strings.TrimSpace(m.NotAfter)
	if s == "" {
		return time.Time{}, false, nil
	}
	t, err = time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false, apperr.Wrap(apperr.CodeInvalidArgument,
			"update manifest not_after must be RFC3339", err)
	}
	return t, true, nil
}

// CanonicalSigningBytes returns the exact bytes that must be signed/verified.
// The signatures field is excluded. Legacy latest is not part of the signed body;
// publishers must use flat v2 fields when signing.
func CanonicalSigningBytes(m *Manifest) ([]byte, error) {
	if m == nil {
		return nil, apperr.New(apperr.CodeInvalidArgument, "update manifest is nil")
	}
	body := signingBody{
		SchemaVersion: m.SchemaVersion,
		Channel:       m.Channel,
		Version:       m.Version,
		Commit:        m.Commit,
		ChangelogURL:  m.ChangelogURL,
		IssuedAt:      m.IssuedAt,
		NotAfter:      m.NotAfter,
		MinSchema:     m.MinSchema,
		MinAppVersion: m.MinAppVersion,
		Artifacts:     m.Artifacts,
		Notes:         m.Notes,
	}
	return json.Marshal(body)
}

// MarshalManifest returns pretty-printed JSON for writing a manifest file.
func MarshalManifest(m *Manifest) ([]byte, error) {
	if m == nil {
		return nil, apperr.New(apperr.CodeInvalidArgument, "update manifest is nil")
	}
	// Do not emit empty latest for v2.
	out := *m
	if out.SchemaVersion == SchemaV2 {
		out.Latest = nil
	}
	return json.MarshalIndent(&out, "", "  ")
}

func isHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}
