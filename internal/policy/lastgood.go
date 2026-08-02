package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/config"
)

// LastGoodRecord is a secret-free cache of the last successfully verified bundle.
// Used only for rollback / downgrade detection (MGR-001).
type LastGoodRecord struct {
	// BundleSeq is the monotonic sequence of the last verified bundle.
	BundleSeq int64 `json:"bundle_seq"`
	// ContentHash is sha256 hex of the signing payload (not a secret).
	ContentHash string `json:"content_hash"`
	// KeyID is the public key id that verified the bundle (not key material).
	KeyID string `json:"key_id"`
	// LoadedAt is when the local agent accepted the bundle (RFC3339).
	LoadedAt string `json:"loaded_at,omitempty"`
	// SchemaVersion of the envelope.
	SchemaVersion int `json:"schema_version,omitempty"`
}

// LastGoodCache persists LastGoodRecord under the XDG cache tree.
type LastGoodCache struct {
	// Path is the JSON file path. Empty disables persistence (in-memory only if Record set).
	Path string
	// Record is the in-memory snapshot (loaded on Open or updated after Verify).
	Record *LastGoodRecord
	// DisableWrite when true skips disk updates (tests).
	DisableWrite bool
}

// DefaultLastGoodPath returns $XDG_CACHE_HOME/jenkins-mcp/policy/last_good.json.
func DefaultLastGoodPath(paths *config.Paths) (string, error) {
	var resolved config.Paths
	if paths != nil {
		resolved = *paths
	} else {
		r, err := config.Resolve()
		if err != nil {
			return "", apperr.Wrap(apperr.CodeInternal, "resolve config paths for policy last-good", err)
		}
		resolved = r
	}
	return resolved.PolicyLastGoodFile(), nil
}

// OpenLastGoodCache loads an existing last-good record if present.
// Missing file is not an error (bootstrap: first verified bundle becomes last-good).
func OpenLastGoodCache(path string) (*LastGoodCache, error) {
	path = strings.TrimSpace(path)
	c := &LastGoodCache{Path: path}
	if path == "" {
		return c, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return nil, apperr.Wrap(apperr.CodePolicyDenial,
			fmt.Sprintf("policy last-good cache unreadable: %s", sanitizePath(path)), err)
	}
	var rec LastGoodRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		// Corrupt cache: fail closed — operators must repair or remove the file.
		return nil, apperr.Wrap(apperr.CodePolicyDenial,
			"policy last-good cache is corrupt (fail closed; remove to re-bootstrap)", err)
	}
	if rec.BundleSeq < 0 {
		return nil, apperr.New(apperr.CodePolicyDenial, "policy last-good cache has invalid bundle_seq")
	}
	c.Record = &rec
	return c, nil
}

// CheckDowngrade returns an error when candidateSeq is a rollback vs last-good.
// Equal seq is allowed only when content hash matches (idempotent reload).
// Higher seq always allowed (forward progress / emergency replacement).
// Zero last-good (bootstrap) always allows.
func (c *LastGoodCache) CheckDowngrade(candidateSeq int64, candidateHash string) error {
	if c == nil || c.Record == nil || c.Record.BundleSeq < 1 {
		return nil
	}
	last := c.Record.BundleSeq
	if candidateSeq > last {
		return nil
	}
	if candidateSeq == last {
		if candidateHash != "" && c.Record.ContentHash != "" && candidateHash == c.Record.ContentHash {
			return nil // same bundle reloaded
		}
		// Same seq, different content → treat as tamper / conflicting publish.
		return apperr.New(apperr.CodePolicyDenial,
			fmt.Sprintf("policy bundle_seq %d conflicts with last-good content (fail closed)", candidateSeq))
	}
	// candidateSeq < last
	return apperr.New(apperr.CodePolicyDenial,
		fmt.Sprintf("policy bundle downgrade rejected: bundle_seq %d < last-good %d (fail closed)",
			candidateSeq, last))
}

// Store writes a successful verification to memory and disk.
func (c *LastGoodCache) Store(env *BundleEnvelope, contentHash string, now time.Time) error {
	if c == nil {
		return nil
	}
	if env == nil {
		return apperr.New(apperr.CodeInvalidArgument, "bundle is nil")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	rec := &LastGoodRecord{
		BundleSeq:     env.BundleSeq,
		ContentHash:   contentHash,
		KeyID:         env.KeyID,
		LoadedAt:      now.UTC().Format(time.RFC3339),
		SchemaVersion: env.SchemaVersion,
	}
	c.Record = rec
	if c.DisableWrite || strings.TrimSpace(c.Path) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(c.Path), 0o700); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "create policy last-good cache dir", err)
	}
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "encode policy last-good cache", err)
	}
	tmp := c.Path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "write policy last-good cache temp", err)
	}
	if err := os.Rename(tmp, c.Path); err != nil {
		_ = os.Remove(tmp)
		return apperr.Wrap(apperr.CodeInternal, "commit policy last-good cache", err)
	}
	return nil
}
