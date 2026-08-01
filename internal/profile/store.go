package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/config"
	"github.com/simonfxr/go-jenkins-mcp/internal/contracts"
)

// Store loads and saves versioned profile documents under XDG config.
// Profile files contain no secrets.
type Store struct {
	Paths config.Paths
}

// NewStore builds a Store for the given paths (usually config.Resolve()).
func NewStore(paths config.Paths) *Store {
	return &Store{Paths: paths}
}

// Load reads, migrates, and validates a profile by id.
func (s *Store) Load(id string) (*Profile, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "profile id is required")
	}
	path := s.Paths.ProfileFile(id)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, apperr.New(apperr.CodeNotFound, fmt.Sprintf("profile %q not found", id))
		}
		return nil, apperr.Wrap(apperr.CodeInternal, "failed to read profile", err)
	}
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, apperr.Wrap(apperr.CodeCorruptCache, "profile JSON is invalid", err)
	}
	// Prefer filename id when document id is empty; reject mismatch.
	if p.ID == "" {
		p.ID = contracts.ProfileID(id)
	} else if string(p.ID) != id {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("profile id %q does not match file %q", p.ID, id))
	}
	if err := Migrate(&p); err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	// Reject documents that still look like they carry secrets after load.
	if secretFieldPresent(data) {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			"profile file must not contain secret fields (token/password/secret)")
	}
	return &p, nil
}

// Save validates and atomically writes a profile document.
func (s *Store) Save(p *Profile) error {
	if p == nil {
		return apperr.New(apperr.CodeInvalidArgument, "profile is nil")
	}
	if p.ConfigVersion == 0 {
		p.ConfigVersion = CurrentConfigVersion
	}
	if err := Migrate(p); err != nil {
		return err
	}
	if err := p.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(s.Paths.ProfilesDir(), 0o700); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to create profiles directory", err)
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to encode profile", err)
	}
	data = append(data, '\n')
	// Belt-and-suspenders: never write secret-looking keys.
	if secretFieldPresent(data) {
		return apperr.New(apperr.CodeInternal, "refusing to write profile with secret-like fields")
	}
	path := s.Paths.ProfileFile(string(p.ID))
	if err := atomicWrite(path, data, 0o600); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to write profile", err)
	}
	return nil
}

// List returns profile ids sorted alphabetically.
func (s *Store) List() ([]string, error) {
	dir := s.Paths.ProfilesDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, apperr.Wrap(apperr.CodeInternal, "failed to list profiles", err)
	}
	var ids []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		if id == "" {
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

// Delete removes a profile file. It does not clear keyring credentials
// (call auth Logout separately). Missing profiles are not an error.
func (s *Store) Delete(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return apperr.New(apperr.CodeInvalidArgument, "profile id is required")
	}
	path := s.Paths.ProfileFile(id)
	err := os.Remove(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return apperr.Wrap(apperr.CodeInternal, "failed to delete profile", err)
	}
	return nil
}

// Exists reports whether a profile file is present.
func (s *Store) Exists(id string) bool {
	_, err := os.Stat(s.Paths.ProfileFile(strings.TrimSpace(id)))
	return err == nil
}

// secretFieldPresent is a canary against accidental secret persistence.
// It looks for JSON object keys (including nested objects/arrays) that must
// never appear in profile files — e.g. client_secret under oidc (OAUTH-001).
func secretFieldPresent(data []byte) bool {
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return false
	}
	return secretKeysIn(raw)
}

func secretKeysIn(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			lk := strings.ToLower(k)
			for _, f := range forbiddenProfileKeys {
				if lk == f {
					return true
				}
			}
			if secretKeysIn(child) {
				return true
			}
		}
	case []any:
		for _, child := range x {
			if secretKeysIn(child) {
				return true
			}
		}
	}
	return false
}

// forbiddenProfileKeys are lower-case JSON keys rejected at any nesting level.
var forbiddenProfileKeys = []string{
	"token", "apitoken", "api_token", "password", "secret",
	"clientsecret", "client_secret", "refreshtoken", "refresh_token",
	"accesstoken", "access_token", "authorization",
	// NET-004: never persist TLS verification disablement or inline key material.
	"insecureskipverify", "insecure_skip_verify", "diagnosticinsecuretls",
	"diagnostic_insecure_tls", "clientkeypem", "client_key_pem",
	"privatekey", "private_key",
	// ARC-009: raw cache keys never in profile JSON (only version flags).
	"cachekey", "cache_key", "encryptionkey", "encryption_key",
	"aeadkey", "aead_key", "cachekeymaterial", "cache_key_material",
}

// atomicWrite writes data to path via a temp file + rename.
func atomicWrite(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".profile-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}
