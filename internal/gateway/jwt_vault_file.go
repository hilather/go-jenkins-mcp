package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// FileJWTVault is a lab/file-backed JWTVault under a single JSON file with
// mode 0600 (HOST-010 offline foundation).
//
// Multi-process safety (HOST-008 Done* lite): process-local mutex + exclusive
// flock on path+".lock" (syscall.Flock on unix/Tier-1 Linux) around read/write.
// Safe for CLI + serve sharing one vault path on a local/shared filesystem.
// Not multi-pod HA; sticky sessions residual.
//
// Path is operator-configurable (env JENKINS_MCP_GATEWAY_JWT_VAULT_PATH).
// Default convention (documented):
//
//	$XDG_DATA_HOME/jenkins-mcp/gateway/jwt_vault.json
//
// File contents hold secrets — never log, never ship in support bundles.
// Store **access tokens** only (never ID tokens).
type FileJWTVault struct {
	path string
	mu   sync.Mutex
}

// fileJWTVaultDoc is the on-disk shape (versioned for future rotation metadata).
type fileJWTVaultDoc struct {
	Version int                     `json:"version"`
	Entries map[string]fileJWTEntry `json:"entries"`
}

type fileJWTEntry struct {
	// Token is a Jenkins-audience access token (secret). Never an ID token.
	Token string `json:"token"`
}

// NewFileJWTVault constructs a file-backed JWT vault at path.
// Parent directories are created on first Put with 0700; the vault file is 0600.
func NewFileJWTVault(path string) (*FileJWTVault, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "gateway jwt vault path is required")
	}
	clean := filepath.Clean(path)
	if clean == "." || clean == string(filepath.Separator) {
		return nil, apperr.New(apperr.CodeInvalidArgument, "gateway jwt vault path is invalid")
	}
	return &FileJWTVault{path: clean}, nil
}

// Path returns the vault file path (non-secret).
func (v *FileJWTVault) Path() string {
	if v == nil {
		return ""
	}
	return v.path
}

// Get implements JWTVault.
func (v *FileJWTVault) Get(ctx context.Context, subjectKey string) (string, bool, error) {
	if err := ctx.Err(); err != nil {
		return "", false, apperr.Wrap(apperr.CodeCancelled, "gateway jwt vault get cancelled", err)
	}
	if err := ValidateSubjectKey(subjectKey); err != nil {
		return "", false, err
	}
	if v == nil {
		return "", false, apperr.New(apperr.CodeInternal, "gateway jwt vault is nil")
	}
	var (
		token string
		ok    bool
	)
	err := v.withLocked(func() error {
		doc, err := v.loadLocked()
		if err != nil {
			return err
		}
		e, found := doc.Entries[strings.TrimSpace(subjectKey)]
		if !found {
			return nil
		}
		token, ok = e.Token, true
		return nil
	})
	if err != nil {
		return "", false, err
	}
	return token, ok, nil
}

// Put implements JWTVault.
func (v *FileJWTVault) Put(ctx context.Context, subjectKey, token string) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "gateway jwt vault put cancelled", err)
	}
	if err := ValidateSubjectKey(subjectKey); err != nil {
		return err
	}
	tok := strings.TrimSpace(token)
	if tok == "" {
		return apperr.New(apperr.CodeInvalidArgument, "gateway jwt vault access token is required")
	}
	if err := rejectIDTokenAsAPICredential(tok); err != nil {
		return err
	}
	if v == nil {
		return apperr.New(apperr.CodeInternal, "gateway jwt vault is nil")
	}
	return v.withLocked(func() error {
		doc, err := v.loadLocked()
		if err != nil {
			return err
		}
		if doc.Entries == nil {
			doc.Entries = make(map[string]fileJWTEntry)
		}
		doc.Version = 1
		doc.Entries[strings.TrimSpace(subjectKey)] = fileJWTEntry{Token: tok}
		return v.saveLocked(doc)
	})
}

// Delete implements JWTVault.
func (v *FileJWTVault) Delete(ctx context.Context, subjectKey string) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "gateway jwt vault delete cancelled", err)
	}
	if err := ValidateSubjectKey(subjectKey); err != nil {
		return err
	}
	if v == nil {
		return nil
	}
	return v.withLocked(func() error {
		doc, err := v.loadLocked()
		if err != nil {
			return err
		}
		if doc.Entries == nil {
			return nil
		}
		delete(doc.Entries, strings.TrimSpace(subjectKey))
		return v.saveLocked(doc)
	})
}

// ListSubjectKeys returns subject keys only (no tokens). Sorted for stable
// admin/status output. Missing vault file → empty list (not an error).
// Never includes secrets.
func (v *FileJWTVault) ListSubjectKeys(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, apperr.Wrap(apperr.CodeCancelled, "gateway jwt vault list cancelled", err)
	}
	if v == nil {
		return nil, apperr.New(apperr.CodeInternal, "gateway jwt vault is nil")
	}
	var out []string
	err := v.withLocked(func() error {
		doc, err := v.loadLocked()
		if err != nil {
			return err
		}
		out = make([]string, 0, len(doc.Entries))
		for k := range doc.Entries {
			out = append(out, k)
		}
		sortSubjectKeys(out)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// FileExists reports whether the vault path is present on disk (non-secret).
func (v *FileJWTVault) FileExists() bool {
	if v == nil || v.path == "" {
		return false
	}
	st, err := os.Stat(v.path)
	return err == nil && !st.IsDir()
}

// withLocked holds the process-local mutex and multi-process flock for the
// duration of fn (load/save under one critical section).
func (v *FileJWTVault) withLocked(fn func() error) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return withVaultFileLock(v.path, fn)
}

func (v *FileJWTVault) loadLocked() (fileJWTVaultDoc, error) {
	raw, err := os.ReadFile(v.path)
	if err != nil {
		if os.IsNotExist(err) {
			return fileJWTVaultDoc{Version: 1, Entries: make(map[string]fileJWTEntry)}, nil
		}
		return fileJWTVaultDoc{}, apperr.Wrap(apperr.CodeInternal, "gateway jwt vault read failed", err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return fileJWTVaultDoc{Version: 1, Entries: make(map[string]fileJWTEntry)}, nil
	}
	var doc fileJWTVaultDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fileJWTVaultDoc{}, apperr.Wrap(apperr.CodeCorruptCache, "gateway jwt vault file is corrupt or unreadable", err)
	}
	if doc.Entries == nil {
		doc.Entries = make(map[string]fileJWTEntry)
	}
	if doc.Version == 0 {
		doc.Version = 1
	}
	return doc, nil
}

func (v *FileJWTVault) saveLocked(doc fileJWTVaultDoc) error {
	if doc.Entries == nil {
		doc.Entries = make(map[string]fileJWTEntry)
	}
	if doc.Version == 0 {
		doc.Version = 1
	}
	dir := filepath.Dir(v.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "gateway jwt vault directory create failed", err)
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "gateway jwt vault encode failed", err)
	}
	raw = append(raw, '\n')
	tmp := v.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "gateway jwt vault write failed", err)
	}
	_ = os.Chmod(tmp, 0o600)
	if err := os.Rename(tmp, v.path); err != nil {
		_ = os.Remove(tmp)
		return apperr.Wrap(apperr.CodeInternal, "gateway jwt vault rename failed", err)
	}
	_ = os.Chmod(v.path, 0o600)
	return nil
}
