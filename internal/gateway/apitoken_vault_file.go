package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// FileAPITokenVault is a lab/file-backed APITokenVault under a single JSON file
// with mode 0600 (HOST-009 foundation).
//
// Multi-process safety (HOST-008 Done* lite): process-local mutex + exclusive
// flock on path+".lock" (syscall.Flock on unix/Tier-1 Linux) around read/write.
// Safe for CLI + serve (or multiple local processes) sharing one vault path on
// a local/shared filesystem. Not multi-pod HA without a shared FS; sticky
// sessions / multi-replica runtime remain residual.
//
// Path is operator-configurable (CLI / env). Default convention (documented):
//
//	$XDG_DATA_HOME/jenkins-mcp/gateway/apitoken_vault.json
//
// File contents hold secrets — never log, never ship in support bundles.
type FileAPITokenVault struct {
	path string
	mu   sync.Mutex
}

// fileVaultDoc is the on-disk shape (versioned for future rotation metadata).
type fileVaultDoc struct {
	Version int                       `json:"version"`
	Entries map[string]fileVaultEntry `json:"entries"`
}

type fileVaultEntry struct {
	Username string `json:"username"`
	Token    string `json:"token"`
}

// NewFileAPITokenVault constructs a file-backed vault at path.
// Parent directories are created on first Put with 0700; the vault file is 0600.
func NewFileAPITokenVault(path string) (*FileAPITokenVault, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "gateway vault path is required")
	}
	// Reject path traversal surprises for operator-supplied paths that are empty after clean.
	clean := filepath.Clean(path)
	if clean == "." || clean == string(filepath.Separator) {
		return nil, apperr.New(apperr.CodeInvalidArgument, "gateway vault path is invalid")
	}
	return &FileAPITokenVault{path: clean}, nil
}

// Path returns the vault file path (non-secret).
func (v *FileAPITokenVault) Path() string {
	if v == nil {
		return ""
	}
	return v.path
}

// Get implements APITokenVault.
func (v *FileAPITokenVault) Get(ctx context.Context, subjectKey string) (string, string, bool, error) {
	if err := ctx.Err(); err != nil {
		return "", "", false, apperr.Wrap(apperr.CodeCancelled, "gateway vault get cancelled", err)
	}
	if err := ValidateSubjectKey(subjectKey); err != nil {
		return "", "", false, err
	}
	if v == nil {
		return "", "", false, apperr.New(apperr.CodeInternal, "gateway vault is nil")
	}
	var (
		username string
		token    string
		ok       bool
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
		username, token, ok = e.Username, e.Token, true
		return nil
	})
	if err != nil {
		return "", "", false, err
	}
	return username, token, ok, nil
}

// Put implements APITokenVault.
func (v *FileAPITokenVault) Put(ctx context.Context, subjectKey, username, token string) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "gateway vault put cancelled", err)
	}
	if err := ValidateSubjectKey(subjectKey); err != nil {
		return err
	}
	user := strings.TrimSpace(username)
	if user == "" {
		return apperr.New(apperr.CodeInvalidArgument, "gateway vault username is required")
	}
	tok := strings.TrimSpace(token)
	if tok == "" {
		return apperr.New(apperr.CodeInvalidArgument, "gateway vault api token is required")
	}
	if v == nil {
		return apperr.New(apperr.CodeInternal, "gateway vault is nil")
	}
	return v.withLocked(func() error {
		doc, err := v.loadLocked()
		if err != nil {
			return err
		}
		if doc.Entries == nil {
			doc.Entries = make(map[string]fileVaultEntry)
		}
		doc.Version = 1
		doc.Entries[strings.TrimSpace(subjectKey)] = fileVaultEntry{Username: user, Token: tok}
		return v.saveLocked(doc)
	})
}

// Delete implements APITokenVault.
func (v *FileAPITokenVault) Delete(ctx context.Context, subjectKey string) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "gateway vault delete cancelled", err)
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

// ListSubjectKeys returns subject keys only (no usernames/tokens). Sorted for
// stable admin/status output. Missing vault file → empty list (not an error).
// Never includes secrets.
func (v *FileAPITokenVault) ListSubjectKeys(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, apperr.Wrap(apperr.CodeCancelled, "gateway vault list cancelled", err)
	}
	if v == nil {
		return nil, apperr.New(apperr.CodeInternal, "gateway vault is nil")
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
func (v *FileAPITokenVault) FileExists() bool {
	if v == nil || v.path == "" {
		return false
	}
	st, err := os.Stat(v.path)
	return err == nil && !st.IsDir()
}

// withLocked holds the process-local mutex and multi-process flock for the
// duration of fn (load/save under one critical section).
func (v *FileAPITokenVault) withLocked(fn func() error) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return withVaultFileLock(v.path, fn)
}

func sortSubjectKeys(keys []string) {
	sort.Strings(keys)
}

func (v *FileAPITokenVault) loadLocked() (fileVaultDoc, error) {
	raw, err := os.ReadFile(v.path)
	if err != nil {
		if os.IsNotExist(err) {
			return fileVaultDoc{Version: 1, Entries: make(map[string]fileVaultEntry)}, nil
		}
		return fileVaultDoc{}, apperr.Wrap(apperr.CodeInternal, "gateway vault read failed", err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return fileVaultDoc{Version: 1, Entries: make(map[string]fileVaultEntry)}, nil
	}
	var doc fileVaultDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		// Fail closed on corrupt vault — do not invent empty success that could
		// look like "not found" elevation across subjects.
		return fileVaultDoc{}, apperr.Wrap(apperr.CodeCorruptCache, "gateway vault file is corrupt or unreadable", err)
	}
	if doc.Entries == nil {
		doc.Entries = make(map[string]fileVaultEntry)
	}
	if doc.Version == 0 {
		doc.Version = 1
	}
	return doc, nil
}

func (v *FileAPITokenVault) saveLocked(doc fileVaultDoc) error {
	if doc.Entries == nil {
		doc.Entries = make(map[string]fileVaultEntry)
	}
	if doc.Version == 0 {
		doc.Version = 1
	}
	dir := filepath.Dir(v.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "gateway vault directory create failed", err)
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "gateway vault encode failed", err)
	}
	raw = append(raw, '\n')
	// Write via temp + rename for atomic replace; mode 0600 on final file.
	tmp := v.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "gateway vault write failed", err)
	}
	// Re-assert mode (some FS ignore WriteFile perm on existing).
	_ = os.Chmod(tmp, 0o600)
	if err := os.Rename(tmp, v.path); err != nil {
		_ = os.Remove(tmp)
		return apperr.Wrap(apperr.CodeInternal, "gateway vault rename failed", err)
	}
	_ = os.Chmod(v.path, 0o600)
	return nil
}
