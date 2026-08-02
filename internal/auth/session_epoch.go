package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// SessionEpochFileName is the non-secret cross-process session invalidation
// marker under a profile data directory. Never stores tokens.
const SessionEpochFileName = "session.epoch"

// SessionEpochFileMode is owner read/write only (0600).
const SessionEpochFileMode os.FileMode = 0o600

// SessionEpoch is a non-secret invalidation value. Content is a monotonic
// sequence, RFC3339 timestamp, and random nonce — never tokens or secrets.
type SessionEpoch struct {
	// Value is the full single-line content of session.epoch (trimmed).
	Value string
	// Seq is the monotonic counter when parseable; 0 if unknown/empty.
	Seq uint64
}

// Empty reports whether no epoch has been established yet.
func (e SessionEpoch) Empty() bool {
	return strings.TrimSpace(e.Value) == ""
}

// SessionEpochStore reads and writes session.epoch under a profile data dir.
// The file coordinates CLI login/logout with a long-lived serve process without
// sharing secrets across processes.
//
// Path: <Dir>/session.epoch
// Mode: 0600; writes are atomic (temp + rename).
type SessionEpochStore struct {
	// Dir is the profile data directory (must already exist or be creatable).
	Dir string
}

// SessionEpochPath returns the absolute path of the epoch file for dir.
func SessionEpochPath(dir string) string {
	return filepath.Join(filepath.Clean(strings.TrimSpace(dir)), SessionEpochFileName)
}

// Path returns the epoch file path for this store.
func (s *SessionEpochStore) Path() string {
	if s == nil {
		return ""
	}
	return SessionEpochPath(s.Dir)
}

// Load reads the current epoch. Missing file → empty epoch (no error).
// Never returns token material; content is treated as opaque non-secret text.
func (s *SessionEpochStore) Load() (SessionEpoch, error) {
	if s == nil || strings.TrimSpace(s.Dir) == "" {
		return SessionEpoch{}, apperr.New(apperr.CodeInternal, "session epoch store is not configured")
	}
	path := s.Path()
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return SessionEpoch{}, nil
		}
		return SessionEpoch{}, apperr.Wrap(apperr.CodeInternal, "failed to read session epoch", err)
	}
	return parseSessionEpoch(string(raw)), nil
}

// Bump writes a new epoch value (monotonic seq + timestamp + nonce), returning it.
// Creates Dir with 0700 when missing. File mode 0600; atomic temp+rename.
func (s *SessionEpochStore) Bump() (SessionEpoch, error) {
	if s == nil || strings.TrimSpace(s.Dir) == "" {
		return SessionEpoch{}, apperr.New(apperr.CodeInternal, "session epoch store is not configured")
	}
	dir := filepath.Clean(strings.TrimSpace(s.Dir))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return SessionEpoch{}, apperr.Wrap(apperr.CodeInternal, "failed to create session epoch directory", err)
	}
	_ = os.Chmod(dir, 0o700)

	prev, _ := s.Load()
	nextSeq := prev.Seq + 1
	if nextSeq == 0 {
		nextSeq = 1
	}
	nonce, err := randomEpochNonce(8)
	if err != nil {
		return SessionEpoch{}, err
	}
	// Format: <seq> <RFC3339Nano> <hex-nonce> — all non-secret, single line.
	line := fmt.Sprintf("%d %s %s\n", nextSeq, time.Now().UTC().Format(time.RFC3339Nano), nonce)
	if err := writeSessionEpochAtomic(s.Path(), []byte(line)); err != nil {
		return SessionEpoch{}, err
	}
	return parseSessionEpoch(line), nil
}

// parseSessionEpoch extracts seq when the first field is an integer; value is
// the full trimmed content. Corrupt/unknown lines still yield a non-empty Value
// so equality checks work.
func parseSessionEpoch(raw string) SessionEpoch {
	v := strings.TrimSpace(raw)
	if v == "" {
		return SessionEpoch{}
	}
	// Reject absurdly large files (canary / abuse bound).
	if len(v) > 4096 {
		v = v[:4096]
	}
	e := SessionEpoch{Value: v}
	fields := strings.Fields(v)
	if len(fields) >= 1 {
		if n, err := strconv.ParseUint(fields[0], 10, 64); err == nil {
			e.Seq = n
		}
	}
	return e
}

func randomEpochNonce(nBytes int) (string, error) {
	if nBytes < 4 {
		nBytes = 4
	}
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", apperr.Wrap(apperr.CodeInternal, "failed to generate session epoch nonce", err)
	}
	return hex.EncodeToString(b), nil
}

// writeSessionEpochAtomic writes data via temp file + chmod 0600 + rename.
func writeSessionEpochAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".session-epoch-*.tmp")
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to create session epoch temp file", err)
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
		return apperr.Wrap(apperr.CodeInternal, "failed to write session epoch temp file", err)
	}
	if err := tmp.Chmod(SessionEpochFileMode); err != nil {
		_ = tmp.Close()
		return apperr.Wrap(apperr.CodeInternal, "failed to set session epoch mode", err)
	}
	if err := tmp.Close(); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to close session epoch temp file", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to rename session epoch file", err)
	}
	cleanup = false
	return nil
}

// SessionEpochWatcher tracks a baseline epoch for one serve process and
// fail-closes when another process bumps the file (logout / re-login).
type SessionEpochWatcher struct {
	Store *SessionEpochStore

	mu    sync.Mutex
	seen  string
	bound bool
}

// Bind records the current epoch as the process baseline (call at serve start).
// Missing file binds empty. Nil watcher/store is a no-op.
func (w *SessionEpochWatcher) Bind() error {
	if w == nil || w.Store == nil {
		return nil
	}
	ep, err := w.Store.Load()
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.seen = ep.Value
	w.bound = true
	return nil
}

// Check returns nil when the epoch is unchanged (or watcher is disabled).
// When the file value differs from the bound baseline, returns a secret-free
// authentication error. Callers should Disable the SessionGuard and clear
// in-memory token bundles.
func (w *SessionEpochWatcher) Check() error {
	if w == nil || w.Store == nil {
		return nil
	}
	ep, err := w.Store.Load()
	if err != nil {
		// Cannot verify continuity — fail closed.
		return apperr.Wrap(apperr.CodeAuthentication, "session epoch unreadable; re-authenticate", err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.bound {
		w.seen = ep.Value
		w.bound = true
		return nil
	}
	if ep.Value != w.seen {
		return apperr.New(apperr.CodeAuthentication,
			"session invalidated by logout or re-login in another process; re-authenticate")
	}
	return nil
}

// Seen returns the bound baseline value (tests/diagnostics; non-secret).
func (w *SessionEpochWatcher) Seen() string {
	if w == nil {
		return ""
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.seen
}

// Changed reports whether Check would fail (without mutating unbound state
// beyond first bind). Prefer Check for fail-closed paths.
func (w *SessionEpochWatcher) Changed() (bool, error) {
	if w == nil || w.Store == nil {
		return false, nil
	}
	ep, err := w.Store.Load()
	if err != nil {
		return false, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.bound {
		return false, nil
	}
	return ep.Value != w.seen, nil
}
