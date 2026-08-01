package auth

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// EnvHTTPJWKSCachePath is the optional same-host multi-process JWKS snapshot
// file path (HOST-001 / HOST-008 residual lite). Empty / unset → memory-only
// RefreshingJWKS (default). When set: public keys only (never private key
// material / tokens); residual-status reports shared_jwks_file=true (path value
// never returned).
//
// Honesty: same-host multi-process share only (flock + 0600 atomic rename).
// Multi-pod external JWKS cache remains residual. Live Entra under load residual.
const EnvHTTPJWKSCachePath = "JENKINS_MCP_HTTP_JWKS_CACHE_PATH"

// jwksFileDoc is the on-disk shape for the optional shared JWKS snapshot.
// Public verification keys only — never private key fields, tokens, or secrets.
type jwksFileDoc struct {
	Version   int    `json:"version"`
	FetchedAt string `json:"fetched_at"` // RFC3339 UTC
	Keys      []JWK  `json:"keys"`
}

// jwksFileCache is a process-local handle for optional file-backed JWKS snapshots.
// Safe for same-host multi-process via flock + atomic rename (HOST-008 lite).
type jwksFileCache struct {
	path string
	mu   sync.Mutex
}

// validateJWKSCachePath cleans and validates an optional JWKS cache path.
// Empty → ("", nil) meaning memory-only. Non-empty invalid → error (fail closed).
func validateJWKSCachePath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", nil
	}
	clean := filepath.Clean(path)
	if clean == "." || clean == string(filepath.Separator) {
		return "", apperr.New(apperr.CodeInvalidArgument, "jwks cache path is invalid")
	}
	return clean, nil
}

// JWKSCachePathConfiguredFromEnviron reports whether
// JENKINS_MCP_HTTP_JWKS_CACHE_PATH is non-empty (secret-free residual bool).
// Does not validate path usability. getenv nil → os.Getenv.
// Never returns the path value.
func JWKSCachePathConfiguredFromEnviron(getenv func(string) string) bool {
	if getenv == nil {
		getenv = os.Getenv
	}
	return strings.TrimSpace(getenv(EnvHTTPJWKSCachePath)) != ""
}

// JWKSCachePathFromEnviron returns the cleaned cache path or empty when unset.
// Fail closed when set but invalid. getenv nil → os.Getenv.
func JWKSCachePathFromEnviron(getenv func(string) string) (string, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	return validateJWKSCachePath(getenv(EnvHTTPJWKSCachePath))
}

func newJWKSFileCache(path string) (*jwksFileCache, error) {
	clean, err := validateJWKSCachePath(path)
	if err != nil {
		return nil, err
	}
	if clean == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "jwks cache path is required")
	}
	return &jwksFileCache{path: clean}, nil
}

// load returns a snapshot from disk. Missing file → (nil, false, nil).
// Corrupt / empty keys / unreadable → (nil, false, err) fail closed (miss for callers).
// Never logs key material.
func (c *jwksFileCache) load() (set *JWKS, fetchedAt time.Time, ok bool, err error) {
	if c == nil || c.path == "" {
		return nil, time.Time{}, false, nil
	}
	var (
		outSet *JWKS
		outAt  time.Time
		found  bool
	)
	ioErr := c.withLocked(func() error {
		// Bound read like FetchJWKS (fail closed on oversized files).
		f, rerr := os.Open(c.path)
		if rerr != nil {
			if os.IsNotExist(rerr) {
				return nil
			}
			return apperr.Wrap(apperr.CodeInternal, "jwks cache read failed", rerr)
		}
		defer f.Close()
		raw, rerr := io.ReadAll(io.LimitReader(f, MaxJWKSBodyBytes+1))
		if rerr != nil {
			return apperr.Wrap(apperr.CodeInternal, "jwks cache read failed", rerr)
		}
		if len(raw) > MaxJWKSBodyBytes {
			return apperr.New(apperr.CodeCorruptCache, "jwks cache file exceeds size limit")
		}
		if len(strings.TrimSpace(string(raw))) == 0 {
			// Empty file: treat as miss (not corrupt enough to poison init).
			return nil
		}
		var doc jwksFileDoc
		if uerr := json.Unmarshal(raw, &doc); uerr != nil {
			return apperr.Wrap(apperr.CodeCorruptCache, "jwks cache file is corrupt or unreadable", uerr)
		}
		if len(doc.Keys) == 0 {
			return apperr.New(apperr.CodeCorruptCache, "jwks cache file has no keys")
		}
		// Reject secret-shaped field names if present at document root (fail closed).
		// Keys themselves are public JWK only (JWK type has no private fields).
		at, perr := time.Parse(time.RFC3339, strings.TrimSpace(doc.FetchedAt))
		if perr != nil || at.IsZero() {
			return apperr.New(apperr.CodeCorruptCache, "jwks cache fetched_at is missing or invalid")
		}
		// Copy keys (public only) so callers cannot mutate disk view via shared slice.
		keys := make([]JWK, len(doc.Keys))
		copy(keys, doc.Keys)
		outSet = &JWKS{Keys: keys}
		outAt = at.UTC()
		found = true
		return nil
	})
	if ioErr != nil {
		return nil, time.Time{}, false, ioErr
	}
	return outSet, outAt, found, nil
}

// save writes a secret-free JWKS snapshot (public keys + fetched_at) mode 0600
// under flock + temp+rename. Best-effort from RefreshingJWKS (success path still
// returns network JWKS if save fails). Never logs key material.
func (c *jwksFileCache) save(set *JWKS, fetchedAt time.Time) error {
	if c == nil || c.path == "" {
		return apperr.New(apperr.CodeInternal, "jwks cache path is required")
	}
	if set == nil || len(set.Keys) == 0 {
		return apperr.New(apperr.CodeInvalidArgument, "jwks cache save requires non-empty keys")
	}
	if fetchedAt.IsZero() {
		fetchedAt = time.Now().UTC()
	}
	// Public fields only — copy through JWK (no private key slots on type).
	keys := make([]JWK, len(set.Keys))
	copy(keys, set.Keys)
	doc := jwksFileDoc{
		Version:   1,
		FetchedAt: fetchedAt.UTC().Format(time.RFC3339),
		Keys:      keys,
	}
	return c.withLocked(func() error {
		return c.saveLocked(doc)
	})
}

func (c *jwksFileCache) withLocked(fn func() error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return withJWKSFileLock(c.path, fn)
}

func (c *jwksFileCache) saveLocked(doc jwksFileDoc) error {
	dir := filepath.Dir(c.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "jwks cache directory create failed", err)
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "jwks cache encode failed", err)
	}
	raw = append(raw, '\n')
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "jwks cache write failed", err)
	}
	_ = os.Chmod(tmp, 0o600)
	if err := os.Rename(tmp, c.path); err != nil {
		_ = os.Remove(tmp)
		return apperr.Wrap(apperr.CodeInternal, "jwks cache rename failed", err)
	}
	_ = os.Chmod(c.path, 0o600)
	return nil
}

// jwksSnapshotFreshEnough reports whether a snapshot fetchedAt is usable under
// maxStale (0 = unlimited stale-if-error residual).
func jwksSnapshotFreshEnough(fetchedAt, now time.Time, maxStale time.Duration) bool {
	if fetchedAt.IsZero() {
		return false
	}
	if maxStale <= 0 {
		return true
	}
	return !now.Before(fetchedAt) && now.Sub(fetchedAt) <= maxStale
}
