package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// EnvGatewayTokenCachePath is the optional file path for FileTokenCache
// (HOST-008 residual lite). When set under Mode C serve wiring, construct
// FileTokenCache instead of MemoryTokenCache.
//
// Empty / unset → process-local MemoryTokenCache (default).
// When set: fail closed if path is invalid (empty after clean / root / ".").
//
// Honesty: same-host multi-process Obtain cache share only (flock + 0600).
// Not multi-pod external Redis/HA. Multi-replica shared Obtain cache residual.
const EnvGatewayTokenCachePath = "JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH"

// FileTokenCache is an optional file-backed Obtain token cache (HOST-008 Done*
// lite). Short-lived access tokens under a single JSON file with mode 0600.
//
// Multi-process safety: process-local mutex + exclusive flock on path+".lock"
// (same primitive as FileAPITokenVault). Safe for same-host multi-process
// (e.g. CLI + serve, or multiple local processes) sharing one path on a
// local/shared filesystem. Not multi-pod HA without a shared FS; external
// multi-pod Obtain cache (Redis/etc.) remains residual.
//
// File contents hold secrets — never log, never ship in support bundles.
// Operators set path via JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH.
type FileTokenCache struct {
	path string
	mu   sync.Mutex
	// TTL is applied when ExpiresAt is zero on Set (0 → DefaultTokenCacheTTL).
	TTL time.Duration
	// now is optional clock override for tests.
	now func() time.Time
}

// fileTokenCacheDoc is the on-disk shape (versioned). Keys are encodeCacheKey
// strings; values hold secret access tokens — never log this document.
type fileTokenCacheDoc struct {
	Version int                            `json:"version"`
	Entries map[string]fileTokenCacheEntry `json:"entries"`
}

type fileTokenCacheEntry struct {
	AccessToken      string `json:"access_token"`
	ExpiresAt        string `json:"expires_at"` // RFC3339 UTC
	JenkinsPrincipal string `json:"jenkins_principal,omitempty"`
	Mode             string `json:"mode,omitempty"`
}

// NewFileTokenCache constructs a file-backed Obtain cache at path.
// Parent directories are created on first write with 0700; the cache file is 0600.
// Fail closed: empty / invalid path rejected (no silent Memory fallthrough).
func NewFileTokenCache(path string, ttl time.Duration) (*FileTokenCache, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "gateway token cache path is required")
	}
	clean := filepath.Clean(path)
	if clean == "." || clean == string(filepath.Separator) {
		return nil, apperr.New(apperr.CodeInvalidArgument, "gateway token cache path is invalid")
	}
	if ttl <= 0 {
		ttl = DefaultTokenCacheTTL
	}
	return &FileTokenCache{
		path: clean,
		TTL:  ttl,
		now:  time.Now,
	}, nil
}

// Path returns the cache file path (non-secret).
func (c *FileTokenCache) Path() string {
	if c == nil {
		return ""
	}
	return c.path
}

// TokenCacheFromEnviron returns MemoryTokenCache when
// JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH is empty, else FileTokenCache.
// Fail closed when the path is set but invalid. getenv nil → os.Getenv.
// ttl 0 → DefaultTokenCacheTTL (same as NewMemoryTokenCache / NewFileTokenCache).
func TokenCacheFromEnviron(getenv func(string) string, ttl time.Duration) (TokenCache, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	path := strings.TrimSpace(getenv(EnvGatewayTokenCachePath))
	if path == "" {
		return NewMemoryTokenCache(ttl), nil
	}
	return NewFileTokenCache(path, ttl)
}

func (c *FileTokenCache) clock() time.Time {
	if c != nil && c.now != nil {
		return c.now()
	}
	return time.Now()
}

// encodeCacheKey builds a stable non-secret map key for disk (never token bytes).
func encodeCacheKey(k CacheKey) string {
	n := k.Normalize()
	// JSON array escapes special characters in identity fields safely.
	raw, err := json.Marshal([4]string{n.Tenant, n.User, n.Workload, n.Profile})
	if err != nil {
		// Should never fail for strings; fall back to join for robustness.
		return n.Tenant + "\x1f" + n.User + "\x1f" + n.Workload + "\x1f" + n.Profile
	}
	return string(raw)
}

// Get implements TokenCache. IO / corrupt failures → miss (fail closed: never
// return partial/garbage tokens). Expired entries are deleted best-effort.
func (c *FileTokenCache) Get(key CacheKey) (CachedToken, bool) {
	if c == nil {
		return CachedToken{}, false
	}
	key = key.Normalize()
	if !key.Valid() {
		return CachedToken{}, false
	}
	var (
		tok CachedToken
		ok  bool
	)
	err := c.withLocked(func() error {
		doc, err := c.loadLocked()
		if err != nil {
			return err
		}
		ek := encodeCacheKey(key)
		e, found := doc.Entries[ek]
		if !found {
			return nil
		}
		parsed, parseOK := parseFileTokenEntry(e)
		if !parseOK || parsed.expired(c.clock()) {
			delete(doc.Entries, ek)
			// Best-effort persist purge of expired/corrupt entry; ignore write errors.
			_ = c.saveLocked(doc)
			return nil
		}
		tok, ok = parsed, true
		return nil
	})
	if err != nil {
		return CachedToken{}, false
	}
	return tok, ok
}

// Set implements TokenCache. Empty tokens ignored. IO failures are silent
// (Obtain still returns the credential; cache is best-effort).
func (c *FileTokenCache) Set(key CacheKey, token CachedToken) {
	if c == nil {
		return
	}
	key = key.Normalize()
	if !key.Valid() || strings.TrimSpace(token.AccessToken) == "" {
		return
	}
	if token.ExpiresAt.IsZero() {
		token.ExpiresAt = c.clock().Add(c.TTL)
	}
	_ = c.withLocked(func() error {
		doc, err := c.loadLocked()
		if err != nil {
			// Fail closed on corrupt JSON: do not invent an empty doc and wipe
			// other subjects. Missing file is already handled in loadLocked.
			return err
		}
		if doc.Entries == nil {
			doc.Entries = make(map[string]fileTokenCacheEntry)
		}
		doc.Version = 1
		doc.Entries[encodeCacheKey(key)] = fileTokenCacheEntry{
			AccessToken:      token.AccessToken,
			ExpiresAt:        token.ExpiresAt.UTC().Format(time.RFC3339),
			JenkinsPrincipal: strings.TrimSpace(token.JenkinsPrincipal),
			Mode:             string(token.Mode),
		}
		return c.saveLocked(doc)
	})
}

// Delete implements TokenCache.
func (c *FileTokenCache) Delete(key CacheKey) {
	if c == nil {
		return
	}
	key = key.Normalize()
	_ = c.withLocked(func() error {
		doc, err := c.loadLocked()
		if err != nil {
			return err
		}
		if doc.Entries == nil {
			return nil
		}
		delete(doc.Entries, encodeCacheKey(key))
		return c.saveLocked(doc)
	})
}

// Clear implements TokenCache.
func (c *FileTokenCache) Clear() {
	if c == nil {
		return
	}
	_ = c.withLocked(func() error {
		return c.saveLocked(fileTokenCacheDoc{Version: 1, Entries: make(map[string]fileTokenCacheEntry)})
	})
}

// StatusMap is a non-secret doctor/status summary (HOST-008 residual honesty).
// Never includes tokens, path contents, or subject inventory.
func (c *FileTokenCache) StatusMap() map[string]any {
	entries := 0
	if c != nil {
		_ = c.withLocked(func() error {
			doc, err := c.loadLocked()
			if err != nil {
				return err
			}
			entries = len(doc.Entries)
			return nil
		})
	}
	return map[string]any{
		"kind":                    "file",
		"shared_token_cache_file": true,  // HOST-008 Done* lite same-host
		"shared_token_cache":      false, // multi-pod external still residual
		"entries":                 entries,
		"ha_multi_replica":        false, // HOST-008 residual
		"path_configured":         c != nil && c.path != "",
	}
}

func (c *FileTokenCache) withLocked(fn func() error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return withVaultFileLock(c.path, fn)
}

func (c *FileTokenCache) loadLocked() (fileTokenCacheDoc, error) {
	raw, err := os.ReadFile(c.path)
	if err != nil {
		if os.IsNotExist(err) {
			return fileTokenCacheDoc{Version: 1, Entries: make(map[string]fileTokenCacheEntry)}, nil
		}
		return fileTokenCacheDoc{}, apperr.Wrap(apperr.CodeInternal, "gateway token cache read failed", err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return fileTokenCacheDoc{Version: 1, Entries: make(map[string]fileTokenCacheEntry)}, nil
	}
	var doc fileTokenCacheDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		// Fail closed on corrupt — do not invent empty success that could mask
		// cross-subject confusion after partial writes.
		return fileTokenCacheDoc{}, apperr.Wrap(apperr.CodeCorruptCache, "gateway token cache file is corrupt or unreadable", err)
	}
	if doc.Entries == nil {
		doc.Entries = make(map[string]fileTokenCacheEntry)
	}
	if doc.Version == 0 {
		doc.Version = 1
	}
	return doc, nil
}

func (c *FileTokenCache) saveLocked(doc fileTokenCacheDoc) error {
	if doc.Entries == nil {
		doc.Entries = make(map[string]fileTokenCacheEntry)
	}
	if doc.Version == 0 {
		doc.Version = 1
	}
	dir := filepath.Dir(c.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "gateway token cache directory create failed", err)
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "gateway token cache encode failed", err)
	}
	raw = append(raw, '\n')
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "gateway token cache write failed", err)
	}
	_ = os.Chmod(tmp, 0o600)
	if err := os.Rename(tmp, c.path); err != nil {
		_ = os.Remove(tmp)
		return apperr.Wrap(apperr.CodeInternal, "gateway token cache rename failed", err)
	}
	_ = os.Chmod(c.path, 0o600)
	return nil
}

func parseFileTokenEntry(e fileTokenCacheEntry) (CachedToken, bool) {
	tok := strings.TrimSpace(e.AccessToken)
	if tok == "" {
		return CachedToken{}, false
	}
	var exp time.Time
	if raw := strings.TrimSpace(e.ExpiresAt); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return CachedToken{}, false
		}
		exp = t
	}
	return CachedToken{
		AccessToken:      tok,
		ExpiresAt:        exp,
		JenkinsPrincipal: strings.TrimSpace(e.JenkinsPrincipal),
		Mode:             Mode(strings.TrimSpace(e.Mode)),
	}, true
}
