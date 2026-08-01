package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// EnvGatewayPrincipalCachePath is the optional file path for FilePrincipalCache
// (HOST-008 residual lite). When set under gateway serve wiring, install
// FilePrincipalCache as the process principal map so CLI subject-invalidate
// and serve share SubjectKey → Jenkins principal on the same host.
//
// Empty / unset → process-local in-memory PrincipalCache (default).
// When set: fail closed if path is invalid (empty after clean / root / ".").
//
// Honesty: same-host multi-process principal map share only (flock + 0600).
// Not multi-pod external HA. Values are non-secret Jenkins principal ids only —
// never access tokens, refresh tokens, or vault secrets.
const EnvGatewayPrincipalCachePath = "JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH"

// forbiddenPrincipalFileKeys are map keys that must never appear in a principal
// cache file (token/secret field names). Load fails closed when present so a
// polluted or mis-shaped document cannot be treated as principal data.
var forbiddenPrincipalFileKeys = map[string]struct{}{
	"access_token":  {},
	"refresh_token": {},
	"token":         {},
	"secret":        {},
	"client_secret": {},
	"authorization": {},
	"password":      {},
	"api_token":     {},
}

// FilePrincipalCache is an optional file-backed non-secret principal map
// (HOST-008 Done* lite). SubjectKey → Jenkins principal only under a single
// JSON file with mode 0600.
//
// Multi-process safety: process-local mutex + exclusive flock on path+".lock"
// (same primitive as FileTokenCache / FileAPITokenVault). Safe for same-host
// multi-process (CLI subject-invalidate + serve) sharing one path on a
// local/shared filesystem. Not multi-pod HA without a shared FS.
//
// Never stores tokens. Operators set path via JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH.
// Optional MaxEntries (LRU) + TTL match in-memory PrincipalCache hygiene.
type FilePrincipalCache struct {
	path string
	mu   sync.Mutex
	// MaxEntries bounds growth (0 = unlimited).
	MaxEntries int
	// TTL is applied on Set when > 0 (0 = no expiry).
	TTL time.Duration
	// now is optional clock override for tests.
	now func() time.Time
}

// filePrincipalCacheDoc is the on-disk shape (versioned). Keys are SubjectKey
// strings; values hold non-secret Jenkins principal ids only — never tokens.
type filePrincipalCacheDoc struct {
	Version int                                `json:"version"`
	Entries map[string]filePrincipalCacheEntry `json:"entries"`
}

// filePrincipalCacheEntry is one durable principal row (secret-free).
type filePrincipalCacheEntry struct {
	Principal  string `json:"principal"`
	LastAccess string `json:"last_access,omitempty"` // RFC3339 UTC for LRU
	ExpiresAt  string `json:"expires_at,omitempty"`  // RFC3339 UTC; empty = no expiry
}

// NewFilePrincipalCache constructs a file-backed principal map at path
// (unlimited entries, no TTL). Parent dirs 0700 on first write; file 0600.
// Fail closed: empty / invalid path rejected (no silent memory fallthrough).
func NewFilePrincipalCache(path string) (*FilePrincipalCache, error) {
	return NewFilePrincipalCacheWithLimits(path, 0, 0)
}

// NewFilePrincipalCacheWithLimits constructs a file-backed principal map with
// optional MaxEntries + TTL (same semantics as NewPrincipalCacheWithLimits).
func NewFilePrincipalCacheWithLimits(path string, maxEntries int, ttl time.Duration) (*FilePrincipalCache, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "gateway principal cache path is required")
	}
	clean := filepath.Clean(path)
	if clean == "." || clean == string(filepath.Separator) {
		return nil, apperr.New(apperr.CodeInvalidArgument, "gateway principal cache path is invalid")
	}
	if maxEntries < 0 {
		maxEntries = 0
	}
	if ttl < 0 {
		ttl = 0
	}
	return &FilePrincipalCache{
		path:       clean,
		MaxEntries: maxEntries,
		TTL:        ttl,
		now:        time.Now,
	}, nil
}

// Path returns the cache file path (non-secret operator config).
func (c *FilePrincipalCache) Path() string {
	if c == nil {
		return ""
	}
	return c.path
}

// PrincipalCachePathConfiguredFromEnviron reports whether
// JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH is non-empty (secret-free residual bool).
// Does not validate path usability (serve fails closed on construct when invalid).
// getenv nil → os.Getenv. Never returns the path value.
func PrincipalCachePathConfiguredFromEnviron(getenv func(string) string) bool {
	if getenv == nil {
		getenv = os.Getenv
	}
	return strings.TrimSpace(getenv(EnvGatewayPrincipalCachePath)) != ""
}

// PrincipalStoreFromEnviron returns the process-local *PrincipalCache when
// JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH is empty, else a new FilePrincipalCache.
// Fail closed when the path is set but invalid. maxEntries/ttl apply to both.
// getenv nil → os.Getenv. Does not install as process singleton (call
// ConfigureProcessPrincipalCacheFromEnviron / setProcessPrincipalStore).
func PrincipalStoreFromEnviron(getenv func(string) string, maxEntries int, ttl time.Duration) (PrincipalStore, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	path := strings.TrimSpace(getenv(EnvGatewayPrincipalCachePath))
	if path == "" {
		return NewPrincipalCacheWithLimits(maxEntries, ttl), nil
	}
	return NewFilePrincipalCacheWithLimits(path, maxEntries, ttl)
}

func (c *FilePrincipalCache) clock() time.Time {
	if c != nil && c.now != nil {
		return c.now()
	}
	return time.Now()
}

// Configure updates MaxEntries + TTL (serve reconfigure). Negative → 0.
func (c *FilePrincipalCache) Configure(maxEntries int, ttl time.Duration) {
	if c == nil {
		return
	}
	if maxEntries < 0 {
		maxEntries = 0
	}
	if ttl < 0 {
		ttl = 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.MaxEntries = maxEntries
	c.TTL = ttl
}

// Set stores a non-secret Jenkins principal for subjectKey (file-backed).
// Empty subjectKey, invalid key, or empty principal is a no-op.
// When MaxEntries > 0 and full, evicts LRU. When TTL > 0, entry expires at now+TTL.
// IO failures are silent (best-effort cache; Obtain still returns credentials).
func (c *FilePrincipalCache) Set(subjectKey, jenkinsPrincipal string) {
	if c == nil {
		return
	}
	key := strings.TrimSpace(subjectKey)
	principal := strings.TrimSpace(jenkinsPrincipal)
	if principal == "" || ValidateSubjectKey(key) != nil {
		return
	}
	if isForbiddenPrincipalFileKey(key) {
		return
	}
	_ = c.withLocked(func() error {
		doc, err := c.loadLocked()
		if err != nil {
			return err
		}
		if doc.Entries == nil {
			doc.Entries = make(map[string]filePrincipalCacheEntry)
		}
		now := c.clock()
		if c.TTL > 0 {
			c.purgeExpiredLocked(doc, now)
		}
		if _, exists := doc.Entries[key]; !exists && c.MaxEntries > 0 && len(doc.Entries) >= c.MaxEntries {
			c.enforceMaxLocked(doc, now)
			if len(doc.Entries) >= c.MaxEntries {
				c.evictOneLRULocked(doc)
			}
		}
		ent := filePrincipalCacheEntry{
			Principal:  principal,
			LastAccess: now.UTC().Format(time.RFC3339Nano),
		}
		if c.TTL > 0 {
			ent.ExpiresAt = now.Add(c.TTL).UTC().Format(time.RFC3339Nano)
		}
		doc.Version = 1
		doc.Entries[key] = ent
		return c.saveLocked(doc)
	})
}

// Get returns the cached Jenkins principal for subjectKey when present and not
// TTL-expired. Expired entries are deleted (miss). Successful Get updates
// lastAccess for LRU eviction. IO/corrupt → miss (fail closed).
func (c *FilePrincipalCache) Get(subjectKey string) (principal string, ok bool) {
	if c == nil {
		return "", false
	}
	key := strings.TrimSpace(subjectKey)
	if key == "" {
		return "", false
	}
	var (
		out string
		hit bool
	)
	err := c.withLocked(func() error {
		doc, err := c.loadLocked()
		if err != nil {
			return err
		}
		ent, found := doc.Entries[key]
		if !found || strings.TrimSpace(ent.Principal) == "" {
			return nil
		}
		now := c.clock()
		if exp, okExp := parsePrincipalExpires(ent.ExpiresAt); okExp && !now.Before(exp) {
			delete(doc.Entries, key)
			_ = c.saveLocked(doc)
			return nil
		}
		ent.LastAccess = now.UTC().Format(time.RFC3339Nano)
		doc.Entries[key] = ent
		// Best-effort persist lastAccess; ignore write errors for Get hit.
		_ = c.saveLocked(doc)
		out = strings.TrimSpace(ent.Principal)
		hit = true
		return nil
	})
	if err != nil {
		return "", false
	}
	return out, hit
}

// Delete removes one subjectKey entry (logout / subject-invalidate companion).
func (c *FilePrincipalCache) Delete(subjectKey string) {
	if c == nil {
		return
	}
	key := strings.TrimSpace(subjectKey)
	_ = c.withLocked(func() error {
		doc, err := c.loadLocked()
		if err != nil {
			return err
		}
		if doc.Entries == nil {
			return nil
		}
		delete(doc.Entries, key)
		return c.saveLocked(doc)
	})
}

// Clear drops all entries (emergency / test reset).
func (c *FilePrincipalCache) Clear() {
	if c == nil {
		return
	}
	_ = c.withLocked(func() error {
		return c.saveLocked(filePrincipalCacheDoc{Version: 1, Entries: make(map[string]filePrincipalCacheEntry)})
	})
}

// Len returns the number of cached principals (non-secret status).
// When TTL > 0, purges expired entries first. IO/corrupt → 0.
func (c *FilePrincipalCache) Len() int {
	if c == nil {
		return 0
	}
	n := 0
	_ = c.withLocked(func() error {
		doc, err := c.loadLocked()
		if err != nil {
			return err
		}
		if c.TTL > 0 {
			now := c.clock()
			if c.purgeExpiredLocked(doc, now) {
				_ = c.saveLocked(doc)
			}
		}
		n = len(doc.Entries)
		return nil
	})
	return n
}

// String is secret-free (entry count only; never principals dump or path secrets).
func (c *FilePrincipalCache) String() string {
	return fmt.Sprintf("file_principal_cache entries=%d", c.Len())
}

// StatusMap is safe for doctor/status (no tokens, no subject inventory, no path value).
func (c *FilePrincipalCache) StatusMap() map[string]any {
	out := map[string]any{
		"kind":                        "file",
		"shared_principal_cache_file": true,  // HOST-008 Done* lite same-host
		"shared_principal_cache":      false, // multi-pod external still residual
		"entries":                     c.Len(),
		"ha_multi_replica":            false,
		"path_configured":             c != nil && c.path != "",
	}
	if c == nil {
		return out
	}
	c.mu.Lock()
	max := c.MaxEntries
	ttl := c.TTL
	c.mu.Unlock()
	if max > 0 {
		out["max_entries"] = max
	}
	if ttl > 0 {
		out["ttl_seconds"] = int(ttl / time.Second)
	}
	return out
}

func (c *FilePrincipalCache) withLocked(fn func() error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return withVaultFileLock(c.path, fn)
}

func (c *FilePrincipalCache) loadLocked() (filePrincipalCacheDoc, error) {
	raw, err := os.ReadFile(c.path)
	if err != nil {
		if os.IsNotExist(err) {
			return filePrincipalCacheDoc{Version: 1, Entries: make(map[string]filePrincipalCacheEntry)}, nil
		}
		return filePrincipalCacheDoc{}, apperr.Wrap(apperr.CodeInternal, "gateway principal cache read failed", err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return filePrincipalCacheDoc{Version: 1, Entries: make(map[string]filePrincipalCacheEntry)}, nil
	}
	// Pre-scan raw JSON object keys for forbidden secret field names (fail closed).
	if err := rejectForbiddenPrincipalJSONKeys(raw); err != nil {
		return filePrincipalCacheDoc{}, err
	}
	var doc filePrincipalCacheDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return filePrincipalCacheDoc{}, apperr.Wrap(apperr.CodeCorruptCache, "gateway principal cache file is corrupt or unreadable", err)
	}
	if doc.Entries == nil {
		doc.Entries = make(map[string]filePrincipalCacheEntry)
	}
	// Reject forbidden keys at the entries map level (subjectKey slot pollution).
	for k := range doc.Entries {
		if isForbiddenPrincipalFileKey(k) {
			return filePrincipalCacheDoc{}, apperr.New(apperr.CodeCorruptCache,
				"gateway principal cache file contains forbidden key (token/secret field name)")
		}
		// Values must be non-secret principal strings only (already typed); empty ok to skip on Get.
	}
	if doc.Version == 0 {
		doc.Version = 1
	}
	return doc, nil
}

func (c *FilePrincipalCache) saveLocked(doc filePrincipalCacheDoc) error {
	if doc.Entries == nil {
		doc.Entries = make(map[string]filePrincipalCacheEntry)
	}
	if doc.Version == 0 {
		doc.Version = 1
	}
	// Never persist forbidden keys.
	for k := range doc.Entries {
		if isForbiddenPrincipalFileKey(k) {
			delete(doc.Entries, k)
		}
	}
	dir := filepath.Dir(c.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "gateway principal cache directory create failed", err)
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "gateway principal cache encode failed", err)
	}
	raw = append(raw, '\n')
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "gateway principal cache write failed", err)
	}
	_ = os.Chmod(tmp, 0o600)
	if err := os.Rename(tmp, c.path); err != nil {
		_ = os.Remove(tmp)
		return apperr.Wrap(apperr.CodeInternal, "gateway principal cache rename failed", err)
	}
	_ = os.Chmod(c.path, 0o600)
	return nil
}

// purgeExpiredLocked drops TTL-expired entries. Returns true if any deleted.
// Caller holds flock (+ process mu via withLocked).
func (c *FilePrincipalCache) purgeExpiredLocked(doc filePrincipalCacheDoc, now time.Time) bool {
	changed := false
	for k, ent := range doc.Entries {
		if exp, ok := parsePrincipalExpires(ent.ExpiresAt); ok && !now.Before(exp) {
			delete(doc.Entries, k)
			changed = true
		}
	}
	return changed
}

// enforceMaxLocked drops LRU until len <= MaxEntries. No-op when MaxEntries <= 0.
func (c *FilePrincipalCache) enforceMaxLocked(doc filePrincipalCacheDoc, now time.Time) {
	if c.MaxEntries <= 0 {
		return
	}
	if c.TTL > 0 {
		c.purgeExpiredLocked(doc, now)
	}
	for len(doc.Entries) > c.MaxEntries {
		if !c.evictOneLRULocked(doc) {
			break
		}
	}
}

// evictOneLRULocked removes the entry with the oldest lastAccess.
func (c *FilePrincipalCache) evictOneLRULocked(doc filePrincipalCacheDoc) bool {
	if len(doc.Entries) == 0 {
		return false
	}
	var victim string
	var oldest time.Time
	first := true
	for k, ent := range doc.Entries {
		la, ok := parsePrincipalExpires(ent.LastAccess) // RFC3339 parse reuse
		if !ok {
			la = time.Time{} // missing → oldest
		}
		if first || la.Before(oldest) {
			victim = k
			oldest = la
			first = false
		}
	}
	if victim == "" {
		return false
	}
	delete(doc.Entries, victim)
	return true
}

func parsePrincipalExpires(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	// Prefer nano (LRU last_access); fall back to RFC3339 second precision.
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t, true
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func isForbiddenPrincipalFileKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	_, ok := forbiddenPrincipalFileKeys[k]
	return ok
}

// rejectForbiddenPrincipalJSONKeys scans top-level and nested object keys for
// forbidden secret field names. Fail closed so token-shaped documents never load.
func rejectForbiddenPrincipalJSONKeys(raw []byte) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		// Let loadLocked report corrupt via typed unmarshal.
		return nil
	}
	for k, v := range top {
		if isForbiddenPrincipalFileKey(k) {
			return apperr.New(apperr.CodeCorruptCache,
				"gateway principal cache file contains forbidden key (token/secret field name)")
		}
		// entries map: check child keys
		if strings.EqualFold(strings.TrimSpace(k), "entries") {
			var entries map[string]json.RawMessage
			if err := json.Unmarshal(v, &entries); err != nil {
				continue
			}
			for ek, ev := range entries {
				if isForbiddenPrincipalFileKey(ek) {
					return apperr.New(apperr.CodeCorruptCache,
						"gateway principal cache file contains forbidden key (token/secret field name)")
				}
				// Entry object must not carry token/secret field names.
				var entObj map[string]json.RawMessage
				if err := json.Unmarshal(ev, &entObj); err != nil {
					continue // may be a bare string residual — typed load rejects
				}
				for fk := range entObj {
					if isForbiddenPrincipalFileKey(fk) {
						return apperr.New(apperr.CodeCorruptCache,
							"gateway principal cache entry contains forbidden field (token/secret)")
					}
				}
			}
		}
	}
	return nil
}
