package gateway

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// EnvGatewayPrincipalCacheMax is optional max entries for process PrincipalCache
// (multi-user hygiene residual lite). Empty → unlimited (0). Non-negative int.
const EnvGatewayPrincipalCacheMax = "JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_MAX"

// EnvGatewayPrincipalCacheTTL is optional entry TTL for process PrincipalCache
// (Go duration, e.g. "1h", "30m"). Empty → no expiry (0).
const EnvGatewayPrincipalCacheTTL = "JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_TTL"

// principalEntry is one non-secret cache row (never tokens).
type principalEntry struct {
	principal  string
	lastAccess time.Time // LRU eviction order
	expiresAt  time.Time // zero = no expiry (TTL disabled)
}

// PrincipalCache is a process-local map from SubjectKey → non-secret Jenkins
// principal (HOST multi-user / MUT-001).
//
// AuthProviderCtx cannot write onto request context after Obtain; this cache
// lets multi-user policy SubjectFromContext (cmd policySubjectFromGatewayCtx)
// and mutation Binding prefer the per-subject Obtain principal (Mode A vault
// username / Credential.JenkinsPrincipal) over HTTP claim / process principal.
//
// Keys are SubjectKey (tenant|subject|profile) — never tokens or secrets.
// Values are non-secret Jenkins user ids only. String/Status never include
// tokens (there are none stored).
//
// Hygiene residual lite (long-running multi-user gateway):
//   - MaxEntries (0 = unlimited default): on Set when full, evict LRU (oldest lastAccess).
//   - TTL (0 = no expiry default): on Get, expired entries are deleted (miss).
//
// Process-local only — multi-pod shared principal map is HOST-008 residual.
type PrincipalCache struct {
	mu      sync.Mutex
	entries map[string]principalEntry // subjectKey → entry
	// MaxEntries bounds growth (0 = unlimited residual default for backward compat).
	MaxEntries int
	// TTL is applied on Set when > 0 (0 = no expiry default).
	TTL time.Duration
	// now is optional clock override for tests.
	now func() time.Time
}

// NewPrincipalCache builds an empty process-local principal cache
// (unlimited entries, no TTL — backward-compatible residual default).
func NewPrincipalCache() *PrincipalCache {
	return &PrincipalCache{entries: make(map[string]principalEntry), now: time.Now}
}

// NewPrincipalCacheWithLimits builds a cache with optional max entries and TTL.
// maxEntries < 0 is treated as 0 (unlimited). ttl < 0 is treated as 0 (no expiry).
func NewPrincipalCacheWithLimits(maxEntries int, ttl time.Duration) *PrincipalCache {
	if maxEntries < 0 {
		maxEntries = 0
	}
	if ttl < 0 {
		ttl = 0
	}
	return &PrincipalCache{
		entries:    make(map[string]principalEntry),
		MaxEntries: maxEntries,
		TTL:        ttl,
		now:        time.Now,
	}
}

// processPrincipalCache is the serve-wide default used by AuthProviderCtx and
// mutationBindingFromGatewayCtx. Tests may inject a private *PrincipalCache
// instead of mutating this global.
var processPrincipalCache = NewPrincipalCache()

// ProcessPrincipalCache returns the process-local default principal cache.
// Never nil after package init.
func ProcessPrincipalCache() *PrincipalCache {
	if processPrincipalCache == nil {
		processPrincipalCache = NewPrincipalCache()
	}
	return processPrincipalCache
}

// ConfigureProcessPrincipalCache sets MaxEntries and TTL on the process-local
// singleton (serve start). Does not replace the pointer — existing callers of
// ProcessPrincipalCache keep the same instance. maxEntries < 0 → 0; ttl < 0 → 0.
// When maxEntries > 0, enforces eviction on any already-present entries.
// Tests should prefer private NewPrincipalCache / NewPrincipalCacheWithLimits
// rather than reconfiguring the process singleton.
func ConfigureProcessPrincipalCache(maxEntries int, ttl time.Duration) {
	c := ProcessPrincipalCache()
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
	if c.now == nil {
		c.now = time.Now
	}
	now := c.clockLocked()
	if c.TTL > 0 {
		c.purgeExpiredLocked(now)
	}
	if c.MaxEntries > 0 {
		c.enforceMaxLocked(now)
	}
}

// ConfigureProcessPrincipalCacheFromEnviron applies
// JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_MAX / _TTL to the process singleton.
// Empty env → unlimited / no expiry (no-op on defaults). Invalid values return
// an error without mutating the cache (fail closed at serve start).
func ConfigureProcessPrincipalCacheFromEnviron(getenv func(string) string) error {
	maxEntries, ttl, err := PrincipalCacheConfigFromEnviron(getenv)
	if err != nil {
		return err
	}
	ConfigureProcessPrincipalCache(maxEntries, ttl)
	return nil
}

// PrincipalCacheConfigFromEnviron parses optional hygiene knobs (secret-free).
// Empty MAX → 0 unlimited. Empty TTL → 0 no expiry.
// Invalid (negative / non-int max, bad duration) fail closed with error.
func PrincipalCacheConfigFromEnviron(getenv func(string) string) (maxEntries int, ttl time.Duration, err error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	if raw := strings.TrimSpace(getenv(EnvGatewayPrincipalCacheMax)); raw != "" {
		v, perr := strconv.Atoi(raw)
		if perr != nil || v < 0 {
			return 0, 0, apperr.New(apperr.CodeInvalidArgument,
				"invalid "+EnvGatewayPrincipalCacheMax+" (non-negative integer; empty = unlimited)")
		}
		maxEntries = v
	}
	if raw := strings.TrimSpace(getenv(EnvGatewayPrincipalCacheTTL)); raw != "" {
		d, perr := time.ParseDuration(raw)
		if perr != nil || d < 0 {
			return 0, 0, apperr.New(apperr.CodeInvalidArgument,
				"invalid "+EnvGatewayPrincipalCacheTTL+" (Go duration e.g. 1h; empty = no expiry)")
		}
		ttl = d
	}
	return maxEntries, ttl, nil
}

func (c *PrincipalCache) clock() time.Time {
	if c != nil && c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *PrincipalCache) clockLocked() time.Time {
	// Caller holds c.mu.
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// Set stores a non-secret Jenkins principal for subjectKey.
// Empty subjectKey, invalid key, or empty principal is a no-op (never stores secrets).
// When MaxEntries > 0 and the cache is full, evicts the LRU entry (oldest lastAccess)
// before insert. When TTL > 0, the entry expires at now+TTL (fixed, not sliding on Get).
func (c *PrincipalCache) Set(subjectKey, jenkinsPrincipal string) {
	if c == nil {
		return
	}
	key := strings.TrimSpace(subjectKey)
	principal := strings.TrimSpace(jenkinsPrincipal)
	if principal == "" || ValidateSubjectKey(key) != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]principalEntry)
	}
	now := c.clockLocked()
	if c.TTL > 0 {
		c.purgeExpiredLocked(now)
	}
	// Replace existing key without growing.
	if _, exists := c.entries[key]; !exists && c.MaxEntries > 0 && len(c.entries) >= c.MaxEntries {
		c.enforceMaxLocked(now)
		// Still full: drop one LRU so the new key fits.
		if len(c.entries) >= c.MaxEntries {
			c.evictOneLRULocked()
		}
	}
	ent := principalEntry{
		principal:  principal,
		lastAccess: now,
	}
	if c.TTL > 0 {
		ent.expiresAt = now.Add(c.TTL)
	}
	c.entries[key] = ent
}

// Get returns the cached Jenkins principal for subjectKey when present and not
// TTL-expired. Expired entries are deleted (miss). Successful Get updates
// lastAccess for LRU eviction.
func (c *PrincipalCache) Get(subjectKey string) (principal string, ok bool) {
	if c == nil {
		return "", false
	}
	key := strings.TrimSpace(subjectKey)
	if key == "" {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		return "", false
	}
	ent, found := c.entries[key]
	if !found || strings.TrimSpace(ent.principal) == "" {
		return "", false
	}
	now := c.clockLocked()
	if !ent.expiresAt.IsZero() && !now.Before(ent.expiresAt) {
		delete(c.entries, key)
		return "", false
	}
	ent.lastAccess = now
	c.entries[key] = ent
	return strings.TrimSpace(ent.principal), true
}

// Delete removes one subjectKey entry (logout / Invalidate companion).
func (c *PrincipalCache) Delete(subjectKey string) {
	if c == nil {
		return
	}
	key := strings.TrimSpace(subjectKey)
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// Clear drops all entries (emergency / test reset).
func (c *PrincipalCache) Clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]principalEntry)
}

// Len returns the number of cached principals (non-secret status).
// When TTL > 0, purges expired entries first so the count is accurate.
func (c *PrincipalCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.TTL > 0 {
		c.purgeExpiredLocked(c.clockLocked())
	}
	return len(c.entries)
}

// String is secret-free (entry count only; never tokens or raw principals dump).
func (c *PrincipalCache) String() string {
	return fmt.Sprintf("principal_cache entries=%d", c.Len())
}

// StatusMap is safe for doctor/status (no tokens, no subject inventory dump).
// Includes max_entries / ttl_seconds only when configured (> 0).
func (c *PrincipalCache) StatusMap() map[string]any {
	out := map[string]any{
		"entries": c.Len(),
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

// purgeExpiredLocked drops TTL-expired entries. Caller holds c.mu.
func (c *PrincipalCache) purgeExpiredLocked(now time.Time) {
	for k, ent := range c.entries {
		if !ent.expiresAt.IsZero() && !now.Before(ent.expiresAt) {
			delete(c.entries, k)
		}
	}
}

// enforceMaxLocked drops LRU entries until len <= MaxEntries.
// Caller holds c.mu. No-op when MaxEntries <= 0.
func (c *PrincipalCache) enforceMaxLocked(now time.Time) {
	if c.MaxEntries <= 0 {
		return
	}
	// Prefer purging expired first when TTL is on.
	if c.TTL > 0 {
		c.purgeExpiredLocked(now)
	}
	for len(c.entries) > c.MaxEntries {
		if !c.evictOneLRULocked() {
			break
		}
	}
}

// evictOneLRULocked removes the entry with the oldest lastAccess.
// Returns false if empty. Caller holds c.mu.
func (c *PrincipalCache) evictOneLRULocked() bool {
	if len(c.entries) == 0 {
		return false
	}
	var victim string
	var oldest time.Time
	first := true
	for k, ent := range c.entries {
		if first || ent.lastAccess.Before(oldest) {
			victim = k
			oldest = ent.lastAccess
			first = false
		}
	}
	if victim == "" {
		return false
	}
	delete(c.entries, victim)
	return true
}

// RememberObtainPrincipal records the Jenkins principal known after a successful
// Obtain for caller. Prefers Credential.JenkinsPrincipal; falls back to Mode A
// Basic HTTPAuth.Username. No-op when principal empty or caller SubjectKey invalid.
// Never stores AccessToken or other secrets.
func RememberObtainPrincipal(cache *PrincipalCache, caller Caller, cred Credential, ha HTTPAuth) {
	if cache == nil || !caller.Valid() {
		return
	}
	principal := strings.TrimSpace(cred.JenkinsPrincipal)
	if principal == "" {
		principal = strings.TrimSpace(ha.Username)
	}
	if principal == "" {
		return
	}
	cache.Set(SubjectKey(caller), principal)
}
