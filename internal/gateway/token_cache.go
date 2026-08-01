package gateway

import (
	"strings"
	"sync"
	"time"
)

// DefaultTokenCacheTTL is the default in-memory access-token cache lifetime.
// Refresh material is never stored in this MVP cache (vault later).
const DefaultTokenCacheTTL = 5 * time.Minute

// CacheKey isolates token entries per tenant, user, workload, and profile
// (GWY-001 / HOST-004 multi-tenant cache isolation).
// Never put token bytes in the key. Prefer Caller.CacheKey() so Tenant is set.
type CacheKey struct {
	// User is the Entra/OIDC subject (sub).
	User string
	// Tenant is the IdP tenant (HOST-004: required for multi-tenant isolation).
	// Empty is allowed for single-tenant labs; production should always set it.
	Tenant string
	// Workload is the AgentCore / gateway workload identity.
	Workload string
	// Profile is the MCP profile namespace.
	Profile string
}

// Normalize returns a trimmed key suitable for map lookup.
func (k CacheKey) Normalize() CacheKey {
	return CacheKey{
		User:     strings.TrimSpace(k.User),
		Tenant:   strings.TrimSpace(k.Tenant),
		Workload: strings.TrimSpace(k.Workload),
		Profile:  strings.TrimSpace(k.Profile),
	}
}

// Valid reports whether the key has the minimum binding fields.
func (k CacheKey) Valid() bool {
	n := k.Normalize()
	return n.User != "" && n.Profile != ""
}

// String is non-secret (no tokens).
func (k CacheKey) String() string {
	n := k.Normalize()
	return "tenant=" + n.Tenant + " user=" + n.User +
		" workload=" + n.Workload + " profile=" + n.Profile
}

// NamespaceSubjectKey returns the stable multi-tenant namespace string
// tenant|user|profile (HOST-004 / SubjectKey shape). Workload is intentionally
// omitted here — it remains a CacheKey dimension for OBO isolation but is not
// part of vault SubjectKey. Empty user yields "".
func (k CacheKey) NamespaceSubjectKey() string {
	n := k.Normalize()
	if n.User == "" {
		return ""
	}
	return SubjectKeyParts(n.Tenant, n.User, n.Profile)
}

// CachedToken is memory-only credential material. It must never be logged,
// serialized into MCP output, or included in Error()/String() implementations.
type CachedToken struct {
	// AccessToken is the Jenkins-audience bearer (secret).
	AccessToken string
	// ExpiresAt is when the cache entry must be treated as stale.
	ExpiresAt time.Time
	// JenkinsPrincipal is the non-secret exchanged subject label when known.
	JenkinsPrincipal string
	// Mode records how the token was obtained.
	Mode Mode
}

// expired reports whether the entry is past ExpiresAt (or empty token).
func (t CachedToken) expired(now time.Time) bool {
	if strings.TrimSpace(t.AccessToken) == "" {
		return true
	}
	if t.ExpiresAt.IsZero() {
		return true
	}
	return !t.ExpiresAt.After(now)
}

// String never includes the access token (canary target).
func (t CachedToken) String() string {
	exp := ""
	if !t.ExpiresAt.IsZero() {
		exp = t.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return "cached_token principal=" + strings.TrimSpace(t.JenkinsPrincipal) +
		" mode=" + t.Mode.String() + " expires=" + exp
}

// TokenCache stores short-lived access tokens keyed by (user, workload, profile).
// Implementations must never log token bytes.
type TokenCache interface {
	Get(key CacheKey) (CachedToken, bool)
	Set(key CacheKey, token CachedToken)
	Delete(key CacheKey)
	// Clear drops all entries (logout / emergency).
	Clear()
}

// MemoryTokenCache is a process-local TTL token cache (GWY-001 foundation).
// Not shared across processes; not a durable vault.
type MemoryTokenCache struct {
	mu      sync.Mutex
	entries map[CacheKey]CachedToken
	// TTL is applied when ExpiresAt is zero on Set (0 → DefaultTokenCacheTTL).
	TTL time.Duration
	// now is optional clock override for tests.
	now func() time.Time
}

// NewMemoryTokenCache builds an empty in-memory cache.
func NewMemoryTokenCache(ttl time.Duration) *MemoryTokenCache {
	if ttl <= 0 {
		ttl = DefaultTokenCacheTTL
	}
	return &MemoryTokenCache{
		entries: make(map[CacheKey]CachedToken),
		TTL:     ttl,
		now:     time.Now,
	}
}

func (c *MemoryTokenCache) clock() time.Time {
	if c != nil && c.now != nil {
		return c.now()
	}
	return time.Now()
}

// Get returns a non-expired entry.
func (c *MemoryTokenCache) Get(key CacheKey) (CachedToken, bool) {
	if c == nil {
		return CachedToken{}, false
	}
	key = key.Normalize()
	if !key.Valid() {
		return CachedToken{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	tok, ok := c.entries[key]
	if !ok || tok.expired(c.clock()) {
		if ok {
			delete(c.entries, key)
		}
		return CachedToken{}, false
	}
	// Return a copy; callers must not rely on shared mutability.
	return tok, true
}

// Set stores a token. Empty tokens are ignored. When ExpiresAt is zero, TTL from now is used.
func (c *MemoryTokenCache) Set(key CacheKey, token CachedToken) {
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
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[CacheKey]CachedToken)
	}
	c.entries[key] = token
}

// Delete removes one key.
func (c *MemoryTokenCache) Delete(key CacheKey) {
	if c == nil {
		return
	}
	key = key.Normalize()
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// Clear removes all entries.
func (c *MemoryTokenCache) Clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[CacheKey]CachedToken)
}
