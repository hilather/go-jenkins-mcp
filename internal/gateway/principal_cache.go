package gateway

import (
	"fmt"
	"strings"
	"sync"
)

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
type PrincipalCache struct {
	mu      sync.RWMutex
	entries map[string]string // subjectKey → jenkins principal
}

// NewPrincipalCache builds an empty process-local principal cache.
func NewPrincipalCache() *PrincipalCache {
	return &PrincipalCache{entries: make(map[string]string)}
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

// Set stores a non-secret Jenkins principal for subjectKey.
// Empty subjectKey, invalid key, or empty principal is a no-op (never stores secrets).
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
		c.entries = make(map[string]string)
	}
	c.entries[key] = principal
}

// Get returns the cached Jenkins principal for subjectKey when present.
func (c *PrincipalCache) Get(subjectKey string) (principal string, ok bool) {
	if c == nil {
		return "", false
	}
	key := strings.TrimSpace(subjectKey)
	if key == "" {
		return "", false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.entries == nil {
		return "", false
	}
	p, ok := c.entries[key]
	if !ok || strings.TrimSpace(p) == "" {
		return "", false
	}
	return strings.TrimSpace(p), true
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
	c.entries = make(map[string]string)
}

// Len returns the number of cached principals (non-secret status).
func (c *PrincipalCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// String is secret-free (entry count only; never tokens or raw principals dump).
func (c *PrincipalCache) String() string {
	return fmt.Sprintf("principal_cache entries=%d", c.Len())
}

// StatusMap is safe for doctor/status (no tokens, no subject inventory dump).
func (c *PrincipalCache) StatusMap() map[string]any {
	return map[string]any{
		"entries": c.Len(),
	}
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
