package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// APITokenVault stores personal Jenkins API tokens keyed by subjectKey.
//
// subjectKey is a stable identity derived from gateway binding (tenant|subject|profile),
// never from MCP tool arguments (GWY-002 / HOST-009). Implementations must never
// log token values; errors must not embed secrets.
//
// Mode A (api_token_vault) only: never a shared service account.
type APITokenVault interface {
	// Get returns the personal Jenkins username and API token for subjectKey.
	// ok=false with err=nil means not found (caller maps to fail-closed Obtain).
	Get(ctx context.Context, subjectKey string) (username, token string, ok bool, err error)
	// Put stores or replaces the personal API token for subjectKey.
	Put(ctx context.Context, subjectKey, username, token string) error
	// Delete removes the entry for subjectKey. Missing entries are success.
	Delete(ctx context.Context, subjectKey string) error
}

// SubjectKey builds the stable vault key for a bound gateway caller.
//
// Format: tenant|subject|profile (trimmed). Subject is required; tenant and
// profile may be empty for single-tenant labs but production gateways should
// always set all three so keys never collide across tenants/profiles.
//
// Never derive subjectKey from tool arguments — only from validated Caller /
// InboundClaims (GWY-002).
func SubjectKey(caller Caller) string {
	return SubjectKeyParts(caller.Tenant, caller.Subject, string(caller.ProfileID))
}

// SubjectKeyParts builds subjectKey from raw identity parts (tests / CLI).
// Empty subject returns "" (callers must reject).
func SubjectKeyParts(tenant, subject, profile string) string {
	sub := strings.TrimSpace(subject)
	if sub == "" {
		return ""
	}
	return strings.Join([]string{
		strings.TrimSpace(tenant),
		sub,
		strings.TrimSpace(profile),
	}, "|")
}

// SubjectKeyHash returns a hex-encoded SHA-256 of subjectKey for filesystem-safe
// names when operators prefer hashed paths. The vault itself keys by SubjectKey
// (or hash when configured); this helper never includes secrets.
func SubjectKeyHash(subjectKey string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(subjectKey)))
	return hex.EncodeToString(sum[:])
}

// ValidateSubjectKey rejects empty or oversized subject keys (fail closed).
func ValidateSubjectKey(subjectKey string) error {
	k := strings.TrimSpace(subjectKey)
	if k == "" {
		return apperr.New(apperr.CodeInvalidArgument, "gateway vault subject key is required")
	}
	// Bound key length (tenant|subject|profile) — not a secret; keep DoS-safe.
	const maxSubjectKeyBytes = 1024
	if len(k) > maxSubjectKeyBytes {
		return apperr.New(apperr.CodeInvalidArgument, "gateway vault subject key exceeds length bound")
	}
	return nil
}

// vaultEntry is an in-memory personal token record (never logged).
type vaultEntry struct {
	Username string
	Token    string
}

// MemoryAPITokenVault is a process-memory APITokenVault for tests and unit labs.
// It is not durable across restarts and must never be treated as production
// multi-replica storage (HOST-008 residual).
type MemoryAPITokenVault struct {
	mu      sync.RWMutex
	entries map[string]vaultEntry
}

// NewMemoryAPITokenVault constructs an empty memory vault.
func NewMemoryAPITokenVault() *MemoryAPITokenVault {
	return &MemoryAPITokenVault{entries: make(map[string]vaultEntry)}
}

// Get implements APITokenVault.
func (v *MemoryAPITokenVault) Get(ctx context.Context, subjectKey string) (string, string, bool, error) {
	if err := ctx.Err(); err != nil {
		return "", "", false, apperr.Wrap(apperr.CodeCancelled, "gateway vault get cancelled", err)
	}
	if err := ValidateSubjectKey(subjectKey); err != nil {
		return "", "", false, err
	}
	if v == nil {
		return "", "", false, nil
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	e, ok := v.entries[strings.TrimSpace(subjectKey)]
	if !ok {
		return "", "", false, nil
	}
	return e.Username, e.Token, true, nil
}

// Put implements APITokenVault.
func (v *MemoryAPITokenVault) Put(ctx context.Context, subjectKey, username, token string) error {
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
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.entries == nil {
		v.entries = make(map[string]vaultEntry)
	}
	v.entries[strings.TrimSpace(subjectKey)] = vaultEntry{Username: user, Token: tok}
	return nil
}

// Delete implements APITokenVault.
func (v *MemoryAPITokenVault) Delete(ctx context.Context, subjectKey string) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "gateway vault delete cancelled", err)
	}
	if err := ValidateSubjectKey(subjectKey); err != nil {
		return err
	}
	if v == nil {
		return nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.entries, strings.TrimSpace(subjectKey))
	return nil
}

// Len returns the number of stored subjects (tests / status only; no secrets).
func (v *MemoryAPITokenVault) Len() int {
	if v == nil {
		return 0
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.entries)
}

// ListSubjectKeys returns subject keys only (no usernames/tokens). Sorted for
// stable admin/status output. Never includes secrets.
func (v *MemoryAPITokenVault) ListSubjectKeys(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, apperr.Wrap(apperr.CodeCancelled, "gateway vault list cancelled", err)
	}
	if v == nil {
		return nil, nil
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]string, 0, len(v.entries))
	for k := range v.entries {
		out = append(out, k)
	}
	sortSubjectKeys(out)
	return out, nil
}
