package mcpserver

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// HOST-001: mid-session subject rebind fail-closed on Streamable HTTP.
//
// MCP clients send Mcp-Session-Id after initialize. The first authenticated
// request that carries a session id establishes a non-secret identity
// fingerprint; subsequent requests on the same session must present the same
// RequestIdentity fingerprint or receive 401 (no tokens/subjects in the body).
//
// Health/ready paths never enter this table. Sessions without an id (e.g.
// initialize) still require a subject when RequireSubject is on, but cannot
// yet be bound — bind happens on the first request that includes the session id.
//
// This table is process-local (GWY-002 wire point). Full gateway.Binding TTL
// revalidation for policy.Subject remains in internal/gateway; continuous JWKS
// rotation under load is residual (serve fetches JWKS once at start).

// HeaderMCPSessionID is the MCP Streamable HTTP session header (SDK constant
// Mcp-Session-Id). Used only for identity binding, never as an auth boundary
// by itself (subject must still be established per request).
const HeaderMCPSessionID = "Mcp-Session-Id"

// DefaultMaxSessionIdentityBinds caps in-process session→fingerprint entries
// (fail-closed memory bound). Overflow evicts an arbitrary entry so new sessions
// can bind; existing session checks still run when the entry remains.
const DefaultMaxSessionIdentityBinds = 4096

// MaxMCPSessionIDBytes is the hard cap on accepted Mcp-Session-Id length.
const MaxMCPSessionIDBytes = 128

// IdentityFingerprint builds a non-secret stable hash of binding-critical
// RequestIdentity fields for mid-session change detection (HOST-001 / GWY-002
// parity with gateway.ClaimsFingerprint for the HTTP transport layer).
// Empty Present() identity yields a deterministic empty-field hash; callers
// must not bind empty subjects under RequireSubject.
func IdentityFingerprint(id RequestIdentity) string {
	raw := strings.Join([]string{
		strings.TrimSpace(id.ExternalSubject),
		strings.TrimSpace(id.Tenant),
		strings.TrimSpace(id.WorkloadID),
		strings.TrimSpace(id.JenkinsPrincipal),
	}, "|")
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:16])
}

// sessionIdentityTable maps MCP session id → identity fingerprint.
// Thread-safe; process-local only (not durable across restarts).
type sessionIdentityTable struct {
	mu      sync.Mutex
	entries map[string]string // sessionID → fingerprint
	max     int
}

func newSessionIdentityTable(max int) *sessionIdentityTable {
	if max <= 0 {
		max = DefaultMaxSessionIdentityBinds
	}
	return &sessionIdentityTable{
		entries: make(map[string]string),
		max:     max,
	}
}

// BindOrCheck establishes or revalidates the fingerprint for sessionID.
//
//   - Empty sessionID or empty fingerprint → no-op (nil). Callers skip bind
//     when there is no MCP session yet or no Present identity.
//   - Oversize sessionID → fail closed.
//   - First see of sessionID → store fingerprint.
//   - Subsequent → require exact match; mismatch fails closed.
//
// Never includes tokens or raw subjects in the returned error.
func (t *sessionIdentityTable) BindOrCheck(sessionID, fingerprint string) error {
	if t == nil {
		return apperr.New(apperr.CodeAuthentication, "session identity table is not configured")
	}
	sid := strings.TrimSpace(sessionID)
	fp := strings.TrimSpace(fingerprint)
	if sid == "" || fp == "" {
		return nil
	}
	if len(sid) > MaxMCPSessionIDBytes {
		return apperr.New(apperr.CodeAuthentication, "mcp session id exceeds length bound")
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if bound, ok := t.entries[sid]; ok {
		if bound != fp {
			return apperr.New(apperr.CodeAuthentication,
				"mcp session identity mismatch; re-authenticate")
		}
		return nil
	}
	// New bind: bound memory.
	if len(t.entries) >= t.max {
		// Evict one arbitrary entry so the process does not grow unbounded.
		// Residual: production sticky sessions + TTL eviction (HOST-001/HOST-004).
		for k := range t.entries {
			delete(t.entries, k)
			break
		}
	}
	t.entries[sid] = fp
	return nil
}

// Len returns the number of bound sessions (tests / diagnostics; non-secret).
func (t *sessionIdentityTable) Len() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// Drop removes a session binding (optional DELETE / logout path; tests).
func (t *sessionIdentityTable) Drop(sessionID string) {
	if t == nil {
		return
	}
	sid := strings.TrimSpace(sessionID)
	if sid == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, sid)
}
