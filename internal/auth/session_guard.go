package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"sync"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// SessionGuard enforces fail-closed tool-path gating when a token is revoked,
// refresh fails, or the bound identity fingerprint changes (OAUTH-006).
//
// It does not store tokens. Call Check before every remote / MCP tool path that
// would use a stale session.
type SessionGuard struct {
	mu          sync.Mutex
	revoked     bool
	refreshFail bool
	// fingerprint is a non-secret hash of binding-critical identity fields.
	fingerprint string
	// disabled forces all Checks to fail (logout).
	disabled bool
}

// NewSessionGuard builds a guard optionally bound to an identity fingerprint.
// Empty fingerprint means identity-change checks are skipped until BindIdentity.
func NewSessionGuard(fingerprint string) *SessionGuard {
	return &SessionGuard{fingerprint: strings.TrimSpace(fingerprint)}
}

// IdentityFingerprint builds a non-secret stable hash of subject + tenant +
// jenkins principal + sorted groups for mid-session change detection.
func IdentityFingerprint(subject, tenant, jenkinsPrincipal string, groups []string) string {
	gs := append([]string(nil), groups...)
	for i := range gs {
		gs[i] = strings.TrimSpace(gs[i])
	}
	sort.Strings(gs)
	raw := strings.Join([]string{
		strings.TrimSpace(subject),
		strings.TrimSpace(tenant),
		strings.TrimSpace(jenkinsPrincipal),
		strings.Join(gs, ","),
	}, "|")
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:16])
}

// BindIdentity sets the expected fingerprint (e.g. after login). Does not clear
// revocation flags.
func (g *SessionGuard) BindIdentity(fingerprint string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.fingerprint = strings.TrimSpace(fingerprint)
}

// MarkRevoked marks the token/session revoked. Subsequent Check fails closed.
func (g *SessionGuard) MarkRevoked() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.revoked = true
}

// MarkRefreshFailed records that token refresh failed. Subsequent Check fails
// closed so a stale access token cannot be used indefinitely.
func (g *SessionGuard) MarkRefreshFailed() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.refreshFail = true
}

// Disable is logout: session cannot be used until a new guard is created.
func (g *SessionGuard) Disable() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.disabled = true
	g.revoked = true
}

// Check returns nil only when the session is still usable for tool paths.
// Nil receiver fails closed.
func (g *SessionGuard) Check() error {
	if g == nil {
		return apperr.New(apperr.CodeAuthentication, "session guard is not configured (fail closed)")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.disabled {
		return apperr.New(apperr.CodeAuthentication, "session is logged out")
	}
	if g.revoked {
		return apperr.New(apperr.CodeAuthentication, "session token is revoked; re-authenticate")
	}
	if g.refreshFail {
		return apperr.New(apperr.CodeAuthentication, "token refresh failed; re-authenticate")
	}
	return nil
}

// CheckIdentity fails closed when the presented fingerprint differs from the
// bound identity (renamed user / swapped subject mid-session).
func (g *SessionGuard) CheckIdentity(fingerprint string) error {
	if err := g.Check(); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	fp := strings.TrimSpace(fingerprint)
	if g.fingerprint == "" {
		// First bind.
		g.fingerprint = fp
		return nil
	}
	if fp != g.fingerprint {
		// Identity change invalidates the session (fail closed).
		g.revoked = true
		return apperr.New(apperr.CodeAuthentication,
			"session identity changed; re-authenticate")
	}
	return nil
}

// Status is a non-secret summary for diagnostics.
func (g *SessionGuard) Status() map[string]any {
	if g == nil {
		return map[string]any{"configured": false, "usable": false}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	usable := !g.disabled && !g.revoked && !g.refreshFail
	return map[string]any{
		"configured":     true,
		"usable":         usable,
		"revoked":        g.revoked,
		"refresh_failed": g.refreshFail,
		"disabled":       g.disabled,
		"has_identity":   g.fingerprint != "",
	}
}
