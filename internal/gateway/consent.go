package gateway

import (
	"errors"
	"fmt"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// ConsentInfo carries authorization-code consent metadata for the caller
// without embedding tokens, client secrets, or authorization codes (GWY-001).
//
// Safe for structured status/MCP progressive messages when redacted by callers
// that never attach token fields.
type ConsentInfo struct {
	// AuthorizationURL is the browser/device authorization URL from the AS
	// (Entra / approved AS), never a Jenkins login URL for 3LO.
	AuthorizationURL string

	// SessionID is an opaque consent/session correlation id (non-secret).
	// It must not be an access token, refresh token, or client secret.
	SessionID string

	// Provider is an optional non-secret provider label (e.g. "agentcore").
	Provider string
}

// Valid reports whether consent metadata has the required non-empty fields.
func (c ConsentInfo) Valid() bool {
	return strings.TrimSpace(c.AuthorizationURL) != "" &&
		strings.TrimSpace(c.SessionID) != ""
}

// StatusMap is a non-secret summary for status/doctor/audit.
func (c ConsentInfo) StatusMap() map[string]any {
	return map[string]any{
		"has_authorization_url": strings.TrimSpace(c.AuthorizationURL) != "",
		"has_session_id":        strings.TrimSpace(c.SessionID) != "",
		"provider":              strings.TrimSpace(c.Provider),
	}
}

// String never embeds secrets; URL host only when present.
func (c ConsentInfo) String() string {
	host := ""
	if u := strings.TrimSpace(c.AuthorizationURL); u != "" {
		// Avoid dumping full URL with potential state query in logs by default.
		if i := strings.Index(u, "://"); i >= 0 {
			rest := u[i+3:]
			if j := strings.IndexAny(rest, "/?"); j >= 0 {
				host = rest[:j]
			} else {
				host = rest
			}
		}
	}
	sid := strings.TrimSpace(c.SessionID)
	if len(sid) > 8 {
		sid = sid[:8] + "…"
	}
	return fmt.Sprintf("consent host=%s session=%s", host, sid)
}

// ConsentRequired is returned when interactive authorization-code consent is
// needed. It is an error so fail-closed callers stop, yet exposes only ConsentInfo.
type ConsentRequired struct {
	Info ConsentInfo
}

// Error implements error without tokens or codes.
func (e *ConsentRequired) Error() string {
	if e == nil {
		return "consent required"
	}
	return "consent required: " + e.Info.String()
}

// AsConsentRequired extracts ConsentRequired from err when present.
func AsConsentRequired(err error) (*ConsentRequired, bool) {
	if err == nil {
		return nil, false
	}
	var cr *ConsentRequired
	if errors.As(err, &cr) && cr != nil {
		return cr, true
	}
	return nil, false
}

// NewConsentRequired builds a ConsentRequired error; rejects empty metadata.
func NewConsentRequired(info ConsentInfo) error {
	if !info.Valid() {
		return apperr.New(apperr.CodeInternal, "consent metadata incomplete")
	}
	return &ConsentRequired{Info: info}
}
