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
// Log-safe: host + truncated session only (full URL is for progressive MCP UX
// via ConsentAuthorizationURL / mapToolErr, not default Error() dumps).
func (e *ConsentRequired) Error() string {
	if e == nil {
		return "consent required"
	}
	return "consent required: " + e.Info.String()
}

// ConsentAuthorizationURL returns the progressive-consent browser URL (auth URL
// only; never an access token). Used by tools.mapToolErr via duck-typed
// progressiveConsent so tools does not import gateway.
func (e *ConsentRequired) ConsentAuthorizationURL() string {
	if e == nil {
		return ""
	}
	return strings.TrimSpace(e.Info.AuthorizationURL)
}

// ConsentSessionID returns the opaque consent/session correlation id (non-secret).
// Never an access token, refresh token, or client secret.
func (e *ConsentRequired) ConsentSessionID() string {
	if e == nil {
		return ""
	}
	return strings.TrimSpace(e.Info.SessionID)
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

// ProgressiveConsentResidualNote is the secret-free honesty string for Mode C
// progressive consent (OAUTH-010 / GWY-001). Operators/agents may surface it
// via doctor gateway_status, gateway qualify residuals, or
// `jenkins-mcp gateway consent-residual`.
//
// Done*: ConsentRequired → operator/model-visible authorization_url + session_id
// only (tools.mapToolErr / AuthProvider preserve metadata; Error() stays host +
// truncated session); process-local consent metadata store (optional file under
// XDG data for crash recovery of metadata only — never tokens).
// Residual: browser 3LO not automated; multi-replica shared consent correlation
// (HOST-008); AgentCore durable vault (not this process-local metadata store).
const ProgressiveConsentResidualNote = "Mode C progressive consent UX residual (OAUTH-010 / GWY-001): browser 3LO not automated; ConsentRequired metadata path (authorization_url + session_id only) Done*; process-local consent metadata store Done* (optional file; never tokens; not multi-replica shared store); multi-replica consent correlation residual"

// ProgressiveConsentResidual is a secret-free residual snapshot for doctor,
// qualify, and CLI surfaces when Mode C ConsentRequired would apply.
// Never includes tokens, refresh material, client secrets, or auth codes.
// Env-only / static honesty — does not require a live Obtain path.
type ProgressiveConsentResidual struct {
	// Browser3LOAutomated is always false until GWY-003 / OAUTH-010 live pin
	// automates interactive authorization-code UX.
	Browser3LOAutomated bool `json:"browser_3lo_automated"`
	// MetadataPathDoneStar is true when ConsentRequired → auth URL + session_id
	// only is implemented on Obtain / AuthProvider / mapToolErr paths.
	MetadataPathDoneStar bool `json:"metadata_path_done_star"`
	// ProcessLocalConsentMetadataStore is true when process-local (optional
	// file-backed) consent metadata store is implemented (Done*). Metadata only
	// — never tokens. Not multi-replica shared store.
	ProcessLocalConsentMetadataStore bool `json:"process_local_consent_metadata_store"`
	// DurableConsentSessionStore is false: AgentCore / multi-replica durable
	// vault remains residual. Process-local metadata store is a separate Done*.
	DurableConsentSessionStore bool `json:"durable_consent_session_store"`
	// MultiReplicaConsentCorrelation is false (HOST-008 residual).
	MultiReplicaConsentCorrelation bool `json:"multi_replica_consent_correlation"`
	// Surfaces documents allowed progressive fields (no tokens).
	Surfaces string `json:"surfaces"`
	// ResidualNote is the operator-facing residual sentence.
	ResidualNote string `json:"residual_note"`
	// LastConsentWouldApply is always true as a static residual marker:
	// when Obtain returns ConsentRequired, only auth URL + session_id surface
	// and metadata may be remembered in the process-local store.
	LastConsentWouldApply bool `json:"last_consent_would_apply"`
}

// NewProgressiveConsentResidual returns the fixed secret-free residual snapshot.
func NewProgressiveConsentResidual() ProgressiveConsentResidual {
	return ProgressiveConsentResidual{
		Browser3LOAutomated:              false,
		MetadataPathDoneStar:             true,
		ProcessLocalConsentMetadataStore: true,
		DurableConsentSessionStore:       false,
		MultiReplicaConsentCorrelation:   false,
		Surfaces:                         "authorization_url + session_id only; never access_token / refresh_token / client_secret / Authorization headers",
		ResidualNote:                     ProgressiveConsentResidualNote,
		LastConsentWouldApply:            true,
	}
}

// StatusMap is a non-secret map for doctor / admin / JSON CLI.
func (r ProgressiveConsentResidual) StatusMap() map[string]any {
	return map[string]any{
		"browser_3lo_automated":                r.Browser3LOAutomated,
		"metadata_path_done_star":              r.MetadataPathDoneStar,
		"process_local_consent_metadata_store": r.ProcessLocalConsentMetadataStore,
		"durable_consent_session_store":        r.DurableConsentSessionStore,
		"multi_replica_consent_correlation":    r.MultiReplicaConsentCorrelation,
		"surfaces":                             r.Surfaces,
		"residual_note":                        r.ResidualNote,
		"last_consent_would_apply":             r.LastConsentWouldApply,
	}
}
