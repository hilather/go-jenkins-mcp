package audit

import (
	"time"
)

// Stable event types (low cardinality).
const (
	TypeLoginSuccess = "login_success"
	TypeLoginFail    = "login_fail"
	TypeServeStart   = "serve_start"
	TypeToolDeny     = "tool_deny"
	TypeToolError    = "tool_error"   // handler/budget/subject-limiter failure (non-deny)
	TypeToolSuccess  = "tool_success" // optional summary; off by default (JENKINS_MCP_AUDIT_TOOL_OK)
	TypeAuthFail     = "auth_fail"    // serve-time identity / credential failures
)

// Decision outcomes recorded on events (not Jenkins grants).
const (
	DecisionAllow   = "allow"
	DecisionDeny    = "deny"
	DecisionSuccess = "success"
	DecisionFail    = "fail"
	DecisionError   = "error"
)

// Event is a privacy-preserving audit record (AUD-001).
//
// Never put tokens, passwords, Authorization headers, full job parameters,
// prompts, log excerpts, or artifact bytes into any string field.
type Event struct {
	// Time is when the event occurred (UTC preferred).
	Time time.Time `json:"time"`
	// Type is a stable event class (see Type* constants).
	Type string `json:"type"`
	// ProfileID is the non-secret connection profile id (may be empty for legacy).
	ProfileID string `json:"profileId,omitempty"`
	// PrincipalID is a verified Jenkins user id or opaque hash — never a token.
	PrincipalID string `json:"principalId,omitempty"`
	// ExternalSubject is an optional validated IdP subject label (OAuth/gateway).
	// Never a token or vault material; redacted and length-capped like PrincipalID.
	// Empty for API-token / stdio single-user residual.
	ExternalSubject string `json:"externalSubject,omitempty"`
	// SubjectKeyHash is an optional opaque hash of the multi-user subject key
	// (tenant|subject|profile) for cross-event correlation without storing the
	// raw key. Prefer audit.HashOpaque(subjectKey); never tokens or vault bytes.
	// Multi-pod fleet aggregation of per-process audit files remains residual.
	SubjectKeyHash string `json:"subjectKeyHash,omitempty"`
	// Tool is the MCP tool name when applicable.
	Tool string `json:"tool,omitempty"`
	// Action is a short verb/class (e.g. read, mutate, login, serve).
	Action string `json:"action,omitempty"`
	// Decision is allow/deny/success/fail/error.
	Decision string `json:"decision,omitempty"`
	// ReasonCode is a stable, non-secret machine code (policy reason, auth code).
	ReasonCode string `json:"reasonCode,omitempty"`
	// Duration is wall time for the operation when known.
	Duration time.Duration `json:"-"`
	// DurationMs is Duration serialized as whole milliseconds.
	DurationMs int64 `json:"durationMs,omitempty"`
	// BytesIn / BytesOut are optional wire or MCP payload sizes (not content).
	BytesIn  *int64 `json:"bytesIn,omitempty"`
	BytesOut *int64 `json:"bytesOut,omitempty"`
	// RequestID correlates related local events (opaque).
	RequestID string `json:"requestId,omitempty"`
	// TargetHash is an optional opaque hash of a high-cardinality target
	// (e.g. job full name). Never store the raw high-cardinality string by default.
	TargetHash string `json:"targetHash,omitempty"`
	// SchemaVersion is the event schema generation (stable for consumers).
	SchemaVersion int `json:"schemaVersion"`
}

// CurrentSchemaVersion is written on every event.
const CurrentSchemaVersion = 1

// Normalize fills schema version, UTC time, and DurationMs from Duration.
// String fields are sanitized (redacted + length-capped).
func (e Event) Normalize() Event {
	if e.SchemaVersion == 0 {
		e.SchemaVersion = CurrentSchemaVersion
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	} else {
		e.Time = e.Time.UTC()
	}
	if e.Duration != 0 && e.DurationMs == 0 {
		e.DurationMs = e.Duration.Milliseconds()
	}
	return sanitizeEvent(e)
}
