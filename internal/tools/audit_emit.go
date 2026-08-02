package tools

import (
	"context"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/audit"
	"github.com/simonfxr/go-jenkins-mcp/internal/telemetry"
)

// EnvAuditToolOK seeds the default for tool_success in audit.DefaultTypeFilter
// when type_filter.json is missing (truthy = 1/true/yes/on). Persistence is
// gated by ReloadingFilterSink / admin audit settings — emit always attempts
// tool_success; disabled types are dropped at the File sink. Metrics
// mcp_tool_ok always record regardless of this env or the type filter.
const EnvAuditToolOK = "JENKINS_MCP_AUDIT_TOOL_OK"

// toolAuditIdentity returns non-secret audit attribution for a tool dispatch
// outcome (tool_ok / tool_deny / tool_error metrics paths that emit audit).
//
// Prefer multi-user effectiveSubject / SubjectKey when wired:
//   - ProfileID / PrincipalID from effective subject (context subject, when
//     SubjectFromContext returns ok, does not fall back to process principal)
//   - ExternalSubject from effective subject when set
//   - SubjectKeyHash = audit.HashOpaque(effectiveSubjectKey) when key is set
//
// Never returns tokens, vault material, or raw oversize subject keys.
func toolAuditIdentity(st regState, ctx context.Context) (profileID, principalID, externalSubject, subjectKeyHash string) {
	profileID = strings.TrimSpace(st.profileID)
	principalID = strings.TrimSpace(st.principalID)

	// Multi-user: when SubjectFromContext is wired and returns ok, attribute
	// exclusively to that subject (even if partial — no process-principal elevate).
	fromCtx := false
	var subj = st.subject
	if st.subjectFromContext != nil && ctx != nil {
		if s, ok := st.subjectFromContext(ctx); ok {
			subj = s
			fromCtx = true
		}
	}
	if pid := strings.TrimSpace(string(subj.ProfileID)); pid != "" {
		profileID = pid
	}
	if fromCtx {
		principalID = strings.TrimSpace(subj.JenkinsUserID)
	} else if j := strings.TrimSpace(subj.JenkinsUserID); j != "" {
		principalID = j
	}
	externalSubject = strings.TrimSpace(subj.ExternalSubject)

	if sk := effectiveSubjectKey(st, ctx); sk != "" {
		// Opaque only — never store raw tenant|subject|profile in audit.
		subjectKeyHash = audit.HashOpaque(sk)
	}
	return profileID, principalID, externalSubject, subjectKeyHash
}

// toolErrorReason returns a stable, secret-free reason code for tool_error audit
// (apperr Code only — never ModelMessage, raw transport, or tokens).
func toolErrorReason(err error) string {
	code := string(apperr.CodeOf(err))
	if code == "" {
		return "error"
	}
	return code
}

// emitToolDeny records a policy/RO denial (AUD-001) and increments mcp_tool_deny
// (OBS-001; MetricPolicyDenials is the same counter). Best-effort: never affects
// the deny decision. Multi-user: attributes ProfileID/PrincipalID/ExternalSubject
// and SubjectKeyHash from effectiveSubject / SubjectKey when available.
func emitToolDeny(ctx context.Context, st regState, toolName, action, reason string, start time.Time) {
	if st.metrics != nil {
		st.metrics.Inc(telemetry.MetricMCPToolDeny, 1)
	}
	profileID, principalID, externalSubject, subjectKeyHash := toolAuditIdentity(st, ctx)
	// Prefer register-time sink; fall back to context-carried sink.
	_ = audit.Emit(ctx, st.audit, audit.Event{
		Time:            time.Now().UTC(),
		Type:            audit.TypeToolDeny,
		ProfileID:       profileID,
		PrincipalID:     principalID,
		ExternalSubject: externalSubject,
		SubjectKeyHash:  subjectKeyHash,
		Tool:            toolName,
		Action:          action,
		Decision:        audit.DecisionDeny,
		ReasonCode:      reason,
		Duration:        time.Since(start),
	})
	// Pilot offline analysis: warn-level structured line (secret-free reason codes only).
	logToolWarn(st, "tool_dispatch_deny",
		"tool", toolName,
		"effect", action,
		"reason", reason,
		"duration_ms", durationMS(start),
	)
}

// emitToolError records a non-deny tool failure (handler / budget / subject
// rate-or-slot limiter) and increments mcp_tool_error (OBS-001). Best-effort:
// never changes the error returned to the host. Multi-user attribution matches
// emitToolDeny via toolAuditIdentity. Reason must be a stable secret-free code
// (prefer toolErrorReason / apperr.CodeOf) — never ModelMessage or tokens.
func emitToolError(ctx context.Context, st regState, toolName, action, reason string, start time.Time) {
	if st.metrics != nil {
		st.metrics.Inc(telemetry.MetricMCPToolError, 1)
	}
	profileID, principalID, externalSubject, subjectKeyHash := toolAuditIdentity(st, ctx)
	_ = audit.Emit(ctx, st.audit, audit.Event{
		Time:            time.Now().UTC(),
		Type:            audit.TypeToolError,
		ProfileID:       profileID,
		PrincipalID:     principalID,
		ExternalSubject: externalSubject,
		SubjectKeyHash:  subjectKeyHash,
		Tool:            toolName,
		Action:          action,
		Decision:        audit.DecisionError,
		ReasonCode:      reason,
		Duration:        time.Since(start),
	})
}

// emitToolOK increments mcp_tool_ok and emits tool_success audit (AUD-001).
// Persistence is controlled by the sink type filter (admin Audit settings /
// type_filter.json; default off for tool_success unless JENKINS_MCP_AUDIT_TOOL_OK
// seeds DefaultTypeFilter). Bare Memory sinks in tests receive every event.
// Multi-user attribution matches deny/error. Best-effort only.
func emitToolOK(ctx context.Context, st regState, toolName, action string, start time.Time) {
	if st.metrics != nil {
		st.metrics.Inc(telemetry.MetricMCPToolOK, 1)
	}
	profileID, principalID, externalSubject, subjectKeyHash := toolAuditIdentity(st, ctx)
	_ = audit.Emit(ctx, st.audit, audit.Event{
		Time:            time.Now().UTC(),
		Type:            audit.TypeToolSuccess,
		ProfileID:       profileID,
		PrincipalID:     principalID,
		ExternalSubject: externalSubject,
		SubjectKeyHash:  subjectKeyHash,
		Tool:            toolName,
		Action:          action,
		Decision:        audit.DecisionSuccess,
		Duration:        time.Since(start),
	})
}
