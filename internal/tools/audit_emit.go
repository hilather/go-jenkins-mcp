package tools

import (
	"context"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/audit"
	"github.com/simonfxr/go-jenkins-mcp/internal/telemetry"
)

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
