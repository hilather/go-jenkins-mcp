package tools

import (
	"context"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/audit"
	"github.com/simonfxr/go-jenkins-mcp/internal/telemetry"
)

// emitToolDeny records a policy/RO denial (AUD-001) and increments mcp_tool_deny
// (OBS-001; MetricPolicyDenials is the same counter). Best-effort: never affects
// the deny decision.
func emitToolDeny(ctx context.Context, st regState, toolName, action, reason string, start time.Time) {
	if st.metrics != nil {
		st.metrics.Inc(telemetry.MetricMCPToolDeny, 1)
	}
	// Prefer register-time sink; fall back to context-carried sink.
	_ = audit.Emit(ctx, st.audit, audit.Event{
		Time:        time.Now().UTC(),
		Type:        audit.TypeToolDeny,
		ProfileID:   st.profileID,
		PrincipalID: st.principalID,
		Tool:        toolName,
		Action:      action,
		Decision:    audit.DecisionDeny,
		ReasonCode:  reason,
		Duration:    time.Since(start),
	})
	// Pilot offline analysis: warn-level structured line (secret-free reason codes only).
	logToolWarn(st, "tool_dispatch_deny",
		"tool", toolName,
		"effect", action,
		"reason", reason,
		"duration_ms", durationMS(start),
	)
}
