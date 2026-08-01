package tools

import (
	"context"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

// methodToolsList is the MCP JSON-RPC method for tool discovery (SDK methodListTools).
const methodToolsList = "tools/list"

// InstallListToolsPolicyFilter installs receiving middleware that filters
// tools/list so only tools currently allowed by the live AuthGate, policy
// evaluator, and read-only gate appear (Wave 28 + Wave 29).
//
// Behavior:
//   - AuthGate set and Check() fails ⇒ empty Tools (session death; do not leak names).
//   - Nil AuthGate ⇒ no session-continuity discovery gate (tests / legacy).
//   - Nil Policy ⇒ pass through the registered set (RO gate still filters mutations).
//   - Evaluate deny / fail-closed ⇒ omit tool from ListTools.
//   - Mutation tools are omitted when the gate is effectively read-only (including
//     DynamicForce flips), even if force-registered for tests.
//   - Job-prefix rules use empty Target{} (discovery is not job-scoped).
//
// Dispatch still re-checks AuthGate, policy, and RO (defense in depth). Call once
// after tools are registered; middleware wraps the server handler for the process.
// AuthGate Check errors are not logged here (no secret leak / audit flood on list);
// CallTool and sticky gates already handle fail-closed audit where configured.
func InstallListToolsPolicyFilter(s *mcp.Server, st regState) {
	if s == nil {
		return
	}
	s.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			res, err := next(ctx, method, req)
			if err != nil || method != methodToolsList {
				return res, err
			}
			list, ok := res.(*mcp.ListToolsResult)
			if !ok || list == nil {
				return res, err
			}
			// Wave 29: session continuity fail-closed on discovery. Check once
			// per tools/list (not per tool). Do not surface Check error text.
			if st.authGate != nil {
				if checkErr := st.authGate.Check(); checkErr != nil {
					list.Tools = nil
					return list, nil
				}
			}
			if len(list.Tools) == 0 {
				return list, nil
			}
			filtered := make([]*mcp.Tool, 0, len(list.Tools))
			for _, tool := range list.Tools {
				if tool == nil {
					continue
				}
				// Multi-user: ListTools middleware has request ctx — pass into filter.
				if listToolsAllows(st, ctx, tool.Name) {
					filtered = append(filtered, tool)
				}
			}
			list.Tools = filtered
			return list, nil
		}
	})
}

// listToolsAllows reports whether a registered tool may appear in ListTools
// under the live RO gate and deny-only policy. Fail closed on deny.
// AuthGate is checked once in InstallListToolsPolicyFilter before per-tool filter.
// Multi-user: uses effectiveSubject(st, ctx) when SubjectFromContext is wired.
func listToolsAllows(st regState, ctx context.Context, name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	class := policy.ToolEffect(name)
	// POL-001: mutations stay hidden while the gate is effective RO (live
	// DynamicForce / force_read_only). Production still omits mutations at
	// Register under RO; this also covers RegisterMutationToolsForTest.
	if class == policy.EffectMutate {
		if st.gate == nil || st.gate.Effective() {
			return false
		}
	}
	// Nil policy ⇒ no MCP RBAC discovery filter (registered set, minus RO).
	if st.policy == nil {
		return true
	}
	subj := effectiveSubject(st, ctx)
	d := st.policy.Evaluate(subj, policy.Action{ToolName: name, Class: class}, policy.Target{})
	// Fail closed: any Denied decision (explicit deny, empty subject, etc.) omits.
	return !d.Denied()
}
