package tools

import (
	"context"
	"encoding/json"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/simonfxr/go-jenkins-mcp/internal/adminops"
	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

// overlayFromMap decodes a JSON-object map into policy.Overlay (MCP tool args).
// Returns nil overlay and nil error when m is nil/empty (caller treats as missing).
func overlayFromMap(m map[string]any) (*policy.Overlay, error) {
	if m == nil || len(m) == 0 {
		return nil, nil
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, apperr.New(apperr.CodeInvalidArgument, "invalid overlay object")
	}
	var o policy.Overlay
	if err := json.Unmarshal(raw, &o); err != nil {
		return nil, apperr.New(apperr.CodeInvalidArgument, "invalid overlay fields")
	}
	return &o, nil
}

// registerAdminOpsTools attaches admin_* management tools when EnableAdminOps
// and AdminOps service are configured (MCP-OPS-001…004). Default off at serve.
func registerAdminOpsTools(s *mcp.Server, st regState, svc *adminops.Service) {
	if svc == nil {
		return
	}

	// --- reads (MCP-OPS-002) ---
	addAdminTool(s, st, &mcp.Tool{
		Name:        "admin_health",
		Description: "Secret-free process health and gateway residual posture (admin MCP). Never tokens.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, adminops.HealthResult, error) {
		out, err := svc.Health(ctx)
		if err != nil {
			return nil, adminops.HealthResult{}, mapToolErr(err)
		}
		return structuredResult(out)
	})

	addAdminTool(s, st, &mcp.Tool{
		Name:        "admin_version",
		Description: "Secret-free build version metadata for this process.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, adminops.VersionResult, error) {
		out, err := svc.Version(ctx)
		if err != nil {
			return nil, adminops.VersionResult{}, mapToolErr(err)
		}
		return structuredResult(out)
	})

	addAdminTool(s, st, &mcp.Tool{
		Name:        "admin_me",
		Description: "Process admin role and permissions (never returns the admin token value).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, adminops.MeResult, error) {
		out, err := svc.Me(ctx)
		if err != nil {
			return nil, adminops.MeResult{}, mapToolErr(err)
		}
		return structuredResult(out)
	})

	addAdminTool(s, st, &mcp.Tool{
		Name:        "admin_gateway_residual_status",
		Description: "Secret-free gateway residual-status map (same honesty as CLI residual-status).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, map[string]any, error) {
		out, err := svc.ResidualStatus(ctx)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		return structuredResult(out)
	})

	addAdminTool(s, st, &mcp.Tool{
		Name:        "admin_list_profiles",
		Description: "List connection profiles (ids, URLs, auth method, read-only). Never credentials.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, map[string]any, error) {
		list, err := svc.ListProfiles(ctx)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		return structuredResult(map[string]any{"profiles": list})
	})

	type profileIDArgs struct {
		ProfileID string `json:"profile_id,omitempty" jsonschema:"Profile id (default: serve profile)"`
	}

	addAdminTool(s, st, &mcp.Tool{
		Name:        "admin_get_profile",
		Description: "Show one connection profile summary (secret-free).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args profileIDArgs) (*mcp.CallToolResult, adminops.ProfileSummary, error) {
		out, err := svc.GetProfile(ctx, args.ProfileID)
		if err != nil {
			return nil, adminops.ProfileSummary{}, mapToolErr(err)
		}
		return structuredResult(out)
	})

	type policyEffectiveArgs struct {
		ProfileID      string `json:"profile_id,omitempty" jsonschema:"Profile id"`
		ReadOnly       bool   `json:"read_only,omitempty" jsonschema:"Simulate --read-only"`
		AllowMutations bool   `json:"allow_mutations,omitempty" jsonschema:"Simulate --allow-mutations"`
	}

	addAdminTool(s, st, &mcp.Tool{
		Name:        "admin_policy_effective",
		Description: "Show effective MCP policy for a profile (secret-free; never signature bytes).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args policyEffectiveArgs) (*mcp.CallToolResult, any, error) {
		out, err := svc.PolicyEffective(ctx, args.ProfileID, args.ReadOnly, args.AllowMutations)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		return structuredResult(out)
	})

	addAdminTool(s, st, &mcp.Tool{
		Name:        "admin_policy_overlay_get",
		Description: "Get plain policy overlay when present (signed-bundle edit residual).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, map[string]any, error) {
		out, err := svc.PolicyOverlayGet(ctx)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		return structuredResult(out)
	})

	addAdminTool(s, st, &mcp.Tool{
		Name:        "admin_metrics",
		Description: "Process-local metrics snapshot (counters/gauges only).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, adminops.MetricsResult, error) {
		out, err := svc.Metrics(ctx)
		if err != nil {
			return nil, adminops.MetricsResult{}, mapToolErr(err)
		}
		return structuredResult(out)
	})

	type auditListArgs struct {
		ProfileID       string `json:"profile_id,omitempty" jsonschema:"Profile id"`
		Limit           int    `json:"limit,omitempty" jsonschema:"Max events (1-200)"`
		Type            string `json:"type,omitempty" jsonschema:"Exact event type filter"`
		Before          string `json:"before,omitempty" jsonschema:"RFC3339 exclusive upper bound"`
		ExternalSubject string `json:"external_subject,omitempty" jsonschema:"Exact IdP subject label (never a token)"`
	}

	addAdminTool(s, st, &mcp.Tool{
		Name:        "admin_audit_list",
		Description: "List privacy-preserving audit events for a profile (same-host JSONL merge).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args auditListArgs) (*mcp.CallToolResult, adminops.AuditListResult, error) {
		out, err := svc.AuditList(ctx, args.ProfileID, args.Limit, args.Type, args.Before, args.ExternalSubject)
		if err != nil {
			return nil, adminops.AuditListResult{}, mapToolErr(err)
		}
		return structuredResult(out)
	})

	addAdminTool(s, st, &mcp.Tool{
		Name:        "admin_audit_settings_get",
		Description: "Get audit event-type catalog and enable/disable map for a profile.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args profileIDArgs) (*mcp.CallToolResult, adminops.AuditSettingsResult, error) {
		out, err := svc.AuditSettingsGet(ctx, args.ProfileID)
		if err != nil {
			return nil, adminops.AuditSettingsResult{}, mapToolErr(err)
		}
		return structuredResult(out)
	})

	type doctorArgs struct {
		ProfileID string `json:"profile_id,omitempty" jsonschema:"Profile id"`
		Offline   bool   `json:"offline,omitempty" jsonschema:"Skip network identity (default true for safety when omitted use true via offline=true)"`
	}

	addAdminTool(s, st, &mcp.Tool{
		Name:        "admin_doctor",
		Description: "Run doctor diagnostics for a profile (prefer offline=true). Secret-free.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args doctorArgs) (*mcp.CallToolResult, any, error) {
		// Default offline true when not explicitly false is hard in JSON;
		// document offline=true for safety. Call with Offline field.
		offline := args.Offline
		// If client omitted, Offline is false — still default to offline for admin MCP safety.
		// Callers that want online set a future online flag residual; for now force offline.
		_ = offline
		out, err := svc.Doctor(ctx, args.ProfileID, true)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		return structuredResult(out)
	})

	addAdminTool(s, st, &mcp.Tool{
		Name:        "admin_security_selfcheck",
		Description: "Offline security self-check report for a profile (canaries; secret-free).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args profileIDArgs) (*mcp.CallToolResult, any, error) {
		out, err := svc.SecuritySelfCheck(ctx, args.ProfileID)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		return structuredResult(out)
	})

	addAdminTool(s, st, &mcp.Tool{
		Name:        "admin_cache_status",
		Description: "L1 cache / data-dir status for a profile (secret-free).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args profileIDArgs) (*mcp.CallToolResult, any, error) {
		out, err := svc.CacheStatus(ctx, args.ProfileID)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		return structuredResult(out)
	})

	addAdminTool(s, st, &mcp.Tool{
		Name:        "admin_gateway_vault_status",
		Description: "Mode A vault inventory honesty (subject key hashes only; never tokens).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, map[string]any, error) {
		out, err := svc.VaultStatus(ctx)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		return structuredResult(out)
	})

	// --- writes (MCP-OPS-003) ---
	type auditSettingsPutArgs struct {
		ProfileID string          `json:"profile_id,omitempty" jsonschema:"Profile id"`
		Enabled   map[string]bool `json:"enabled" jsonschema:"Map of known audit types to enabled"`
	}
	addAdminTool(s, st, &mcp.Tool{
		Name:        "admin_audit_settings_put",
		Description: "Enable/disable audit event types (gateway_ops). Partial map merges; unknown keys ignored.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args auditSettingsPutArgs) (*mcp.CallToolResult, adminops.AuditSettingsResult, error) {
		out, err := svc.AuditSettingsPut(ctx, args.ProfileID, args.Enabled)
		if err != nil {
			return nil, adminops.AuditSettingsResult{}, mapToolErr(err)
		}
		return structuredResult(out)
	})

	type cachePlanArgs struct {
		ProfileID   string `json:"profile_id,omitempty" jsonschema:"Profile id"`
		TargetBytes int64  `json:"target_bytes,omitempty" jsonschema:"Target reclaim bytes (0=default)"`
	}
	addAdminTool(s, st, &mcp.Tool{
		Name:        "admin_cache_evict_plan",
		Description: "Non-destructive cache eviction plan for a profile.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args cachePlanArgs) (*mcp.CallToolResult, map[string]any, error) {
		out, err := svc.CacheEvictPlan(ctx, args.ProfileID, args.TargetBytes)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		return structuredResult(out)
	})

	type cacheEvictArgs struct {
		ProfileID   string `json:"profile_id,omitempty" jsonschema:"Profile id"`
		TargetBytes int64  `json:"target_bytes,omitempty" jsonschema:"Target reclaim bytes"`
		Confirm     string `json:"confirm" jsonschema:"Must be exactly EVICT"`
	}
	addAdminTool(s, st, &mcp.Tool{
		Name:        "admin_cache_evict",
		Description: "Destructive cache eviction (operator). Requires confirm=EVICT.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args cacheEvictArgs) (*mcp.CallToolResult, map[string]any, error) {
		out, err := svc.CacheEvict(ctx, args.ProfileID, args.TargetBytes, args.Confirm)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		return structuredResult(out)
	})

	type supportBundleArgs struct {
		ProfileID string `json:"profile_id,omitempty" jsonschema:"Profile id"`
		Preview   bool   `json:"preview,omitempty" jsonschema:"When true, plan only (no write)"`
	}
	addAdminTool(s, st, &mcp.Tool{
		Name:        "admin_support_bundle",
		Description: "Create or preview a secret-free support bundle (operator).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args supportBundleArgs) (*mcp.CallToolResult, map[string]any, error) {
		out, err := svc.SupportBundle(ctx, args.ProfileID, args.Preview)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		return structuredResult(out)
	})

	type subjectInvalidateArgs struct {
		SubjectKey string `json:"subject_key,omitempty" jsonschema:"Stable subject key tenant|subject|profile"`
		Tenant     string `json:"tenant,omitempty" jsonschema:"Tenant when composing key"`
		SubjectID  string `json:"subject_id,omitempty" jsonschema:"Subject id when composing key"`
		Profile    string `json:"profile,omitempty" jsonschema:"Profile when composing key"`
		Confirm    string `json:"confirm" jsonschema:"Non-empty confirm (e.g. INVALIDATE)"`
	}
	addAdminTool(s, st, &mcp.Tool{
		Name:        "admin_subject_invalidate",
		Description: "Force re-auth residual: clear process principal cache for a subject (gateway_ops). Confirm required.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args subjectInvalidateArgs) (*mcp.CallToolResult, map[string]any, error) {
		out, err := svc.SubjectInvalidate(ctx, args.SubjectKey, args.Tenant, args.SubjectID, args.Profile, args.Confirm)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		return structuredResult(out)
	})

	type consentPurgeArgs struct {
		Action    string `json:"action" jsonschema:"expire|clear_all|session"`
		SessionID string `json:"session_id,omitempty" jsonschema:"Required when action=session"`
		Confirm   string `json:"confirm,omitempty" jsonschema:"Required CLEAR_ALL when action=clear_all"`
	}
	addAdminTool(s, st, &mcp.Tool{
		Name:        "admin_consent_purge",
		Description: "Purge progressive consent metadata (gateway_ops). clear_all requires confirm=CLEAR_ALL.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args consentPurgeArgs) (*mcp.CallToolResult, map[string]any, error) {
		out, err := svc.ConsentPurge(ctx, args.Action, args.SessionID, args.Confirm)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		return structuredResult(out)
	})

	type policyValidateArgs struct {
		ProfileID string         `json:"profile_id,omitempty" jsonschema:"Profile id for audit correlation"`
		Overlay   map[string]any `json:"overlay,omitempty" jsonschema:"Draft overlay object (version, force_read_only, deny_tools, ...)"`
	}
	// Overlay args arrive as a generic map from MCP JSON; decode to policy.Overlay.
	addAdminTool(s, st, &mcp.Tool{
		Name:        "admin_policy_validate",
		Description: "Dry-run validate a policy overlay draft (policy_write). Does not write.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args policyValidateArgs) (*mcp.CallToolResult, map[string]any, error) {
		ov, err := overlayFromMap(args.Overlay)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		out, err := svc.PolicyValidate(ctx, ov, args.ProfileID)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		return structuredResult(out)
	})

	type policyApplyArgs struct {
		ProfileID string         `json:"profile_id,omitempty" jsonschema:"Profile id"`
		Overlay   map[string]any `json:"overlay,omitempty" jsonschema:"Draft overlay"`
		Confirm   string         `json:"confirm" jsonschema:"Must be APPLY"`
	}
	addAdminTool(s, st, &mcp.Tool{
		Name:        "admin_policy_apply",
		Description: "Apply policy overlay (policy_write). Requires confirm=APPLY. Signed-bundle durable write residual.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args policyApplyArgs) (*mcp.CallToolResult, map[string]any, error) {
		ov, err := overlayFromMap(args.Overlay)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		out, err := svc.PolicyApply(ctx, ov, args.ProfileID, args.Confirm)
		if err != nil {
			return nil, nil, mapToolErr(err)
		}
		return structuredResult(out)
	})
}

// addAdminTool registers an admin_* tool as EffectRead (management, not Jenkins
// mutation). Fail-closed via adminops role gates inside handlers.
func addAdminTool[In, Out any](
	s *mcp.Server,
	st regState,
	t *mcp.Tool,
	h func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, Out, error),
) {
	addTool(s, st, t, policy.EffectRead, h)
}
