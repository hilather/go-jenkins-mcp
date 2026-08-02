package fleetcache

import (
	"context"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Admin facade helpers for FLC-063 (BFF + admin MCP parity).
// Pure/secret-free maps only — role gates live in admin / adminops.

// AdminSPAResidual documents SPA residual honesty when BFF+MCP land first.
const AdminSPAResidual = "SPA page residual; BFF+MCP Done* (FLC-063)"

// AdminDrainResidual documents that drain trigger is not exposed on this surface.
const AdminDrainResidual = "drain_trigger residual; status drain_active only; multi-member drain not via this API"

// AdminRepairResidual documents that repair trigger is not exposed on this surface.
const AdminRepairResidual = "repair_trigger residual; use library/CLI residual; not via this admin surface"

// AdminPurgeHTTPResidual documents multi-member HTTP peer purge residual.
const AdminPurgeHTTPResidual = "no_http_peer_purge_prop; process_local_tombstones only"

// StatusSnapshot builds the secret-free operator status map used by BFF/MCP.
// When members/opts are zero, returns default-off process-local honesty.
func StatusSnapshot(cfg Config, metrics *FleetCacheMetrics, members []MemberCacheView, opts StatusOptions) map[string]any {
	st := BuildFleetCacheStatus(cfg, metrics, members, opts)
	return StatusMap(st, cfg)
}

// StatusMap nests FleetCacheStatus with config budgets and SPA residual honesty.
func StatusMap(st FleetCacheStatus, cfg Config) map[string]any {
	mode := cfg.Mode
	if mode == "" {
		mode = ModeOff
	}
	m := st.Map()
	// Surface budgets for operator parity with Config.StatusSummary.
	m["peer_lookup_timeout"] = cfg.PeerLookupTimeout.String()
	m["max_peer_streams"] = cfg.MaxPeerStreams
	m["max_peer_lookups"] = cfg.MaxPeerLookups
	m["origin_fallback"] = cfg.OriginFallback
	m["spa_residual"] = AdminSPAResidual
	m["drain_residual"] = AdminDrainResidual
	m["repair_residual"] = AdminRepairResidual
	if mode == ModeOff || !cfg.Active() {
		m["mode_default_off"] = true
	}
	return m
}

// DoctorChecksMaps returns secret-free doctor check maps for BFF/MCP JSON.
func DoctorChecksMaps(cfg Config, st FleetCacheStatus) []map[string]any {
	checks := DoctorFleetCache(cfg, st)
	out := make([]map[string]any, 0, len(checks)+2)
	for _, c := range checks {
		row := map[string]any{
			"name": c.Name,
			"ok":   c.OK,
		}
		if c.Residual != "" {
			row["residual"] = c.Residual
		}
		out = append(out, row)
	}
	// Honesty checks for surfaces not yet operator-triggered via admin.
	out = append(out, map[string]any{
		"name":     "admin_spa",
		"ok":       true,
		"residual": AdminSPAResidual,
	})
	out = append(out, map[string]any{
		"name":     "admin_drain_repair",
		"ok":       true,
		"residual": AdminDrainResidual + "; " + AdminRepairResidual,
	})
	return out
}

// DoctorSnapshot is the full doctor response envelope (secret-free).
func DoctorSnapshot(cfg Config, metrics *FleetCacheMetrics, members []MemberCacheView, opts StatusOptions) map[string]any {
	st := BuildFleetCacheStatus(cfg, metrics, members, opts)
	return map[string]any{
		"status":   StatusMap(st, cfg),
		"checks":   DoctorChecksMaps(cfg, st),
		"residual": "process-local aggregation; multi-member fan-out residual; mode default off",
	}
}

// PurgeResultMap is the secret-free JSON shape for purge outcomes (BFF/MCP parity).
func PurgeResultMap(res PurgeResult, plan PurgePlan) map[string]any {
	m := map[string]any{
		"status":         res.Status,
		"locator_hash":   res.LocatorHash,
		"confirm_token":  PurgeConfirmToken, // name of required confirm, not a secret
		"tombstone_put":  res.TombstonePut,
		"truncated":      plan.Truncated,
		"max_owners":     DefaultMaxPurgeOwners,
		"http_peer_prop": false,
		"purge_residual": AdminPurgeHTTPResidual,
		"spa_residual":   AdminSPAResidual,
	}
	if res.ManifestDigest != "" {
		m["manifest_digest"] = res.ManifestDigest
	}
	if len(res.PurgedMembers) > 0 {
		m["purged_members"] = append([]string(nil), res.PurgedMembers...)
	}
	if len(res.ResidualMembers) > 0 {
		m["residual_members"] = append([]string(nil), res.ResidualMembers...)
	}
	if res.Residual != "" {
		m["residual"] = res.Residual
	} else if plan.Residual != "" {
		m["residual"] = plan.Residual
	}
	if len(plan.Targets) > 0 {
		m["planned_targets"] = append([]string(nil), plan.Targets...)
	}
	return m
}

// NopPurgeSink is an idempotent empty PurgeSink for process-local tombstone-only purge
// when no durable fleet object mapping is wired into the admin process.
type NopPurgeSink struct{}

// GetCommitted always returns ok=false.
func (NopPurgeSink) GetCommitted(_ context.Context, _ string) (CommittedMapping, bool, error) {
	return CommittedMapping{}, false, nil
}

// DeleteCommitted is a no-op success (idempotent absent mapping).
func (NopPurgeSink) DeleteCommitted(_ context.Context, _, _ string) error {
	return nil
}

// AdminPurgeOptions configures the shared admin purge path (FLC-063).
type AdminPurgeOptions struct {
	// Role is the console role string (operator|policy_admin). Viewer must be
	// rejected by the caller before calling AdminPurge.
	Role string
	// Confirm must equal PurgeConfirmToken ("PURGE").
	Confirm string
	// LocatorHash required (64-hex preferred; library lowercases/trims).
	LocatorHash string
	// ManifestDigest optional version scope.
	ManifestDigest string
	// MaxOwners optional bound (0 → default).
	MaxOwners int
	// TargetMemberIDs optional owner filter.
	TargetMemberIDs []string
	// Reason secret-free operator note (scrubbed).
	Reason string
	// Owners planned owner list for PlanPurge (may be empty → local-only).
	Owners []string
	// Sink optional; nil → NopPurgeSink (tombstone-only honesty).
	Sink PurgeSink
	// Tombstones optional; nil → process ActiveTombstones or ephemeral memory.
	Tombstones TombstoneStore
	// Now optional clock (zero → UTC now).
	Now time.Time
	// LocalOnly when true applies ApplyPurgeLocal only (ignores multi-owner sinks).
	// Default true for admin BFF/MCP (no HTTP peer fan-out).
	LocalOnly bool
}

// AdminPurge validates role+confirm, plans a bounded purge, applies local sink +
// tombstone, and returns a secret-free result map. Never touches Jenkins.
// Multi-member HTTP peer purge remains residual (AdminPurgeHTTPResidual).
func AdminPurge(ctx context.Context, opts AdminPurgeOptions) (map[string]any, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	role := strings.ToLower(strings.TrimSpace(opts.Role))
	// Map console role strings onto purge library roles.
	switch role {
	case PurgeRoleOperator, PurgeRolePolicyAdmin:
		// ok
	case "viewer", "":
		return nil, apperr.New(apperr.CodeAuthorization, "fleet-cache purge requires operator or policy_admin")
	default:
		// Unknown role fail closed.
		return nil, apperr.New(apperr.CodeAuthorization, "fleet-cache purge requires operator or policy_admin")
	}
	if strings.TrimSpace(opts.Confirm) != PurgeConfirmToken {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			`fleet-cache purge requires confirm exactly "PURGE"`)
	}

	req := PurgeRequest{
		LocatorHash:     opts.LocatorHash,
		ManifestDigest:  opts.ManifestDigest,
		OperatorRole:    role,
		Confirm:         PurgeConfirmToken,
		MaxOwners:       opts.MaxOwners,
		TargetMemberIDs: opts.TargetMemberIDs,
		Reason:          opts.Reason,
	}
	plan, err := PlanPurge(req, opts.Owners)
	if err != nil && plan.Action == PurgeActionDeny {
		return PurgeResultMap(PurgeResult{
			Status:         PurgeStatusDenied,
			LocatorHash:    plan.LocatorHash,
			ManifestDigest: plan.ManifestDigest,
			Residual:       plan.Residual,
		}, plan), err
	}

	sink := opts.Sink
	if sink == nil {
		sink = NopPurgeSink{}
	}
	ts := opts.Tombstones
	if ts == nil {
		if ActiveTombstones != nil {
			ts = ActiveTombstones
		} else {
			ts = NewMemoryTombstoneStore()
		}
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	// Admin surface is process-local only (no HTTP peer prop).
	res, applyErr := ApplyPurgeLocal(ctx, sink, req, ts, now)
	// Enrich residual honesty for multi-member residual.
	if res.Residual == "" || res.Residual == PurgeResidualIdempotent || res.Residual == PurgeResidualNoOwners {
		// Keep library residual; always surface HTTP residual in map.
	}
	out := PurgeResultMap(res, plan)
	if applyErr != nil && res.Status == PurgeStatusDenied {
		return out, applyErr
	}
	// Non-deny apply errors still return partial honesty map.
	if applyErr != nil {
		out["error"] = "apply_failed"
		return out, applyErr
	}
	return out, nil
}
