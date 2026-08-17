package adminops

import (
	"context"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/audit"
	"github.com/hilather/go-jenkins-mcp/internal/cachecontrol"
)

// CacheControl returns the shared control-plane service when wired (ADR 0018).
// Nil is valid: typed inventory tools return capability_missing until serve wires it.
func (s *Service) CacheControl() *cachecontrol.Service {
	if s == nil {
		return nil
	}
	return s.cfg.CacheControl
}

// CacheInventory lists registered cache types with effective modes (viewer+).
// Secret-free. When CacheControl is nil, returns a process-default inventory
// from the static registry (no overrides) so tools remain discoverable.
func (s *Service) CacheInventory(ctx context.Context) (map[string]any, error) {
	if err := RequirePermission(s.Role(), PermRead); err != nil {
		return nil, err
	}
	svc := s.ensureCacheControl()
	inv := svc.Inventory(ctx)
	items := make([]map[string]any, 0, len(inv))
	for _, it := range inv {
		items = append(items, map[string]any{
			"typeId":             string(it.Descriptor.TypeID),
			"displayName":        it.Descriptor.DisplayName,
			"storageClass":       string(it.Descriptor.StorageClass),
			"implementation":     it.Descriptor.Implementation,
			"availability":       string(it.Descriptor.Availability),
			"availabilityReason": it.Descriptor.AvailabilityReason,
			"mode":               string(it.Mode),
			"modeSource":         it.ModeSource,
			"fleetShare":         it.FleetShare,
			"configRevision":     it.ConfigRevision,
			"purgeEpoch":         it.PurgeEpoch,
			"supportsList":       it.Descriptor.SupportsList,
			"supportsPurge":      it.Descriptor.SupportsPurge,
			"sizeAccounting":     string(it.Descriptor.SizeAccounting),
		})
	}
	eff := svc.Effective()
	return map[string]any{
		"types":            items,
		"revision":         eff.Revision,
		"globalEnabled":    eff.Global.Enabled,
		"allowRawDump":     eff.Global.AllowRawDump,
		"runtimeOverrides": eff.Global.RuntimeOverridesEnabled,
		"compatibility":    "admin_cache_status / admin_cache_evict* remain log-store surfaces",
	}, nil
}

// CacheEffectiveConfig returns the effective config snapshot (viewer+), secret-free.
func (s *Service) CacheEffectiveConfig(ctx context.Context, typeID string) (map[string]any, error) {
	if err := RequirePermission(s.Role(), PermRead); err != nil {
		return nil, err
	}
	_ = ctx
	svc := s.ensureCacheControl()
	eff := svc.Effective()
	out := map[string]any{
		"revision": eff.Revision,
		"loadedAt": eff.LoadedAt.UTC().Format("2006-01-02T15:04:05Z"),
		"global": map[string]any{
			"enabled":                 eff.Global.Enabled,
			"runtimeOverridesEnabled": eff.Global.RuntimeOverridesEnabled,
			"telemetryEnabled":        eff.Global.TelemetryEnabled,
			"allowRawDump":            eff.Global.AllowRawDump,
			"maxTotalBytes":           eff.Global.MaxTotalBytes,
		},
	}
	typeID = strings.TrimSpace(typeID)
	if typeID == "" {
		types := map[string]any{}
		for id, tc := range eff.Types {
			types[string(id)] = effectiveTypeMap(tc)
		}
		out["types"] = types
		return out, nil
	}
	id := cachecontrol.TypeID(typeID)
	tc, ok := eff.TypeConfig(id)
	if !ok {
		return nil, apperr.New(apperr.CodeInvalidArgument, "unknown cache type")
	}
	out["type"] = effectiveTypeMap(tc)
	// Field provenance for mode when present
	if fs, ok := eff.SourceDetails["types."+typeID+".mode"]; ok {
		out["modeProvenance"] = map[string]any{
			"value":   fs.Value,
			"source":  string(fs.Source),
			"mutable": fs.Mutable,
		}
	}
	return out, nil
}

func effectiveTypeMap(tc cachecontrol.EffectiveTypeConfig) map[string]any {
	return map[string]any{
		"typeId":           string(tc.TypeID),
		"mode":             string(tc.Mode),
		"modeSource":       string(tc.ModeSource),
		"telemetryEnabled": tc.TelemetryEnabled,
		"softBytes":        tc.SoftBytes,
		"hardBytes":        tc.HardBytes,
		"fleetShare":       tc.FleetShare,
		"purgeEpoch":       tc.PurgeEpoch,
		"configRevision":   tc.ConfigRevision,
		"l0MaxEntries":     tc.L0MaxEntries,
	}
}

// CachePatchModeArgs is a minimal mode patch (operator).
type CachePatchModeArgs struct {
	ProfileID        string
	TypeID           string
	Mode             string
	ExpectedRevision uint64
	Reason           string
	Confirm          string // optional; not required for mode patch
}

// classifyCachePatchError maps cachecontrol Patch failures (stable Reason*
// prefixes) to typed apperr codes + audit reasons.
func classifyCachePatchError(err error) (code apperr.Code, reason string) {
	msg := err.Error()
	for _, r := range []string{
		cachecontrol.ReasonRuntimeMutationsOff,
		cachecontrol.ReasonCASConflict,
		cachecontrol.ReasonUnknownType,
		cachecontrol.ReasonUnknownField,
		cachecontrol.ReasonUnsupportedMode,
		cachecontrol.ReasonUnqualified,
		cachecontrol.ReasonConstraintViolation,
	} {
		if strings.HasPrefix(msg, r) {
			reason = r
			break
		}
	}
	switch reason {
	case cachecontrol.ReasonRuntimeMutationsOff:
		return apperr.CodePolicyDenial, reason
	case "":
		return apperr.CodeInternal, "patch_failed"
	default:
		return apperr.CodeInvalidArgument, reason
	}
}

// decisionForReason audits "deny" only for policy-gate rejections.
func decisionForReason(reason string) string {
	if reason == cachecontrol.ReasonRuntimeMutationsOff {
		return audit.DecisionDeny
	}
	return audit.DecisionFail
}

// CachePatchMode applies a single-type mode override (operator, CAS).
func (s *Service) CachePatchMode(ctx context.Context, args CachePatchModeArgs) (map[string]any, error) {
	if err := RequirePermission(s.Role(), PermCacheDestructive); err != nil {
		return nil, err
	}
	svc := s.cfg.CacheControl
	if svc == nil || s.cfg.CacheControlStore == nil {
		return nil, apperr.New(apperr.CodeCapabilityMissing, "cache control override store not configured")
	}
	m, err := cachecontrol.ParseMode(args.Mode)
	if err != nil {
		return nil, apperr.New(apperr.CodeInvalidArgument, "invalid mode")
	}
	id := cachecontrol.TypeID(strings.TrimSpace(args.TypeID))
	if !id.Valid() {
		return nil, apperr.New(apperr.CodeInvalidArgument, "unknown cache type")
	}
	res, err := svc.Patch(ctx, cachecontrol.PatchRequest{
		ProfileID:        firstNonEmptyStr(args.ProfileID, s.cfg.DefaultProfileID),
		ExpectedRevision: args.ExpectedRevision,
		Reason:           strings.TrimSpace(args.Reason),
		ActorIDHash:      "admin_mcp",
		Source:           "admin_mcp",
		Types: map[cachecontrol.TypeID]cachecontrol.TypeConfig{
			id: {Mode: &m},
		},
	})
	if err != nil {
		// Preserve the typed failure reason (CAS conflict / runtime mutations
		// disabled / unqualified type) instead of erasing it into a generic
		// invalid_argument, and audit the real decision: "deny" only for the
		// policy gate, "fail" for operational failures.
		code, reason := classifyCachePatchError(err)
		s.emitWriteAudit(s.profileID(args.ProfileID), audit.TypeAdminCacheEvict, "cache_mode_patch", decisionForReason(reason), reason)
		return nil, apperr.New(code, "cache mode patch rejected: "+reason)
	}
	s.emitWriteAudit(s.profileID(args.ProfileID), audit.TypeAdminCacheEvict, "cache_mode_patch", "allow", "admin_mcp")
	return map[string]any{
		"revision": res.Revision,
		"typeId":   string(id),
		"mode":     string(m),
		"note":     "mode change does not purge data",
	}, nil
}

// CachePlanOpArgs plans a lifecycle operation.
type CachePlanOpArgs struct {
	TypeID   string
	Kind     string // dump|purge|verify|repair|gc
	DumpMode string
	Reason   string
}

// CachePlanOp returns a plan with confirm token (operator for destructive kinds).
func (s *Service) CachePlanOp(ctx context.Context, args CachePlanOpArgs) (map[string]any, error) {
	// Viewer may plan verify; destructive needs operator
	kind := cachecontrol.OperationKind(strings.TrimSpace(args.Kind))
	switch kind {
	case cachecontrol.OpPurge, cachecontrol.OpRepair, cachecontrol.OpGC, cachecontrol.OpDump:
		if err := RequirePermission(s.Role(), PermCacheDestructive); err != nil {
			return nil, err
		}
	default:
		if err := RequirePermission(s.Role(), PermRead); err != nil {
			return nil, err
		}
	}
	svc := s.ensureCacheControl()
	id := cachecontrol.TypeID(strings.TrimSpace(args.TypeID))
	if !id.Valid() {
		return nil, apperr.New(apperr.CodeInvalidArgument, "unknown cache type")
	}
	req := cachecontrol.OperationRequest{
		Kind:   kind,
		TypeID: id,
		Reason: strings.TrimSpace(args.Reason),
	}
	if kind == cachecontrol.OpDump {
		dm := cachecontrol.DumpMode(strings.TrimSpace(args.DumpMode))
		if dm == "" {
			dm = cachecontrol.DumpMetadata
		}
		if !dm.Valid() {
			return nil, apperr.New(apperr.CodeInvalidArgument, "invalid dump mode")
		}
		req.DumpMode = dm
	}
	plan, err := svc.PlanOperation(ctx, req)
	if err != nil {
		return nil, apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	return map[string]any{
		"planId":         plan.PlanID,
		"kind":           string(plan.Kind),
		"typeId":         string(plan.TypeID),
		"dumpMode":       string(plan.DumpMode),
		"confirmToken":   plan.ConfirmToken,
		"expiresAtUnix":  plan.ExpiresAtUnix,
		"estimatedBytes": plan.EstimatedBytes,
		"notes":          plan.Notes,
		// Never return large dump body inline.
		"inlinePayload": false,
	}, nil
}

// CacheTelemetry returns low-cardinality rollups (viewer+).
func (s *Service) CacheTelemetry(_ context.Context) (map[string]any, error) {
	if err := RequirePermission(s.Role(), PermRead); err != nil {
		return nil, err
	}
	svc := s.ensureCacheControl()
	rows := svc.Telemetry().Snapshot()
	list := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		list = append(list, map[string]any{
			"typeId":  string(r.TypeID),
			"layer":   r.Layer,
			"outcome": r.Outcome,
			"reason":  r.Reason,
			"count":   r.Count,
			"bytes":   r.Bytes,
		})
	}
	return map[string]any{
		"rollups": list,
		"note":    "low-cardinality only; no job names, paths, URLs, or subjects",
	}, nil
}

// ensureCacheControl returns wired service or an ephemeral defaults-only service.
func (s *Service) ensureCacheControl() *cachecontrol.Service {
	if s != nil && s.cfg.CacheControl != nil {
		return s.cfg.CacheControl
	}
	// Ephemeral: inventory/effective still work with built-in defaults (no overrides).
	svc, err := cachecontrol.NewService(cachecontrol.ServiceConfig{
		Registry:  cachecontrol.DefaultRegistry(),
		ProfileID: s.cfg.DefaultProfileID,
	})
	if err != nil {
		// Unreachable for defaults
		panic(err)
	}
	return svc
}

func firstNonEmptyStr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return strings.TrimSpace(a)
	}
	return strings.TrimSpace(b)
}
