package cachecontrol

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Service is the shared control-plane facade used by adminops, tools, and CLI.
// Handlers stay thin; business logic lives here.
type Service struct {
	reg        *Registry
	store      *OverrideStore
	profile    string
	server     *DeclarativeConfig
	profileCfg *DeclarativeConfig
	startup    StartupConstraints
	now        func() time.Time

	mu       sync.Mutex
	snap     atomic.Pointer[EffectiveConfig]
	recorder *TelemetryRecorder
}

// ServiceConfig wires a Service.
type ServiceConfig struct {
	Registry      *Registry
	OverrideStore *OverrideStore
	ProfileID     string
	ServerConfig  *DeclarativeConfig
	ProfileConfig *DeclarativeConfig
	Startup       StartupConstraints
	Now           func() time.Time
	// Telemetry optional; nil creates an in-memory recorder.
	Telemetry *TelemetryRecorder
}

// NewService constructs a Service and loads the initial effective snapshot.
func NewService(cfg ServiceConfig) (*Service, error) {
	reg := cfg.Registry
	if reg == nil {
		reg = DefaultRegistry()
	}
	s := &Service{
		reg:        reg,
		store:      cfg.OverrideStore,
		profile:    cfg.ProfileID,
		server:     cfg.ServerConfig,
		profileCfg: cfg.ProfileConfig,
		startup:    cfg.Startup,
		now:        cfg.Now,
		recorder:   cfg.Telemetry,
	}
	if s.now == nil {
		s.now = func() time.Time { return time.Now().UTC() }
	}
	if s.recorder == nil {
		s.recorder = NewTelemetryRecorder()
	}
	if err := s.Reload(context.Background()); err != nil {
		return nil, err
	}
	return s, nil
}

// Registry returns the type registry.
func (s *Service) Registry() *Registry {
	if s == nil {
		return nil
	}
	return s.reg
}

// Telemetry returns the recorder (never nil after NewService).
func (s *Service) Telemetry() *TelemetryRecorder {
	if s == nil {
		return nil
	}
	return s.recorder
}

// Effective returns the current atomic snapshot (never nil after successful NewService).
func (s *Service) Effective() EffectiveConfig {
	if s == nil {
		return EffectiveConfig{}
	}
	p := s.snap.Load()
	if p == nil {
		return EffectiveConfig{}
	}
	return *p
}

// Reload recomputes EffectiveConfig from disk overrides + declarative layers.
func (s *Service) Reload(ctx context.Context) error {
	if s == nil {
		return fmt.Errorf("nil service")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var ov *RuntimeOverrides
	var epochs map[TypeID]uint64
	if s.store != nil {
		var err error
		ov, err = s.store.LoadOverrides(ctx, s.profile, s.now())
		if err != nil {
			return err
		}
		epochs, err = s.store.LoadPurgeEpochs(ctx, s.profile)
		if err != nil {
			return err
		}
	}
	eff, err := Resolve(ResolveInputs{
		Server:      s.server,
		Profile:     s.profileCfg,
		Overrides:   ov,
		Startup:     s.startup,
		Registry:    s.reg,
		Now:         s.now,
		PurgeEpochs: epochs,
	})
	if err != nil {
		return err
	}
	s.snap.Store(&eff)
	return nil
}

// Inventory returns descriptors plus effective mode for each type (secret-free).
func (s *Service) Inventory(ctx context.Context) []InventoryItem {
	_ = ctx
	if s == nil {
		return nil
	}
	eff := s.Effective()
	inv := s.reg.Inventory()
	out := make([]InventoryItem, 0, len(inv))
	for _, d := range inv {
		item := InventoryItem{Descriptor: d}
		if tc, ok := eff.TypeConfig(d.TypeID); ok {
			item.Mode = tc.Mode
			item.ModeSource = string(tc.ModeSource)
			item.FleetShare = tc.FleetShare
			item.ConfigRevision = tc.ConfigRevision
			item.PurgeEpoch = tc.PurgeEpoch
		}
		out = append(out, item)
	}
	return out
}

// InventoryItem is a secret-free inventory row.
type InventoryItem struct {
	Descriptor     Descriptor `json:"descriptor"`
	Mode           Mode       `json:"mode"`
	ModeSource     string     `json:"modeSource,omitempty"`
	FleetShare     bool       `json:"fleetShare"`
	ConfigRevision uint64     `json:"configRevision"`
	PurgeEpoch     uint64     `json:"purgeEpoch"`
}

// SnapshotType returns adapter snapshot for a type.
func (s *Service) SnapshotType(ctx context.Context, id TypeID) (TypeSnapshot, error) {
	if s == nil {
		return TypeSnapshot{}, fmt.Errorf("nil service")
	}
	a, ok := s.reg.Get(id)
	if !ok {
		return TypeSnapshot{}, fmt.Errorf("%s: %s", ReasonUnknownType, id)
	}
	tc, ok := s.Effective().TypeConfig(id)
	if !ok {
		return TypeSnapshot{}, fmt.Errorf("%s: %s", ReasonUnknownType, id)
	}
	return a.Snapshot(ctx, tc)
}

// Patch applies runtime overrides (CAS) and reloads. Rejects when runtime mutations disabled.
func (s *Service) Patch(ctx context.Context, req PatchRequest) (PatchResult, error) {
	if s == nil {
		return PatchResult{}, fmt.Errorf("nil service")
	}
	eff := s.Effective()
	if !eff.Global.RuntimeOverridesEnabled || s.startup.DisableRuntimeMutations {
		return PatchResult{}, fmt.Errorf("%s", ReasonRuntimeMutationsOff)
	}
	// Validate modes against registry
	for id, tc := range req.Types {
		d, ok := s.reg.Descriptor(id)
		if !ok {
			return PatchResult{}, fmt.Errorf("%s: %s", ReasonUnknownType, id)
		}
		if tc.Mode != nil {
			if !d.SupportsMode(*tc.Mode) {
				return PatchResult{}, fmt.Errorf("%s: types.%s mode %s", ReasonUnsupportedMode, id, *tc.Mode)
			}
			if *tc.Mode != ModeOff && !d.EnablementAllowed() {
				return PatchResult{}, fmt.Errorf("%s: types.%s", ReasonUnqualified, id)
			}
		}
	}
	if req.ProfileID == "" {
		req.ProfileID = s.profile
	}
	if s.store == nil {
		return PatchResult{}, apperrMissingStore()
	}
	res, err := s.store.Patch(ctx, req)
	if err != nil {
		return PatchResult{}, err
	}
	if err := s.Reload(ctx); err != nil {
		return res, err
	}
	return res, nil
}

// ResetOverrides clears runtime overrides and reloads.
func (s *Service) ResetOverrides(ctx context.Context, typeID TypeID, expectedRevision uint64) (PatchResult, error) {
	if s == nil {
		return PatchResult{}, fmt.Errorf("nil service")
	}
	if !s.Effective().Global.RuntimeOverridesEnabled || s.startup.DisableRuntimeMutations {
		return PatchResult{}, fmt.Errorf("%s", ReasonRuntimeMutationsOff)
	}
	if s.store == nil {
		return PatchResult{}, apperrMissingStore()
	}
	res, err := s.store.Reset(ctx, s.profile, typeID, expectedRevision)
	if err != nil {
		return PatchResult{}, err
	}
	if err := s.Reload(ctx); err != nil {
		return res, err
	}
	return res, nil
}

// PlanOperation builds a lifecycle plan via the adapter and persists it when a store is wired.
func (s *Service) PlanOperation(ctx context.Context, req OperationRequest) (OperationPlan, error) {
	if s == nil {
		return OperationPlan{}, fmt.Errorf("nil service")
	}
	a, ok := s.reg.Get(req.TypeID)
	if !ok {
		return OperationPlan{}, fmt.Errorf("%s: %s", ReasonUnknownType, req.TypeID)
	}
	// Raw dump gated
	if req.Kind == OpDump && req.DumpMode == DumpRaw && !s.Effective().Global.AllowRawDump {
		return OperationPlan{}, fmt.Errorf("%s", ReasonRawDumpDisabled)
	}
	plan, err := a.Plan(ctx, req)
	if err != nil {
		return OperationPlan{}, err
	}
	if plan.ConfirmToken == "" {
		switch req.Kind {
		case OpPurge:
			plan.ConfirmToken = "PURGE"
		case OpDump:
			plan.ConfirmToken = "DUMP"
		case OpRepair:
			plan.ConfirmToken = "REPAIR"
		case OpGC:
			plan.ConfirmToken = "GC"
		case OpVerify:
			plan.ConfirmToken = "VERIFY"
		}
	}
	if plan.ExpiresAtUnix == 0 {
		ttl := s.Effective().Global.PlanTTL
		if ttl <= 0 {
			ttl = 10 * time.Minute
		}
		plan.ExpiresAtUnix = s.now().Add(ttl).Unix()
	}
	if plan.PlanID == "" {
		plan.PlanID = fmt.Sprintf("%s-%s-%d", req.Kind, req.TypeID, s.now().UnixNano())
	}
	// Durable plan record when override store is present (AC4).
	if s.store != nil {
		eff := s.Effective()
		tc, _ := eff.TypeConfig(req.TypeID)
		rec := OperationRecord{
			PlanID:         plan.PlanID,
			ProfileID:      s.profile,
			Kind:           plan.Kind,
			TypeID:         plan.TypeID,
			DumpMode:       plan.DumpMode,
			ConfirmToken:   plan.ConfirmToken,
			Fingerprint:    plan.Fingerprint,
			State:          OpStatePlanned,
			EstimatedBytes: plan.EstimatedBytes,
			EstimatedCount: plan.EstimatedCount,
			Reason:         req.Reason,
			Notes:          plan.Notes,
			ExpiresAtUnix:  plan.ExpiresAtUnix,
			ConfigRevision: eff.Revision,
			PurgeEpoch:     tc.PurgeEpoch,
		}
		if err := s.store.SavePlan(ctx, rec); err != nil {
			return OperationPlan{}, err
		}
	}
	return plan, nil
}

// ExecuteOperation runs a plan with confirm token check.
// Purge epoch is bumped only after adapter.Execute succeeds (not theater).
// When a store is present, plan is loaded and state transitions are durable.
func (s *Service) ExecuteOperation(ctx context.Context, plan OperationPlan, confirm string, actorHash, source string) error {
	if s == nil {
		return fmt.Errorf("nil service")
	}
	// Prefer durable plan when available.
	if s.store != nil && plan.PlanID != "" {
		rec, err := s.store.LoadPlan(ctx, plan.PlanID)
		if err != nil {
			return err
		}
		if rec.State != OpStatePlanned {
			return fmt.Errorf("%s: plan state %s", ReasonUnsupportedOp, rec.State)
		}
		plan.ConfirmToken = rec.ConfirmToken
		plan.Kind = rec.Kind
		plan.TypeID = rec.TypeID
		plan.DumpMode = rec.DumpMode
		plan.ExpiresAtUnix = rec.ExpiresAtUnix
		if confirm == "" {
			_ = s.store.UpdatePlanState(ctx, plan.PlanID, OpStateFailed, ReasonConfirmRequired, rec.PurgeEpoch)
			return fmt.Errorf("%s", ReasonConfirmRequired)
		}
		if confirm != rec.ConfirmToken {
			_ = s.store.UpdatePlanState(ctx, plan.PlanID, OpStateFailed, ReasonConfirmMismatch, rec.PurgeEpoch)
			return fmt.Errorf("%s", ReasonConfirmMismatch)
		}
		if rec.ExpiresAtUnix > 0 && s.now().Unix() > rec.ExpiresAtUnix {
			_ = s.store.UpdatePlanState(ctx, plan.PlanID, OpStateExpired, ReasonPlanExpired, rec.PurgeEpoch)
			return fmt.Errorf("%s", ReasonPlanExpired)
		}
		_ = s.store.UpdatePlanState(ctx, plan.PlanID, OpStateRunning, "", rec.PurgeEpoch)
	} else {
		if plan.ConfirmToken != "" {
			if confirm == "" {
				return fmt.Errorf("%s", ReasonConfirmRequired)
			}
			if confirm != plan.ConfirmToken {
				return fmt.Errorf("%s", ReasonConfirmMismatch)
			}
		}
		if plan.ExpiresAtUnix > 0 && s.now().Unix() > plan.ExpiresAtUnix {
			return fmt.Errorf("%s", ReasonPlanExpired)
		}
	}
	a, ok := s.reg.Get(plan.TypeID)
	if !ok {
		return fmt.Errorf("%s: %s", ReasonUnknownType, plan.TypeID)
	}
	eff := s.Effective()
	tc, _ := eff.TypeConfig(plan.TypeID)
	oc := OperationContext{
		ActorIDHash:    actorHash,
		Source:         source,
		Confirm:        confirm,
		ConfigRevision: eff.Revision,
		PurgeEpoch:     tc.PurgeEpoch,
	}
	execErr := a.Execute(ctx, oc, plan)
	if execErr != nil {
		if s.store != nil && plan.PlanID != "" {
			// Record an honest execution-failure code; ReasonUnsupportedOp is
			// for plan-shape rejections, not adapter IO/cancel failures.
			_ = s.store.UpdatePlanState(ctx, plan.PlanID, OpStateFailed, "execute_failed", tc.PurgeEpoch)
		}
		return execErr
	}
	// Success: only then bump purge epoch for purge ops.
	newEpoch := tc.PurgeEpoch
	if plan.Kind == OpPurge && s.store != nil {
		ep, err := s.store.BumpPurgeEpoch(ctx, s.profile, plan.TypeID)
		if err != nil {
			if s.store != nil && plan.PlanID != "" {
				_ = s.store.UpdatePlanState(ctx, plan.PlanID, OpStateFailed, "purge_epoch_bump_failed", tc.PurgeEpoch)
			}
			return err
		}
		newEpoch = ep
		_ = s.Reload(ctx)
	}
	if s.store != nil && plan.PlanID != "" {
		_ = s.store.UpdatePlanState(ctx, plan.PlanID, OpStateSucceeded, "", newEpoch)
	}
	return nil
}

// PurgeEpoch returns the current purge epoch for a type (0 if unknown).
func (s *Service) PurgeEpoch(id TypeID) uint64 {
	if s == nil {
		return 0
	}
	tc, ok := s.Effective().TypeConfig(id)
	if !ok {
		return 0
	}
	return tc.PurgeEpoch
}

// ModePolicy implements a simple gate for resourcecache / store adapters.
func (s *Service) ModePolicy(kind string) (allowLookup, allowFill bool) {
	if s == nil {
		return true, true // nil service = compat (no control plane)
	}
	eff := s.Effective()
	if !eff.Global.Enabled {
		return false, false
	}
	m := ModeForResourceKind(eff, kind)
	// console_log is not a resource kind string match for ModeForResourceKind when called with TypeID
	if TypeID(kind).Valid() {
		m = eff.TypeMode(TypeID(kind))
	}
	return ShouldLookup(true, m), ShouldFill(true, m)
}

// AllowLookup reports whether kind may be read from cache.
func (s *Service) AllowLookup(kind string) bool {
	l, _ := s.ModePolicy(kind)
	return l
}

// AllowFill reports whether kind may be written to cache.
func (s *Service) AllowFill(kind string) bool {
	_, f := s.ModePolicy(kind)
	return f
}

func apperrMissingStore() error {
	return fmt.Errorf("cache-control override store not configured")
}
