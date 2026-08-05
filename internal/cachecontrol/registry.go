package cachecontrol

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// Registry is an immutable map of type ID → adapter built at process startup.
type Registry struct {
	byID map[TypeID]Adapter
	// descriptors cached at build for concurrent reads without adapter call cost.
	desc map[TypeID]Descriptor
}

// Builder constructs a Registry. Not safe for concurrent use until Build.
type Builder struct {
	mu   sync.Mutex
	byID map[TypeID]Adapter
	desc map[TypeID]Descriptor
}

// NewBuilder returns an empty registry builder.
func NewBuilder() *Builder {
	return &Builder{
		byID: make(map[TypeID]Adapter),
		desc: make(map[TypeID]Descriptor),
	}
}

// Register adds an adapter. Duplicate TypeID or invalid descriptor fails.
func (b *Builder) Register(a Adapter) error {
	if b == nil {
		return fmt.Errorf("nil builder")
	}
	if a == nil {
		return fmt.Errorf("nil adapter")
	}
	d := a.Descriptor(context.Background())
	if err := validateDescriptor(d); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.byID[d.TypeID]; ok {
		return fmt.Errorf("duplicate cache type registration: %s", d.TypeID)
	}
	b.byID[d.TypeID] = a
	b.desc[d.TypeID] = d
	return nil
}

// Build freezes the registry. Further Register calls on the builder must not
// mutate the returned Registry (builder maps are copied).
func (b *Builder) Build() (*Registry, error) {
	if b == nil {
		return nil, fmt.Errorf("nil builder")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	byID := make(map[TypeID]Adapter, len(b.byID))
	desc := make(map[TypeID]Descriptor, len(b.desc))
	for id, a := range b.byID {
		byID[id] = a
		desc[id] = b.desc[id]
	}
	return &Registry{byID: byID, desc: desc}, nil
}

func validateDescriptor(d Descriptor) error {
	if !d.TypeID.Valid() {
		return fmt.Errorf("invalid type id %q", d.TypeID)
	}
	if d.DisplayName == "" {
		return fmt.Errorf("type %s: displayName required", d.TypeID)
	}
	if d.StorageClass == "" {
		return fmt.Errorf("type %s: storageClass required", d.TypeID)
	}
	if !d.Availability.Valid() {
		return fmt.Errorf("type %s: invalid availability %q", d.TypeID, d.Availability)
	}
	if len(d.SupportedModes) == 0 {
		return fmt.Errorf("type %s: supportedModes required", d.TypeID)
	}
	for _, m := range d.SupportedModes {
		if !m.Valid() {
			return fmt.Errorf("type %s: invalid mode %q", d.TypeID, m)
		}
	}
	// Unqualified/unavailable must support off.
	if !d.EnablementAllowed() && !d.SupportsMode(ModeOff) {
		return fmt.Errorf("type %s: unavailable/unqualified types must support mode off", d.TypeID)
	}
	return nil
}

// Get returns the adapter for id, or false.
func (r *Registry) Get(id TypeID) (Adapter, bool) {
	if r == nil {
		return nil, false
	}
	a, ok := r.byID[id]
	return a, ok
}

// Descriptor returns the registered descriptor, or false.
func (r *Registry) Descriptor(id TypeID) (Descriptor, bool) {
	if r == nil {
		return Descriptor{}, false
	}
	d, ok := r.desc[id]
	return d, ok
}

// Inventory returns descriptors sorted by type ID.
func (r *Registry) Inventory() []Descriptor {
	if r == nil || len(r.desc) == 0 {
		return nil
	}
	ids := make([]TypeID, 0, len(r.desc))
	for id := range r.desc {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	out := make([]Descriptor, 0, len(ids))
	for _, id := range ids {
		out = append(out, r.desc[id])
	}
	return out
}

// Len returns the number of registered types.
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	return len(r.byID)
}

// DefaultRegistry builds the production registry with static placeholders for
// all closed type IDs. Concrete store adapters may replace placeholders later
// via a custom Builder; this default ensures inventory is always complete.
func DefaultRegistry() *Registry {
	b := NewBuilder()
	for _, d := range defaultDescriptors() {
		_ = b.Register(&staticAdapter{d: d})
	}
	reg, err := b.Build()
	if err != nil {
		// defaultDescriptors is static and must always validate.
		panic("cachecontrol: default registry: " + err.Error())
	}
	return reg
}

// staticAdapter is a no-op management adapter used until store adapters wire in.
type staticAdapter struct {
	d Descriptor
}

func (a *staticAdapter) Descriptor(context.Context) Descriptor { return a.d }

func (a *staticAdapter) Snapshot(_ context.Context, cfg EffectiveTypeConfig) (TypeSnapshot, error) {
	return TypeSnapshot{
		TypeID:         a.d.TypeID,
		Mode:           cfg.Mode,
		Availability:   a.d.Availability,
		SizeAccounting: a.d.SizeAccounting,
		ConfigRevision: cfg.ConfigRevision,
		PurgeEpoch:     cfg.PurgeEpoch,
		Notes:          a.d.AvailabilityReason,
	}, nil
}

func (a *staticAdapter) ListEntries(context.Context, EntryQuery) (EntryPage, error) {
	if !a.d.SupportsList {
		return EntryPage{}, fmt.Errorf("%s: %s", a.d.TypeID, ReasonUnsupportedOp)
	}
	return EntryPage{}, nil
}

func (a *staticAdapter) Plan(_ context.Context, req OperationRequest) (OperationPlan, error) {
	switch req.Kind {
	case OpDump:
		if !a.d.SupportsDump(req.DumpMode) {
			return OperationPlan{}, fmt.Errorf("%s: %s", a.d.TypeID, ReasonUnsupportedOp)
		}
	case OpPurge:
		if !a.d.SupportsPurge {
			return OperationPlan{}, fmt.Errorf("%s: %s", a.d.TypeID, ReasonUnsupportedOp)
		}
	case OpVerify:
		if !a.d.SupportsVerify {
			return OperationPlan{}, fmt.Errorf("%s: %s", a.d.TypeID, ReasonUnsupportedOp)
		}
	case OpRepair:
		if !a.d.SupportsRepair {
			return OperationPlan{}, fmt.Errorf("%s: %s", a.d.TypeID, ReasonUnsupportedOp)
		}
	case OpGC:
		if !a.d.SupportsGC {
			return OperationPlan{}, fmt.Errorf("%s: %s", a.d.TypeID, ReasonUnsupportedOp)
		}
	default:
		return OperationPlan{}, fmt.Errorf("%s: %s", a.d.TypeID, ReasonUnsupportedOp)
	}
	if !a.d.EnablementAllowed() && req.Kind != OpDump {
		// Still allow metadata dump planning notes for unqualified types? Pack:
		// unqualified stays off; reject enablement-like ops. Dump metadata may
		// still be unsupported until adapter ships — reject if not in list.
	}
	return OperationPlan{
		Kind:     req.Kind,
		TypeID:   a.d.TypeID,
		DumpMode: req.DumpMode,
		Notes:    "static adapter: plan not executable until store adapter wires Execute",
	}, nil
}

func (a *staticAdapter) Execute(context.Context, OperationContext, OperationPlan) error {
	return fmt.Errorf("%s: %s", a.d.TypeID, ReasonUnsupportedOp)
}

func defaultDescriptors() []Descriptor {
	commonModes := []Mode{ModeOff, ModeReadOnly, ModeWriteOnly, ModeReadWrite}
	dyn := []string{"mode", "quota.softBytes", "quota.hardBytes", "freshness.buildingTTL", "freshness.terminalTTL", "telemetryEnabled", "fleetShare.enabled"}
	startup := []string{"roots", "encryption", "dump.root", "dump.allowRaw", "ratarmount.binary"}

	rc := func(id TypeID, name string, class StorageClass, dumps []DumpMode) Descriptor {
		return Descriptor{
			TypeID:             id,
			DisplayName:        name,
			StorageClass:       class,
			Implementation:     "resourcecache",
			Availability:       AvailabilityAvailable,
			SchemaVersion:      1,
			SupportedModes:     commonModes,
			DynamicFields:      dyn,
			StartupOnlyFields:  startup,
			SelectorFields:     []string{"jobFullName", "buildNumber", "selector", "variant"},
			SupportsList:       true,
			SupportsDumpModes:  dumps,
			SupportsPurge:      true,
			SupportsVerify:     true,
			SupportsRepair:     false,
			SupportsGC:         true,
			SupportsPinning:    false,
			SupportsRangeRead:  false,
			SupportsFleetShare: true, // capability; default config keeps enabled=false
			SizeAccounting:     SizeExact,
		}
	}

	return []Descriptor{
		{
			TypeID:             TypeConsoleLog,
			DisplayName:        "Console log (L1/L2)",
			StorageClass:       ClassStreamLog,
			Implementation:     "store",
			Availability:       AvailabilityAvailable,
			SchemaVersion:      1,
			SupportedModes:     commonModes,
			DynamicFields:      dyn,
			StartupOnlyFields:  startup,
			SelectorFields:     []string{"jobFullName", "buildNumber"},
			SupportsList:       true,
			SupportsDumpModes:  []DumpMode{DumpMetadata, DumpSanitized, DumpStorageNative},
			SupportsPurge:      true,
			SupportsVerify:     true,
			SupportsRepair:     true,
			SupportsGC:         true,
			SupportsPinning:    true,
			SupportsRangeRead:  true,
			SupportsFleetShare: true,
			SizeAccounting:     SizeExact,
		},
		rc(TypeStageLog, "Pipeline stage log", ClassStreamLog, []DumpMode{DumpMetadata, DumpSanitized, DumpStorageNative}),
		rc(TypeArtifactBlob, "Artifact blob", ClassImmutableBlob, []DumpMode{DumpMetadata, DumpStorageNative}),
		rc(TypeArtifactCatalog, "Artifact catalog", ClassStructuredResource, []DumpMode{DumpMetadata, DumpSanitized}),
		rc(TypeArtifactText, "Artifact text", ClassDerivedResult, []DumpMode{DumpMetadata, DumpSanitized}),
		rc(TypeArtifactInspection, "Artifact inspection", ClassDerivedResult, []DumpMode{DumpMetadata, DumpSanitized}),
		rc(TypeTestReport, "Test report", ClassStructuredResource, []DumpMode{DumpMetadata, DumpSanitized}),
		rc(TypePipelineStages, "Pipeline stages", ClassStructuredResource, []DumpMode{DumpMetadata, DumpSanitized}),
		rc(TypeBuildChanges, "Build changes", ClassStructuredResource, []DumpMode{DumpMetadata, DumpSanitized}),
		{
			TypeID:             TypeDiagnosticFetch,
			DisplayName:        "Diagnostic fetch (process-local)",
			StorageClass:       ClassEphemeralStructured,
			Implementation:     "diagnostics",
			Availability:       AvailabilityAvailable,
			SchemaVersion:      1,
			SupportedModes:     commonModes,
			DynamicFields:      []string{"mode", "maxEntries", "freshness.buildingTTL", "freshness.terminalTTL", "telemetryEnabled"},
			StartupOnlyFields:  startup,
			SelectorFields:     []string{"kind"},
			SupportsList:       false,
			SupportsDumpModes:  []DumpMode{DumpMetadata},
			SupportsPurge:      true, // reset
			SupportsVerify:     false,
			SupportsRepair:     false,
			SupportsGC:         false,
			SupportsPinning:    false,
			SupportsRangeRead:  false,
			SupportsFleetShare: false,
			SizeAccounting:     SizeEstimated,
		},
		{
			TypeID:             TypeSurveySummary,
			DisplayName:        "Survey summary",
			StorageClass:       ClassDerivedSummary,
			Implementation:     "store.survey",
			Availability:       AvailabilityAvailable,
			SchemaVersion:      1,
			SupportedModes:     commonModes,
			DynamicFields:      dyn,
			StartupOnlyFields:  startup,
			SelectorFields:     []string{"jobFullName", "buildNumber"},
			SupportsList:       true,
			SupportsDumpModes:  []DumpMode{DumpMetadata, DumpSanitized},
			SupportsPurge:      true,
			SupportsVerify:     false,
			SupportsRepair:     false,
			SupportsGC:         true,
			SupportsPinning:    false,
			SupportsRangeRead:  false,
			SupportsFleetShare: false,
			SizeAccounting:     SizeEstimated,
		},
		{
			TypeID:             TypeRatarmountIndex,
			DisplayName:        "ratarmount index (optional)",
			StorageClass:       ClassDerivedIndex,
			Implementation:     "ratarmount-rs",
			Availability:       AvailabilityUnqualified,
			AvailabilityReason: "ARC-000 qualification open; FUSE not required for core MCP",
			SchemaVersion:      0,
			SupportedModes:     []Mode{ModeOff}, // only off until qualified
			DynamicFields:      []string{"mode"},
			StartupOnlyFields:  append(startup, "ratarmount.binary", "ratarmount.sandbox"),
			SelectorFields:     []string{"artifactDigest"},
			SupportsList:       false,
			SupportsDumpModes:  []DumpMode{DumpMetadata},
			SupportsPurge:      false,
			SupportsVerify:     false,
			SupportsRepair:     false,
			SupportsGC:         false,
			SupportsPinning:    false,
			SupportsRangeRead:  false,
			SupportsFleetShare: false,
			SizeAccounting:     SizeNotAvailable,
		},
	}
}
