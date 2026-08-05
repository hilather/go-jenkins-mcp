package cachecontrol

import (
	"fmt"
	"time"
)

// ResolveInputs are layers for EffectiveConfig computation.
type ResolveInputs struct {
	// Server is optional server-wide file config (nil if absent).
	Server *DeclarativeConfig
	// Profile is optional profile cache section (nil if absent).
	Profile *DeclarativeConfig
	// Overrides are persistent runtime overrides (nil if none).
	Overrides *RuntimeOverrides
	// Startup constraints (flags/env); zero value is safe.
	Startup StartupConstraints
	// Registry is used to reject enablement of unqualified types (optional).
	Registry *Registry
	// Now is optional clock; defaults to time.Now.
	Now func() time.Time
	// PurgeEpochs optional per-type purge epoch from DB.
	PurgeEpochs map[TypeID]uint64
}

// Resolve merges layers into an immutable EffectiveConfig.
// Nil Server/Profile/Overrides ⇒ built-in defaults only (compatibility).
func Resolve(in ResolveInputs) (EffectiveConfig, error) {
	now := time.Now().UTC()
	if in.Now != nil {
		now = in.Now().UTC()
	}
	base := BuiltInDefaults()
	if err := ValidateDeclarative(in.Server); err != nil {
		return EffectiveConfig{}, err
	}
	if err := ValidateDeclarative(in.Profile); err != nil {
		return EffectiveConfig{}, err
	}

	rev := uint64(0)
	if in.Overrides != nil {
		rev = in.Overrides.Revision
	}

	eff := EffectiveConfig{
		Revision:      rev,
		LoadedAt:      now,
		Types:         make(map[TypeID]EffectiveTypeConfig, len(AllTypeIDs())),
		SourceDetails: make(map[string]FieldSource),
	}

	// Global merge: built_in ← server ← profile ← startup.
	g := mergeGlobal(base.Cache.Global, nil, SourceBuiltIn)
	gSrc := map[string]ConfigSource{}
	markGlobalSources(gSrc, SourceBuiltIn)
	if in.Server != nil {
		g = mergeGlobal(g, &in.Server.Cache.Global, SourceServerConfig)
		markGlobalSources(gSrc, SourceServerConfig)
	}
	if in.Profile != nil {
		g = mergeGlobal(g, &in.Profile.Cache.Global, SourceProfileConfig)
		markGlobalSources(gSrc, SourceProfileConfig)
	}
	// Startup hard limits / raw dump / runtime mutations.
	eg, gFieldSources := materializeGlobal(g, gSrc, in.Startup)
	eff.Global = eg
	for k, v := range gFieldSources {
		eff.SourceDetails[k] = v
	}

	// Per-type: start from defaults chain then type-specific.
	for _, id := range AllTypeIDs() {
		tc, sources := resolveOneType(id, base, in)
		// Force off
		for _, fo := range in.Startup.ForceOff {
			if fo == id {
				tc.Mode = ModeOff
				sources["mode"] = FieldSource{
					Value:           ModeOff,
					Source:          SourceEmergencyForceOff,
					BaselineValue:   sources["mode"].Value,
					BaselineSource:  sources["mode"].Source,
					Mutable:         false,
					RestartRequired: false,
				}
			}
		}
		// Unqualified/unavailable cannot leave off
		if in.Registry != nil {
			if d, ok := in.Registry.Descriptor(id); ok && !d.EnablementAllowed() {
				if tc.Mode != ModeOff {
					return EffectiveConfig{}, fmt.Errorf("%s: types.%s mode=%s", ReasonUnqualified, id, tc.Mode)
				}
				if !d.SupportsMode(tc.Mode) {
					tc.Mode = ModeOff
					sources["mode"] = FieldSource{
						Value: ModeOff, Source: SourceStartupConstraint, Mutable: false, RestartRequired: false,
					}
				}
			}
		}
		// Ratarmount hard rule even without registry
		if id == TypeRatarmountIndex && tc.Mode != ModeOff {
			// Without a qualified adapter, reject enablement
			if in.Registry == nil {
				tc.Mode = ModeOff
				sources["mode"] = FieldSource{
					Value: ModeOff, Source: SourceStartupConstraint, Mutable: false,
					BaselineValue: ModeOff, BaselineSource: SourceBuiltIn,
				}
			}
		}
		// Raw dump not allowed in type list when global disallows
		if !eg.AllowRawDump {
			filtered := make([]DumpMode, 0, len(tc.AllowedDumpModes))
			for _, m := range tc.AllowedDumpModes {
				if m != DumpRaw {
					filtered = append(filtered, m)
				}
			}
			tc.AllowedDumpModes = filtered
		}
		// Soft/hard ceilings
		if eg.MaxTotalBytes > 0 && tc.HardBytes > eg.MaxTotalBytes {
			tc.HardBytes = eg.MaxTotalBytes
		}
		if eg.MaxSingleObjectBytes > 0 && tc.MaxObjectBytes > eg.MaxSingleObjectBytes {
			tc.MaxObjectBytes = eg.MaxSingleObjectBytes
		}
		if pe, ok := in.PurgeEpochs[id]; ok {
			tc.PurgeEpoch = pe
		}
		tc.ConfigRevision = rev
		if fs, ok := sources["mode"]; ok {
			tc.ModeSource = fs.Source
		}
		eff.Types[id] = tc
		for field, fs := range sources {
			eff.SourceDetails[fmt.Sprintf("types.%s.%s", id, field)] = fs
		}
	}

	// Runtime mutations disabled still allows reading overrides already applied;
	// the flag is enforced at patch API, not here.

	return eff, nil
}

func resolveOneType(id TypeID, base DeclarativeConfig, in ResolveInputs) (EffectiveTypeConfig, map[string]FieldSource) {
	// Layer stack for TypeConfig fragments with sources.
	type layer struct {
		tc  TypeConfig
		src ConfigSource
	}
	layers := []layer{
		{base.Cache.Defaults, SourceBuiltIn},
	}
	if t, ok := base.Cache.Types[string(id)]; ok {
		layers = append(layers, layer{t, SourceBuiltIn})
	}
	if in.Server != nil {
		layers = append(layers, layer{in.Server.Cache.Defaults, SourceServerConfig})
		if t, ok := in.Server.Cache.Types[string(id)]; ok {
			layers = append(layers, layer{t, SourceServerConfig})
		}
	}
	if in.Profile != nil {
		layers = append(layers, layer{in.Profile.Cache.Defaults, SourceProfileConfig})
		if t, ok := in.Profile.Cache.Types[string(id)]; ok {
			layers = append(layers, layer{t, SourceProfileConfig})
		}
	}
	if in.Overrides != nil {
		if t, ok := in.Overrides.Types[id]; ok {
			layers = append(layers, layer{t, SourceRuntimeOverride})
		}
	}

	// Start from zero then apply layers.
	var acc TypeConfig
	sources := map[string]FieldSource{}
	for _, ly := range layers {
		acc = mergeTypeConfig(acc, ly.tc, ly.src, sources)
	}
	return materializeType(id, acc, sources), sources
}

func mergeTypeConfig(base, over TypeConfig, src ConfigSource, sources map[string]FieldSource) TypeConfig {
	out := base
	set := func(field string, val any, mutable bool) {
		prev := sources[field]
		sources[field] = FieldSource{
			Value:          val,
			Source:         src,
			BaselineValue:  prev.Value,
			BaselineSource: prev.Source,
			Mutable:        mutable,
		}
	}
	if over.Mode != nil {
		out.Mode = over.Mode
		set("mode", *over.Mode, true)
	}
	if over.TelemetryEnabled != nil {
		out.TelemetryEnabled = over.TelemetryEnabled
		set("telemetryEnabled", *over.TelemetryEnabled, true)
	}
	if over.Quota != nil {
		if out.Quota == nil {
			out.Quota = &QuotaConfig{}
		}
		if over.Quota.SoftBytes != nil {
			out.Quota.SoftBytes = over.Quota.SoftBytes
			set("quota.softBytes", *over.Quota.SoftBytes, true)
		}
		if over.Quota.HardBytes != nil {
			out.Quota.HardBytes = over.Quota.HardBytes
			set("quota.hardBytes", *over.Quota.HardBytes, true)
		}
		if over.Quota.HighWatermark != nil {
			out.Quota.HighWatermark = over.Quota.HighWatermark
			set("quota.highWatermark", *over.Quota.HighWatermark, true)
		}
		if over.Quota.LowWatermark != nil {
			out.Quota.LowWatermark = over.Quota.LowWatermark
			set("quota.lowWatermark", *over.Quota.LowWatermark, true)
		}
	}
	if over.Freshness != nil {
		if out.Freshness == nil {
			out.Freshness = &FreshnessConfig{}
		}
		if over.Freshness.BuildingTTL != nil {
			out.Freshness.BuildingTTL = over.Freshness.BuildingTTL
			set("freshness.buildingTTL", over.Freshness.BuildingTTL.D, true)
		}
		if over.Freshness.TerminalTTL != nil {
			out.Freshness.TerminalTTL = over.Freshness.TerminalTTL
			set("freshness.terminalTTL", over.Freshness.TerminalTTL.D, true)
		}
		if over.Freshness.StaleIfError != nil {
			out.Freshness.StaleIfError = over.Freshness.StaleIfError
			set("freshness.staleIfError", over.Freshness.StaleIfError.D, true)
		}
		if over.Freshness.RevalidateAfter != nil {
			out.Freshness.RevalidateAfter = over.Freshness.RevalidateAfter
			set("freshness.revalidateAfter", over.Freshness.RevalidateAfter.D, true)
		}
	}
	if over.Eviction != nil {
		if out.Eviction == nil {
			out.Eviction = &EvictionConfig{}
		}
		if over.Eviction.Priority != nil {
			out.Eviction.Priority = over.Eviction.Priority
			set("eviction.priority", *over.Eviction.Priority, true)
		}
		if over.Eviction.MinimumAge != nil {
			out.Eviction.MinimumAge = over.Eviction.MinimumAge
			set("eviction.minimumAge", over.Eviction.MinimumAge.D, true)
		}
	}
	if over.L0 != nil {
		if out.L0 == nil {
			out.L0 = &L0Config{}
		}
		if over.L0.Enabled != nil {
			out.L0.Enabled = over.L0.Enabled
			set("l0.enabled", *over.L0.Enabled, true)
		}
		if over.L0.MaxEntries != nil {
			out.L0.MaxEntries = over.L0.MaxEntries
			set("l0.maxEntries", *over.L0.MaxEntries, true)
		}
	}
	if over.FleetShare != nil && over.FleetShare.Enabled != nil {
		out.FleetShare = &FleetShareConfig{Enabled: over.FleetShare.Enabled}
		set("fleetShare.enabled", *over.FleetShare.Enabled, true)
	}
	if over.Dump != nil && over.Dump.AllowedModes != nil {
		out.Dump = &TypeDumpConfig{AllowedModes: append([]DumpMode(nil), over.Dump.AllowedModes...)}
		set("dump.allowedModes", over.Dump.AllowedModes, true)
	}
	if over.MaxEntries != nil {
		out.MaxEntries = over.MaxEntries
		set("maxEntries", *over.MaxEntries, true)
	}
	if over.MaxObjectBytes != nil {
		out.MaxObjectBytes = over.MaxObjectBytes
		set("maxObjectBytes", *over.MaxObjectBytes, true)
	}
	return out
}

func materializeType(id TypeID, tc TypeConfig, sources map[string]FieldSource) EffectiveTypeConfig {
	et := EffectiveTypeConfig{
		TypeID:           id,
		Mode:             ModeReadWrite,
		TelemetryEnabled: true,
		SoftBytes:        2 << 30,
		HardBytes:        4 << 30,
		HighWatermark:    0.90,
		LowWatermark:     0.75,
		BuildingTTL:      5 * time.Second,
		TerminalTTL:      720 * time.Hour,
		RevalidateAfter:  time.Hour,
		EvictionPriority: 100,
		MinAge:           5 * time.Minute,
		L0Enabled:        true,
		L0MaxEntries:     64,
		FleetShare:       false,
		AllowedDumpModes: []DumpMode{DumpMetadata, DumpSanitized},
	}
	if id == TypeRatarmountIndex {
		et.Mode = ModeOff
	}
	if tc.Mode != nil {
		et.Mode = *tc.Mode
	}
	if tc.TelemetryEnabled != nil {
		et.TelemetryEnabled = *tc.TelemetryEnabled
	}
	if tc.Quota != nil {
		if tc.Quota.SoftBytes != nil {
			et.SoftBytes = *tc.Quota.SoftBytes
		}
		if tc.Quota.HardBytes != nil {
			et.HardBytes = *tc.Quota.HardBytes
		}
		if tc.Quota.HighWatermark != nil {
			et.HighWatermark = *tc.Quota.HighWatermark
		}
		if tc.Quota.LowWatermark != nil {
			et.LowWatermark = *tc.Quota.LowWatermark
		}
	}
	if tc.Freshness != nil {
		if tc.Freshness.BuildingTTL != nil {
			et.BuildingTTL = tc.Freshness.BuildingTTL.D
		}
		if tc.Freshness.TerminalTTL != nil {
			et.TerminalTTL = tc.Freshness.TerminalTTL.D
		}
		if tc.Freshness.StaleIfError != nil {
			et.StaleIfError = tc.Freshness.StaleIfError.D
		}
		if tc.Freshness.RevalidateAfter != nil {
			et.RevalidateAfter = tc.Freshness.RevalidateAfter.D
		}
	}
	if tc.Eviction != nil {
		if tc.Eviction.Priority != nil {
			et.EvictionPriority = *tc.Eviction.Priority
		}
		if tc.Eviction.MinimumAge != nil {
			et.MinAge = tc.Eviction.MinimumAge.D
		}
	}
	if tc.L0 != nil {
		if tc.L0.Enabled != nil {
			et.L0Enabled = *tc.L0.Enabled
		}
		if tc.L0.MaxEntries != nil {
			et.L0MaxEntries = *tc.L0.MaxEntries
		}
	}
	if tc.FleetShare != nil && tc.FleetShare.Enabled != nil {
		et.FleetShare = *tc.FleetShare.Enabled
	}
	if tc.Dump != nil && len(tc.Dump.AllowedModes) > 0 {
		et.AllowedDumpModes = append([]DumpMode(nil), tc.Dump.AllowedModes...)
	}
	if tc.MaxEntries != nil {
		et.MaxEntries = *tc.MaxEntries
	}
	if tc.MaxObjectBytes != nil {
		et.MaxObjectBytes = *tc.MaxObjectBytes
	}
	// Ensure mode source exists for tests
	if _, ok := sources["mode"]; !ok {
		sources["mode"] = FieldSource{Value: et.Mode, Source: SourceBuiltIn, Mutable: true}
	}
	return et
}

func mergeGlobal(base GlobalConfig, over *GlobalConfig, _ ConfigSource) GlobalConfig {
	if over == nil {
		return base
	}
	out := base
	if over.Enabled != nil {
		out.Enabled = over.Enabled
	}
	if over.RuntimeOverrides != nil {
		if out.RuntimeOverrides == nil {
			out.RuntimeOverrides = &RuntimeOvConfig{}
		}
		if over.RuntimeOverrides.Enabled != nil {
			out.RuntimeOverrides.Enabled = over.RuntimeOverrides.Enabled
		}
		if over.RuntimeOverrides.PollInterval != nil {
			out.RuntimeOverrides.PollInterval = over.RuntimeOverrides.PollInterval
		}
	}
	if over.Telemetry != nil {
		if out.Telemetry == nil {
			out.Telemetry = &TelemetryConfig{}
		}
		if over.Telemetry.Enabled != nil {
			out.Telemetry.Enabled = over.Telemetry.Enabled
		}
		if over.Telemetry.RollupsEnabled != nil {
			out.Telemetry.RollupsEnabled = over.Telemetry.RollupsEnabled
		}
		if over.Telemetry.Retention != nil {
			out.Telemetry.Retention = over.Telemetry.Retention
		}
		if over.Telemetry.FlushInterval != nil {
			out.Telemetry.FlushInterval = over.Telemetry.FlushInterval
		}
	}
	if over.OperationManager != nil {
		if out.OperationManager == nil {
			out.OperationManager = &OpManagerConfig{}
		}
		if over.OperationManager.MaxConcurrent != nil {
			out.OperationManager.MaxConcurrent = over.OperationManager.MaxConcurrent
		}
		if over.OperationManager.MaxQueued != nil {
			out.OperationManager.MaxQueued = over.OperationManager.MaxQueued
		}
		if over.OperationManager.PlanTTL != nil {
			out.OperationManager.PlanTTL = over.OperationManager.PlanTTL
		}
		if over.OperationManager.RecordRetention != nil {
			out.OperationManager.RecordRetention = over.OperationManager.RecordRetention
		}
	}
	if over.Dump != nil {
		if out.Dump == nil {
			out.Dump = &DumpGlobalConfig{}
		}
		if over.Dump.Root != "" {
			out.Dump.Root = over.Dump.Root
		}
		if over.Dump.MaxBytes != nil {
			out.Dump.MaxBytes = over.Dump.MaxBytes
		}
		if over.Dump.Retention != nil {
			out.Dump.Retention = over.Dump.Retention
		}
		if over.Dump.AllowMetadata != nil {
			out.Dump.AllowMetadata = over.Dump.AllowMetadata
		}
		if over.Dump.AllowSanitized != nil {
			out.Dump.AllowSanitized = over.Dump.AllowSanitized
		}
		if over.Dump.AllowStorageNative != nil {
			out.Dump.AllowStorageNative = over.Dump.AllowStorageNative
		}
		if over.Dump.AllowRaw != nil {
			out.Dump.AllowRaw = over.Dump.AllowRaw
		}
		if over.Dump.RequireEncryptionForRaw != nil {
			out.Dump.RequireEncryptionForRaw = over.Dump.RequireEncryptionForRaw
		}
	}
	if over.HardLimits != nil {
		if out.HardLimits == nil {
			out.HardLimits = &HardLimits{}
		}
		if over.HardLimits.MaxTotalBytes != nil {
			out.HardLimits.MaxTotalBytes = over.HardLimits.MaxTotalBytes
		}
		if over.HardLimits.MaxSingleObjectBytes != nil {
			out.HardLimits.MaxSingleObjectBytes = over.HardLimits.MaxSingleObjectBytes
		}
		if over.HardLimits.MaxDumpBytes != nil {
			out.HardLimits.MaxDumpBytes = over.HardLimits.MaxDumpBytes
		}
		if over.HardLimits.MaxOperationConcurrency != nil {
			out.HardLimits.MaxOperationConcurrency = over.HardLimits.MaxOperationConcurrency
		}
	}
	return out
}

func markGlobalSources(m map[string]ConfigSource, src ConfigSource) {
	keys := []string{
		"global.enabled", "global.runtimeOverrides.enabled", "global.telemetry.enabled",
		"global.dump.allowRaw", "global.hardLimits.maxTotalBytes",
	}
	for _, k := range keys {
		m[k] = src
	}
}

func materializeGlobal(g GlobalConfig, gSrc map[string]ConfigSource, st StartupConstraints) (EffectiveGlobal, map[string]FieldSource) {
	eg := EffectiveGlobal{
		Enabled:                 true,
		RuntimeOverridesEnabled: true,
		TelemetryEnabled:        true,
		RollupsEnabled:          true,
		AllowRawDump:            false,
		MaxTotalBytes:           100 << 30,
		MaxSingleObjectBytes:    20 << 30,
		MaxDumpBytes:            20 << 30,
		MaxOperationConcurrency: 4,
		PlanTTL:                 10 * time.Minute,
	}
	fs := map[string]FieldSource{}
	srcOf := func(k string) ConfigSource {
		if s, ok := gSrc[k]; ok {
			return s
		}
		return SourceBuiltIn
	}
	if g.Enabled != nil {
		eg.Enabled = *g.Enabled
	}
	fs["global.enabled"] = FieldSource{Value: eg.Enabled, Source: srcOf("global.enabled"), Mutable: false, RestartRequired: false}

	if g.RuntimeOverrides != nil && g.RuntimeOverrides.Enabled != nil {
		eg.RuntimeOverridesEnabled = *g.RuntimeOverrides.Enabled
	}
	if st.DisableRuntimeMutations {
		eg.RuntimeOverridesEnabled = false
		fs["global.runtimeOverrides.enabled"] = FieldSource{
			Value: false, Source: SourceStartupConstraint, Mutable: false, RestartRequired: true,
		}
	} else {
		fs["global.runtimeOverrides.enabled"] = FieldSource{
			Value: eg.RuntimeOverridesEnabled, Source: srcOf("global.runtimeOverrides.enabled"), Mutable: true,
		}
	}

	if g.Telemetry != nil {
		if g.Telemetry.Enabled != nil {
			eg.TelemetryEnabled = *g.Telemetry.Enabled
		}
		if g.Telemetry.RollupsEnabled != nil {
			eg.RollupsEnabled = *g.Telemetry.RollupsEnabled
		}
	}
	fs["global.telemetry.enabled"] = FieldSource{Value: eg.TelemetryEnabled, Source: srcOf("global.telemetry.enabled"), Mutable: true}

	if g.Dump != nil && g.Dump.AllowRaw != nil {
		eg.AllowRawDump = *g.Dump.AllowRaw
	}
	// Startup gate wins: cannot enable raw unless startup allows.
	if !st.AllowRawDump {
		eg.AllowRawDump = false
		fs["global.dump.allowRaw"] = FieldSource{
			Value: false, Source: SourceStartupConstraint, Mutable: false, RestartRequired: true,
		}
	} else {
		fs["global.dump.allowRaw"] = FieldSource{Value: eg.AllowRawDump, Source: srcOf("global.dump.allowRaw"), Mutable: false, RestartRequired: true}
	}

	if g.HardLimits != nil {
		if g.HardLimits.MaxTotalBytes != nil {
			eg.MaxTotalBytes = *g.HardLimits.MaxTotalBytes
		}
		if g.HardLimits.MaxSingleObjectBytes != nil {
			eg.MaxSingleObjectBytes = *g.HardLimits.MaxSingleObjectBytes
		}
		if g.HardLimits.MaxDumpBytes != nil {
			eg.MaxDumpBytes = *g.HardLimits.MaxDumpBytes
		}
		if g.HardLimits.MaxOperationConcurrency != nil {
			eg.MaxOperationConcurrency = *g.HardLimits.MaxOperationConcurrency
		}
	}
	if st.MaxTotalBytes > 0 {
		eg.MaxTotalBytes = st.MaxTotalBytes
		fs["global.hardLimits.maxTotalBytes"] = FieldSource{Value: eg.MaxTotalBytes, Source: SourceStartupConstraint, Mutable: false, RestartRequired: true}
	} else {
		fs["global.hardLimits.maxTotalBytes"] = FieldSource{Value: eg.MaxTotalBytes, Source: srcOf("global.hardLimits.maxTotalBytes"), Mutable: false, RestartRequired: true}
	}
	if st.MaxSingleObjectBytes > 0 {
		eg.MaxSingleObjectBytes = st.MaxSingleObjectBytes
	}
	if st.MaxDumpBytes > 0 {
		eg.MaxDumpBytes = st.MaxDumpBytes
	}
	if st.MaxOperationConcurrency > 0 {
		eg.MaxOperationConcurrency = st.MaxOperationConcurrency
	}
	if st.DumpRoot != "" {
		eg.DumpRoot = st.DumpRoot
	} else if g.Dump != nil {
		eg.DumpRoot = g.Dump.Root
	}
	if g.OperationManager != nil && g.OperationManager.PlanTTL != nil {
		eg.PlanTTL = g.OperationManager.PlanTTL.D
	}
	return eg, fs
}

// TypeMode returns the effective mode for id, or ModeOff if unknown.
func (e EffectiveConfig) TypeMode(id TypeID) Mode {
	if e.Types == nil {
		return ModeOff
	}
	tc, ok := e.Types[id]
	if !ok {
		return ModeOff
	}
	return tc.Mode
}

// TypeConfig returns the effective type config, or zero/false.
func (e EffectiveConfig) TypeConfig(id TypeID) (EffectiveTypeConfig, bool) {
	if e.Types == nil {
		return EffectiveTypeConfig{}, false
	}
	tc, ok := e.Types[id]
	return tc, ok
}
