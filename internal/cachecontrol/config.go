package cachecontrol

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// DeclarativeConfig is the versioned cache control document (file or profile section).
// Absent document ⇒ BuiltInDefaults() via Resolve.
type DeclarativeConfig struct {
	Version int              `json:"version" yaml:"version"`
	Cache   DeclarativeCache `json:"cache" yaml:"cache"`
}

// DeclarativeCache holds global, defaults, and per-type sections.
type DeclarativeCache struct {
	Global   GlobalConfig          `json:"global,omitempty" yaml:"global,omitempty"`
	Defaults TypeConfig            `json:"defaults,omitempty" yaml:"defaults,omitempty"`
	Types    map[string]TypeConfig `json:"types,omitempty" yaml:"types,omitempty"`
}

// GlobalConfig is process/profile-wide cache control settings.
type GlobalConfig struct {
	Enabled          *bool             `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	RuntimeOverrides *RuntimeOvConfig  `json:"runtimeOverrides,omitempty" yaml:"runtimeOverrides,omitempty"`
	Telemetry        *TelemetryConfig  `json:"telemetry,omitempty" yaml:"telemetry,omitempty"`
	OperationManager *OpManagerConfig  `json:"operationManager,omitempty" yaml:"operationManager,omitempty"`
	Dump             *DumpGlobalConfig `json:"dump,omitempty" yaml:"dump,omitempty"`
	HardLimits       *HardLimits       `json:"hardLimits,omitempty" yaml:"hardLimits,omitempty"`
}

// RuntimeOvConfig controls persistent runtime override feature.
type RuntimeOvConfig struct {
	Enabled      *bool         `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	PollInterval *DurationJSON `json:"pollInterval,omitempty" yaml:"pollInterval,omitempty"`
}

// TelemetryConfig controls typed cache telemetry.
type TelemetryConfig struct {
	Enabled        *bool         `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	RollupsEnabled *bool         `json:"rollupsEnabled,omitempty" yaml:"rollupsEnabled,omitempty"`
	Retention      *DurationJSON `json:"retention,omitempty" yaml:"retention,omitempty"`
	FlushInterval  *DurationJSON `json:"flushInterval,omitempty" yaml:"flushInterval,omitempty"`
}

// OpManagerConfig bounds concurrent lifecycle operations.
type OpManagerConfig struct {
	MaxConcurrent   *int          `json:"maxConcurrent,omitempty" yaml:"maxConcurrent,omitempty"`
	MaxQueued       *int          `json:"maxQueued,omitempty" yaml:"maxQueued,omitempty"`
	PlanTTL         *DurationJSON `json:"planTTL,omitempty" yaml:"planTTL,omitempty"`
	RecordRetention *DurationJSON `json:"recordRetention,omitempty" yaml:"recordRetention,omitempty"`
}

// DumpGlobalConfig is startup-influenced dump policy.
type DumpGlobalConfig struct {
	Root                    string        `json:"root,omitempty" yaml:"root,omitempty"`
	MaxBytes                *int64        `json:"maxBytes,omitempty" yaml:"maxBytes,omitempty"`
	Retention               *DurationJSON `json:"retention,omitempty" yaml:"retention,omitempty"`
	AllowMetadata           *bool         `json:"allowMetadata,omitempty" yaml:"allowMetadata,omitempty"`
	AllowSanitized          *bool         `json:"allowSanitized,omitempty" yaml:"allowSanitized,omitempty"`
	AllowStorageNative      *bool         `json:"allowStorageNative,omitempty" yaml:"allowStorageNative,omitempty"`
	AllowRaw                *bool         `json:"allowRaw,omitempty" yaml:"allowRaw,omitempty"`
	RequireEncryptionForRaw *bool         `json:"requireEncryptionForRaw,omitempty" yaml:"requireEncryptionForRaw,omitempty"`
}

// HardLimits are process ceilings (startup-only weakening denied).
type HardLimits struct {
	MaxTotalBytes           *int64 `json:"maxTotalBytes,omitempty" yaml:"maxTotalBytes,omitempty"`
	MaxSingleObjectBytes    *int64 `json:"maxSingleObjectBytes,omitempty" yaml:"maxSingleObjectBytes,omitempty"`
	MaxDumpBytes            *int64 `json:"maxDumpBytes,omitempty" yaml:"maxDumpBytes,omitempty"`
	MaxOperationConcurrency *int   `json:"maxOperationConcurrency,omitempty" yaml:"maxOperationConcurrency,omitempty"`
}

// TypeConfig is per-type or defaults configuration (all fields optional).
type TypeConfig struct {
	Mode             *Mode             `json:"mode,omitempty" yaml:"mode,omitempty"`
	TelemetryEnabled *bool             `json:"telemetryEnabled,omitempty" yaml:"telemetryEnabled,omitempty"`
	Quota            *QuotaConfig      `json:"quota,omitempty" yaml:"quota,omitempty"`
	Freshness        *FreshnessConfig  `json:"freshness,omitempty" yaml:"freshness,omitempty"`
	Eviction         *EvictionConfig   `json:"eviction,omitempty" yaml:"eviction,omitempty"`
	L0               *L0Config         `json:"l0,omitempty" yaml:"l0,omitempty"`
	FleetShare       *FleetShareConfig `json:"fleetShare,omitempty" yaml:"fleetShare,omitempty"`
	Dump             *TypeDumpConfig   `json:"dump,omitempty" yaml:"dump,omitempty"`
	MaxEntries       *int              `json:"maxEntries,omitempty" yaml:"maxEntries,omitempty"`
	MaxObjectBytes   *int64            `json:"maxObjectBytes,omitempty" yaml:"maxObjectBytes,omitempty"`
}

// QuotaConfig holds soft/hard bytes and watermarks.
type QuotaConfig struct {
	SoftBytes     *int64   `json:"softBytes,omitempty" yaml:"softBytes,omitempty"`
	HardBytes     *int64   `json:"hardBytes,omitempty" yaml:"hardBytes,omitempty"`
	HighWatermark *float64 `json:"highWatermark,omitempty" yaml:"highWatermark,omitempty"`
	LowWatermark  *float64 `json:"lowWatermark,omitempty" yaml:"lowWatermark,omitempty"`
}

// FreshnessConfig holds TTL policy.
// TerminalTTL of 0 means no time-based expiry (not immediate expiry).
type FreshnessConfig struct {
	BuildingTTL     *DurationJSON `json:"buildingTTL,omitempty" yaml:"buildingTTL,omitempty"`
	TerminalTTL     *DurationJSON `json:"terminalTTL,omitempty" yaml:"terminalTTL,omitempty"`
	StaleIfError    *DurationJSON `json:"staleIfError,omitempty" yaml:"staleIfError,omitempty"`
	RevalidateAfter *DurationJSON `json:"revalidateAfter,omitempty" yaml:"revalidateAfter,omitempty"`
}

// EvictionConfig holds eviction priority knobs.
type EvictionConfig struct {
	Priority   *int          `json:"priority,omitempty" yaml:"priority,omitempty"`
	MinimumAge *DurationJSON `json:"minimumAge,omitempty" yaml:"minimumAge,omitempty"`
}

// L0Config is in-process hot cache settings.
type L0Config struct {
	Enabled    *bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	MaxEntries *int  `json:"maxEntries,omitempty" yaml:"maxEntries,omitempty"`
}

// FleetShareConfig is a distribution capability, not a payload type.
type FleetShareConfig struct {
	Enabled *bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`
}

// TypeDumpConfig lists allowed dump modes for the type (within startup allowlist).
type TypeDumpConfig struct {
	AllowedModes []DumpMode `json:"allowedModes,omitempty" yaml:"allowedModes,omitempty"`
}

// DurationJSON marshals time.Duration as a string (e.g. "5s", "720h").
type DurationJSON struct {
	D time.Duration
}

func (d DurationJSON) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.D.String())
}

func (d *DurationJSON) UnmarshalJSON(b []byte) error {
	if d == nil {
		return fmt.Errorf("nil DurationJSON")
	}
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		if s == "" {
			d.D = 0
			return nil
		}
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("duration: %w", err)
		}
		d.D = parsed
		return nil
	}
	// allow numeric nanoseconds for internal tests
	var n int64
	if err := json.Unmarshal(b, &n); err == nil {
		d.D = time.Duration(n)
		return nil
	}
	return fmt.Errorf("duration must be string like 5s")
}

// StartupConstraints are immutable process safety rails (flags/env).
type StartupConstraints struct {
	// ForceOff forces these types to mode off (highest precedence).
	ForceOff []TypeID
	// DisableRuntimeMutations blocks runtime override APIs.
	DisableRuntimeMutations bool
	// AllowRawDump is the startup capability for raw dump (default false).
	AllowRawDump bool
	// MaxTotalBytes ceiling (0 = use built-in default ceiling).
	MaxTotalBytes int64
	// MaxSingleObjectBytes ceiling.
	MaxSingleObjectBytes int64
	// MaxDumpBytes ceiling.
	MaxDumpBytes int64
	// MaxOperationConcurrency ceiling.
	MaxOperationConcurrency int
	// DumpRoot is the only allowed dump destination root (startup-only).
	DumpRoot string
}

// RuntimeOverrides is a revisioned set of per-type field patches.
type RuntimeOverrides struct {
	Revision uint64
	// Types maps type id → partial TypeConfig overlays.
	Types map[TypeID]TypeConfig
	// Expired fields are not present; caller filters before Resolve.
}

// EffectiveConfig is an immutable resolved snapshot.
type EffectiveConfig struct {
	Revision uint64
	LoadedAt time.Time
	Global   EffectiveGlobal
	Types    map[TypeID]EffectiveTypeConfig
	// SourceDetails maps "types.<id>.mode" etc. → provenance.
	SourceDetails map[string]FieldSource
}

// EffectiveGlobal is resolved global settings.
type EffectiveGlobal struct {
	Enabled                 bool
	RuntimeOverridesEnabled bool
	TelemetryEnabled        bool
	RollupsEnabled          bool
	AllowRawDump            bool
	MaxTotalBytes           int64
	MaxSingleObjectBytes    int64
	MaxDumpBytes            int64
	MaxOperationConcurrency int
	DumpRoot                string
	PlanTTL                 time.Duration
}

// EffectiveTypeConfig is the resolved per-type view used by data paths and admin.
type EffectiveTypeConfig struct {
	TypeID           TypeID
	Mode             Mode
	TelemetryEnabled bool
	SoftBytes        int64
	HardBytes        int64
	HighWatermark    float64
	LowWatermark     float64
	BuildingTTL      time.Duration
	// TerminalTTL 0 means no time-based expiry.
	TerminalTTL      time.Duration
	StaleIfError     time.Duration
	RevalidateAfter  time.Duration
	EvictionPriority int
	MinAge           time.Duration
	L0Enabled        bool
	L0MaxEntries     int
	FleetShare       bool
	MaxEntries       int
	MaxObjectBytes   int64
	AllowedDumpModes []DumpMode
	// PurgeEpoch is supplied by override DB / adapter state (0 if unknown).
	PurgeEpoch uint64
	// ConfigRevision echoes the snapshot revision.
	ConfigRevision uint64
	// ModeSource is convenience for mode provenance.
	ModeSource ConfigSource
}

// FieldSource is provenance for one effective field.
type FieldSource struct {
	Value           any          `json:"value"`
	Source          ConfigSource `json:"source"`
	BaselineValue   any          `json:"baselineValue,omitempty"`
	BaselineSource  ConfigSource `json:"baselineSource,omitempty"`
	Mutable         bool         `json:"mutable"`
	RestartRequired bool         `json:"restartRequired"`
}

// boolPtr / helpers for defaults construction.
func boolPtr(v bool) *bool          { return &v }
func intPtr(v int) *int             { return &v }
func int64Ptr(v int64) *int64       { return &v }
func float64Ptr(v float64) *float64 { return &v }
func modePtr(m Mode) *Mode          { return &m }
func durPtr(d time.Duration) *DurationJSON {
	return &DurationJSON{D: d}
}

// BuiltInDefaults returns the compatibility baseline when all new config is absent.
// Available types: read_write. ratarmount_index: off. Fleet share: false. Raw dump: false.
func BuiltInDefaults() DeclarativeConfig {
	defMode := ModeReadWrite
	off := ModeOff
	falseV := false
	trueV := true
	return DeclarativeConfig{
		Version: 1,
		Cache: DeclarativeCache{
			Global: GlobalConfig{
				Enabled: boolPtr(true),
				RuntimeOverrides: &RuntimeOvConfig{
					Enabled:      boolPtr(true),
					PollInterval: durPtr(2 * time.Second),
				},
				Telemetry: &TelemetryConfig{
					Enabled:        boolPtr(true),
					RollupsEnabled: boolPtr(true),
					Retention:      durPtr(720 * time.Hour),
					FlushInterval:  durPtr(10 * time.Second),
				},
				OperationManager: &OpManagerConfig{
					MaxConcurrent:   intPtr(2),
					MaxQueued:       intPtr(32),
					PlanTTL:         durPtr(10 * time.Minute),
					RecordRetention: durPtr(720 * time.Hour),
				},
				Dump: &DumpGlobalConfig{
					AllowMetadata:           boolPtr(true),
					AllowSanitized:          boolPtr(true),
					AllowStorageNative:      boolPtr(true),
					AllowRaw:                boolPtr(false),
					RequireEncryptionForRaw: boolPtr(true),
					MaxBytes:                int64Ptr(20 << 30),
					Retention:               durPtr(24 * time.Hour),
				},
				HardLimits: &HardLimits{
					MaxTotalBytes:           int64Ptr(100 << 30),
					MaxSingleObjectBytes:    int64Ptr(20 << 30),
					MaxDumpBytes:            int64Ptr(20 << 30),
					MaxOperationConcurrency: intPtr(4),
				},
			},
			Defaults: TypeConfig{
				Mode:             &defMode,
				TelemetryEnabled: &trueV,
				Quota: &QuotaConfig{
					SoftBytes:     int64Ptr(2 << 30),
					HardBytes:     int64Ptr(4 << 30),
					HighWatermark: float64Ptr(0.90),
					LowWatermark:  float64Ptr(0.75),
				},
				Freshness: &FreshnessConfig{
					BuildingTTL:     durPtr(5 * time.Second),
					TerminalTTL:     durPtr(720 * time.Hour),
					StaleIfError:    durPtr(0),
					RevalidateAfter: durPtr(1 * time.Hour),
				},
				Eviction: &EvictionConfig{
					Priority:   intPtr(100),
					MinimumAge: durPtr(5 * time.Minute),
				},
				L0: &L0Config{
					Enabled:    boolPtr(true),
					MaxEntries: intPtr(64),
				},
				FleetShare: &FleetShareConfig{Enabled: &falseV},
				Dump: &TypeDumpConfig{
					AllowedModes: []DumpMode{DumpMetadata, DumpSanitized},
				},
			},
			Types: map[string]TypeConfig{
				string(TypeRatarmountIndex): {
					Mode: &off,
				},
			},
		},
	}
}

// ParseDeclarativeJSON parses a declarative document. Empty input is valid (nil doc).
func ParseDeclarativeJSON(data []byte) (*DeclarativeConfig, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}
	var doc DeclarativeConfig
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("cache config: %w", err)
	}
	if doc.Version == 0 {
		doc.Version = 1
	}
	if doc.Version != 1 {
		return nil, fmt.Errorf("cache config: unsupported version %d", doc.Version)
	}
	return &doc, nil
}

// ValidateDeclarative checks structural invariants without merging.
func ValidateDeclarative(doc *DeclarativeConfig) error {
	if doc == nil {
		return nil
	}
	if doc.Version != 0 && doc.Version != 1 {
		return fmt.Errorf("%s: version", ReasonConstraintViolation)
	}
	for id, tc := range doc.Cache.Types {
		if !TypeID(id).Valid() {
			return fmt.Errorf("%s: types.%s", ReasonUnknownType, id)
		}
		if err := validateTypeConfig(TypeID(id), tc); err != nil {
			return err
		}
	}
	if err := validateTypeConfig(TypeID("defaults"), doc.Cache.Defaults); err != nil {
		return err
	}
	return nil
}

func validateTypeConfig(id TypeID, tc TypeConfig) error {
	if tc.Mode != nil && !tc.Mode.Valid() {
		return fmt.Errorf("%s: types.%s.mode", ReasonUnsupportedMode, id)
	}
	if tc.Quota != nil {
		q := tc.Quota
		if q.SoftBytes != nil && q.HardBytes != nil && *q.SoftBytes > *q.HardBytes {
			return fmt.Errorf("%s: types.%s.quota soft>hard", ReasonConstraintViolation, id)
		}
		if q.HighWatermark != nil && q.LowWatermark != nil {
			if !(*q.LowWatermark > 0 && *q.LowWatermark < *q.HighWatermark && *q.HighWatermark <= 1) {
				return fmt.Errorf("%s: types.%s.quota watermarks", ReasonConstraintViolation, id)
			}
		}
	}
	if tc.Dump != nil {
		for _, m := range tc.Dump.AllowedModes {
			if !m.Valid() {
				return fmt.Errorf("%s: types.%s.dump.allowedModes", ReasonConstraintViolation, id)
			}
		}
	}
	return nil
}
