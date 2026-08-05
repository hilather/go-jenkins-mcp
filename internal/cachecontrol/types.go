package cachecontrol

import (
	"fmt"
	"strings"
)

// TypeID is a stable cache type identifier (closed set for v1).
type TypeID string

const (
	TypeConsoleLog         TypeID = "console_log"
	TypeStageLog           TypeID = "stage_log"
	TypeArtifactBlob       TypeID = "artifact_blob"
	TypeArtifactCatalog    TypeID = "artifact_catalog"
	TypeArtifactText       TypeID = "artifact_text"
	TypeArtifactInspection TypeID = "artifact_inspection"
	TypeTestReport         TypeID = "test_report"
	TypePipelineStages     TypeID = "pipeline_stages"
	TypeBuildChanges       TypeID = "build_changes"
	TypeDiagnosticFetch    TypeID = "diagnostic_fetch"
	TypeSurveySummary      TypeID = "survey_summary"
	TypeRatarmountIndex    TypeID = "ratarmount_index"
)

// AllTypeIDs returns the closed ordered set of managed type IDs.
func AllTypeIDs() []TypeID {
	return []TypeID{
		TypeConsoleLog,
		TypeStageLog,
		TypeArtifactBlob,
		TypeArtifactCatalog,
		TypeArtifactText,
		TypeArtifactInspection,
		TypeTestReport,
		TypePipelineStages,
		TypeBuildChanges,
		TypeDiagnosticFetch,
		TypeSurveySummary,
		TypeRatarmountIndex,
	}
}

// Valid reports whether id is a known type ID.
func (id TypeID) Valid() bool {
	for _, k := range AllTypeIDs() {
		if k == id {
			return true
		}
	}
	return false
}

// Mode is the runtime cache mode for a type.
type Mode string

const (
	ModeOff       Mode = "off"
	ModeReadOnly  Mode = "read_only"
	ModeWriteOnly Mode = "write_only"
	ModeReadWrite Mode = "read_write"
)

// AllModes returns the closed set of modes.
func AllModes() []Mode {
	return []Mode{ModeOff, ModeReadOnly, ModeWriteOnly, ModeReadWrite}
}

// Valid reports whether m is a known mode.
func (m Mode) Valid() bool {
	switch m {
	case ModeOff, ModeReadOnly, ModeWriteOnly, ModeReadWrite:
		return true
	default:
		return false
	}
}

// ParseMode parses a mode string (case-sensitive snake_case).
func ParseMode(s string) (Mode, error) {
	m := Mode(strings.TrimSpace(s))
	if !m.Valid() {
		return "", fmt.Errorf("unknown cache mode %q", s)
	}
	return m, nil
}

// AllowsRead reports whether the mode may serve existing entries.
func (m Mode) AllowsRead() bool {
	return m == ModeReadOnly || m == ModeReadWrite
}

// AllowsWrite reports whether the mode may fill/update entries.
func (m Mode) AllowsWrite() bool {
	return m == ModeWriteOnly || m == ModeReadWrite
}

// StorageClass is the physical/logical storage class for a type.
type StorageClass string

const (
	ClassStreamLog           StorageClass = "stream_log"
	ClassImmutableBlob       StorageClass = "immutable_blob"
	ClassStructuredResource  StorageClass = "structured_resource"
	ClassDerivedResult       StorageClass = "derived_result"
	ClassEphemeralStructured StorageClass = "ephemeral_structured"
	ClassDerivedSummary      StorageClass = "derived_summary"
	ClassDerivedIndex        StorageClass = "derived_index"
)

// Availability is adapter readiness for operators and enablement gates.
type Availability string

const (
	AvailabilityAvailable   Availability = "available"
	AvailabilityUnavailable Availability = "unavailable"
	AvailabilityDegraded    Availability = "degraded"
	AvailabilityUnqualified Availability = "unqualified"
)

// Valid reports whether a is a known availability.
func (a Availability) Valid() bool {
	switch a {
	case AvailabilityAvailable, AvailabilityUnavailable, AvailabilityDegraded, AvailabilityUnqualified:
		return true
	default:
		return false
	}
}

// SizeAccounting describes how byte sizes are reported.
type SizeAccounting string

const (
	SizeExact        SizeAccounting = "exact"
	SizeEstimated    SizeAccounting = "estimated"
	SizeNotAvailable SizeAccounting = "not_available"
)

// DumpMode is an export mode for lifecycle dumps.
type DumpMode string

const (
	DumpMetadata      DumpMode = "metadata"
	DumpSanitized     DumpMode = "sanitized"
	DumpStorageNative DumpMode = "storage_native"
	DumpRaw           DumpMode = "raw"
)

// AllDumpModes returns the closed dump mode set.
func AllDumpModes() []DumpMode {
	return []DumpMode{DumpMetadata, DumpSanitized, DumpStorageNative, DumpRaw}
}

// Valid reports whether d is a known dump mode.
func (d DumpMode) Valid() bool {
	switch d {
	case DumpMetadata, DumpSanitized, DumpStorageNative, DumpRaw:
		return true
	default:
		return false
	}
}

// ConfigSource identifies where an effective field value came from.
type ConfigSource string

const (
	SourceBuiltIn           ConfigSource = "built_in"
	SourceServerConfig      ConfigSource = "server_config"
	SourceProfileConfig     ConfigSource = "profile_config"
	SourceRuntimeOverride   ConfigSource = "runtime_override"
	SourceStartupConstraint ConfigSource = "startup_constraint"
	SourceEmergencyForceOff ConfigSource = "emergency_force_off"
)

// OperationKind is a lifecycle operation kind.
type OperationKind string

const (
	OpDump   OperationKind = "dump"
	OpPurge  OperationKind = "purge"
	OpVerify OperationKind = "verify"
	OpRepair OperationKind = "repair"
	OpGC     OperationKind = "gc"
)

// OperationState is a plan/execution state for lifecycle ops.
type OperationState string

const (
	OpStatePlanned   OperationState = "planned"
	OpStateRunning   OperationState = "running"
	OpStateSucceeded OperationState = "succeeded"
	OpStateFailed    OperationState = "failed"
	OpStateCancelled OperationState = "cancelled"
	OpStateExpired   OperationState = "expired"
)

// Stable error reason codes for control-plane failures (machine-stable).
const (
	ReasonUnknownType         = "unknown_type"
	ReasonUnknownField        = "unknown_field"
	ReasonUnsupportedMode     = "unsupported_mode"
	ReasonUnsupportedOp       = "unsupported_operation"
	ReasonUnavailable         = "type_unavailable"
	ReasonUnqualified         = "type_unqualified"
	ReasonConstraintViolation = "constraint_violation"
	ReasonCASConflict         = "cas_conflict"
	ReasonRuntimeMutationsOff = "runtime_mutations_disabled"
	ReasonRawDumpDisabled     = "raw_dump_disabled"
	ReasonConfirmRequired     = "confirm_required"
	ReasonConfirmMismatch     = "confirm_mismatch"
	ReasonPlanExpired         = "plan_expired"
	ReasonModeDisallowsRead   = "mode_disallows_read"
	ReasonModeDisallowsWrite  = "mode_disallows_write"
)
