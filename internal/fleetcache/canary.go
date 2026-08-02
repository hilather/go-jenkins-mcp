package fleetcache

import (
	"fmt"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Canary rollout criteria + fail-closed transitions (FLC-072).
//
// Offline library: entry/exit/rollback checklists, adjacent-only promotions,
// any→off rollback without data migration, and preconditions for read/full.
// Live multi-host canary orchestration remains residual (see CanaryHonestyResidual).

// CanaryStage is a fleet-cache canary rollout stage (ADR 0016 modes).
type CanaryStage string

const (
	// CanaryStageOff is local-only (product default; rollback target).
	CanaryStageOff CanaryStage = "off"
	// CanaryStageShadow is placement/metrics only; no peer payload I/O.
	CanaryStageShadow CanaryStage = "shadow"
	// CanaryStageRead is MVP A owner-directed peer read.
	CanaryStageRead CanaryStage = "read"
	// CanaryStageFull is fill + RF2 + repair (later gate).
	CanaryStageFull CanaryStage = "full"
)

// Stable residual / reason codes (secret-free, low-cardinality).
const (
	// ResidualRollbackNoMigration documents that rollback needs no data migration.
	ResidualRollbackNoMigration = "rollback_no_migration"
	// ResidualTransitionAdjacentOnly denies non-adjacent promotions.
	ResidualTransitionAdjacentOnly = "transition_adjacent_only"
	// ResidualTransitionUnknownStage denies unknown from/to stages.
	ResidualTransitionUnknownStage = "transition_unknown_stage"
	// ResidualTransitionNoopSame is a no-op when from==to.
	ResidualTransitionNoopSame = "transition_noop_same"
	// ResidualTransitionAllowed is a normal allowed adjacent step.
	ResidualTransitionAllowed = "transition_allowed"
	// ResidualPrecondOK means preconditions hold for the requested mode.
	ResidualPrecondOK = "precond_ok"
	// ResidualPrecondHandlersNotLive fail-closes read/full without peer handlers.
	ResidualPrecondHandlersNotLive = "precond_handlers_not_live"
	// ResidualPrecondOriginFallbackRequired fail-closes read/full without origin fallback.
	ResidualPrecondOriginFallbackRequired = "precond_origin_fallback_required"
	// ResidualPrecondModeOff always OK (local plane).
	ResidualPrecondModeOff = "precond_mode_off"
	// ResidualPrecondShadowNoPeerIO shadow does not require peer I/O wiring.
	ResidualPrecondShadowNoPeerIO = "precond_shadow_no_peer_io"
	// ResidualPrecondUnknownMode fail-closes unknown ModeRequested.
	ResidualPrecondUnknownMode = "precond_unknown_mode"
	// ResidualCanaryUnknownStage is CriteriaFor unknown stage.
	ResidualCanaryUnknownStage = "canary_unknown_stage"
)

// CanaryHonestyResidual is the offline vs live multi-host residual (secret-free).
// FLC-072 ships the criteria library + unit transitions; live multi-host canary
// orchestration / operator dashboards remain residual.
const CanaryHonestyResidual = "FLC-072 Done* offline canary criteria library; live multi-host canary residual; mode default off; no silent full enable"

// Entry / exit / rollback checklist codes (secret-free stable tokens).
const (
	// Shadow stage
	CritShadowEntryModeOffOrPrior    = "entry_mode_off_or_prior_shadow"
	CritShadowEntryPlacementLive     = "entry_placement_library_live"
	CritShadowEntryMetricsLocal      = "entry_metrics_process_local_ok"
	CritShadowEntryOperatorApproval  = "entry_operator_approval_shadow"
	CritShadowExitPlacementMatch     = "exit_placement_predictions_match"
	CritShadowExitZeroPeerPayload    = "exit_zero_peer_payload_bytes"
	CritShadowExitNoAuthSpikes       = "exit_no_auth_denial_spikes"
	CritShadowRollbackSetModeOff     = "rollback_set_mode_off"
	CritShadowRollbackNoMigration    = "rollback_no_data_migration"
	CritShadowRollbackLocalUnchanged = "rollback_local_plane_a_unchanged"

	// Read stage
	CritReadEntryShadowExitOK     = "entry_shadow_exit_criteria_met"
	CritReadEntryHandlersLive     = "entry_peer_read_handlers_live"
	CritReadEntryOriginFallback   = "entry_origin_fallback_on"
	CritReadEntrySmallPool        = "entry_small_controller_pool"
	CritReadEntryOperatorApproval = "entry_operator_approval_read"
	CritReadExitSourceParity      = "exit_source_metadata_parity"
	CritReadExitOriginProven      = "exit_origin_fallback_proven"
	CritReadExitNoCorruption      = "exit_no_corruption_alerts"
	CritReadRollbackSetModeOff    = "rollback_set_mode_off"
	CritReadRollbackNoMigration   = "rollback_no_data_migration"
	CritReadRollbackLocalIntact   = "rollback_local_cache_intact"

	// Full stage
	CritFullEntryReadExitOK         = "entry_read_exit_criteria_met"
	CritFullEntryHandlersLive       = "entry_peer_read_handlers_live"
	CritFullEntryOriginFallback     = "entry_origin_fallback_on"
	CritFullEntryRF2LibraryLive     = "entry_rf2_repair_library_live"
	CritFullEntryStrictLimits       = "entry_strict_budget_limits"
	CritFullEntryOperatorApproval   = "entry_operator_approval_full"
	CritFullExitReplicaHealth       = "exit_replica_health_ok"
	CritFullExitMeasuredSavings     = "exit_measured_savings_justify"
	CritFullExitNoUnexplainedAlerts = "exit_no_unexplained_auth_or_corruption"
	CritFullRollbackSetModeOff      = "rollback_set_mode_off"
	CritFullRollbackNoMigration     = "rollback_no_data_migration"
	CritFullRollbackLocalRestored   = "rollback_local_behavior_restored"

	// Off stage (local-only baseline)
	CritOffEntryDefaultLocal = "entry_mode_off_local_only"
	CritOffExitN_A           = "exit_n_a_default"
	CritOffRollbackN_A       = "rollback_n_a_already_off"
)

// CanaryCriteria is the entry/exit/rollback checklist for one stage.
// All strings are stable secret-free codes (never tokens, URLs with creds, or job free-text).
type CanaryCriteria struct {
	Stage    CanaryStage
	Entry    []string
	Exit     []string
	Rollback []string
}

// CriteriaFor returns entry/exit/rollback criteria for a canary stage.
// Unknown stages error fail-closed (no silent empty enable checklist).
func CriteriaFor(stage CanaryStage) (CanaryCriteria, error) {
	s := normalizeCanaryStage(stage)
	switch s {
	case CanaryStageOff:
		return CanaryCriteria{
			Stage:    CanaryStageOff,
			Entry:    []string{CritOffEntryDefaultLocal},
			Exit:     []string{CritOffExitN_A},
			Rollback: []string{CritOffRollbackN_A},
		}, nil
	case CanaryStageShadow:
		return CanaryCriteria{
			Stage: CanaryStageShadow,
			Entry: []string{
				CritShadowEntryModeOffOrPrior,
				CritShadowEntryPlacementLive,
				CritShadowEntryMetricsLocal,
				CritShadowEntryOperatorApproval,
			},
			Exit: []string{
				CritShadowExitPlacementMatch,
				CritShadowExitZeroPeerPayload,
				CritShadowExitNoAuthSpikes,
			},
			Rollback: []string{
				CritShadowRollbackSetModeOff,
				CritShadowRollbackNoMigration,
				CritShadowRollbackLocalUnchanged,
			},
		}, nil
	case CanaryStageRead:
		return CanaryCriteria{
			Stage: CanaryStageRead,
			Entry: []string{
				CritReadEntryShadowExitOK,
				CritReadEntryHandlersLive,
				CritReadEntryOriginFallback,
				CritReadEntrySmallPool,
				CritReadEntryOperatorApproval,
			},
			Exit: []string{
				CritReadExitSourceParity,
				CritReadExitOriginProven,
				CritReadExitNoCorruption,
			},
			Rollback: []string{
				CritReadRollbackSetModeOff,
				CritReadRollbackNoMigration,
				CritReadRollbackLocalIntact,
			},
		}, nil
	case CanaryStageFull:
		return CanaryCriteria{
			Stage: CanaryStageFull,
			Entry: []string{
				CritFullEntryReadExitOK,
				CritFullEntryHandlersLive,
				CritFullEntryOriginFallback,
				CritFullEntryRF2LibraryLive,
				CritFullEntryStrictLimits,
				CritFullEntryOperatorApproval,
			},
			Exit: []string{
				CritFullExitReplicaHealth,
				CritFullExitMeasuredSavings,
				CritFullExitNoUnexplainedAlerts,
			},
			Rollback: []string{
				CritFullRollbackSetModeOff,
				CritFullRollbackNoMigration,
				CritFullRollbackLocalRestored,
			},
		}, nil
	default:
		return CanaryCriteria{}, apperr.New(apperr.CodeInvalidArgument,
			"unknown canary stage (want off|shadow|read|full); residual="+ResidualCanaryUnknownStage)
	}
}

// CanaryTransition is a validated stage change (or denied residual).
type CanaryTransition struct {
	From     CanaryStage
	To       CanaryStage
	Residual string
	Allowed  bool
}

// stageOrder is the promotion ladder (adjacent steps only for non-rollback).
var stageOrder = []CanaryStage{
	CanaryStageOff,
	CanaryStageShadow,
	CanaryStageRead,
	CanaryStageFull,
}

func stageIndex(s CanaryStage) int {
	s = normalizeCanaryStage(s)
	for i, st := range stageOrder {
		if st == s {
			return i
		}
	}
	return -1
}

// ValidateTransition fail-closes non-adjacent promotions.
// Allowed paths: same stage (noop), any→off (rollback), or adjacent ladder steps
// (off↔shadow↔read↔full). off→full and off→read are denied (no silent full enable).
func ValidateTransition(from, to CanaryStage) CanaryTransition {
	fromN := normalizeCanaryStage(from)
	toN := normalizeCanaryStage(to)
	tr := CanaryTransition{From: fromN, To: toN}

	fi := stageIndex(fromN)
	ti := stageIndex(toN)
	if fi < 0 || ti < 0 {
		tr.Allowed = false
		tr.Residual = ResidualTransitionUnknownStage
		return tr
	}
	if fromN == toN {
		tr.Allowed = true
		tr.Residual = ResidualTransitionNoopSame
		return tr
	}
	// Rollback to local-only is always allowed (no migration).
	if toN == CanaryStageOff {
		tr.Allowed = true
		tr.Residual = ResidualRollbackNoMigration
		return tr
	}
	// Adjacent only (one step up or down the ladder, excluding handled rollback).
	diff := fi - ti
	if diff < 0 {
		diff = -diff
	}
	if diff == 1 {
		tr.Allowed = true
		tr.Residual = ResidualTransitionAllowed
		return tr
	}
	tr.Allowed = false
	tr.Residual = ResidualTransitionAdjacentOnly
	return tr
}

// RollbackToOff is always allowed from any known stage; no data migration.
// Restores local-only behavior (mode off). Unknown from → still maps To=off Allowed.
func RollbackToOff(from CanaryStage) CanaryTransition {
	fromN := normalizeCanaryStage(from)
	if stageIndex(fromN) < 0 {
		// Unknown treated as off-target rollback of a bad stage string.
		fromN = CanaryStage(strings.TrimSpace(string(from)))
		if fromN == "" {
			fromN = CanaryStageOff
		}
	}
	return CanaryTransition{
		From:     fromN,
		To:       CanaryStageOff,
		Residual: ResidualRollbackNoMigration,
		Allowed:  true,
	}
}

// ApplyCanaryMode maps a canary stage to fleetcache.Mode (fail-closed on unknown).
// Empty stage maps to ModeOff (same as ResolveConfig empty mode).
func ApplyCanaryMode(stage CanaryStage) (Mode, error) {
	s := normalizeCanaryStage(stage)
	if s == "" {
		return ModeOff, nil
	}
	switch s {
	case CanaryStageOff:
		return ModeOff, nil
	case CanaryStageShadow:
		return ModeShadow, nil
	case CanaryStageRead:
		return ModeRead, nil
	case CanaryStageFull:
		return ModeFull, nil
	default:
		return ModeOff, apperr.New(apperr.CodeInvalidArgument,
			"invalid canary stage for mode map (want off|shadow|read|full)")
	}
}

// CanaryPrecondition gates enabling peer-capable modes (read/full).
// Shadow does not require peer I/O; read/full require handlers live + origin fallback.
// Missing preconditions fail closed (no silent full enable).
type CanaryPrecondition struct {
	// HandlersLive: owner-directed lookup + decoded read library paths available.
	HandlersLive bool
	// OriginFallback: authorized Jenkins origin fallback is on (product non-negotiable).
	OriginFallback bool
	// ModeRequested: target Mode (off|shadow|read|full).
	ModeRequested Mode
}

// CheckCanaryPreconditions fail-closes read/full without handlers + origin fallback.
// Returns (ok, residual). Residual is always a stable secret-free code.
func CheckCanaryPreconditions(p CanaryPrecondition) (ok bool, residual string) {
	mode := Mode(strings.ToLower(strings.TrimSpace(string(p.ModeRequested))))
	if mode == "" {
		mode = ModeOff
	}
	switch mode {
	case ModeOff:
		return true, ResidualPrecondModeOff
	case ModeShadow:
		// Placement/metrics only; peer I/O not required.
		return true, ResidualPrecondShadowNoPeerIO
	case ModeRead, ModeFull:
		if !p.HandlersLive {
			return false, ResidualPrecondHandlersNotLive
		}
		if !p.OriginFallback {
			return false, ResidualPrecondOriginFallbackRequired
		}
		return true, ResidualPrecondOK
	default:
		return false, ResidualPrecondUnknownMode
	}
}

// ParseCanaryStage parses a stage string (empty → off). Unknown → error.
func ParseCanaryStage(raw string) (CanaryStage, error) {
	s := normalizeCanaryStage(CanaryStage(raw))
	if s == "" {
		return CanaryStageOff, nil
	}
	if stageIndex(s) < 0 {
		return "", apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("invalid canary stage %q (want off|shadow|read|full)", strings.TrimSpace(raw)))
	}
	return s, nil
}

// KnownCanaryStages returns the promotion ladder in order.
func KnownCanaryStages() []CanaryStage {
	out := make([]CanaryStage, len(stageOrder))
	copy(out, stageOrder)
	return out
}

func normalizeCanaryStage(s CanaryStage) CanaryStage {
	return CanaryStage(strings.ToLower(strings.TrimSpace(string(s))))
}
