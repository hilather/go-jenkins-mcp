package cachecontrol

// Decision is the data-path cache decision after mode evaluation.
type Decision string

const (
	// DecisionBypassOrigin skips cache read/write and uses origin only.
	DecisionBypassOrigin Decision = "bypass_origin"
	// DecisionLookupOnly attempts cache read; never fills.
	DecisionLookupOnly Decision = "lookup_only"
	// DecisionFillOnly never serves cache; may fill after origin.
	DecisionFillOnly Decision = "fill_only"
	// DecisionCacheAside is normal read-through / write-through-aside.
	DecisionCacheAside Decision = "cache_aside"
)

// Decide returns the data-path decision for a mode.
// Global cache disabled is treated as off.
func Decide(globalEnabled bool, mode Mode) Decision {
	if !globalEnabled || mode == ModeOff || !mode.Valid() {
		return DecisionBypassOrigin
	}
	switch mode {
	case ModeReadOnly:
		return DecisionLookupOnly
	case ModeWriteOnly:
		return DecisionFillOnly
	case ModeReadWrite:
		return DecisionCacheAside
	default:
		return DecisionBypassOrigin
	}
}

// ShouldLookup is true when the mode may attempt a cache read.
func ShouldLookup(globalEnabled bool, mode Mode) bool {
	d := Decide(globalEnabled, mode)
	return d == DecisionLookupOnly || d == DecisionCacheAside
}

// ShouldFill is true when the mode may commit a cache fill after origin.
func ShouldFill(globalEnabled bool, mode Mode) bool {
	d := Decide(globalEnabled, mode)
	return d == DecisionFillOnly || d == DecisionCacheAside
}

// ModeForResourceKind maps resourcecache kind strings to TypeID modes via EffectiveConfig.
// Unknown kinds return ModeOff (fail closed for unregistered kinds).
func ModeForResourceKind(eff EffectiveConfig, kind string) Mode {
	id := TypeID(kind)
	if !id.Valid() {
		return ModeOff
	}
	// Only resource kinds that are TypeIDs (stage_log, artifact_*, etc.)
	return eff.TypeMode(id)
}
