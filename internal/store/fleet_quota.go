package store

import (
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

// FleetQuotaRoleFromMapping is a thin store → fleetcache hook (FLC-050).
// Maps fleet_object_mapping / import journal status to a CopyRole.
//
// Residual: partial — committed mappings return unknown without RF-membership
// context (callers with SelectPrimaryOwners may upgrade to required/near).
// Non-fleet generations have no mapping; leave role empty/unknown at the planner.
func FleetQuotaRoleFromMapping(status string) string {
	return fleetcache.InferCopyRoleFromMappingStatus(status)
}

// FleetAwareQuotaActive reports whether owner-aware quota ordering should run.
// Mode off/shadow (product default off) keeps existing non-fleet quota order
// unchanged. Shadow is placement/metrics only — no local reclaim reorder.
func FleetAwareQuotaActive(mode fleetcache.Mode) bool {
	m := fleetcache.Mode(strings.ToLower(strings.TrimSpace(string(mode))))
	switch m {
	case fleetcache.ModeRead, fleetcache.ModeFull:
		return true
	default:
		return false
	}
}

// OrderFleetEvictCandidates reorders pure fleetcache candidates when fleet-aware.
// When fleetAware is false, input order is preserved (ARC-007 non-fleet path).
func OrderFleetEvictCandidates(cands []fleetcache.EvictCandidate, fleetAware bool) []fleetcache.EvictCandidate {
	return fleetcache.OrderEvictCandidates(cands, fleetAware)
}

// ShouldSkipFleetL1Release defers L1 release for active required owner replicas
// when fleet-aware; mode-off never skips on role alone.
func ShouldSkipFleetL1Release(role string, fleetAware bool) bool {
	return fleetcache.ShouldSkipL1Release(role, fleetAware)
}

// OwnerRemovalFleetResidual returns under_replicated_enqueue_repair when a
// required owner replica was removed (must not remain falsely healthy).
func OwnerRemovalFleetResidual(removedRequired bool) string {
	return fleetcache.OwnerRemovalResidual(removedRequired)
}
