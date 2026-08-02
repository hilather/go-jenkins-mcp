package fleetcache

import "strings"

// Copy-role labels for fleet-aware quota / L1 release planning (FLC-050).
// Secret-free, low-cardinality; used only when fleet-aware mode is on.
const (
	// CopyRoleRequired is a healthy RF owner replica (must not be preferred for reclaim).
	CopyRoleRequired = "required"
	// CopyRoleNear is a non-RF near-cache copy (FLC-033); reclaim before required.
	CopyRoleNear = "near"
	// CopyRoleIncomplete is staging / partial / quarantined local material.
	CopyRoleIncomplete = "incomplete"
	// CopyRoleObsolete is superseded or no-longer-needed material.
	CopyRoleObsolete = "obsolete"
	// CopyRoleUnknown is role not yet classified (store hook partial residual).
	CopyRoleUnknown = "unknown"
)

// Quota residual codes (secret-free).
const (
	// ResidualPinSkip: candidate is pinned; never selected for reclaim/release.
	ResidualPinSkip = "pin_skip"
	// ResidualUnderReplicatedEnqueueRepair: required owner was removed under hard
	// disk safety — must not remain falsely healthy; enqueue repair (FLC-044).
	ResidualUnderReplicatedEnqueueRepair = "under_replicated_enqueue_repair"
)

// EvictCandidate is one local object considered for reclaim under owner-aware
// quota (FLC-050). Pure planner input; store attaches metadata when available.
//
// Secret-free: no tokens, paths with credentials, or raw subject keys.
type EvictCandidate struct {
	GenerationID int64
	// LocatorHash is the fleet locator hash when known (64 hex); empty for non-fleet.
	LocatorHash string
	// CopyRole is required | near | incomplete | obsolete | unknown.
	CopyRole string
	// Bytes is estimated reclaimable physical bytes.
	Bytes int64
	// IsHardSafety is true when disk hard threshold forces removal (wins over role).
	IsHardSafety bool
	// Pinned is true when pin/lease protects the object (always deferred when fleetAware).
	Pinned bool
}

// keyedEvict is the sort record for OrderEvictCandidates (fleetAware path).
type keyedEvict struct {
	idx  int
	c    EvictCandidate
	pin  int // 0 = not pinned, 1 = pinned (deferred)
	hard int // 0 = hard safety (and not pinned), 1 = soft
	role int // lower = evict sooner
}

// roleEvictPriority returns lower = evict sooner when fleetAware.
// Incomplete < near < obsolete < unknown < required.
func roleEvictPriority(role string) int {
	switch NormalizeCopyRole(role) {
	case CopyRoleIncomplete:
		return 0
	case CopyRoleNear:
		return 1
	case CopyRoleObsolete:
		return 2
	case CopyRoleUnknown:
		return 3
	case CopyRoleRequired:
		return 4
	default:
		return 3
	}
}

// NormalizeCopyRole lowercases and maps empty/unknown labels to CopyRoleUnknown.
func NormalizeCopyRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case CopyRoleRequired:
		return CopyRoleRequired
	case CopyRoleNear:
		return CopyRoleNear
	case CopyRoleIncomplete:
		return CopyRoleIncomplete
	case CopyRoleObsolete:
		return CopyRoleObsolete
	case CopyRoleUnknown, "":
		return CopyRoleUnknown
	default:
		return CopyRoleUnknown
	}
}

// OrderEvictCandidates returns candidates ordered for reclaim.
//
// When fleetAware is false (mode off / non-fleet path): preserves input order
// and does not reorder by CopyRole — existing non-fleet quota order wins.
//
// When fleetAware is true:
//  1. Pinned candidates are deferred to the end (callers skip with ResidualPinSkip).
//  2. IsHardSafety candidates come before non-hard candidates (hard disk wins).
//  3. Among equal hard-safety tier: incomplete < near < obsolete < unknown < required.
//  4. Stable on original index for ties.
//
// Pins are never ordered first when fleetAware (even if IsHardSafety).
func OrderEvictCandidates(cands []EvictCandidate, fleetAware bool) []EvictCandidate {
	if len(cands) == 0 {
		return nil
	}
	out := make([]EvictCandidate, len(cands))
	copy(out, cands)
	if !fleetAware {
		// Mode off: do not reorder by role (or pin/hard flags). Stable input order.
		return out
	}

	keys := make([]keyedEvict, len(out))
	for i, c := range out {
		k := keyedEvict{idx: i, c: c, role: roleEvictPriority(c.CopyRole), hard: 1}
		if c.Pinned {
			k.pin = 1
		} else if c.IsHardSafety {
			k.hard = 0
		}
		keys[i] = k
	}
	// Stable insertion sort; candidate lists are small (per-profile generations).
	for i := 1; i < len(keys); i++ {
		j := i
		for j > 0 && evictLess(keys[j], keys[j-1]) {
			keys[j], keys[j-1] = keys[j-1], keys[j]
			j--
		}
	}
	for i, k := range keys {
		out[i] = k.c
	}
	return out
}

func evictLess(a, b keyedEvict) bool {
	if a.pin != b.pin {
		return a.pin < b.pin
	}
	if a.hard != b.hard {
		return a.hard < b.hard
	}
	if a.role != b.role {
		return a.role < b.role
	}
	return a.idx < b.idx
}

// ShouldSkipL1Release reports whether L1 frame release should be deferred for a
// copy with the given role when fleetAware is on.
//
// Active required owner replicas skip L1 release so RF health is not silently
// degraded by packing-side cleanup. Near / incomplete / obsolete do not skip.
// When fleetAware is false, always returns false (non-fleet release unchanged).
func ShouldSkipL1Release(role string, fleetAware bool) bool {
	if !fleetAware {
		return false
	}
	return NormalizeCopyRole(role) == CopyRoleRequired
}

// OwnerRemovalResidual returns the secret-free residual when a local copy was
// removed under quota/eviction. If a required owner replica was removed, the
// residual signals under-replication and that repair must be enqueued — the
// object must not remain falsely healthy.
//
// When removedRequired is false, returns empty string (no repair residual).
func OwnerRemovalResidual(removedRequired bool) string {
	if !removedRequired {
		return ""
	}
	return ResidualUnderReplicatedEnqueueRepair
}

// InferCopyRoleFromMappingStatus maps a fleet_object_mapping / import journal
// status string to a best-effort CopyRole (store hook partial residual).
//
// Committed mappings without RF-membership context return unknown — callers
// that know local membership among SelectPrimaryOwners may upgrade to required
// or near. Staging/quarantined → incomplete. Empty/aborted → obsolete.
func InferCopyRoleFromMappingStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "committed":
		return CopyRoleUnknown // store hook partial: may be required or near
	case "staging", "quarantined":
		return CopyRoleIncomplete
	case "aborted", "obsolete":
		return CopyRoleObsolete
	case "near":
		return CopyRoleNear
	case "required":
		return CopyRoleRequired
	default:
		return CopyRoleUnknown
	}
}

// PinSkipResidual returns ResidualPinSkip when pinned is true; else empty.
// Callers use this when filtering deferred pin candidates from apply lists.
func PinSkipResidual(pinned bool) string {
	if pinned {
		return ResidualPinSkip
	}
	return ""
}
