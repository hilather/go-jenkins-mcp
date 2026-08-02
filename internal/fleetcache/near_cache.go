package fleetcache

import "strings"

// Optional verified near-cache promotion (FLC-033).
//
// Near copies are non-owner bandwidth wins: a requesting non-owner may retain a
// bounded local copy after verified import when reuse justifies it. Product
// default is off (DefaultNearCachePolicy.Enabled=false). Near role never counts
// toward RF — FilterRFObservations strips near members before PlanRF2Replication
// / PlanRepair; placement SelectPrimaryOwners is unchanged by promotion.

// Default near-cache admission bounds (secret-free constants).
const (
	// DefaultNearMaxObjectBytes refuses promotion of huge logs (8 MiB raw).
	DefaultNearMaxObjectBytes int64 = 8 << 20
	// DefaultNearMinRepeatAccess requires N prior hits before promote.
	DefaultNearMinRepeatAccess = 2
)

// Near residual codes (secret-free, low-cardinality).
const (
	NearResidualDisabled           = "near_disabled"
	NearResidualNoStore            = "near_no_store"
	NearResidualTooLarge           = "near_too_large"
	NearResidualSingleUse          = "near_single_use"
	NearResidualAuthzDeny          = "near_authz_deny"
	NearResidualManifestUnverified = "near_manifest_unverified"
	NearResidualLowSpace           = "near_low_space"
	NearResidualAdmitted           = "near_admitted"
)

// NearCachePolicy controls optional verified near-cache promotion (FLC-033).
// Enabled defaults false (product honesty: remote peer reads work without near).
type NearCachePolicy struct {
	// Enabled: when false, AdmitNearCache always denies (near_disabled).
	Enabled bool
	// MaxObjectBytes: refuse promote if TotalRawBytes > this (default 8 MiB when 0).
	MaxObjectBytes int64
	// MinRepeatAccess: require N prior hits before promote (default 2 when 0).
	MinRepeatAccess int
	// FreeSpaceMinBytes: if FreeSpaceBytes is known and below this, deny (0 = skip).
	FreeSpaceMinBytes int64
	// NoStore: policy override never promote (even when Enabled).
	NoStore bool
}

// DefaultNearCachePolicy returns product defaults: promotion disabled.
// Bounds are populated so callers enabling later inherit safe limits.
func DefaultNearCachePolicy() NearCachePolicy {
	return NearCachePolicy{
		Enabled:           false,
		MaxObjectBytes:    DefaultNearMaxObjectBytes,
		MinRepeatAccess:   DefaultNearMinRepeatAccess,
		FreeSpaceMinBytes: 0,
		NoStore:           false,
	}
}

// NearAdmitRequest is pure admission input (no credentials, no job free-text required).
// LocatorHash may be empty for unit tests; residual codes never embed secrets.
type NearAdmitRequest struct {
	LocatorHash      string
	TotalRawBytes    int64
	PriorAccessCount int
	// FreeSpaceBytes is available free space; 0 means unknown (skip free-space check).
	FreeSpaceBytes int64
	// AuthzAllowed must be true (cache hit ≠ authorization; fail closed).
	AuthzAllowed bool
	// ManifestVerified must be true after verified import/digest check.
	ManifestVerified bool
	Policy           NearCachePolicy
}

// NearAdmitResult is the admission decision (secret-free residual).
type NearAdmitResult struct {
	Admit    bool
	CopyRole string // CopyRoleNear if Admit; empty otherwise
	// Residual: near_disabled | near_no_store | near_too_large | near_single_use |
	// near_authz_deny | near_manifest_unverified | near_low_space | near_admitted
	Residual string
}

// AdmitNearCache evaluates whether a non-owner may retain a near-role local copy.
//
// Rules (first match wins):
//  1. !Enabled → near_disabled
//  2. NoStore → near_no_store
//  3. !AuthzAllowed → near_authz_deny
//  4. !ManifestVerified → near_manifest_unverified
//  5. TotalRawBytes > MaxObjectBytes → near_too_large (huge log / single-use evidence bound)
//  6. PriorAccessCount < MinRepeatAccess → near_single_use
//  7. FreeSpace known and < FreeSpaceMinBytes → near_low_space
//  8. else → admit with CopyRoleNear
//
// Zero MaxObjectBytes / MinRepeatAccess on Policy use package defaults.
// FreeSpaceBytes==0 is unknown (skip space check); FreeSpaceMinBytes==0 skips.
func AdmitNearCache(req NearAdmitRequest) NearAdmitResult {
	pol := req.Policy
	if pol.MaxObjectBytes <= 0 {
		pol.MaxObjectBytes = DefaultNearMaxObjectBytes
	}
	if pol.MinRepeatAccess <= 0 {
		pol.MinRepeatAccess = DefaultNearMinRepeatAccess
	}

	if !pol.Enabled {
		return NearAdmitResult{Residual: NearResidualDisabled}
	}
	if pol.NoStore {
		return NearAdmitResult{Residual: NearResidualNoStore}
	}
	if !req.AuthzAllowed {
		return NearAdmitResult{Residual: NearResidualAuthzDeny}
	}
	if !req.ManifestVerified {
		return NearAdmitResult{Residual: NearResidualManifestUnverified}
	}
	raw := req.TotalRawBytes
	if raw < 0 {
		raw = 0
	}
	if raw > pol.MaxObjectBytes {
		return NearAdmitResult{Residual: NearResidualTooLarge}
	}
	if req.PriorAccessCount < pol.MinRepeatAccess {
		return NearAdmitResult{Residual: NearResidualSingleUse}
	}
	// Free space: FreeSpaceBytes==0 means unknown (skip); only compare when known >0.
	if pol.FreeSpaceMinBytes > 0 && req.FreeSpaceBytes > 0 && req.FreeSpaceBytes < pol.FreeSpaceMinBytes {
		return NearAdmitResult{Residual: NearResidualLowSpace}
	}

	return NearAdmitResult{
		Admit:    true,
		CopyRole: CopyRoleNear,
		Residual: NearResidualAdmitted,
	}
}

// FilterRFObservations drops members marked as near-cache from the RF observation
// map so near copies never count as committed RF owners for PlanRF2Replication /
// PlanRepair / RF health. nearMembers keys are member IDs; true means near role.
//
// Nil or empty nearMembers returns a shallow copy of obs (nil in → nil out).
// Returned map never aliases the input map.
func FilterRFObservations(obs map[string]ReplicaObservation, nearMembers map[string]bool) map[string]ReplicaObservation {
	if obs == nil {
		return nil
	}
	out := make(map[string]ReplicaObservation, len(obs))
	for id, o := range obs {
		if nearMembers != nil && nearMembers[id] {
			continue
		}
		out[id] = o
	}
	return out
}

// CountHealthyRFFromObservations counts required owners with committed matching digest.
// Use after FilterRFObservations so near-only members never inflate healthy RF.
// requiredOwners empty → 0. Secret-free pure helper for metrics/RFHealth wiring.
func CountHealthyRFFromObservations(requiredOwners []string, digest string, obs map[string]ReplicaObservation) int {
	if len(requiredOwners) == 0 || obs == nil {
		return 0
	}
	// Empty digest: no match (fail closed).
	if digest == "" {
		return 0
	}
	n := 0
	for _, id := range requiredOwners {
		o, ok := obs[id]
		if !ok {
			continue
		}
		if o.Status == "committed" && strings.EqualFold(o.Digest, digest) {
			n++
		}
	}
	return n
}
