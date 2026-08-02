package fleetcache

import (
	"strings"
)

// Isolation residual codes (FLC-052) — low-cardinality, secret-free.
// Shared physical cache bytes never elevate authorization across subjects,
// controllers, fleets, or pools.
const (
	// IsolationResidualOK: locator scope matches expected fleet/pool/controller and authz allows.
	IsolationResidualOK = "isolation_ok"
	// IsolationResidualAuthzDeny: FreshnessGate (or equivalent) denied independent current authorization.
	IsolationResidualAuthzDeny = "isolation_authz_deny"
	// IsolationResidualControllerMismatch: object controller_id ≠ request expected controller.
	IsolationResidualControllerMismatch = "isolation_controller_mismatch"
	// IsolationResidualFleetMismatch: object fleet_id ≠ request expected fleet.
	IsolationResidualFleetMismatch = "isolation_fleet_mismatch"
	// IsolationResidualPoolMismatch: object cache_pool ≠ request expected pool.
	IsolationResidualPoolMismatch = "isolation_pool_mismatch"
	// IsolationResidualLocatorInvalid: locator failed validation (fail closed).
	IsolationResidualLocatorInvalid = "isolation_locator_invalid"
	// IsolationResidualLocatorHashMismatch: provided request locator_hash ≠ Locator.Hash().
	IsolationResidualLocatorHashMismatch = "isolation_locator_hash_mismatch"
)

// IsolationRequest is a pure composition of locator identity + authz + fleet/pool/controller scope.
// All fields must be secret-free (opaque subject hash only if present; never tokens/cookies).
type IsolationRequest struct {
	// Locator is the cache object identity under test (fleet/pool/controller/job/build only).
	Locator Locator
	// ExpectedFleetID is the caller's bound fleet; empty skips fleet match (not recommended for peers).
	ExpectedFleetID string
	// ExpectedCachePool is the caller's bound cache pool; empty skips pool match.
	ExpectedCachePool string
	// ExpectedControllerID is the caller's bound controller; empty skips controller match.
	ExpectedControllerID string
	// RequestLocatorHash, when non-empty, must equal Locator.Hash() (wire/request binding).
	RequestLocatorHash string
	// AuthzAllowed is the FreshnessGate (or equivalent deny-only probe) outcome.
	// Physical presence of sealed bytes on a sink must not set this true for a denied subject.
	AuthzAllowed bool
}

// IsolationResult is secret-free: Allowed plus a stable residual code only.
type IsolationResult struct {
	Allowed  bool
	Residual string
}

// IsolationCheck composes locator equality, fleet/pool/controller match, and authz (FLC-052).
// Order: validate locator → optional hash bind → fleet → pool → controller → authz.
// Never elevates on cache hit; never embeds secrets in residuals.
func IsolationCheck(req IsolationRequest) IsolationResult {
	if err := req.Locator.validate(); err != nil {
		return IsolationResult{Allowed: false, Residual: IsolationResidualLocatorInvalid}
	}
	if h := strings.ToLower(strings.TrimSpace(req.RequestLocatorHash)); h != "" {
		got, err := req.Locator.Hash()
		if err != nil || !strings.EqualFold(got, h) {
			return IsolationResult{Allowed: false, Residual: IsolationResidualLocatorHashMismatch}
		}
	}
	// Exact match after trim (same fail-closed style as assertion Expected.FleetID).
	if exp := strings.TrimSpace(req.ExpectedFleetID); exp != "" {
		if exp != strings.TrimSpace(req.Locator.FleetID) {
			return IsolationResult{Allowed: false, Residual: IsolationResidualFleetMismatch}
		}
	}
	if exp := strings.TrimSpace(req.ExpectedCachePool); exp != "" {
		if exp != strings.TrimSpace(req.Locator.CachePool) {
			return IsolationResult{Allowed: false, Residual: IsolationResidualPoolMismatch}
		}
	}
	if exp := strings.TrimSpace(req.ExpectedControllerID); exp != "" {
		if exp != strings.TrimSpace(req.Locator.ControllerID) {
			return IsolationResult{Allowed: false, Residual: IsolationResidualControllerMismatch}
		}
	}
	if !req.AuthzAllowed {
		return IsolationResult{Allowed: false, Residual: IsolationResidualAuthzDeny}
	}
	return IsolationResult{Allowed: true, Residual: IsolationResidualOK}
}

// IsolationHonestyResidual documents FLC-052 isolation proof status (secret-free).
// Locator identity is fleet/pool/controller/job/build only — never profile/user IDs.
// Crypto key isolation remains residual FLC-053; metrics residual FLC-061.
func IsolationHonestyResidual() string {
	return "FLC-052 isolation proofs Done*; locator excludes profile/user IDs; " +
		"shared physical bytes do not elevate authz; crypto key isolation residual FLC-053; " +
		"metrics residual FLC-061; mode default off"
}
