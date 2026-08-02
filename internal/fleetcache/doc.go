// Package fleetcache is the pure-Go multi-fleet peer shared-cache coordination
// layer (FLC epic / ADR 0016).
//
// Phase foundation (this package today):
//   - Fail-closed budget/mode defaults (default mode off)
//   - Canonical locator and sealed-version identity (no local profile/generation IDs)
//
// Runtime peer protocol, fill leases, and RF2 are later FLC tasks. This package
// must not claim peer-read Done until those land. Operator SoT:
// docs/fleet/shared-cache-architecture.md and docs/fleet/shared-cache-slos.md.
//
// HOST-008 multi-pod vault/session HA remains cancelled; members stay independent.
package fleetcache
