// Package fleetcache is the pure-Go multi-fleet peer shared-cache coordination
// layer (FLC epic / ADR 0016).
//
// Phase foundation (this package today):
//   - Fail-closed budget/mode defaults (default mode off) + operator StatusSummary
//   - Canonical locator and sealed-version identity (no local profile/generation IDs)
//   - Wire protocol validation, placement, scoped peer assertions (HMAC + nonce)
//
// Runtime peer-read HTTP handlers, fill leases, and RF2 are later FLC tasks.
// Mode=read alone is not peer-read Done (PeerReadHandlersLive is always false here).
// Operator SoT: docs/fleet/shared-cache-architecture.md and docs/fleet/shared-cache-slos.md.
//
// HOST-008 multi-pod vault/session HA remains cancelled; members stay independent.
package fleetcache
