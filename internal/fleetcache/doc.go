// Package fleetcache is the pure-Go multi-fleet peer shared-cache coordination
// layer (FLC epic / ADR 0016).
//
// Library surfaces (mode default off):
//   - Placement, wire, peer-read, fill, RF2, repair, partition, quota roles, purge
//   - Isolation, metrics, status/doctor, near-cache admission, canary criteria (FLC-072)
//   - Admin facade for BFF/MCP (FLC-063)
//   - Running durable prefix (FLC-080) + finalize without recompress (FLC-081)
//
// Operator runbook: docs/fleet/shared-cache-operator.md (FLC-064).
// Offline release gate: docs/fleet/shared-cache-release-gate.md (FLC-073).
// Object classes: AdmitObjectClass default-deny; console_log only (FLC-082).
// HOST-008 cancelled. Mode default off.
package fleetcache
