// Package cachecontrol is the unified cache control plane (ADR 0018).
//
// It provides:
//   - Stable type IDs, modes, availability, and capability descriptors
//   - An immutable startup registry of managed cache types
//   - Declarative configuration resolution (built-in → server → profile →
//     runtime override → startup/emergency constraints)
//   - Mode helpers for data-path lookup/fill decisions
//   - Shared vocabulary for adminops, telemetry, and lifecycle plan/confirm
//
// It does not replace internal/store (console logs) or internal/resourcecache
// (typed non-log resources). Adapters wrap those stores.
//
// Compatibility: when no cache-control configuration is present, built-in
// defaults match pre-feature behavior (available types read_write;
// ratarmount_index off/unqualified; fleet share off; raw dump disallowed).
//
// Security: mode gates never authorize access. Callers must still authenticate,
// apply MCP/Jenkins policy, re-authorize on hits, redact, and enforce budgets.
package cachecontrol
