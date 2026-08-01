// Package mutation implements the controlled-mutation safety gate (MUT-001/002).
//
// Before any Jenkins write (start/stop/cancel queue), tools must:
//  1. Preview — describe the intended action (job, redacted params, endpoint class)
//     without executing.
//  2. Confirm — present a short-lived, single-use token bound to
//     profile + principal + external subject + tenant + action + target hash.
//  3. Execute only after a valid confirm; never auto-retry POST failures (NET-003).
//
// For start_job (MUT-002), callers must also:
//   - NormalizeParams (reject sensitive names)
//   - ValidateAgainstDefinitions (unknown names, bad choices, secret/unsupported types)
//   - Re-fetch definitions on confirm so job config changes fail closed
//
// Mutations remain behind the global read-only kill switch (POL-001): when
// read-only is effective, Preview and Confirm fail closed even if a token exists.
// Audit events are emitted for preview, confirm, and deny (AUD-001), including
// rate-limit and cooldown denials (reason codes only; no secrets). Audit
// ProfileID/PrincipalID prefer the effective Binding (BindingFromContext when
// multi-user) over process defaults. When Binding carries ExternalSubject,
// events also include ExternalSubject and SubjectKeyHash =
// audit.HashOpaque(tenant|external|profile) for multi-user correlation — never
// raw subject keys, confirmation tokens, or vault material. Multi-pod / fleet
// audit aggregation remains residual (per-process JSONL only).
//
// # Subject binding (HOST-006 multi-user foundation)
//
// Confirmation tokens store a Binding fingerprint at Preview and re-check it at
// Confirm against the effective request subject. Process defaults come from
// Config.ProfileID / PrincipalID / ExternalSubject / Tenant. When
// Config.BindingFromContext is set and returns ok, that per-request Binding is
// used for issue, match, cooldown keys, and audit attribution — so Alice's
// preview token is rejected for Bob on a shared Manager (reason
// binding_mismatch). Never derive Binding from tool arguments.
//
// # MUT-001 defaults (NewManager zero values)
//
// | Field                 | Zero means                                      | Negative means | Production default |
// |-----------------------|-------------------------------------------------|----------------|--------------------|
// | TTL                   | live TokenTTL() if >0 else DefaultTokenTTL      | same as zero†  | 2m                 |
// | MaxPreviewsPerMinute  | process live if set, else DefaultMaxPreviews…   | unlimited*     | 30 / sliding 1m    |
// | ConfirmCooldown       | live ConfirmCooldown() if >0 else Default…      | off**          | 5s per target hash |
//
// †TTL operator path (Wave 53 Track A): --mutation-token-ttl /
// JENKINS_MCP_MUTATION_TOKEN_TTL; empty/0/"0s" → DefaultTokenTTL; min 10s /
// absolute max 15m fail closed. Serve SetTokenTTL installs the process live
// value used when Config.TTL ≤ 0. There is no unlimited/disabled TTL library
// hatch (≤0 always yields a positive TTL). Operator path cannot set 0/disable.
//
// *Negative MaxPreviewsPerMinute is a library/test escape hatch only. Operator
// path (ResolveMaxPreviewsPerMinute / --mutation-max-previews-per-minute /
// JENKINS_MCP_MUTATION_MAX_PREVIEWS_PER_MINUTE) never yields unlimited: empty/0
// → default 30; invalid/negative/above AbsoluteMaxPreviewsPerMinute (300) fail closed.
//
// **ConfirmCooldown operator path (Wave 52 Track A): --mutation-confirm-cooldown /
// JENKINS_MCP_MUTATION_CONFIRM_COOLDOWN; empty/0/"0s" → DefaultConfirmCooldown;
// min 1s / absolute max 5m fail closed. Serve SetConfirmCooldown installs the
// process live value used when Config.ConfirmCooldown is 0. Residual: library
// Config negative still disables cooldown for tests; operator path cannot set 0.
//
// ConfirmCooldown vs TokenTTL (MUT-001 residual fix): after ResolveConfirmCooldown
// and ResolveTokenTTL, serve calls EnsureConfirmCooldownLessThanTokenTTL and fails
// closed when cooldown ≥ TTL so cooldown cannot exhaust (or equal) the token
// window. Package defaults keep DefaultConfirmCooldown (5s) < DefaultTokenTTL (2m).
//
// Preview exceed → apperr.CodeThrottled + reason preview_rate_limited.
// Confirm during cooldown → apperr.CodePolicyDenial + reason confirm_cooldown
// (token not consumed; successful execute remains single-use).
//
// Pilot note: production default is still read-only; --allow-mutations is
// test/pilot only and cannot defeat enterprise force_read_only.
package mutation
