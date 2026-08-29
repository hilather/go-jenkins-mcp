/**
 * Residual caveat + HOST-* body copy for leftover operator-console pages.
 * Badge + one-line caveat stay visible; HOST-* copy goes in ResidualCallout details.
 * Never tokens, live GO, or fleet graphs.
 */

export const PROFILES_RESIDUAL_CAVEAT =
  "Secret-free profiles — tokens and keyring material are never returned; support bundle create is operator-only.";

export const PROFILES_RESIDUAL_DETAILS =
  "GET /admin/v1/profiles returns hasCredential presence only. Security self-check is offline canaries. Support-bundle create writes a scrubbed zip under XDG cache and returns path + size (not file bytes). Never dump tokens into the console.";

export const POLICY_RESIDUAL_CAVEAT =
  "Subject rate overlay knobs lower only; process-local (HOST-006 / HOST-008).";

export const POLICY_RESIDUAL_DETAILS =
  "max_tools_per_minute / max_tools_burst overlay knobs lower only under a live gateway serve via SubjectRateLimiter.LowerRate (never raise above the env bootstrap ceiling). Raising the bootstrap needs a serve restart with higher JENKINS_MCP_SUBJECT_RATE_*. Rate is process-local; multi-replica shared rate remains residual (HOST-008). Empty draft fields omit the overlay keys (no change).";

export const ACCESS_RESIDUAL_CAVEAT =
  "Pilot break-glass only — multi-fleet source of truth remains signed config (MGR-001).";

export const ACCESS_RESIDUAL_DETAILS =
  "SPA Access edits the plain overlay subjects.users / subjects.groups. Production SoT is signed fleet config. Preview is a dry-run deny-only evaluator for a hypothetical subject (not process authn). path_base is a basename only.";

export const AUDIT_RESIDUAL_CAVEAT =
  "Type filter is File-sink persist for this profile — not a live stream (no SSE).";

export const AUDIT_RESIDUAL_DETAILS =
  "Enable/disable writes audit/type_filter.json; serve reloads on mtime/size (no restart). Catalog comes from KnownEventTypes. external_subject is an exact IdP subject label (never a token). Client exact filter remains residual for older BFFs that ignore the query param.";

export const DOCTOR_RESIDUAL_CAVEAT =
  "Offline residual — not production GO. Never tokens or subjects.";

export const DOCTOR_RESIDUAL_DETAILS =
  "HOST-007 doctor embed (gateway_residual_status) — same secret-free map as gateway residual-status / Overview residual card. Informational only; does not drive overall. Live pin residual honesty pointer is the payload doc field (never tokens).";

export const CACHE_RESIDUAL_CAVEAT =
  "Pin list and full cache repair remain CLI residuals — this page is quota and eviction only.";

export const CACHE_RESIDUAL_DETAILS =
  "GET /admin/v1/profiles/{id}/cache usage is this admin process store, not Metrics gauges and not a fleet graph. available:false means the store is unavailable — do not invent a quota. Pin list and cache repair stay on the CLI.";
