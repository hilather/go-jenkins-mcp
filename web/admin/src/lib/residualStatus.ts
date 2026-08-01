/**
 * HOST-007 residual-status SPA helpers.
 * Pure field picks from CLI/BFF snake_case map (diagnostics.BuildGatewayResidualStatus).
 * Never tokens, subjects, vault paths, or live GO claims.
 */

import type {
  GatewayProgressiveConsent,
  GatewayResidualStatusResponse,
} from "../api/types";

/**
 * Consent store same-host file lite honesty (OAUTH-010 / HOST-007).
 * residual-status progressive_consent.file_backed when CONSENT_STORE_PATH set.
 * Path never shown; not multi-pod shared consent store.
 */
export const CONSENT_FILE_BACKED_HONESTY =
  "same-host consent metadata file when true (JENKINS_MCP_CONSENT_STORE_PATH); path never shown; not multi-pod HA";

/**
 * OAUTH-010 Done* lite: file-backed reload-before-persist under flock.
 * True only when progressive_consent.file_backed; not multi-replica HA.
 */
export const CONSENT_SAME_HOST_RELOAD_HONESTY =
  "same-host file reload-before-persist flock lite when true (admin/CLI purge not resurrected by serve Put); not multi-pod HA";

/** Consent metadata never stores tokens (always false on residual-status). */
export const CONSENT_STORES_TOKENS_HONESTY =
  "always false — progressive consent metadata only (authorization_url + session_id); never tokens";

/** Multi-replica shared consent store residual (always false). */
export const CONSENT_MULTI_REPLICA_SHARED_HONESTY =
  "always false — process/file-local only (HOST-008 multi-pod shared consent residual)";

/** Same-host file rate lite honesty (HOST-008); not multi-pod shared rate. */
export const SHARED_SUBJECT_RATE_FILE_HONESTY =
  "same-host FileSubjectRateLimiter lite when true (JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH); not multi-pod HA — path never shown";

/** Same-host FileJWKS lite honesty (HOST-001/HOST-008); not multi-pod external JWKS. */
export const SHARED_JWKS_FILE_HONESTY =
  "same-host FileJWKS lite when true (JENKINS_MCP_HTTP_JWKS_CACHE_PATH); not multi-pod external JWKS HA — path never shown; public keys only";

/** Same-host FileTokenCache lite honesty (HOST-008); not multi-pod external Obtain cache. */
export const SHARED_TOKEN_CACHE_FILE_HONESTY =
  "same-host FileTokenCache lite when true (JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH); not multi-pod Redis/HA — path never shown; secrets never shown";

/** Mode A shared vault path residual lite (HOST-008); env path set only; not multi-pod vault HA. */
export const SHARED_API_TOKEN_VAULT_FILE_HONESTY =
  "same-host FileAPITokenVault path residual when true (JENKINS_MCP_GATEWAY_VAULT_PATH set; default XDG does not count); not multi-pod vault HA — path never shown; vault never opened; secrets never shown";

/** Mode B shared JWT vault path residual lite (HOST-008); env path set only; not multi-pod vault HA. */
export const SHARED_JWT_VAULT_FILE_HONESTY =
  "same-host FileJWTVault path residual when true (JENKINS_MCP_GATEWAY_JWT_VAULT_PATH set; default XDG does not count); not multi-pod vault HA — path never shown; vault never opened; secrets never shown";

/**
 * Principal cache entry count is the process that served residual-status
 * (admin BFF), not necessarily the MCP gateway serve process.
 */
export const PRINCIPAL_CACHE_PROCESS_HONESTY =
  "this process (admin BFF residual-status); not necessarily MCP serve";

/** Optional hygiene knobs when env set; never subjects. */
export const PRINCIPAL_CACHE_HYGIENE_HONESTY =
  "optional env hygiene (omit = unlimited / no TTL); process-local residual";

/**
 * SubjectLimiter concurrency slots are process-local (HOST-008 residual).
 * residual-status always emits subject_slots_process_local=true; never multi-pod HA.
 */
export const SUBJECT_SLOTS_PROCESS_LOCAL_HONESTY =
  "SubjectLimiter concurrency slots process-local only (HOST-008 residual; not multi-pod shared concurrency)";

/** Optional SubjectLimiter MaxSubjects hygiene when env set; never subjects. */
export const SUBJECT_LIMITER_MAX_SUBJECTS_HONESTY =
  "optional map hygiene (JENKINS_MCP_GATEWAY_SUBJECT_LIMITER_MAX_SUBJECTS; omit = unlimited); process-local only";

/**
 * Live mode pin + gateway_ready honesty on residual-status surfaces.
 * residual-status always emits false; SPA must not claim production GO.
 */
export const LIVE_PIN_RESIDUAL_HONESTY =
  "offline residual — not production GO";

/** gateway_ready on residual-status is always false (Ready is serve /readyz). */
export const GATEWAY_READY_RESIDUAL_HONESTY =
  "residual-status always false; Ready only on serve /readyz";

/** HOST-008 Tier A single-replica default (ha_multi_replica). */
export const HA_MULTI_REPLICA_RESIDUAL_HONESTY =
  "HOST-008 Tier A single-replica default";

export interface ResidualLivePinFields {
  /** Always false on residual-status (Mode A live Obtain pin residual). */
  mode_a_live_obtain_qualified: boolean;
  /** Always false on residual-status (Mode B live RS pin residual). */
  mode_b_live_rs_qualified: boolean;
  /** Always false on residual-status (Mode C live AgentCore pin residual). */
  mode_c_live_agentcore_qualified: boolean;
  /** Always false on residual-status (Ready is serve /readyz). */
  gateway_ready: boolean;
  /** Always false until multi-replica runtime (HOST-008 Tier A). */
  ha_multi_replica: boolean;
}

/**
 * Pick live pin / gateway_ready / ha_multi_replica residual bools.
 * Defaults false when missing (fail-closed honesty; never invent true).
 * Never tokens/subjects; never claims live GO.
 */
export function pickResidualLivePinFields(
  data: GatewayResidualStatusResponse | null | undefined,
): ResidualLivePinFields {
  if (!data) {
    return {
      mode_a_live_obtain_qualified: false,
      mode_b_live_rs_qualified: false,
      mode_c_live_agentcore_qualified: false,
      gateway_ready: false,
      ha_multi_replica: false,
    };
  }
  return {
    // residual-status always emits false; treat missing as false (not live GO).
    mode_a_live_obtain_qualified: data.mode_a_live_obtain_qualified === true,
    mode_b_live_rs_qualified: data.mode_b_live_rs_qualified === true,
    mode_c_live_agentcore_qualified: data.mode_c_live_agentcore_qualified === true,
    gateway_ready: data.gateway_ready === true,
    ha_multi_replica: data.ha_multi_replica === true,
  };
}

/** Format a residual live-pin bool as no/false (preferred) or yes/true. */
export function formatResidualBool(value: boolean): string {
  return value ? "yes/true" : "no/false";
}

export interface ResidualRateCacheFields {
  /** Always present on residual-status (bool from Go map). */
  shared_subject_rate_file: boolean;
  /** HOST-008 FilePrincipalCache path configured (bool only; never path). */
  shared_principal_cache_file: boolean;
  /** HOST-001/HOST-008 FileJWKS path configured (bool only; never path). */
  shared_jwks_file: boolean;
  /** HOST-008 FileTokenCache path configured (bool only; never path/tokens). */
  shared_token_cache_file: boolean;
  /** HOST-008 Mode A vault path env configured (bool only; never path/tokens). */
  shared_api_token_vault_file: boolean;
  /** HOST-008 Mode B JWT vault path env configured (bool only; never path/tokens). */
  shared_jwt_vault_file: boolean;
  /** Present when MaxSubjects env > 0. */
  subject_rate_max_subjects?: number;
  /**
   * Present when SubjectLimiter MaxSubjects env > 0 (omit = unlimited).
   * HOST-006 / HOST-007 residual lite.
   */
  subject_limiter_max_subjects?: number;
  /**
   * Always true on current residual-status (concurrency slots process-local).
   * Explicit true only; missing/older BFF → false for fail-closed pick.
   */
  subject_slots_process_local: boolean;
  /** Process-local or file Len() count. */
  principal_cache_entries?: number;
  /** BFF honesty sentence when present. */
  principal_cache_process_note?: string;
  /** Present only when max_entries hygiene env > 0. */
  principal_cache_max_entries?: number;
  /** Present only when TTL hygiene env > 0. */
  principal_cache_ttl_seconds?: number;
}

/**
 * Pick secret-free rate/cache residual fields from residual-status JSON.
 * Mirrors snake_case keys from diagnostics.BuildGatewayResidualStatus.
 */
export function pickResidualRateCacheFields(
  data: GatewayResidualStatusResponse | null | undefined,
): ResidualRateCacheFields {
  if (!data) {
    return {
      shared_subject_rate_file: false,
      shared_principal_cache_file: false,
      shared_jwks_file: false,
      shared_token_cache_file: false,
      shared_api_token_vault_file: false,
      shared_jwt_vault_file: false,
      subject_slots_process_local: false,
    };
  }
  // Fail-closed honesty: only explicit boolean true counts as shared-file lite.
  // Never treat truthy strings/numbers as true (Boolean("false") === true).
  const out: ResidualRateCacheFields = {
    shared_subject_rate_file: data.shared_subject_rate_file === true,
    shared_principal_cache_file: data.shared_principal_cache_file === true,
    shared_jwks_file: data.shared_jwks_file === true,
    shared_token_cache_file: data.shared_token_cache_file === true,
    shared_api_token_vault_file: data.shared_api_token_vault_file === true,
    shared_jwt_vault_file: data.shared_jwt_vault_file === true,
    subject_slots_process_local: data.subject_slots_process_local === true,
  };
  if (typeof data.subject_rate_max_subjects === "number") {
    out.subject_rate_max_subjects = data.subject_rate_max_subjects;
  }
  if (typeof data.subject_limiter_max_subjects === "number") {
    out.subject_limiter_max_subjects = data.subject_limiter_max_subjects;
  }
  if (typeof data.principal_cache_entries === "number") {
    out.principal_cache_entries = data.principal_cache_entries;
  }
  if (typeof data.principal_cache_process_note === "string" && data.principal_cache_process_note) {
    out.principal_cache_process_note = data.principal_cache_process_note;
  }
  if (typeof data.principal_cache_max_entries === "number") {
    out.principal_cache_max_entries = data.principal_cache_max_entries;
  }
  if (typeof data.principal_cache_ttl_seconds === "number") {
    out.principal_cache_ttl_seconds = data.principal_cache_ttl_seconds;
  }
  return out;
}

/** Format principal cache max/ttl for Overview when present. */
export function formatPrincipalCacheHygiene(
  maxEntries?: number,
  ttlSeconds?: number,
): string | null {
  const parts: string[] = [];
  if (typeof maxEntries === "number" && Number.isFinite(maxEntries) && maxEntries > 0) {
    parts.push(`max_entries=${maxEntries}`);
  }
  if (typeof ttlSeconds === "number" && Number.isFinite(ttlSeconds) && ttlSeconds > 0) {
    parts.push(`ttl_seconds=${ttlSeconds}`);
  }
  return parts.length ? parts.join(" · ") : null;
}

/**
 * Progressive consent residual honesty fields (HOST-007 SPA).
 * Nested under residual-status progressive_consent (ProgressiveConsentResidual
 * + consent-store StatusMap honesty). Fail-closed: only explicit true for
 * file_backed / same_host_reload; stores_tokens / multi_replica_shared only
 * true when explicit true (else false). Never path/tokens/session inventory.
 */
export interface ResidualProgressiveConsentFields {
  metadata_path_done_star: boolean;
  browser_3lo_automated: boolean;
  stores_tokens: boolean;
  multi_replica_shared: boolean;
  file_backed: boolean;
  same_host_reload_before_persist: boolean;
}

/**
 * Pick progressive_consent honesty fields from residual-status (or nested map).
 * Accepts full residual response or the progressive_consent nest alone.
 */
export function pickProgressiveConsentFields(
  data:
    | GatewayResidualStatusResponse
    | GatewayProgressiveConsent
    | null
    | undefined,
): ResidualProgressiveConsentFields {
  const pc: GatewayProgressiveConsent | undefined | null =
    data && "progressive_consent" in data
      ? (data as GatewayResidualStatusResponse).progressive_consent
      : (data as GatewayProgressiveConsent | null | undefined);

  if (!pc) {
    return {
      metadata_path_done_star: false,
      browser_3lo_automated: false,
      stores_tokens: false,
      multi_replica_shared: false,
      file_backed: false,
      same_host_reload_before_persist: false,
    };
  }
  return {
    metadata_path_done_star: pc.metadata_path_done_star === true,
    browser_3lo_automated: pc.browser_3lo_automated === true,
    // Fail closed: only explicit true would claim tokens/multi-replica (must never).
    stores_tokens: pc.stores_tokens === true,
    multi_replica_shared: pc.multi_replica_shared === true,
    file_backed: pc.file_backed === true,
    same_host_reload_before_persist: pc.same_host_reload_before_persist === true,
  };
}
