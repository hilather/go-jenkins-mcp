/**
 * HOST-007 residual-status SPA helpers.
 * Pure field picks from CLI/BFF snake_case map (diagnostics.BuildGatewayResidualStatus).
 * Never tokens, subjects, vault paths, or live GO claims.
 */

import type { GatewayResidualStatusResponse } from "../api/types";

/** Same-host file rate lite honesty (HOST-008); not multi-pod shared rate. */
export const SHARED_SUBJECT_RATE_FILE_HONESTY =
  "same-host FileSubjectRateLimiter lite when true (JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH); not multi-pod HA — path never shown";

/** Same-host FileJWKS lite honesty (HOST-001/HOST-008); not multi-pod external JWKS. */
export const SHARED_JWKS_FILE_HONESTY =
  "same-host FileJWKS lite when true (JENKINS_MCP_HTTP_JWKS_CACHE_PATH); not multi-pod external JWKS HA — path never shown; public keys only";

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
  /** Present when MaxSubjects env > 0. */
  subject_rate_max_subjects?: number;
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
    };
  }
  const out: ResidualRateCacheFields = {
    shared_subject_rate_file: Boolean(data.shared_subject_rate_file),
    shared_principal_cache_file: Boolean(data.shared_principal_cache_file),
    shared_jwks_file: Boolean(data.shared_jwks_file),
  };
  if (typeof data.subject_rate_max_subjects === "number") {
    out.subject_rate_max_subjects = data.subject_rate_max_subjects;
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
