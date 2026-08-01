/**
 * HOST-007 residual-status SPA helpers.
 * Pure field picks from CLI/BFF snake_case map (diagnostics.BuildGatewayResidualStatus).
 * Never tokens, subjects, vault paths, or live GO claims.
 */

import type { GatewayResidualStatusResponse } from "../api/types";

/** Same-host file rate lite honesty (HOST-008); not multi-pod shared rate. */
export const SHARED_SUBJECT_RATE_FILE_HONESTY =
  "same-host FileSubjectRateLimiter lite when true (JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH); not multi-pod HA — path never shown";

/**
 * Principal cache entry count is the process that served residual-status
 * (admin BFF), not necessarily the MCP gateway serve process.
 */
export const PRINCIPAL_CACHE_PROCESS_HONESTY =
  "this process (admin BFF residual-status); not necessarily MCP serve";

/** Optional hygiene knobs when env set; never subjects. */
export const PRINCIPAL_CACHE_HYGIENE_HONESTY =
  "optional env hygiene (omit = unlimited / no TTL); process-local residual";

export interface ResidualRateCacheFields {
  /** Always present on residual-status (bool from Go map). */
  shared_subject_rate_file: boolean;
  /** HOST-008 FilePrincipalCache path configured (bool only; never path). */
  shared_principal_cache_file: boolean;
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
    return { shared_subject_rate_file: false, shared_principal_cache_file: false };
  }
  const out: ResidualRateCacheFields = {
    shared_subject_rate_file: Boolean(data.shared_subject_rate_file),
    shared_principal_cache_file: Boolean(data.shared_principal_cache_file),
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
