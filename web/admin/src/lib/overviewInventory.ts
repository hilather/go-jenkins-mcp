/**
 * Field inventories for Overview re-rank. Compact layout must keep these keys.
 * session_id is consent-purge *input* only (API never echoes it).
 */

export const OVERVIEW_HEALTH_DL_KEYS = [
  "status",
  "version",
  "commit",
  "uiBuild",
  "credentialMode",
  "multiUserEnabled",
  "gatewayReady",
  "haMultiReplica",
  "sessionAffinityRecommended",
  "multiPodVaultResidual",
  "kubernetesEnvDetected",
  "rateEnabled",
  "ratePerMinute",
  "rateBurst",
  "sharedSubjectRateFile",
  "sharedPrincipalCacheFile",
  "sharedJwksFile",
  "sharedTokenCacheFile",
  "residual",
] as const;

export const OVERVIEW_VERSION_DL_KEYS = [
  "version",
  "commit",
  "buildTime",
  "goVersion",
  "os/arch",
] as const;

export const OVERVIEW_VAULT_UNIQUE_KEYS = [
  "mode",
  "enabledModes",
  "vaultConfigured",
  "entryCount",
  "subjects",
  "residual",
] as const;

export const OVERVIEW_RESIDUAL_STATUS_DL_KEYS = [
  "mode_a / mode_b / mode_c enabled",
  "mode_a_live_obtain_qualified",
  "mode_b_live_rs_qualified",
  "mode_c_live_agentcore_qualified",
  "gateway_ready",
  "mode_matrix",
  "multi_user_enabled",
  "ha_multi_replica",
  "session_affinity_recommended",
  "multi_pod_vault_residual",
  "kubernetes_env_detected",
  "multi_pod_residual_checklist",
  "rateEnabled / ratePerMinute / rateBurst",
  "shared_subject_rate_file",
  "subject_rate_max_subjects",
  "subject_limiter_max_subjects",
  "subject_slots_process_local",
  "shared_principal_cache_file",
  "shared_jwks_file",
  "shared_token_cache_file",
  "shared_api_token_vault_file",
  "shared_jwt_vault_file",
  "principal_cache_entries",
  "principal_cache max / ttl",
  "residual_id (Mode B)",
  "residual_ids",
  "progressive_consent (Mode C residual)",
  "file_backed",
  "same_host_reload_before_persist",
  "multi_replica_shared",
  "stores_tokens",
  "progressive_consent_residual",
  "residual_note",
  "doc",
] as const;

export const OVERVIEW_MODE_C_HONESTY_KEYS = [
  "progressiveConsentMetadataDoneStar",
  "progressiveConsentBrowser3loAutomated",
  "progressiveConsentFileBacked",
  "progressiveConsentSameHostReload",
  "progressiveConsentStoresTokens",
  "progressiveConsentMultiReplicaShared",
  "progressiveConsentResidual",
] as const;

/** Consent purge inputs (session_id never echoed in the response). */
export const CONSENT_PURGE_INPUT_KEYS = [
  "action",
  "session_id",
  "CLEAR_ALL",
] as const;

export const CONSENT_PURGE_RESULT_KEYS = [
  "action",
  "deleted_count",
  "remaining_count",
  "metadata_only / stores_tokens",
  "file_backed",
  "residual_note",
  "admin_note",
] as const;

export const SUBJECT_INVALIDATE_INPUT_KEYS = [
  "subject_key",
  "tenant",
  "subject_id",
  "profile",
] as const;

export const SUBJECT_INVALIDATE_RESULT_KEYS = [
  "subject_key",
  "subject_key_hash",
  "principal_cleared",
  "token_cache_cleared",
  "token_cache_entries_deleted",
  "token_cache_note",
  "principal_process_note",
  "token_cache_admin_note",
  "residual_note",
] as const;

export const K8S_CHECKLIST_ITEMS = [
  "sticky sessions or shared session store",
  "durable shared vault (not emptyDir)",
  "shared subject rate",
  "shared Obtain / token cache",
  "haMultiReplica=false until runtime HA",
] as const;

export const RESIDUALS_V1_TOPICS = [
  "optional admin token localStorage Bearer",
  "policy overlay validate/apply policy_admin",
  "gateway vault write CLI-only vault-put",
  "Mode C progressive consent metadata",
  "multi-pod / HA HOST-008",
  "gateway residual-status HOST-007",
  "subject invalidate HOST-007",
  "consent purge HOST-007 CLEAR_ALL",
  "BFF loopback-only ADR 0014",
] as const;

export const VAULT_PUT_SNIPPET = `jenkins-mcp gateway vault-put \\
  --subject 'tenant|sub|profile' \\
  --user alice \\
  --token-env MY_TOKEN`;

export function formatHealthRateCaption(
  ratePerMinute?: number,
  rateBurst?: number,
): string | null {
  if (typeof ratePerMinute !== "number" || typeof rateBurst !== "number") {
    return null;
  }
  return `${ratePerMinute} / min · burst ${rateBurst} · process-local health (not a /metrics field)`;
}

export function formatBytesMiB(n: number): string {
  const mib = n / (1024 * 1024);
  if (!Number.isFinite(mib)) {
    return "—";
  }
  return `${mib.toFixed(1)} MiB`;
}
