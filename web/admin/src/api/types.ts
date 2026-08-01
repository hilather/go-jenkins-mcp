/**
 * Admin BFF API v1 types (UI-001 scaffold).
 * Contract: docs/admin/api-v1.md + ADR 0014.
 * Shapes mirror secret-free CLI JSON (policy show-effective, doctor, audit.Event).
 */

/** Common error body from /admin/v1/* */

export interface ApiErrorBody {
  code: string;
  message: string;
}

export interface HealthResponse {
  status: string;
  version: string;
  commit: string;
  uiBuild?: string;
  /** HOST-011 mode ids only (secret-free). */
  enabledModes?: string[];
  /** Primary JENKINS_MCP_GATEWAY_CREDENTIAL_MODE id. */
  credentialMode?: string;
  /** JENKINS_MCP_GATEWAY_MULTI_USER env parse (foundation residual, not production GO). */
  multiUserEnabled?: boolean;
  /** Always false on admin BFF (Ready is MCP serve /readyz). */
  gatewayReady?: boolean;
  /** Always false (HOST-008 Tier A single-replica residual). */
  haMultiReplica?: boolean;
  /** True when multi-user env set (HOST-008 sticky Service scaffold honesty; not multi-replica Done). */
  sessionAffinityRecommended?: boolean;
  /**
   * Always true (HOST-008 multi-pod durable vault residual honesty).
   * Parity with doctor gateway_status.multi_pod_vault_residual. Not multi-replica Done.
   */
  multiPodVaultResidual?: boolean;
  /**
   * True when KUBERNETES_SERVICE_HOST is set (in-cluster residual).
   * When true, residual / SPA checklist covers sticky, shared vault, rate, Obtain cache.
   */
  kubernetesEnvDetected?: boolean;
  /** HOST-006 rate env residual (process-local; not multi-replica shared rate). */
  rateEnabled?: boolean;
  /** Resolved bootstrap tools/min (default or env); 0 when disabled. Never tokens. */
  ratePerMinute?: number;
  /** Resolved bootstrap burst; 0 when rate disabled. Never tokens. */
  rateBurst?: number;
  /**
   * HOST-008 Done* lite: true when JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH set
   * (same-host FileSubjectRateLimiter). Not multi-pod HA. Path never returned.
   */
  sharedSubjectRateFile?: boolean;
  /**
   * HOST-008 Done* lite: true when JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH set
   * (same-host FilePrincipalCache). Not multi-pod HA. Path never returned. Never tokens.
   */
  sharedPrincipalCacheFile?: boolean;
  /**
   * HOST-001 / HOST-008 Done* lite: true when JENKINS_MCP_HTTP_JWKS_CACHE_PATH set
   * (same-host public JWKS snapshot). Not multi-pod external JWKS HA. Path never returned.
   */
  sharedJwksFile?: boolean;
  /**
   * OAUTH-010 / GWY-001: ConsentRequired → authorization_url + session_id only
   * path Done* (always true). Static residual; never tokens or authorize query.
   */
  progressiveConsentMetadataDoneStar?: boolean;
  /**
   * Browser 3LO automation residual — always false until GWY-003. Static only.
   */
  progressiveConsentBrowser3loAutomated?: boolean;
  /**
   * Secret-free residual note when Mode C (agentcore_3lo_obo) is enabled.
   * Never authorization_url with secrets, tokens, or client secrets.
   */
  progressiveConsentResidual?: string;
  /** Multi-user / HA / rate honesty note when relevant (never tokens). */
  residual?: string;
}

/** Subset of `jenkins-mcp version --json`. */

export interface VersionResponse {
  version: string;
  commit: string;
  buildTime: string;
  goVersion: string;
  os: string;
  arch: string;
}

/**
 * Effective policy (mirror `policy show-effective --json` /
 * policy.EffectivePolicyExplain). Field names use snake_case as emitted by Go.
 */

export interface EffectivePolicy {
  profile_id?: string;
  policy_present: boolean;
  policy_path_base?: string;
  signature_state: string;
  force_read_only: boolean;
  /** MGR-002: enterprise pin forces fleet telemetry off (env cannot re-enable). */
  fleet_telemetry_force_off?: boolean;
  mode?: string;
  deny_tools?: string[];
  deny_job_prefixes?: string[];
  deny_node_names?: string[];
  deny_view_names?: string[];
  deny_artifact_paths?: string[];
  deny_branch_names?: string[];
  max_result_bytes?: number;
  /** HOST-006: optional per-subject tools/min cap (lower only vs serve bootstrap). */
  max_tools_per_minute?: number;
  /** HOST-006: optional per-subject burst cap (lower only). */
  max_tools_burst?: number;
  bundle_seq?: number;
  key_id?: string;
  content_hash?: string;
  read_only?: Record<string, unknown>;
  notes?: string[];
}

export interface MetricsResponse {
  available: boolean;
  counters: Record<string, number>;
  gauges: Record<string, number>;
  residual?: string;
}

/** Privacy-preserving audit record (internal/audit.Event). */

export interface AuditEvent {
  time: string;
  type: string;
  profileId?: string;
  principalId?: string;
  /** Optional IdP subject label (gateway multi-user); never a token. */
  externalSubject?: string;
  /** Opaque HashOpaque(tenant|subject|profile); never raw subject key or vault material. */
  subjectKeyHash?: string;
  tool?: string;
  action?: string;
  decision?: string;
  reasonCode?: string;
  durationMs?: number;
  bytesIn?: number;
  bytesOut?: number;
  requestId?: string;
  targetHash?: string;
  schemaVersion: number;
}

export interface AuditListResponse {
  profileId: string;
  events: AuditEvent[];
  truncated: boolean;
}

export type DoctorStatus = "ok" | "warn" | "fail" | "skip";

export interface DoctorCheck {
  name: string;
  status: DoctorStatus | string;
  message: string;
  details?: Record<string, unknown>;
}

/** Bounded doctor summary (internal/diagnostics.Report). */

export interface DoctorReport {
  profileId: string;
  version?: string;
  commit?: string;
  overall: DoctorStatus | string;
  checks: DoctorCheck[];
  /**
   * HOST-007 / OPS doctor residual embed: same secret-free map as
   * `gateway residual-status` / GET /admin/v1/gateway/residual-status.
   * Informational only (does not drive overall); optional on older BFF.
   * Never tokens/subjects. SPA Doctor card hides when absent.
   */
  gateway_residual_status?: GatewayResidualStatusResponse;
}

export interface AuditQuery {
  limit?: number;
  type?: string;
  before?: string;
}

/** GET /admin/v1/me (UI-003). Never includes the token value. */

export interface MeResponse {
  authenticated: boolean;
  role: string;
  permissions: string[];
  tokenConfigured: boolean;
  residual?: string;
}

/** Secret-free profile summary (UI-007). Never includes tokens/keyring payloads. */

export interface ProfileSummary {
  id: string;
  displayName?: string;
  jenkinsURL: string;
  jenkinsHost?: string;
  authMethod: string;
  username?: string;
  readOnly: boolean;
  hasCredential: boolean;
  cacheEncryption: boolean;
  dataDirSet?: boolean;
}

export interface ProfileListResponse {
  profiles: ProfileSummary[];
}

/** GET /admin/v1/profiles/{id}/cache */

export interface CacheUsageStats {
  profile?: string;
  l1_physical_bytes?: number;
  l1_logical_bytes?: number;
  l2_physical_bytes?: number;
  l2_logical_bytes?: number;
  total_physical_bytes?: number;
  generations?: number;
  packs?: number;
  quota_bytes?: number;
  over_quota?: boolean;
  free_bytes?: number;
  low_disk?: boolean;
}

export interface CacheSummaryResponse {
  profileId: string;
  available: boolean;
  needsEviction?: boolean;
  usage?: CacheUsageStats;
  pins?: number;
  residual?: string;
}

export interface EvictionCandidate {
  kind: string;
  id: string;
  bytes: number;
  age?: string;
  reason?: string;
}

/** POST cache/evict-plan and cache/evict */

export interface EvictionPlanResponse {
  profileId: string;
  needsEviction: boolean;
  usage: CacheUsageStats;
  bytesNeeded: number;
  totalReclaimBytes: number;
  dryRun: boolean;
  applied?: boolean;
  pinsSkipped: number;
  candidates: EvictionCandidate[];
  plannedAt?: string;
  evicted?: number;
  failed?: number;
  reclaimedBytes?: number;
  interrupted?: boolean;
  journalRecovered?: number;
  journalReclaimedBytes?: number;
  journalConsistent?: boolean;
  errors?: string[];
}

/** POST /admin/v1/profiles/{id}/support-bundle */

export interface SupportBundleResponse {
  profileId: string;
  preview: boolean;
  path?: string;
  bytes?: number;
  createdAt?: string;
  included: string[];
  excluded: string[];
  outputPath?: string;
  categories?: string[];
}

/** GET /admin/v1/profiles/{id}/security-selfcheck */

export interface SelfCheckItem {
  name?: string;
  status?: string;
  message?: string;
  details?: Record<string, unknown>;
}

export interface SecuritySelfCheckReport {
  overall: string;
  version?: string;
  commit?: string;
  profile_id?: string;
  items: SelfCheckItem[];
  residuals?: string[];
  independent_review_required?: boolean;
  generated_at?: string;
}

export interface PolicyOverlay {
  version: number;
  force_read_only: boolean;
  /** MGR-002: force fleet telemetry off (lower-only pin; admin cannot clear when set). */
  fleet_telemetry_force_off?: boolean;
  mode?: string;
  deny_tools?: string[];
  deny_job_prefixes?: string[];
  deny_node_names?: string[];
  deny_view_names?: string[];
  deny_artifact_paths?: string[];
  deny_branch_names?: string[];
  max_result_bytes?: number;
  /** HOST-006: optional per-subject tools/min (positive int; omit = no overlay change). */
  max_tools_per_minute?: number;
  /** HOST-006: optional per-subject burst (positive int; omit = no overlay change). */
  max_tools_burst?: number;
}

/** GET /admin/v1/policy/overlay */

export interface OverlayGetResponse {
  available: boolean;
  path_base?: string;
  signature_state?: string;
  overlay?: PolicyOverlay;
  notes?: string[];
  residual?: string;
}

export interface PolicyFieldError {
  field: string;
  message: string;
}

/** POST /admin/v1/policy/validate body + response */

export interface PolicyValidateRequest {
  overlay: PolicyOverlay;
  profileId?: string;
}

export interface PolicyValidateResponse {
  valid: boolean;
  errors?: PolicyFieldError[];
  effectivePreview?: EffectivePolicy;
  notes?: string[];
}

/** POST /admin/v1/policy/apply response */

export interface PolicyApplyResponse {
  applied: boolean;
  path_base?: string;
  effective?: EffectivePolicy;
  errors?: PolicyFieldError[];
  notes?: string[];
}

/**
 * GET /admin/v1/gateway/vault (HOST-011 / HOST-009 residual).
 * Secret-free: SubjectKeyHash only; never tokens or raw subject keys.
 */

export interface GatewayVaultResponse {
  mode: string;
  enabledModes?: string[];
  /** JENKINS_MCP_GATEWAY_MULTI_USER env parse (foundation residual). */
  multiUserEnabled?: boolean;
  /** Always false (HOST-008 Tier A residual). */
  haMultiReplica?: boolean;
  /** True when multi-user env set (HOST-008 sticky scaffold honesty; not multi-replica Done). */
  sessionAffinityRecommended?: boolean;
  /**
   * Always true (HOST-008 multi-pod vault residual; parity with doctor multi_pod_vault_residual).
   * Not multi-replica Done.
   */
  multiPodVaultResidual?: boolean;
  /**
   * True when KUBERNETES_SERVICE_HOST set; residual notes multi-pod checklist (not HA Done).
   */
  kubernetesEnvDetected?: boolean;
  /** HOST-006 rate env residual (process-local only). */
  rateEnabled?: boolean;
  /** Resolved bootstrap tools/min; 0 when disabled. Never tokens. */
  ratePerMinute?: number;
  /** Resolved bootstrap burst; 0 when rate disabled. Never tokens. */
  rateBurst?: number;
  /**
   * HOST-008 Done* lite: true when JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH set
   * (same-host file rate). Not multi-pod HA. Path never returned.
   */
  sharedSubjectRateFile?: boolean;
  /**
   * HOST-008 Done* lite: true when JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH set
   * (same-host FilePrincipalCache). Not multi-pod HA. Path never returned. Never tokens.
   */
  sharedPrincipalCacheFile?: boolean;
  /**
   * HOST-001 / HOST-008 Done* lite: true when JENKINS_MCP_HTTP_JWKS_CACHE_PATH set
   * (same-host public JWKS snapshot). Not multi-pod external JWKS HA. Path never returned.
   */
  sharedJwksFile?: boolean;
  vaultConfigured: boolean;
  entryCount: number;
  subjects: string[];
  residual?: string;
}

/**
 * GET /admin/v1/gateway/residual-status (HOST-007).
 * Same secret-free map as `jenkins-mcp gateway residual-status` (CLI field names).
 * Never tokens, subjects, or vault bytes. Hide card on 404 (older BFF residual).
 */

export interface GatewayResidualModeMatrix {
  primary?: string;
  enabled?: string[];
  residual?: string;
  valid?: boolean;
}

export interface GatewayProgressiveConsent {
  metadata_path_done_star?: boolean;
  browser_3lo_automated?: boolean;
  residual_note?: string;
  [key: string]: unknown;
}

export interface GatewayResidualStatusResponse {
  mode_matrix?: GatewayResidualModeMatrix;
  mode_matrix_residual?: string;
  mode_a_enabled?: boolean;
  mode_b_enabled?: boolean;
  mode_c_enabled?: boolean;
  mode_a_live_obtain_qualified?: boolean;
  mode_b_live_rs_qualified?: boolean;
  mode_c_live_agentcore_qualified?: boolean;
  /** Always oauth009_offline (Mode B residual id pointer). */
  residual_id?: string;
  oauth009_offline?: boolean;
  oauth009_offline_only?: boolean;
  residual_ids?: string[];
  multi_user_enabled?: boolean;
  gateway_ready?: boolean;
  ha_multi_replica?: boolean;
  session_affinity_recommended?: boolean;
  multi_pod_vault_residual?: boolean;
  kubernetes_env_detected?: boolean;
  vault_path_emptydir_heuristic?: boolean;
  replicas_env_residual?: boolean;
  multi_pod_residual_checklist?: string;
  progressive_consent?: GatewayProgressiveConsent;
  progressive_consent_residual?: string;
  progressive_consent_surfaces?: string[];
  /** HOST-006 rate knobs (admin health field names; process-local). */
  rateEnabled?: boolean;
  ratePerMinute?: number;
  rateBurst?: number;
  /**
   * HOST-008 Done* lite: true when JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH set
   * (same-host FileSubjectRateLimiter). Snake_case CLI/BFF residual-status key.
   * Not multi-pod HA. Path value never returned.
   */
  shared_subject_rate_file?: boolean;
  /**
   * HOST-008 Done* lite: true when JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH set
   * (same-host FilePrincipalCache). Path never returned. Never tokens.
   */
  shared_principal_cache_file?: boolean;
  /**
   * HOST-001 / HOST-008 Done* lite: true when JENKINS_MCP_HTTP_JWKS_CACHE_PATH set
   * (same-host FileJWKS / public JWKS snapshot). Path never returned.
   * Not multi-pod external JWKS HA. Public keys only — never tokens.
   */
  shared_jwks_file?: boolean;
  /**
   * Optional MaxSubjects for rate map hygiene when env > 0 (omit = unlimited).
   */
  subject_rate_max_subjects?: number;
  /**
   * Principal cache entry count (never subjects). When shared_principal_cache_file,
   * BFF may open file for Len(); else this-process memory.
   */
  principal_cache_entries?: number;
  /** Honesty sentence from BFF residual-status (process vs file Len). */
  principal_cache_process_note?: string;
  /**
   * Optional PrincipalCache max_entries hygiene when env > 0 (omit = unlimited).
   * Snake_case; never subjects/tokens.
   */
  principal_cache_max_entries?: number;
  /**
   * Optional PrincipalCache TTL seconds when env > 0 (omit = no TTL).
   * Snake_case; never subjects/tokens.
   */
  principal_cache_ttl_seconds?: number;
  residual_note?: string;
  /** Pointer e.g. docs/gateway/live-pin-blockers.md */
  doc?: string;
}

/**
 * POST /admin/v1/gateway/subject-invalidate request (HOST-007).
 * Identity key parts only — never tokens.
 */
export interface GatewaySubjectInvalidateRequest {
  /** Preferred: tenant|subject|profile */
  subject_key?: string;
  tenant?: string;
  subject_id?: string;
  profile?: string;
  /** Optional exact CacheKey fallback (usually unused with FileTokenCache purge). */
  workload?: string;
}

/**
 * POST /admin/v1/gateway/subject-invalidate response (CLI StatusMap + admin notes).
 * Secret-free forever: never tokens, vault bytes, or path values.
 */
export interface GatewaySubjectInvalidateResponse {
  subject_key?: string;
  subject_key_hash?: string;
  principal_cleared?: boolean;
  token_cache_cleared?: boolean;
  token_cache_entries_deleted?: number;
  token_cache_note?: string;
  residual_note?: string;
  cleared?: {
    principal?: boolean;
    token_cache?: boolean;
  };
  doc?: string;
  token_cache_path_configured?: boolean;
  principal_cache_path_configured?: boolean;
  token_cache_admin_note?: string;
  principal_process_note?: string;
  [key: string]: unknown;
}

/**
 * POST /admin/v1/gateway/consent-purge request (HOST-007 Mode C residual lite).
 * Metadata purge only — never tokens. session_id is a correlation id (not echoed).
 */
export interface GatewayConsentPurgeRequest {
  /** purge_expired (default) | delete_session | clear_all */
  action?: "purge_expired" | "delete_session" | "clear_all" | string;
  /** Required for delete_session (never returned in response). */
  session_id?: string;
  /** Explicit flag required for clear_all (mirrors CLI --all). */
  clear_all?: boolean;
  /**
   * Exact confirm token required for clear_all (must be "CLEAR_ALL").
   * Parity with cache confirm:"EVICT" and CLI --confirm=CLEAR_ALL.
   * Not required for purge_expired / delete_session.
   */
  confirm?: string;
  /** Optional path override (never returned in full; basename residual only). */
  path?: string;
}

/**
 * POST /admin/v1/gateway/consent-purge response (CLI secret-free summary + admin notes).
 * Never tokens, session_id echo, or full path values.
 */
export interface GatewayConsentPurgeResponse {
  action?: string;
  deleted_count?: number;
  remaining_count?: number;
  metadata_only?: boolean;
  stores_tokens?: boolean;
  process_local?: boolean;
  multi_replica_shared?: boolean;
  browser_3lo_automated?: boolean;
  durable_agentcore_vault_residual?: boolean;
  file_backed?: boolean;
  file_basename?: string;
  consent_store_path_configured?: boolean;
  residual_note?: string;
  doc?: string;
  admin_note?: string;
  [key: string]: unknown;
}
