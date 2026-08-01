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
  /** Multi-user / HA honesty note when relevant (never tokens). */
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
  mode?: string;
  deny_tools?: string[];
  deny_job_prefixes?: string[];
  deny_node_names?: string[];
  deny_view_names?: string[];
  deny_artifact_paths?: string[];
  deny_branch_names?: string[];
  max_result_bytes?: number;
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
  mode?: string;
  deny_tools?: string[];
  deny_job_prefixes?: string[];
  deny_node_names?: string[];
  deny_view_names?: string[];
  deny_artifact_paths?: string[];
  deny_branch_names?: string[];
  max_result_bytes?: number;
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
  vaultConfigured: boolean;
  entryCount: number;
  subjects: string[];
  residual?: string;
}
