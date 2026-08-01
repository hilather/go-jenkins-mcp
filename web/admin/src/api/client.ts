/**
 * Fetch helper for /admin/v1 (ADR 0014 / docs/admin/api-v1.md).
 *
 * Residual (v1 / UI-003): optional admin token is read from localStorage key
 * `jenkins-mcp.admin.token` and sent as Authorization: Bearer.
 * Pilot-only UX; never log the token value. Role comes from GET /admin/v1/me
 * (process-wide --admin-role), not from the browser.
 */

import { buildAuditQueryString } from "../lib/auditQuery";
import type {
  ApiErrorBody,
  AuditListResponse,
  AuditQuery,
  CacheSummaryResponse,
  DoctorReport,
  EffectivePolicy,
  EvictionPlanResponse,
  GatewayResidualStatusResponse,
  GatewayVaultResponse,
  HealthResponse,
  MeResponse,
  MetricsResponse,
  OverlayGetResponse,
  PolicyApplyResponse,
  PolicyOverlay,
  PolicyValidateRequest,
  PolicyValidateResponse,
  ProfileListResponse,
  ProfileSummary,
  SecuritySelfCheckReport,
  SupportBundleResponse,
  VersionResponse,
} from "./types";

export { buildAuditQueryString } from "../lib/auditQuery";

export const PROFILE_STORAGE_KEY = "jenkins-mcp.admin.profile";
export const TOKEN_STORAGE_KEY = "jenkins-mcp.admin.token";
export const DEFAULT_PROFILE = "corp";

const API_BASE = "/admin/v1";

/** Thrown for non-2xx admin API responses. Safe for UI display. */
export class AdminApiError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(status: number, body: ApiErrorBody | null, fallbackMessage: string) {
    const code = body?.code?.trim() || `http_${status}`;
    const message = body?.message?.trim() || fallbackMessage;
    super(message);
    this.name = "AdminApiError";
    this.code = code;
    this.status = status;
  }
}

export function getProfileId(): string {
  if (typeof window === "undefined") {
    return DEFAULT_PROFILE;
  }
  try {
    const params = new URLSearchParams(window.location.search);
    const fromQuery = params.get("profile")?.trim();
    if (fromQuery) {
      return fromQuery;
    }
    const stored = window.localStorage.getItem(PROFILE_STORAGE_KEY)?.trim();
    if (stored) {
      return stored;
    }
  } catch {
    // ignore storage / location failures
  }
  return DEFAULT_PROFILE;
}

export function setProfileId(profileId: string): void {
  const id = profileId.trim() || DEFAULT_PROFILE;
  try {
    window.localStorage.setItem(PROFILE_STORAGE_KEY, id);
  } catch {
    // ignore quota / private mode
  }
}

/** Optional shared secret. Never log the returned value. */

export function getAdminToken(): string | null {
  if (typeof window === "undefined") {
    return null;
  }
  try {
    const t = window.localStorage.getItem(TOKEN_STORAGE_KEY)?.trim();
    return t || null;
  } catch {
    return null;
  }
}

/**
 * Store or clear the optional admin shared secret (pilot localStorage UX).
 * Never log the token value.
 */

export function setAdminToken(token: string | null): void {
  if (typeof window === "undefined") {
    return;
  }
  try {
    const t = token?.trim() ?? "";
    if (!t) {
      window.localStorage.removeItem(TOKEN_STORAGE_KEY);
      return;
    }
    window.localStorage.setItem(TOKEN_STORAGE_KEY, t);
  } catch {
    // ignore quota / private mode
  }
}

function buildHeaders(): HeadersInit {
  const headers: Record<string, string> = {
    Accept: "application/json",
  };
  const token = getAdminToken();
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  return headers;
}

async function parseErrorBody(res: Response): Promise<ApiErrorBody | null> {
  try {
    const data: unknown = await res.json();
    if (
      data &&
      typeof data === "object" &&
      ("code" in data || "message" in data)
    ) {
      const o = data as Record<string, unknown>;
      return {
        code: typeof o.code === "string" ? o.code : "",
        message: typeof o.message === "string" ? o.message : res.statusText,
      };
    }
  } catch {
    // non-JSON error body
  }
  return null;
}

export async function adminFetch<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  // Never attach the localStorage admin token to absolute / third-party URLs.
  if (/^https?:\/\//i.test(path) || path.startsWith("//")) {
    throw new AdminApiError(
      400,
      {
        code: "invalid_argument",
        message: "absolute admin API URLs are not allowed",
      },
      "absolute admin API URLs are not allowed",
    );
  }
  const url = `${API_BASE}${path.startsWith("/") ? path : `/${path}`}`;

  const res = await fetch(url, {
    ...init,
    headers: {
      ...buildHeaders(),
      ...(init?.headers ?? {}),
    },
  });

  if (!res.ok) {
    const body = await parseErrorBody(res);
    throw new AdminApiError(
      res.status,
      body,
      `Admin API request failed (${res.status})`,
    );
  }

  if (res.status === 204) {
    return undefined as T;
  }

  return (await res.json()) as T;
}

export function fetchHealth(): Promise<HealthResponse> {
  return adminFetch<HealthResponse>("/health");
}

export function fetchVersion(): Promise<VersionResponse> {
  return adminFetch<VersionResponse>("/version");
}

/**
 * GET /admin/v1/gateway/vault — Mode A vault inventory + HOST-011 mode matrix.
 * Secret-free (SubjectKeyHash only). Hide card on 404 (older BFF residual).
 */

export function fetchGatewayVault(): Promise<GatewayVaultResponse> {
  return adminFetch<GatewayVaultResponse>("/gateway/vault");
}

/**
 * GET /admin/v1/gateway/residual-status — unified gateway residual snapshot
 * (same secret-free fields as `jenkins-mcp gateway residual-status`).
 * Hide card on 404 (older BFF residual). Never tokens/subjects.
 */

export function fetchGatewayResidualStatus(): Promise<GatewayResidualStatusResponse> {
  return adminFetch<GatewayResidualStatusResponse>("/gateway/residual-status");
}

/** Process role + permissions (UI-003). Never returns the token value. */

export function fetchMe(): Promise<MeResponse> {
  return adminFetch<MeResponse>("/me");
}

export function fetchEffectivePolicy(
  profileId: string = getProfileId(),
): Promise<EffectivePolicy> {
  const id = encodeURIComponent(profileId);
  return adminFetch<EffectivePolicy>(`/profiles/${id}/policy/effective`);
}

export function fetchMetrics(): Promise<MetricsResponse> {
  return adminFetch<MetricsResponse>("/metrics");
}

export function fetchAudit(
  profileId: string = getProfileId(),
  query: AuditQuery = {},
): Promise<AuditListResponse> {
  const id = encodeURIComponent(profileId);
  const qs = buildAuditQueryString(query);
  return adminFetch<AuditListResponse>(
    `/profiles/${id}/audit${qs ? `?${qs}` : ""}`,
  );
}

/** Offline doctor by default (v1 safety). */

export function fetchDoctor(
  profileId: string = getProfileId(),
  offline = true,
): Promise<DoctorReport> {
  const id = encodeURIComponent(profileId);
  const offlineParam = offline ? "1" : "0";
  return adminFetch<DoctorReport>(
    `/profiles/${id}/doctor?offline=${offlineParam}`,
  );
}

/** GET /admin/v1/profiles — secret-free list (UI-007). */

export function fetchProfiles(): Promise<ProfileListResponse> {
  return adminFetch<ProfileListResponse>("/profiles");
}

/** GET /admin/v1/profiles/{id} — secret-free detail. */

export function fetchProfile(
  profileId: string = getProfileId(),
): Promise<ProfileSummary> {
  const id = encodeURIComponent(profileId);
  return adminFetch<ProfileSummary>(`/profiles/${id}`);
}

/** GET /admin/v1/profiles/{id}/cache — quota/usage (available:false when no store). */

export function fetchCacheSummary(
  profileId: string = getProfileId(),
): Promise<CacheSummaryResponse> {
  const id = encodeURIComponent(profileId);
  return adminFetch<CacheSummaryResponse>(`/profiles/${id}/cache`);
}

/** POST .../cache/evict-plan — non-destructive (all roles with read). */

export function postCacheEvictPlan(
  profileId: string = getProfileId(),
  targetBytes = 0,
): Promise<EvictionPlanResponse> {
  const id = encodeURIComponent(profileId);
  return adminFetch<EvictionPlanResponse>(`/profiles/${id}/cache/evict-plan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ targetBytes }),
  });
}

/**
 * POST .../cache/evict — operator only; confirm must be exactly "EVICT".
 * Viewer / policy_admin → 403.
 */

export function postCacheEvict(
  profileId: string = getProfileId(),
  confirm: string,
  targetBytes = 0,
): Promise<EvictionPlanResponse> {
  const id = encodeURIComponent(profileId);
  return adminFetch<EvictionPlanResponse>(`/profiles/${id}/cache/evict`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ confirm, targetBytes }),
  });
}

/** POST .../support-bundle — operator only (cache_destructive). */

export function postSupportBundle(
  profileId: string = getProfileId(),
  opts: { preview?: boolean; offline?: boolean } = {},
): Promise<SupportBundleResponse> {
  const id = encodeURIComponent(profileId);
  const preview = opts.preview === true;
  const offline = opts.offline !== false;
  return adminFetch<SupportBundleResponse>(`/profiles/${id}/support-bundle`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ preview, offline }),
  });
}

/** GET .../security-selfcheck — offline, secret-free. */

export function fetchSecuritySelfCheck(
  profileId: string = getProfileId(),
): Promise<SecuritySelfCheckReport> {
  const id = encodeURIComponent(profileId);
  return adminFetch<SecuritySelfCheckReport>(
    `/profiles/${id}/security-selfcheck`,
  );
}

/** True when /me permissions include cache_destructive (operator). */

export function hasCacheDestructive(me: MeResponse | null | undefined): boolean {
  return Boolean(me?.permissions?.includes("cache_destructive"));
}

/** Format AdminApiError (or unknown) for UI — never includes tokens. */

export function formatApiError(err: unknown): { code: string; message: string } {
  if (err instanceof AdminApiError) {
    return { code: err.code, message: err.message };
  }
  if (err instanceof Error) {
    return { code: "client_error", message: err.message };
  }
  return { code: "client_error", message: "Unknown error" };
}

export function fetchPolicyOverlay(): Promise<OverlayGetResponse> {
  return adminFetch<OverlayGetResponse>("/policy/overlay");
}

/** POST /admin/v1/policy/validate (requires policy_write). */

export function validatePolicyOverlay(
  overlay: PolicyOverlay,
  profileId: string = getProfileId(),
): Promise<PolicyValidateResponse> {
  const body: PolicyValidateRequest = {
    overlay,
    profileId: profileId || undefined,
  };
  return adminFetch<PolicyValidateResponse>("/policy/validate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

/** POST /admin/v1/policy/apply (requires policy_write). Never sends keys. */

export function applyPolicyOverlay(
  overlay: PolicyOverlay,
  profileId: string = getProfileId(),
): Promise<PolicyApplyResponse> {
  const body: PolicyValidateRequest = {
    overlay,
    profileId: profileId || undefined,
  };
  return adminFetch<PolicyApplyResponse>("/policy/apply", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

/** True when /me permissions include policy_write (UI-004). */

export function hasPolicyWrite(me: MeResponse | null | undefined): boolean {
  if (!me?.permissions?.length) {
    return false;
  }
  return me.permissions.includes("policy_write");
}

/**
 * Parse newline- or comma-separated deny list text into trimmed unique entries.
 * Empty lines ignored. Does not invent secrets.
 */

export function parseDenyListText(text: string): string[] {
  const parts = text
    .split(/[\n,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  const seen = new Set<string>();
  const out: string[] = [];
  for (const p of parts) {
    if (!seen.has(p)) {
      seen.add(p);
      out.push(p);
    }
  }
  return out;
}

/** Join deny list for textarea display. */

export function formatDenyListText(items?: string[]): string {
  if (!items?.length) {
    return "";
  }
  return items.join("\n");
}
