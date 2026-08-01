import { afterEach, describe, expect, it, vi } from "vitest";
import {
  AdminApiError,
  DEFAULT_PROFILE,
  TOKEN_STORAGE_KEY,
  applyPolicyOverlay,
  buildAuditQueryString,
  fetchMe,
  formatApiError,
  formatDenyListText,
  hasCacheDestructive,
  hasGatewayOps,
  hasPolicyWrite,
  parseDenyListText,
  postGatewaySubjectInvalidate,
  setAdminToken,
  validatePolicyOverlay,
} from "./client";
import type { MeResponse } from "./types";

describe("AdminApiError", () => {
  it("uses API code and message when present", () => {
    const err = new AdminApiError(
      403,
      { code: "permission_denied", message: "admin token required" },
      "fallback",
    );
    expect(err.status).toBe(403);
    expect(err.code).toBe("permission_denied");
    expect(err.message).toBe("admin token required");
    expect(err.name).toBe("AdminApiError");
  });

  it("falls back when body is null", () => {
    const err = new AdminApiError(502, null, "Admin API request failed (502)");
    expect(err.code).toBe("http_502");
    expect(err.message).toBe("Admin API request failed (502)");
  });
});

describe("formatApiError", () => {
  it("formats AdminApiError for UI display", () => {
    const err = new AdminApiError(
      404,
      { code: "not_found", message: "profile not found" },
      "fallback",
    );
    expect(formatApiError(err)).toEqual({
      code: "not_found",
      message: "profile not found",
    });
  });

  it("formats generic Error without crashing", () => {
    expect(formatApiError(new Error("network down"))).toEqual({
      code: "client_error",
      message: "network down",
    });
  });
});

describe("DEFAULT_PROFILE", () => {
  it("defaults to corp", () => {
    expect(DEFAULT_PROFILE).toBe("corp");
  });
});

describe("buildAuditQueryString (re-export)", () => {
  it("builds query for fetchAudit path", () => {
    const qs = buildAuditQueryString({ limit: 10, type: "login" });
    expect(qs).toContain("limit=10");
    expect(qs).toContain("type=login");
  });
});

describe("adminFetch absolute URL guard", () => {
  it("rejects absolute URLs without calling fetch (no Bearer exfil)", async () => {
    const canary = "planted-spa-token-never-exfil";
    setAdminToken(canary);
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const { adminFetch } = await import("./client");
    await expect(
      adminFetch("https://evil.example/admin/v1/health"),
    ).rejects.toMatchObject({
      code: "invalid_argument",
      status: 400,
    });
    expect(fetchMock).not.toHaveBeenCalled();
    window.localStorage.removeItem(TOKEN_STORAGE_KEY);
    vi.unstubAllGlobals();
  });
});

describe("fetchMe", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    try {
      window.localStorage.removeItem(TOKEN_STORAGE_KEY);
    } catch {
      // ignore
    }
  });

  it("calls GET /admin/v1/me and returns role (never logs token)", async () => {
    const canary = "planted-spa-token-never-log";
    setAdminToken(canary);
    const meBody = {
      authenticated: true,
      role: "viewer",
      permissions: ["read"],
      tokenConfigured: true,
    };
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => meBody,
    });
    vi.stubGlobal("fetch", fetchMock);

    const me = await fetchMe();
    expect(me.role).toBe("viewer");
    expect(me.permissions).toEqual(["read"]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/admin/v1/me");
    const headers = init.headers as Record<string, string>;
    expect(headers.Authorization).toBe(`Bearer ${canary}`);
    // Response must not invent a token field
    expect(me).not.toHaveProperty("token");
    expect(JSON.stringify(me)).not.toContain(canary);
  });

  it("surfaces 401 authentication without echoing secrets", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      statusText: "Unauthorized",
      json: async () => ({
        code: "authentication",
        message: "unauthorized",
      }),
    });
    vi.stubGlobal("fetch", fetchMock);

    await expect(fetchMe()).rejects.toMatchObject({
      status: 401,
      code: "authentication",
    });
  });
});

describe("hasPolicyWrite", () => {
  it("is true only when permissions include policy_write", () => {
    expect(hasPolicyWrite(null)).toBe(false);
    expect(
      hasPolicyWrite({
        authenticated: true,
        role: "viewer",
        permissions: ["read"],
        tokenConfigured: true,
      }),
    ).toBe(false);
    expect(
      hasPolicyWrite({
        authenticated: true,
        role: "operator",
        permissions: ["read", "cache_destructive"],
        tokenConfigured: true,
      }),
    ).toBe(false);
    expect(
      hasPolicyWrite({
        authenticated: true,
        role: "policy_admin",
        permissions: ["read", "policy_write"],
        tokenConfigured: true,
      }),
    ).toBe(true);
  });
});

describe("parseDenyListText / formatDenyListText", () => {
  it("parses newlines and commas, trims, dedupes", () => {
    expect(parseDenyListText("a\nb, c\n\na")).toEqual(["a", "b", "c"]);
    expect(formatDenyListText(["x", "y"])).toBe("x\ny");
    expect(formatDenyListText(undefined)).toBe("");
  });
});

describe("validatePolicyOverlay / applyPolicyOverlay", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    try {
      window.localStorage.removeItem(TOKEN_STORAGE_KEY);
    } catch {
      // ignore
    }
  });

  it("POSTs draft overlay without private keys and never echoes canary", async () => {
    const canary = "planted-spa-token-policy-write";
    setAdminToken(canary);
    const overlay = {
      version: 1,
      force_read_only: true,
      mode: "pilot",
      deny_tools: ["t1"],
      max_tools_per_minute: 12,
      max_tools_burst: 3,
    };
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        valid: true,
        effectivePreview: {
          policy_present: true,
          force_read_only: true,
          max_tools_per_minute: 12,
          max_tools_burst: 3,
        },
      }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const res = await validatePolicyOverlay(overlay, "corp");
    expect(res.valid).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/admin/v1/policy/validate");
    expect(init.method).toBe("POST");
    const body = JSON.parse(String(init.body)) as {
      overlay: Record<string, unknown>;
      profileId: string;
    };
    expect(body.profileId).toBe("corp");
    expect(body.overlay.force_read_only).toBe(true);
    expect(body.overlay.max_tools_per_minute).toBe(12);
    expect(body.overlay.max_tools_burst).toBe(3);
    expect(body.overlay).not.toHaveProperty("private_key");
    expect(body.overlay).not.toHaveProperty("signature");
    expect(JSON.stringify(res)).not.toContain(canary);
  });

  it("apply posts to /policy/apply", async () => {
    setAdminToken("tok");
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ applied: true, path_base: "overlay.json" }),
    });
    vi.stubGlobal("fetch", fetchMock);
    const res = await applyPolicyOverlay(
      { version: 1, force_read_only: true },
      "corp",
    );
    expect(res.applied).toBe(true);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/admin/v1/policy/apply");
    expect(init.method).toBe("POST");
  });
});

describe("hasCacheDestructive (UI-007)", () => {
  it("is true only when permissions include cache_destructive", () => {
    const viewer: MeResponse = {
      authenticated: true,
      role: "viewer",
      permissions: ["read"],
      tokenConfigured: true,
    };
    const operator: MeResponse = {
      authenticated: true,
      role: "operator",
      permissions: ["read", "cache_destructive", "gateway_ops"],
      tokenConfigured: true,
    };
    expect(hasCacheDestructive(viewer)).toBe(false);
    expect(hasCacheDestructive(operator)).toBe(true);
    expect(hasCacheDestructive(null)).toBe(false);
  });
});

describe("hasGatewayOps (HOST-007)", () => {
  it("is true for operator and policy_admin gateway_ops", () => {
    expect(hasGatewayOps(null)).toBe(false);
    expect(
      hasGatewayOps({
        authenticated: true,
        role: "viewer",
        permissions: ["read"],
        tokenConfigured: true,
      }),
    ).toBe(false);
    expect(
      hasGatewayOps({
        authenticated: true,
        role: "operator",
        permissions: ["read", "cache_destructive", "gateway_ops"],
        tokenConfigured: true,
      }),
    ).toBe(true);
    expect(
      hasGatewayOps({
        authenticated: true,
        role: "policy_admin",
        permissions: ["read", "policy_write", "gateway_ops"],
        tokenConfigured: true,
      }),
    ).toBe(true);
  });
});

describe("postGatewaySubjectInvalidate (HOST-007)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    setAdminToken(null);
  });

  it("POSTs identity fields only (never tokens)", async () => {
    const canary = "planted-spa-token-never-in-body";
    setAdminToken(canary);
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        subject_key: "t|alice|corp",
        principal_cleared: true,
        token_cache_cleared: false,
        residual_note: "multi-pod residual",
      }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const res = await postGatewaySubjectInvalidate({
      subject_key: "t|alice|corp",
    });
    expect(res.principal_cleared).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/admin/v1/gateway/subject-invalidate");
    expect(init.method).toBe("POST");
    const body = JSON.parse(String(init.body));
    // Client strips to identity key fields only (never tokens).
    expect(body).toEqual({ subject_key: "t|alice|corp" });
    expect(Object.keys(body).sort()).toEqual(["subject_key"]);
    expect(JSON.stringify(body)).not.toContain(canary);
    // Bearer is header-only for admin shared secret (not Jenkins token).
    const headers = init.headers as Record<string, string>;
    expect(headers.Authorization).toBe(`Bearer ${canary}`);
  });

  it("composes tenant/subject_id/profile when subject_key empty", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ subject_key: "tid|sub|corp", principal_cleared: true }),
    });
    vi.stubGlobal("fetch", fetchMock);
    await postGatewaySubjectInvalidate({
      tenant: "tid",
      subject_id: "sub",
      profile: "corp",
    });
    const body = JSON.parse(String((fetchMock.mock.calls[0] as [string, RequestInit])[1].body));
    expect(body).toEqual({
      tenant: "tid",
      subject_id: "sub",
      profile: "corp",
    });
  });
});
