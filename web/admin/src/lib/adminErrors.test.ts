import { describe, expect, it, vi } from "vitest";
import { AdminApiError } from "../api/client";
import {
  invalidateAfterTokenChange,
  isAdminAuthError,
  isBffUnreachable,
} from "./adminErrors";

describe("isAdminAuthError", () => {
  it("detects 401 authentication", () => {
    const err = new AdminApiError(
      401,
      { code: "authentication", message: "admin token required" },
      "fallback",
    );
    expect(isAdminAuthError(err)).toBe(true);
    expect(isBffUnreachable(err)).toBe(false);
  });

  it("detects 403 permission_denied as auth, not down", () => {
    const err = new AdminApiError(
      403,
      { code: "permission_denied", message: "denied" },
      "fallback",
    );
    expect(isAdminAuthError(err)).toBe(true);
    expect(isBffUnreachable(err)).toBe(false);
  });
});

describe("isBffUnreachable", () => {
  it("treats Vite-proxy 502 AdminApiError as unreachable", () => {
    const err = new AdminApiError(502, null, "Admin API request failed (502)");
    expect(err.code).toBe("http_502");
    expect(isBffUnreachable(err)).toBe(true);
    expect(isAdminAuthError(err)).toBe(false);
  });

  it("treats 500 as unreachable", () => {
    const err = new AdminApiError(500, null, "Admin API request failed (500)");
    expect(isBffUnreachable(err)).toBe(true);
  });

  it("treats TypeError / failed to fetch as unreachable", () => {
    expect(isBffUnreachable(new TypeError("Failed to fetch"))).toBe(true);
    expect(isBffUnreachable(new Error("network down"))).toBe(true);
  });
});

describe("invalidateAfterTokenChange", () => {
  it("persists token before invalidate (no stale Bearer refetch)", () => {
    const order: string[] = [];
    invalidateAfterTokenChange(
      () => {
        order.push("invalidate");
      },
      () => {
        order.push("persist");
      },
    );
    expect(order).toEqual(["persist", "invalidate"]);
  });

  it("does not skip persist when invalidate throws", () => {
    const persist = vi.fn();
    expect(() =>
      invalidateAfterTokenChange(() => {
        throw new Error("qc");
      }, persist),
    ).toThrow("qc");
    expect(persist).toHaveBeenCalledOnce();
  });
});
