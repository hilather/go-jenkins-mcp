/**
 * Distinguish admin auth failures from BFF-down / proxy errors.
 * formatApiError does not expose HTTP status — callers must use AdminApiError.
 */

import { AdminApiError } from "../api/client";

/** 401/403 or authentication code — BFF is up; token/role is wrong. */
export function isAdminAuthError(err: unknown): boolean {
  if (!(err instanceof AdminApiError)) {
    return false;
  }
  if (err.status === 401 || err.status === 403) {
    return true;
  }
  return err.code === "authentication";
}

/**
 * Network / TypeError, or AdminApiError with 5xx / http_5xx.
 * Vite proxy returns 500/502 HTML when admin serve is down (not TypeError).
 * Never treat 401/403 permission_denied as unreachable.
 */
export function isBffUnreachable(err: unknown): boolean {
  if (isAdminAuthError(err)) {
    return false;
  }
  if (err instanceof AdminApiError) {
    if (err.status >= 500) {
      return true;
    }
    return /^http_5\d\d$/.test(err.code);
  }
  if (err instanceof TypeError) {
    return true;
  }
  if (err instanceof Error) {
    const m = err.message.toLowerCase();
    return m.includes("failed to fetch") || m.includes("network");
  }
  return false;
}

/** Persist/clear token first, then invalidate every query (no allow-list). */
export function invalidateAfterTokenChange(
  invalidateAll: () => void,
  persistToken: () => void,
): void {
  persistToken();
  invalidateAll();
}
