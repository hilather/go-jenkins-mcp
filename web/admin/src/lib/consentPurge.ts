/**
 * HOST-007 consent-purge SPA helpers (Mode C residual lite).
 * Pure submit gate for Overview form — mirrors BFF/CLI confirm:"CLEAR_ALL".
 */

/** Exact confirm token for destructive clear_all (parity with cache EVICT). */
export const CLEAR_ALL_CONFIRM_TOKEN = "CLEAR_ALL";

export type ConsentPurgeAction = "purge_expired" | "delete_session" | "clear_all";

/**
 * Whether the consent-purge form may submit.
 * clear_all requires typing CLEAR_ALL exactly; purge_expired always ok;
 * delete_session needs a non-empty session_id.
 */
export function canSubmitConsentPurge(opts: {
  action: ConsentPurgeAction;
  sessionId?: string;
  confirmDraft?: string;
}): boolean {
  switch (opts.action) {
    case "purge_expired":
      return true;
    case "delete_session":
      return (opts.sessionId?.trim().length ?? 0) > 0;
    case "clear_all":
      // Exact match (no trim) — same as BFF confirm field and CLI --confirm.
      return opts.confirmDraft === CLEAR_ALL_CONFIRM_TOKEN;
    default:
      return false;
  }
}
