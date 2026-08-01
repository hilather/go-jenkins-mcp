/**
 * Audit list query builders (UI-006).
 * Pure helpers so URL params stay unit-testable without fetch.
 */

import type { AuditEvent, AuditQuery } from "../api/types";

export const AUDIT_LIMIT_OPTIONS = [10, 50, 100, 200] as const;
export type AuditLimit = (typeof AUDIT_LIMIT_OPTIONS)[number];

export const DEFAULT_AUDIT_LIMIT: AuditLimit = 50;

/** Build query string params for GET .../audit (no leading ?). */
export function buildAuditQueryString(query: AuditQuery = {}): string {
  const params = new URLSearchParams();
  if (query.limit != null && Number.isFinite(query.limit)) {
    const lim = Math.min(200, Math.max(1, Math.floor(query.limit)));
    params.set("limit", String(lim));
  }
  if (query.type?.trim()) {
    params.set("type", query.type.trim());
  }
  if (query.before?.trim()) {
    params.set("before", query.before.trim());
  }
  return params.toString();
}

/** Normalize limit to allowed page sizes (API max 200). */
export function normalizeAuditLimit(raw: number | string | undefined): AuditLimit {
  const n = typeof raw === "string" ? Number.parseInt(raw, 10) : raw;
  if (n === 10 || n === 50 || n === 100 || n === 200) {
    return n;
  }
  return DEFAULT_AUDIT_LIMIT;
}

/**
 * Cursor for "load older": exclusive upper bound = oldest event time on page.
 * Returns null when no events.
 */
export function olderBeforeCursor(events: AuditEvent[] | undefined): string | null {
  if (!events?.length) {
    return null;
  }
  // Events are typically newest-first; take the last row's time.
  const last = events[events.length - 1];
  const t = last?.time?.trim();
  return t || null;
}

/**
 * Convert datetime-local input value (local wall clock) to RFC3339 for `before`.
 * Empty input → undefined. Invalid → return trimmed raw string (server may reject).
 */
export function datetimeLocalToRfc3339(localValue: string): string | undefined {
  const v = localValue?.trim();
  if (!v) {
    return undefined;
  }
  // datetime-local is "YYYY-MM-DDTHH:mm" or with seconds.
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) {
    return v;
  }
  return d.toISOString();
}

/** Scrubbed export of loaded audit events (schema fields only as present). */
export function buildAuditExportPayload(
  profileId: string,
  events: AuditEvent[],
  meta: { truncated: boolean; filters: AuditQuery },
  exportedAt: string = new Date().toISOString(),
): Record<string, unknown> {
  return {
    exportedAt,
    source: "GET /admin/v1/profiles/{id}/audit",
    note: "privacy-preserving audit fields only; client-side page export, size-capped to loaded events",
    profileId,
    truncated: meta.truncated,
    filters: {
      limit: meta.filters.limit ?? null,
      type: meta.filters.type ?? null,
      before: meta.filters.before ?? null,
    },
    eventCount: events.length,
    events,
  };
}

/** Ordered keys present on an audit event for detail drawer (no invented fields). */
export const AUDIT_EVENT_FIELD_ORDER = [
  "time",
  "type",
  "schemaVersion",
  "profileId",
  "principalId",
  "externalSubject",
  "subjectKeyHash",
  "tool",
  "action",
  "decision",
  "reasonCode",
  "durationMs",
  "bytesIn",
  "bytesOut",
  "requestId",
  "targetHash",
] as const;

export function presentAuditFields(
  ev: AuditEvent,
): Array<{ key: string; value: string }> {
  const out: Array<{ key: string; value: string }> = [];
  for (const key of AUDIT_EVENT_FIELD_ORDER) {
    if (!(key in ev)) {
      continue;
    }
    const raw = (ev as unknown as Record<string, unknown>)[key];
    if (raw === undefined || raw === null || raw === "") {
      continue;
    }
    out.push({ key, value: String(raw) });
  }
  // Any extra enumerable keys (forward-compat) that are not secrets by contract.
  for (const [k, v] of Object.entries(ev)) {
    if ((AUDIT_EVENT_FIELD_ORDER as readonly string[]).includes(k)) {
      continue;
    }
    if (v === undefined || v === null || v === "") {
      continue;
    }
    // Never surface obvious secret-shaped keys if API ever drifts.
    const lower = k.toLowerCase();
    if (
      lower.includes("token") ||
      lower.includes("password") ||
      lower.includes("secret") ||
      lower.includes("authorization") ||
      lower.includes("cookie")
    ) {
      continue;
    }
    out.push({ key: k, value: String(v) });
  }
  return out;
}
