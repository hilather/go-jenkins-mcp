/**
 * Bounded client-side history for metrics dashboard (UI-005).
 * Caps series length to bound SPA memory; no high-cardinality labels.
 */

/** Max points retained per series (process-local SPA ring buffer). */
export const METRICS_HISTORY_MAX_POINTS = 60;

/** Preferred counter/gauge names when present in a snapshot. */
export const PREFERRED_METRIC_KEYS = [
  "tool_calls",
  "mcp_tool_ok",
  "mcp_tool_error",
  "mcp_tool_deny",
  "http_requests",
  "http_errors",
  "http_bytes_in",
  "http_bytes_out",
  "circuit_open",
  "cache_evict",
  "cache_maint",
  "identity_reverify_deny",
] as const;

export interface MetricsSnapshotMaps {
  counters: Record<string, number>;
  gauges: Record<string, number>;
}

export interface HistoryPoint {
  t: number;
  v: number;
}

/** name → ring of {t, v} points (newest last). */
export type MetricsHistory = Record<string, HistoryPoint[]>;

/**
 * Pick which metric keys to track for sparklines.
 * Prefer known operational names when present; else top N by absolute value.
 */
export function selectMetricKeys(
  maps: MetricsSnapshotMaps,
  maxKeys = 8,
): string[] {
  const merged: Record<string, number> = {
    ...(maps.counters ?? {}),
    ...(maps.gauges ?? {}),
  };
  const preferred = PREFERRED_METRIC_KEYS.filter((k) => k in merged);
  if (preferred.length >= maxKeys) {
    return preferred.slice(0, maxKeys);
  }
  const preferredSet = new Set<string>(preferred);
  const rest = Object.entries(merged)
    .filter(([k]) => !preferredSet.has(k))
    .sort((a, b) => Math.abs(b[1]) - Math.abs(a[1]) || a[0].localeCompare(b[0]))
    .map(([k]) => k);
  return [...preferred, ...rest].slice(0, maxKeys);
}

/**
 * Append one snapshot into a bounded history map for the given keys.
 * Missing keys get value 0 for that tick so series stay aligned.
 */
export function appendMetricsHistory(
  prev: MetricsHistory,
  maps: MetricsSnapshotMaps,
  keys: string[],
  nowMs: number = Date.now(),
  maxPoints: number = METRICS_HISTORY_MAX_POINTS,
): MetricsHistory {
  const merged: Record<string, number> = {
    ...(maps.counters ?? {}),
    ...(maps.gauges ?? {}),
  };
  const next: MetricsHistory = { ...prev };
  for (const key of keys) {
    const series = [...(next[key] ?? [])];
    series.push({ t: nowMs, v: Number(merged[key] ?? 0) });
    if (series.length > maxPoints) {
      series.splice(0, series.length - maxPoints);
    }
    next[key] = series;
  }
  // Drop series no longer selected to bound memory.
  for (const k of Object.keys(next)) {
    if (!keys.includes(k)) {
      delete next[k];
    }
  }
  return next;
}

/** Build a secret-free export payload from current snapshot + residual note. */
export function buildMetricsExportPayload(
  snapshot: {
    available: boolean;
    counters: Record<string, number>;
    gauges: Record<string, number>;
    residual?: string;
  },
  exportedAt: string = new Date().toISOString(),
): Record<string, unknown> {
  return {
    exportedAt,
    source: "GET /admin/v1/metrics",
    note: "process-local snapshot only; no fleet aggregation",
    available: snapshot.available,
    counters: snapshot.counters ?? {},
    gauges: snapshot.gauges ?? {},
    residual: snapshot.residual ?? "",
  };
}
