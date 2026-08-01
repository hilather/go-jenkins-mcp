import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchMetrics } from "../api/client";
import { ErrorBanner, Loading } from "../components/ErrorBanner";
import { downloadJson } from "../lib/download";
import {
  METRICS_HISTORY_MAX_POINTS,
  appendMetricsHistory,
  buildMetricsExportPayload,
  selectMetricKeys,
  type MetricsHistory,
} from "../lib/metricsHistory";
import { sparklinePoints } from "../lib/sparkline";

const REFRESH_MS = 15_000;

function MapTable({
  title,
  data,
}: {
  title: string;
  data: Record<string, number>;
}) {
  const entries = Object.entries(data ?? {}).sort(([a], [b]) =>
    a.localeCompare(b),
  );
  return (
    <div className="card">
      <h2>{title}</h2>
      {entries.length === 0 ? (
        <p className="muted">Empty.</p>
      ) : (
        <table className="data">
          <thead>
            <tr>
              <th>name</th>
              <th>value</th>
            </tr>
          </thead>
          <tbody>
            {entries.map(([k, v]) => (
              <tr key={k}>
                <td className="mono">{k}</td>
                <td className="mono">{v}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function Sparkline({
  series,
  label,
}: {
  series: { t: number; v: number }[];
  label: string;
}) {
  const latest = series.length ? series[series.length - 1].v : 0;
  const pts = sparklinePoints(series);
  return (
    <div className="sparkline-row" title={label}>
      <div className="sparkline-meta">
        <span className="mono sparkline-name">{label}</span>
        <span className="mono sparkline-value">{latest}</span>
      </div>
      {pts ? (
        <svg
          className="sparkline-svg"
          viewBox="0 0 120 28"
          width="120"
          height="28"
          role="img"
          aria-label={`${label} history, ${series.length} points, latest ${latest}`}
        >
          <polyline
            fill="none"
            stroke="currentColor"
            strokeWidth="1.5"
            points={pts}
          />
        </svg>
      ) : (
        <span className="muted sparkline-empty">need ≥2 samples</span>
      )}
    </div>
  );
}

export function MetricsPage() {
  const [paused, setPaused] = useState(false);
  const [tabHidden, setTabHidden] = useState(
    () =>
      typeof document !== "undefined" &&
      document.visibilityState === "hidden",
  );
  const [history, setHistory] = useState<MetricsHistory>({});

  useEffect(() => {
    const onVis = () => {
      setTabHidden(document.visibilityState === "hidden");
    };
    document.addEventListener("visibilitychange", onVis);
    return () => document.removeEventListener("visibilitychange", onVis);
  }, []);

  const autoRefresh = !paused && !tabHidden;

  const q = useQuery({
    queryKey: ["metrics"],
    queryFn: fetchMetrics,
    retry: 1,
    refetchInterval: autoRefresh ? REFRESH_MS : false,
    refetchIntervalInBackground: false,
  });

  // Record one history sample per successful fetch (including flat counters).
  useEffect(() => {
    if (!q.isSuccess || !q.data) {
      return;
    }
    const maps = {
      counters: q.data.counters ?? {},
      gauges: q.data.gauges ?? {},
    };
    const keys = selectMetricKeys(maps, 8);
    if (keys.length === 0 && !q.data.available) {
      return;
    }
    // Still track preferred empty series when available so sparklines can start.
    const trackKeys =
      keys.length > 0
        ? keys
        : selectMetricKeys(
            { counters: maps.counters, gauges: maps.gauges },
            8,
          );
    if (trackKeys.length === 0) {
      return;
    }
    setHistory((prev) =>
      appendMetricsHistory(prev, maps, trackKeys, q.dataUpdatedAt || Date.now()),
    );
  }, [q.dataUpdatedAt, q.isSuccess, q.data]);

  const trackedKeys = useMemo(() => Object.keys(history).sort(), [history]);

  const exportSnapshot = () => {
    if (!q.data) {
      return;
    }
    const payload = buildMetricsExportPayload({
      available: q.data.available,
      counters: q.data.counters ?? {},
      gauges: q.data.gauges ?? {},
      residual: q.data.residual,
    });
    downloadJson("metrics-snapshot.json", payload);
  };

  const refreshStateLabel = paused
    ? "paused (manual)"
    : tabHidden
      ? "paused (tab hidden)"
      : `auto every ${REFRESH_MS / 1000}s`;

  return (
    <>
      <h1 className="page-title">Metrics</h1>
      <p className="page-sub">
        Process-local telemetry snapshot (
        <code>GET /admin/v1/metrics</code>). No fleet aggregation in v1.
      </p>

      <div className="banner warn" role="status">
        <strong>Residual:</strong> counters/gauges are{" "}
        <em>process-local only</em> for the admin BFF / linked serve registry.
        Multi-process fleet aggregation is out of scope (MGR-002 residual). Empty
        maps when the registry is unset are expected, not an error. Subject quota
        counters (<code>mcp_subject_rate_quota</code> /{" "}
        <code>mcp_subject_slot_quota</code>) are process-local HOST-006 CodeQuota
        totals only — never subject keys as labels; multi-pod aggregation residual.
        History sparklines are browser-session only (max{" "}
        {METRICS_HISTORY_MAX_POINTS} points per key).
      </div>

      <div className="toolbar">
        <button
          type="button"
          className="btn"
          onClick={() => setPaused((p) => !p)}
          aria-pressed={paused}
        >
          {paused ? "Resume auto-refresh" : "Pause auto-refresh"}
        </button>
        <button
          type="button"
          className="btn"
          onClick={() => void q.refetch()}
          disabled={q.isFetching}
        >
          Refresh now
        </button>
        <button
          type="button"
          className="btn"
          onClick={exportSnapshot}
          disabled={!q.isSuccess}
        >
          Export JSON
        </button>
        <span className="toolbar-meta muted" role="status">
          {refreshStateLabel}
          {q.isFetching ? " · fetching…" : ""}
          {q.dataUpdatedAt
            ? ` · last ${new Date(q.dataUpdatedAt).toLocaleTimeString()}`
            : ""}
        </span>
      </div>

      {q.isLoading && <Loading />}
      {q.isError && <ErrorBanner error={q.error} />}

      {q.isSuccess && (
        <>
          {!q.data.available && (
            <div className="banner warn" role="status">
              Metrics registry not available.
              {q.data.residual ? ` ${q.data.residual}` : ""}
            </div>
          )}
          {q.data.available && q.data.residual && (
            <div className="banner warn" role="status">
              {q.data.residual}
            </div>
          )}
          <div className="card">
            <h2>Status</h2>
            <dl className="dl">
              <dt>available</dt>
              <dd>{String(q.data.available)}</dd>
              <dt>tracked series</dt>
              <dd>
                {trackedKeys.length
                  ? trackedKeys.join(", ")
                  : "(waiting for samples)"}
              </dd>
            </dl>
          </div>

          {trackedKeys.length > 0 && (
            <div className="card">
              <h2>
                History sparklines{" "}
                <span className="muted" style={{ fontWeight: 400 }}>
                  (session ring ≤ {METRICS_HISTORY_MAX_POINTS})
                </span>
              </h2>
              <div className="sparkline-list">
                {trackedKeys.map((k) => (
                  <Sparkline key={k} label={k} series={history[k] ?? []} />
                ))}
              </div>
            </div>
          )}

          <MapTable title="Counters" data={q.data.counters} />
          <MapTable title="Gauges" data={q.data.gauges} />
        </>
      )}
    </>
  );
}
