import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchMetrics } from "../api/client";
import { EChart } from "../components/charts/EChart";
import { ErrorBanner, Loading } from "../components/ErrorBanner";
import { PageHeader } from "../components/PageHeader";
import { downloadJson } from "../lib/download";
import {
  historyLineOption,
  multiHistoryLineOption,
  snapshotBarOption,
} from "../lib/metricCharts";
import {
  METRICS_HISTORY_MAX_POINTS,
  appendMetricsHistory,
  buildMetricsExportPayload,
  selectMetricKeys,
  type MetricsHistory,
} from "../lib/metricsHistory";

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
      <h2>{title} (table)</h2>
      {entries.length === 0 ? (
        <p className="muted">Empty.</p>
      ) : (
        <div className="table-scroll">
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
        </div>
      )}
    </div>
  );
}

function HistoryCard({
  label,
  series,
}: {
  label: string;
  series: { t: number; v: number }[];
}) {
  const latest = series.length ? series[series.length - 1].v : 0;
  const option = useMemo(
    () => historyLineOption(label, series),
    [label, series],
  );
  return (
    <div className="metric-chart-card" title={label}>
      <div className="metric-chart-head">
        <span className="mono sparkline-name">{label}</span>
        <span className="mono sparkline-value">{latest}</span>
      </div>
      {option ? (
        <EChart
          option={option}
          height={140}
          ariaLabel={`${label} history, ${series.length} points, latest ${latest}`}
        />
      ) : (
        <p className="muted metric-chart-empty">
          need ≥2 samples for ECharts history
        </p>
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

  const countersBar = useMemo(
    () => snapshotBarOption("Counters", q.data?.counters ?? {}),
    [q.data?.counters],
  );
  const gaugesBar = useMemo(
    () => snapshotBarOption("Gauges", q.data?.gauges ?? {}),
    [q.data?.gauges],
  );
  const overlay = useMemo(
    () => multiHistoryLineOption(history, 6),
    [history],
  );

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
      <PageHeader title="Metrics">
        Process-local telemetry · charts: <strong>Apache ECharts</strong>
      </PageHeader>

      <div className="banner warn" role="status">
        <strong>Residual:</strong> counters/gauges are{" "}
        <em>process-local only</em> for the admin BFF / linked serve registry.
        Multi-process fleet aggregation is out of scope (MGR-002 residual). Empty
        maps when the registry is unset are expected, not an error. Subject quota
        counters (<code>mcp_subject_rate_quota</code> /{" "}
        <code>mcp_subject_slot_quota</code>) are process-local HOST-006 CodeQuota
        totals only — never subject keys as labels; multi-pod aggregation residual.
        History series are browser-session only (max{" "}
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
              <dt>chart library</dt>
              <dd>Apache ECharts (canvas)</dd>
            </dl>
          </div>

          <div className="metrics-charts-grid">
            <div className="card metric-snapshot-card">
              <h2>Counters snapshot</h2>
              <EChart
                option={countersBar}
                height={Math.max(
                  160,
                  Math.min(
                    360,
                    64 + Object.keys(q.data.counters ?? {}).length * 22,
                  ),
                )}
                ariaLabel="Counters bar chart"
              />
            </div>
            <div className="card metric-snapshot-card">
              <h2>Gauges snapshot</h2>
              <EChart
                option={gaugesBar}
                height={Math.max(
                  160,
                  Math.min(
                    360,
                    64 + Object.keys(q.data.gauges ?? {}).length * 22,
                  ),
                )}
                ariaLabel="Gauges bar chart"
              />
            </div>
          </div>

          {overlay && (
            <div className="card">
              <h2>
                History overlay{" "}
                <span className="muted" style={{ fontWeight: 400 }}>
                  (ECharts · session ring ≤ {METRICS_HISTORY_MAX_POINTS})
                </span>
              </h2>
              <EChart
                option={overlay}
                height={280}
                ariaLabel="Multi-series metrics history"
              />
            </div>
          )}

          {trackedKeys.length > 0 && (
            <div className="card">
              <h2>
                Per-metric history{" "}
                <span className="muted" style={{ fontWeight: 400 }}>
                  (ECharts line)
                </span>
              </h2>
              <div className="metric-chart-list">
                {trackedKeys.map((k) => (
                  <HistoryCard key={k} label={k} series={history[k] ?? []} />
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
