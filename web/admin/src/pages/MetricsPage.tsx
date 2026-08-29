import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchHealth, fetchMetrics } from "../api/client";
import { EChart } from "../components/charts/EChart";
import { ResidualCallout } from "../components/ResidualCallout";
import { ErrorBanner, Loading } from "../components/ErrorBanner";
import { PageHeader } from "../components/PageHeader";
import { StatusChipRow } from "../components/StatusChip";
import { downloadJson } from "../lib/download";
import {
  cacheUsageMeterOption,
  leftoverSnapshotRows,
  pickNamedRows,
  subjectQuotaLineOption,
  toolOutcomesLineOption,
} from "../lib/metricCharts";
import { formatBytesMiB, formatHealthRateCaption } from "../lib/overviewInventory";
import {
  HTTP_BYTE_KEYS,
  HTTP_COUNT_KEYS,
  LEFTOVER_COUNT_KEYS,
  METRICS_HISTORY_MAX_POINTS,
  SUBJECT_QUOTA_KEYS,
  TOOL_OUTCOME_KEYS,
  appendMetricsHistory,
  buildMetricsExportPayload,
  type MetricsHistory,
} from "../lib/metricsHistory";
import type { StatusChip } from "../lib/overviewHealth";

const REFRESH_MS = 15_000;

const CLAIMED_METRIC_KEYS = [
  ...TOOL_OUTCOME_KEYS,
  ...SUBJECT_QUOTA_KEYS,
  ...HTTP_COUNT_KEYS,
  ...HTTP_BYTE_KEYS,
  ...LEFTOVER_COUNT_KEYS,
  "cache_usage_bytes",
  "cache_quota_bytes",
] as const;

function MapTable({
  title,
  subtitle,
  data,
}: {
  title: string;
  subtitle?: string;
  data: Record<string, number>;
}) {
  const entries = Object.entries(data ?? {}).sort(([a], [b]) =>
    a.localeCompare(b),
  );
  return (
    <div className="card">
      <h2>
        {title}{" "}
        {subtitle ? (
          <span className="muted" style={{ fontWeight: 400 }}>
            ({subtitle})
          </span>
        ) : null}
      </h2>
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

  const healthQ = useQuery({
    queryKey: ["health"],
    queryFn: fetchHealth,
    retry: 1,
    staleTime: 30_000,
  });

  useEffect(() => {
    if (!q.isSuccess || !q.data || !q.data.available) {
      return;
    }
    const maps = {
      counters: q.data.counters ?? {},
      gauges: q.data.gauges ?? {},
    };
    const trackKeys = [...TOOL_OUTCOME_KEYS, ...SUBJECT_QUOTA_KEYS];
    setHistory((prev) =>
      appendMetricsHistory(prev, maps, trackKeys, q.dataUpdatedAt || Date.now()),
    );
  }, [q.dataUpdatedAt, q.isSuccess, q.data]);

  const counters = q.data?.counters ?? {};
  const gauges = q.data?.gauges ?? {};
  const available = Boolean(q.data?.available);

  const outcomes = useMemo(() => toolOutcomesLineOption(history), [history]);
  const quotaChart = useMemo(() => subjectQuotaLineOption(history), [history]);
  const cacheMeter = useMemo(
    () =>
      cacheUsageMeterOption(
        Number(gauges.cache_usage_bytes ?? 0),
        Number(gauges.cache_quota_bytes ?? 0),
      ),
    [gauges.cache_usage_bytes, gauges.cache_quota_bytes],
  );

  const httpCounts = pickNamedRows(counters, HTTP_COUNT_KEYS);
  const httpBytes = pickNamedRows(counters, HTTP_BYTE_KEYS);
  const leftoverNamed = pickNamedRows(counters, LEFTOVER_COUNT_KEYS);
  const leftoverOther = leftoverSnapshotRows(counters, gauges, CLAIMED_METRIC_KEYS);

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

  const rateCaption = formatHealthRateCaption(
    healthQ.data?.ratePerMinute,
    healthQ.data?.rateBurst,
  );

  const chips: StatusChip[] = available
    ? [
        {
          id: "registry",
          label: "Registry",
          value: "available",
          tone: "ok",
        },
        {
          id: "tool_calls",
          label: "tool_calls",
          value: String(counters.tool_calls ?? 0),
          tone: "neutral",
        },
        {
          id: "ok",
          label: "mcp_tool_ok",
          value: String(counters.mcp_tool_ok ?? 0),
          tone: "ok",
        },
        {
          id: "err-deny",
          label: "error / deny",
          value: `${counters.mcp_tool_error ?? 0} · ${counters.mcp_tool_deny ?? 0}`,
          tone: "warn",
        },
        {
          id: "hits",
          label: "cache_hits",
          value: String(counters.cache_hits ?? 0),
          tone: "neutral",
        },
        {
          id: "quota",
          label: "quota denials",
          value: `rate ${counters.mcp_subject_rate_quota ?? 0} · slot ${counters.mcp_subject_slot_quota ?? 0}`,
          tone: "residual",
        },
      ]
    : [
        {
          id: "registry",
          label: "Registry",
          value: "unavailable",
          tone: "residual",
          title: "No linked serve registry — not a live zero snapshot",
        },
      ];

  const usage = Number(gauges.cache_usage_bytes ?? 0);
  const quota = Number(gauges.cache_quota_bytes ?? 0);

  return (
    <>
      <PageHeader title="Metrics">
        Process-local counters for this process. No fleet, no job graphs —
        GET /admin/v1/metrics only.
      </PageHeader>

      <StatusChipRow chips={chips} />

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
          Export snapshot
        </button>
        <span className="toolbar-meta muted" role="status">
          {refreshStateLabel}
          {" · session ring ≤ "}
          {METRICS_HISTORY_MAX_POINTS}
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
          <ResidualCallout
            caveat="Process-local snapshot · no fleet aggregation · session history ≤ 60 pts"
          >
            {q.data.residual ? <p className="muted">{q.data.residual}</p> : null}
            <p className="muted">
              available={String(q.data.available)}. Export is the current
              snapshot only (not the session ring). Never subject keys.
            </p>
          </ResidualCallout>

          {!available && (
            <div className="banner warn" role="status">
              Metrics registry not available.
              {q.data.residual ? ` ${q.data.residual}` : ""}{" "}
              Empty maps are expected — not a live zero process.
            </div>
          )}

          {available && (
            <>
              <div className="metrics-split">
                <div className="card metric-snapshot-card">
                  <h2>
                    Tool outcomes{" "}
                    <span className="muted" style={{ fontWeight: 400 }}>
                      cumulative counts · y includes 0
                    </span>
                  </h2>
                  <EChart
                    option={outcomes}
                    height={280}
                    ariaLabel="Tool outcome cumulative counts"
                  />
                  <p className="chart-caption muted">
                    Same unit. tool_calls = ok + error + deny. Quota denials
                    also increment mcp_tool_error (not a fourth outcome). Not a
                    rate — flat means no new Inc this interval.
                  </p>
                </div>
                <div>
                  <div className="card metric-snapshot-card">
                    <h2>
                      Cache posture{" "}
                      <span className="muted" style={{ fontWeight: 400 }}>
                        gauges · bytes
                      </span>
                    </h2>
                    <EChart
                      option={cacheMeter}
                      height={140}
                      ariaLabel="Cache usage versus quota"
                    />
                    <p className="chart-caption muted">
                      {quota > 0
                        ? `${formatBytesMiB(usage)} cache_usage_bytes of ${formatBytesMiB(quota)} quota`
                        : "cache_quota_bytes missing — no invented quota. One comparison, one unit."}
                    </p>
                  </div>
                  <div className="card metric-snapshot-card">
                    <h2>
                      Subject quota{" "}
                      <span className="residual-badge">HOST-006</span>
                    </h2>
                    <EChart
                      option={quotaChart}
                      height={180}
                      ariaLabel="Subject rate and slot quota denials"
                    />
                    <p className="chart-caption muted">
                      CodeQuota totals.
                      {rateCaption ? ` ${rateCaption}.` : " "}
                      Never subject keys.
                    </p>
                  </div>
                </div>
              </div>

              <div className="metrics-tables">
                <MapTable
                  title="Jenkins HTTP"
                  subtitle="counts"
                  data={httpCounts}
                />
                <MapTable
                  title="Bytes"
                  subtitle="not on the count charts"
                  data={httpBytes}
                />
              </div>
              <MapTable
                title="Other registry counts"
                subtitle="leftover preferred + overflow"
                data={{ ...leftoverNamed, ...leftoverOther }}
              />
            </>
          )}
        </>
      )}
    </>
  );
}
