/**
 * ECharts option builders for admin metrics (UI-005).
 *
 * Agent policy: all charts in the admin SPA MUST use Apache ECharts
 * (via echarts / echarts-for-react). Do not add Recharts, Chart.js, D3
 * chart shells, or ad-hoc SVG chart libraries. Pure helpers here stay
 * free of React so unit tests can assert options without a browser.
 */

import type { AdminChartOption } from "../components/charts/EChart";
import {
  chartAnimationDuration,
  chartThemeDark,
  resolveChartTheme,
  type ChartThemeTokens,
  type MediaQueryProbe,
} from "./uiTheme";

export interface MetricSeriesPoint {
  t: number;
  v: number;
}

/** @deprecated Prefer AdminChartOption; alias for option builders. */
export type EChartsOption = AdminChartOption;

/** @deprecated Use resolveChartTheme() — kept for callers expecting chartTheme. */
export const chartTheme = chartThemeDark;

export type ChartOptionOpts = {
  /** Injectable media probe (tests); default uses window.matchMedia. */
  probe?: MediaQueryProbe;
  theme?: ChartThemeTokens;
};

function themeOf(opts?: ChartOptionOpts): ChartThemeTokens {
  return opts?.theme ?? resolveChartTheme(opts?.probe);
}

function animOf(opts?: ChartOptionOpts): number {
  return chartAnimationDuration(opts?.probe);
}

function baseGrid(): NonNullable<EChartsOption["grid"]> {
  return {
    left: 48,
    right: 16,
    top: 28,
    bottom: 32,
    containLabel: false,
  };
}

/**
 * Time-series line chart for one metric history ring (session-local).
 * Returns null when fewer than 2 points (caller shows empty state).
 */
export function historyLineOption(
  label: string,
  series: MetricSeriesPoint[],
  opts?: ChartOptionOpts,
): EChartsOption | null {
  if (!series || series.length < 2) {
    return null;
  }
  const theme = themeOf(opts);
  const times = series.map((p) => p.t);
  const values = series.map((p) => p.v);
  return {
    backgroundColor: theme.bg,
    animationDuration: animOf(opts),
    textStyle: { color: theme.text, fontFamily: theme.font },
    tooltip: {
      trigger: "axis",
      confine: true,
      valueFormatter: (v) => String(v ?? ""),
    },
    grid: { ...baseGrid(), top: 16, bottom: 24, left: 40, right: 12 },
    xAxis: {
      type: "time",
      axisLabel: {
        color: theme.textMuted,
        fontSize: 10,
        hideOverlap: true,
      },
      axisLine: { lineStyle: { color: theme.border } },
      splitLine: { show: false },
    },
    yAxis: {
      type: "value",
      scale: true,
      axisLabel: { color: theme.textMuted, fontSize: 10 },
      splitLine: { lineStyle: { color: theme.border, type: "dashed" } },
    },
    series: [
      {
        name: label,
        type: "line",
        showSymbol: series.length <= 12,
        symbolSize: 6,
        smooth: prefersSmooth(opts) ? 0.2 : 0,
        lineStyle: { width: 2, color: theme.accent },
        itemStyle: { color: theme.accent },
        areaStyle: { color: theme.accentSoft },
        data: times.map((t, i) => [t, values[i]]),
      },
    ],
  };
}

function prefersSmooth(opts?: ChartOptionOpts): boolean {
  return animOf(opts) > 0;
}

/**
 * Horizontal bar chart of a counter/gauge map snapshot (top N by |value|).
 * Empty maps return an option with a graphic "Empty" note so the card still
 * mounts a chart surface (metrics must always have a visualization shell).
 */
export function snapshotBarOption(
  title: string,
  data: Record<string, number>,
  maxBars = 16,
  opts?: ChartOptionOpts,
): EChartsOption {
  const theme = themeOf(opts);
  const entries = Object.entries(data ?? {})
    .map(([name, value]) => ({ name, value: Number(value) || 0 }))
    .sort((a, b) => Math.abs(b.value) - Math.abs(a.value))
    .slice(0, maxBars)
    .reverse(); // category axis bottom→top: largest at top after reverse

  if (entries.length === 0) {
    return {
      backgroundColor: theme.bg,
      animationDuration: animOf(opts),
      title: {
        text: title,
        left: "center",
        top: "middle",
        textStyle: {
          color: theme.textMuted,
          fontSize: 13,
          fontWeight: 400,
          fontFamily: theme.font,
        },
        subtext: "No series in this snapshot",
        subtextStyle: { color: theme.textMuted, fontSize: 11 },
      },
      xAxis: { show: false },
      yAxis: { show: false },
      series: [],
    };
  }

  return {
    backgroundColor: theme.bg,
    animationDuration: animOf(opts),
    textStyle: { color: theme.text, fontFamily: theme.font },
    tooltip: {
      trigger: "axis",
      axisPointer: { type: "shadow" },
      confine: true,
    },
    grid: {
      left: 12,
      right: 28,
      top: 8,
      bottom: 8,
      containLabel: true,
    },
    xAxis: {
      type: "value",
      axisLabel: { color: theme.textMuted, fontSize: 10 },
      splitLine: { lineStyle: { color: theme.border, type: "dashed" } },
    },
    yAxis: {
      type: "category",
      data: entries.map((e) => e.name),
      axisLabel: {
        color: theme.text,
        fontSize: 11,
        fontFamily: theme.mono,
        width: 160,
        overflow: "truncate",
      },
      axisLine: { lineStyle: { color: theme.border } },
      axisTick: { show: false },
    },
    series: [
      {
        name: title,
        type: "bar",
        data: entries.map((e) => e.value),
        itemStyle: {
          color: theme.accent,
          borderRadius: [0, 4, 4, 0],
        },
        label: {
          show: true,
          position: "right",
          color: theme.textMuted,
          fontSize: 10,
          fontFamily: theme.mono,
        },
      },
    ],
  };
}

/** Multi-series overlay for tracked history keys (compact dashboard). */
export function multiHistoryLineOption(
  seriesByKey: Record<string, MetricSeriesPoint[]>,
  maxSeries = 6,
  opts?: ChartOptionOpts,
): EChartsOption | null {
  const theme = themeOf(opts);
  const keys = Object.keys(seriesByKey)
    .filter((k) => (seriesByKey[k]?.length ?? 0) >= 2)
    .sort()
    .slice(0, maxSeries);
  if (keys.length === 0) {
    return null;
  }
  const palette = [
    theme.accent,
    theme.ok,
    theme.warn,
    "#a78bfa",
    "#22d3ee",
    "#fb7185",
  ];
  const smooth = prefersSmooth(opts) ? 0.15 : 0;
  return {
    backgroundColor: theme.bg,
    animationDuration: animOf(opts),
    textStyle: { color: theme.text, fontFamily: theme.font },
    legend: {
      type: "scroll",
      bottom: 0,
      textStyle: { color: theme.textMuted, fontSize: 10 },
      pageTextStyle: { color: theme.textMuted },
    },
    tooltip: { trigger: "axis", confine: true },
    grid: { ...baseGrid(), bottom: 48 },
    xAxis: {
      type: "time",
      axisLabel: { color: theme.textMuted, fontSize: 10, hideOverlap: true },
      axisLine: { lineStyle: { color: theme.border } },
      splitLine: { show: false },
    },
    yAxis: {
      type: "value",
      scale: true,
      axisLabel: { color: theme.textMuted, fontSize: 10 },
      splitLine: { lineStyle: { color: theme.border, type: "dashed" } },
    },
    series: keys.map((name, i) => {
      const pts = seriesByKey[name] ?? [];
      return {
        name,
        type: "line" as const,
        showSymbol: false,
        smooth,
        lineStyle: { width: 2, color: palette[i % palette.length] },
        itemStyle: { color: palette[i % palette.length] },
        data: pts.map((p) => [p.t, p.v]),
      };
    }),
  };
}
