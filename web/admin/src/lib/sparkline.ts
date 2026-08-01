/**
 * Deprecated pure-geometry helpers (pre-ECharts).
 *
 * Agent policy: **do not** use these for admin UI charts. All charts must use
 * Apache ECharts via `components/charts/EChart` and `lib/metricCharts.ts`.
 * Kept only for unit coverage of scaling math; prefer `metricCharts` for new work.
 */

export interface SparklinePoint {
  t: number;
  v: number;
}

/**
 * Build an SVG polyline points string for a series.
 * Returns empty string if fewer than 2 points.
 */
export function sparklinePoints(
  series: SparklinePoint[],
  width = 120,
  height = 28,
  pad = 2,
): string {
  if (!series || series.length < 2) {
    return "";
  }
  const values = series.map((p) => p.v);
  let min = Math.min(...values);
  let max = Math.max(...values);
  if (min === max) {
    // Flat line: center vertically.
    min -= 1;
    max += 1;
  }
  const n = series.length;
  const innerW = width - pad * 2;
  const innerH = height - pad * 2;
  return series
    .map((p, i) => {
      const x = pad + (n === 1 ? innerW / 2 : (i / (n - 1)) * innerW);
      const y = pad + innerH - ((p.v - min) / (max - min)) * innerH;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
}

/** Mini bar widths as percentages of max value (for CSS bar lists). */
export function barPercents(series: SparklinePoint[]): number[] {
  if (!series.length) {
    return [];
  }
  const max = Math.max(...series.map((p) => Math.abs(p.v)), 1);
  return series.map((p) => Math.round((Math.abs(p.v) / max) * 100));
}
