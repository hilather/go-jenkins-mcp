import { describe, expect, it } from "vitest";
import {
  historyLineOption,
  multiHistoryLineOption,
  snapshotBarOption,
} from "./metricCharts";
import { chartThemeLight } from "./uiTheme";

describe("historyLineOption", () => {
  it("returns null for fewer than 2 points", () => {
    expect(historyLineOption("x", [])).toBeNull();
    expect(historyLineOption("x", [{ t: 1, v: 1 }])).toBeNull();
  });

  it("builds a line series with time-value pairs", () => {
    const opt = historyLineOption("mcp_ok", [
      { t: 1000, v: 1 },
      { t: 2000, v: 3 },
    ]);
    expect(opt).not.toBeNull();
    const series = opt!.series as { type: string; data: [number, number][] }[];
    expect(series).toHaveLength(1);
    expect(series[0].type).toBe("line");
    expect(series[0].data).toEqual([
      [1000, 1],
      [2000, 3],
    ]);
  });
});

describe("snapshotBarOption", () => {
  it("returns empty-state option without series data", () => {
    const opt = snapshotBarOption("Counters", {});
    expect(opt.series).toEqual([]);
    expect(opt.title).toBeTruthy();
  });

  it("sorts by magnitude and uses bar type", () => {
    const opt = snapshotBarOption("Gauges", { a: 1, b: 10, c: 5 });
    const series = opt.series as { type: string; data: number[] }[];
    expect(series[0].type).toBe("bar");
    // Reversed so largest ends at top of category axis.
    expect(series[0].data).toEqual([1, 5, 10]);
  });

  it("caps bar count", () => {
    const data: Record<string, number> = {};
    for (let i = 0; i < 30; i++) {
      data[`m${i}`] = i;
    }
    const opt = snapshotBarOption("Counters", data, 5);
    const yAxis = opt.yAxis as { data: string[] };
    expect(yAxis.data).toHaveLength(5);
  });
});

describe("multiHistoryLineOption", () => {
  it("returns null when no series has ≥2 points", () => {
    expect(multiHistoryLineOption({ a: [{ t: 1, v: 1 }] })).toBeNull();
  });

  it("includes only series with enough points", () => {
    const opt = multiHistoryLineOption({
      short: [{ t: 1, v: 1 }],
      long: [
        { t: 1, v: 1 },
        { t: 2, v: 2 },
      ],
    });
    expect(opt).not.toBeNull();
    const series = opt!.series as { name: string }[];
    expect(series.map((s) => s.name)).toEqual(["long"]);
  });

  it("zeros animation under reduced-motion probe", () => {
    const opt = historyLineOption(
      "x",
      [
        { t: 1, v: 1 },
        { t: 2, v: 2 },
      ],
      { probe: (q) => q.includes("prefers-reduced-motion") },
    );
    expect(opt?.animationDuration).toBe(0);
  });

  it("uses light theme tokens when probe asks for light", () => {
    const opt = snapshotBarOption(
      "C",
      { a: 2 },
      16,
      { theme: chartThemeLight },
    );
    const series = opt.series as { itemStyle: { color: string } }[];
    expect(series[0].itemStyle.color).toBe(chartThemeLight.accent);
  });
});
