import { describe, expect, it } from "vitest";
import {
  cacheUsageMeterOption,
  historyLineOption,
  leftoverSnapshotRows,
  multiHistoryLineOption,
  pickNamedRows,
  snapshotBarOption,
  subjectQuotaLineOption,
  toolOutcomesLineOption,
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

  it("uses explicit light theme only when passed (force-dark default)", () => {
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

describe("toolOutcomesLineOption", () => {
  it("includes 0 on the y axis and never byte keys", () => {
    const opt = toolOutcomesLineOption({
      tool_calls: [
        { t: 1, v: 1 },
        { t: 2, v: 3 },
      ],
      mcp_tool_ok: [
        { t: 1, v: 1 },
        { t: 2, v: 2 },
      ],
      jenkins_http_wire_bytes_total: [
        { t: 1, v: 1000 },
        { t: 2, v: 2000 },
      ],
    });
    const y = opt.yAxis as { min?: number; scale?: boolean };
    expect(y.min).toBe(0);
    expect(y.scale).toBe(false);
    const series = opt.series as { name: string }[];
    const names = series.map((s) => s.name);
    expect(names).toEqual(
      expect.arrayContaining(["tool_calls", "mcp_tool_ok"]),
    );
    expect(names.some((n) => /bytes/i.test(n))).toBe(false);
  });

  it("returns empty shell when fewer than 2 points", () => {
    const opt = toolOutcomesLineOption({ tool_calls: [{ t: 1, v: 0 }] });
    expect(opt.series).toEqual([]);
    expect(opt.title).toBeTruthy();
  });
});

describe("cacheUsageMeterOption", () => {
  it("reads usage/quota as one bar and never invents 256 MiB", () => {
    const opt = cacheUsageMeterOption(18 * 1024 * 1024, 256 * 1024 * 1024);
    const series = opt.series as { type: string; data: number[] }[];
    expect(series[0].type).toBe("bar");
    expect(series[0].data[0]).toBe(18 * 1024 * 1024);
    const x = opt.xAxis as { max?: number };
    expect(x.max).toBe(256 * 1024 * 1024);
  });

  it("empty shell when quota missing — not a fake 256 MiB", () => {
    const fromCountersOnly = cacheUsageMeterOption(0, 0);
    expect(fromCountersOnly.series).toEqual([]);
    const text = JSON.stringify(fromCountersOnly);
    expect(text).not.toContain("268435456");
  });
});

describe("subjectQuotaLineOption", () => {
  it("only plots CodeQuota names", () => {
    const opt = subjectQuotaLineOption({
      mcp_subject_rate_quota: [
        { t: 1, v: 1 },
        { t: 2, v: 3 },
      ],
      mcp_subject_slot_quota: [
        { t: 1, v: 0 },
        { t: 2, v: 1 },
      ],
      "tenant|alice|secret": [
        { t: 1, v: 99 },
        { t: 2, v: 99 },
      ],
    });
    const names = (opt.series as { name: string }[]).map((s) => s.name);
    expect(names).toEqual(["mcp_subject_rate_quota", "mcp_subject_slot_quota"]);
  });
});

describe("pickNamedRows / leftoverSnapshotRows", () => {
  it("splits HTTP counts from leftover registry names", () => {
    const counters = {
      jenkins_http_requests_total: 140,
      mcp_bytes_out: 12,
      tool_calls: 3,
    };
    expect(pickNamedRows(counters, ["jenkins_http_requests_total"])).toEqual({
      jenkins_http_requests_total: 140,
    });
    const left = leftoverSnapshotRows(counters, { cache_usage_bytes: 1 }, [
      "tool_calls",
      "jenkins_http_requests_total",
      "cache_usage_bytes",
    ]);
    expect(left).toEqual({ mcp_bytes_out: 12 });
  });
});
