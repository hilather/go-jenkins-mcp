import { describe, expect, it } from "vitest";
import {
  METRICS_HISTORY_MAX_POINTS,
  appendMetricsHistory,
  buildMetricsExportPayload,
  selectMetricKeys,
} from "./metricsHistory";

describe("selectMetricKeys", () => {
  it("prefers known operational names when present", () => {
    const keys = selectMetricKeys({
      counters: {
        tool_calls: 10,
        mcp_tool_ok: 8,
        zzz_other: 999,
      },
      gauges: { cache_evict: 1 },
    });
    expect(keys[0]).toBe("tool_calls");
    expect(keys).toContain("mcp_tool_ok");
    expect(keys).toContain("cache_evict");
    expect(keys.indexOf("tool_calls")).toBeLessThan(keys.indexOf("zzz_other"));
  });

  it("falls back to top N by absolute value when preferred missing", () => {
    const keys = selectMetricKeys(
      {
        counters: { a: 1, b: 50, c: 10 },
        gauges: { d: 100 },
      },
      3,
    );
    expect(keys).toEqual(["d", "b", "c"]);
  });

  it("caps key count", () => {
    const counters: Record<string, number> = {};
    for (let i = 0; i < 20; i++) {
      counters[`m${i}`] = i;
    }
    expect(selectMetricKeys({ counters, gauges: {} }, 5)).toHaveLength(5);
  });
});

describe("appendMetricsHistory", () => {
  it("appends points and caps series length", () => {
    let hist = appendMetricsHistory(
      {},
      { counters: { tool_calls: 1 }, gauges: {} },
      ["tool_calls"],
      1000,
      3,
    );
    hist = appendMetricsHistory(
      hist,
      { counters: { tool_calls: 2 }, gauges: {} },
      ["tool_calls"],
      2000,
      3,
    );
    hist = appendMetricsHistory(
      hist,
      { counters: { tool_calls: 3 }, gauges: {} },
      ["tool_calls"],
      3000,
      3,
    );
    hist = appendMetricsHistory(
      hist,
      { counters: { tool_calls: 4 }, gauges: {} },
      ["tool_calls"],
      4000,
      3,
    );
    expect(hist.tool_calls).toHaveLength(3);
    expect(hist.tool_calls.map((p) => p.v)).toEqual([2, 3, 4]);
    expect(hist.tool_calls[0].t).toBe(2000);
  });

  it("uses 0 for missing keys and drops unselected series", () => {
    let hist = appendMetricsHistory(
      {},
      { counters: { a: 1, b: 2 }, gauges: {} },
      ["a", "b"],
      1,
    );
    hist = appendMetricsHistory(
      hist,
      { counters: { a: 3 }, gauges: {} },
      ["a"],
      2,
    );
    expect(hist.a).toHaveLength(2);
    expect(hist.a[1].v).toBe(3);
    expect(hist.b).toBeUndefined();
  });

  it("default max points is METRICS_HISTORY_MAX_POINTS", () => {
    expect(METRICS_HISTORY_MAX_POINTS).toBe(60);
    let hist: ReturnType<typeof appendMetricsHistory> = {};
    for (let i = 0; i < 65; i++) {
      hist = appendMetricsHistory(
        hist,
        { counters: { x: i }, gauges: {} },
        ["x"],
        i,
      );
    }
    expect(hist.x).toHaveLength(60);
    expect(hist.x[0].v).toBe(5);
    expect(hist.x[59].v).toBe(64);
  });
});

describe("buildMetricsExportPayload", () => {
  it("builds secret-free snapshot envelope", () => {
    const payload = buildMetricsExportPayload(
      {
        available: true,
        counters: { tool_calls: 1 },
        gauges: {},
        residual: "process-local",
      },
      "2026-01-01T00:00:00.000Z",
    );
    expect(payload).toEqual({
      exportedAt: "2026-01-01T00:00:00.000Z",
      source: "GET /admin/v1/metrics",
      note: "process-local snapshot only; no fleet aggregation",
      available: true,
      counters: { tool_calls: 1 },
      gauges: {},
      residual: "process-local",
    });
    const text = JSON.stringify(payload);
    expect(text.toLowerCase()).not.toContain("authorization");
    expect(text.toLowerCase()).not.toContain("password");
    expect(text.toLowerCase()).not.toContain("token");
  });
});
