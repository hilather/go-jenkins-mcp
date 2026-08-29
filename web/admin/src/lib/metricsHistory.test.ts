import { describe, expect, it } from "vitest";
import {
  FORBIDDEN_METRIC_ALIASES,
  METRICS_HISTORY_MAX_POINTS,
  PREFERRED_METRIC_KEYS,
  appendMetricsHistory,
  buildMetricsExportPayload,
  selectMetricKeys,
} from "./metricsHistory";

describe("PREFERRED_METRIC_KEYS", () => {
  it("matches Go registry and excludes forbidden aliases", () => {
    expect(PREFERRED_METRIC_KEYS).toContain("tool_calls");
    expect(PREFERRED_METRIC_KEYS).toContain("mcp_tool_error");
    expect(PREFERRED_METRIC_KEYS).toContain("jenkins_http_wire_bytes_total");
    expect(PREFERRED_METRIC_KEYS).toContain("cache_evict_items");
    expect(PREFERRED_METRIC_KEYS).toContain("cache_maint_ticks");
    expect(PREFERRED_METRIC_KEYS).toContain("jenkins_circuit_open_events_total");
    expect(PREFERRED_METRIC_KEYS).toContain("cache_usage_bytes");
    for (const banned of FORBIDDEN_METRIC_ALIASES) {
      expect(PREFERRED_METRIC_KEYS).not.toContain(banned);
    }
  });
});

describe("selectMetricKeys", () => {
  it("prefers Go registry names and never forbidden aliases", () => {
    const keys = selectMetricKeys({
      counters: {
        tool_calls: 10,
        mcp_tool_ok: 8,
        jenkins_http_requests_total: 4,
        cache_hits: 2,
        cache_evict_items: 1,
        http_requests: 99,
        cache_evict: 50,
        identity_reverify_deny: 7,
        zzz_other: 999,
      },
      gauges: { cache_usage_bytes: 100 },
    });
    expect(keys[0]).toBe("tool_calls");
    expect(keys).toContain("mcp_tool_ok");
    expect(keys).toContain("cache_evict_items");
    expect(keys).toContain("jenkins_http_requests_total");
    expect(keys).not.toContain("cache_evict");
    expect(keys).not.toContain("http_requests");
    expect(keys).not.toContain("identity_reverify_deny");
    expect(keys.indexOf("tool_calls")).toBeLessThan(keys.indexOf("zzz_other"));
  });

  // HOST-006 / OBS residual lite: subject quota counters are preferred when present;
  // never subject keys as series names.
  it("prefers subject quota counters without subject-key labels", () => {
    const keys = selectMetricKeys({
      counters: {
        mcp_subject_rate_quota: 3,
        mcp_subject_slot_quota: 1,
        "tenant|alice|secret-canary": 99,
      },
      gauges: {},
    });
    expect(keys).toContain("mcp_subject_rate_quota");
    expect(keys).toContain("mcp_subject_slot_quota");
    expect(keys.indexOf("mcp_subject_rate_quota")).toBeLessThan(
      keys.indexOf("tenant|alice|secret-canary"),
    );
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
