import { describe, expect, it } from "vitest";
import type { AuditEvent } from "../api/types";
import {
  buildAuditExportPayload,
  buildAuditQueryString,
  datetimeLocalToRfc3339,
  normalizeAuditLimit,
  olderBeforeCursor,
  presentAuditFields,
} from "./auditQuery";

describe("buildAuditQueryString", () => {
  it("returns empty string with no params", () => {
    expect(buildAuditQueryString({})).toBe("");
  });

  it("includes limit, type, before", () => {
    const qs = buildAuditQueryString({
      limit: 50,
      type: "tool_deny",
      before: "2026-01-01T00:00:00Z",
    });
    const params = new URLSearchParams(qs);
    expect(params.get("limit")).toBe("50");
    expect(params.get("type")).toBe("tool_deny");
    expect(params.get("before")).toBe("2026-01-01T00:00:00Z");
  });

  it("clamps limit to 1..200", () => {
    expect(new URLSearchParams(buildAuditQueryString({ limit: 999 })).get("limit")).toBe(
      "200",
    );
    expect(new URLSearchParams(buildAuditQueryString({ limit: 0 })).get("limit")).toBe(
      "1",
    );
  });

  it("trims type and before; omits blank type", () => {
    expect(buildAuditQueryString({ type: "  " })).toBe("");
    expect(
      new URLSearchParams(buildAuditQueryString({ type: "  auth_fail  " })).get(
        "type",
      ),
    ).toBe("auth_fail");
  });
});

describe("normalizeAuditLimit", () => {
  it("accepts allowed sizes", () => {
    expect(normalizeAuditLimit(10)).toBe(10);
    expect(normalizeAuditLimit("100")).toBe(100);
    expect(normalizeAuditLimit(200)).toBe(200);
  });

  it("defaults unknown values to 50", () => {
    expect(normalizeAuditLimit(75)).toBe(50);
    expect(normalizeAuditLimit(undefined)).toBe(50);
  });
});

describe("olderBeforeCursor", () => {
  it("returns last event time", () => {
    const events: AuditEvent[] = [
      { time: "2026-01-02T00:00:00Z", type: "a", schemaVersion: 1 },
      { time: "2026-01-01T00:00:00Z", type: "b", schemaVersion: 1 },
    ];
    expect(olderBeforeCursor(events)).toBe("2026-01-01T00:00:00Z");
  });

  it("returns null for empty", () => {
    expect(olderBeforeCursor([])).toBeNull();
    expect(olderBeforeCursor(undefined)).toBeNull();
  });
});

describe("datetimeLocalToRfc3339", () => {
  it("returns undefined for empty", () => {
    expect(datetimeLocalToRfc3339("")).toBeUndefined();
    expect(datetimeLocalToRfc3339("   ")).toBeUndefined();
  });

  it("converts valid local datetime to ISO string", () => {
    const iso = datetimeLocalToRfc3339("2026-06-15T12:30");
    expect(iso).toMatch(/^2026-06-15T/);
    expect(iso?.endsWith("Z") || iso?.includes("+") || iso?.includes("-")).toBe(
      true,
    );
  });
});

describe("presentAuditFields", () => {
  it("shows only present schema fields", () => {
    const fields = presentAuditFields({
      time: "t1",
      type: "tool_deny",
      schemaVersion: 1,
      decision: "deny",
      tool: "jenkins_get_job",
    });
    const keys = fields.map((f) => f.key);
    expect(keys).toEqual([
      "time",
      "type",
      "schemaVersion",
      "tool",
      "decision",
    ]);
  });

  it("skips secret-shaped extra keys (canary)", () => {
    const ev = {
      time: "t1",
      type: "x",
      schemaVersion: 1,
      password: "should-not-appear",
      access_token: "tok",
      Authorization: "Bearer x",
    } as AuditEvent & Record<string, unknown>;
    const fields = presentAuditFields(ev as AuditEvent);
    const blob = JSON.stringify(fields);
    expect(blob).not.toContain("should-not-appear");
    expect(blob).not.toContain("Bearer");
    expect(blob.toLowerCase()).not.toContain("password");
    expect(blob.toLowerCase()).not.toContain("token");
  });
});

describe("buildAuditExportPayload", () => {
  it("exports loaded events only with filter meta", () => {
    const events: AuditEvent[] = [
      { time: "t1", type: "a", schemaVersion: 1 },
    ];
    const payload = buildAuditExportPayload(
      "corp",
      events,
      { truncated: true, filters: { limit: 50, type: "a" } },
      "2026-01-01T00:00:00.000Z",
    );
    expect(payload.profileId).toBe("corp");
    expect(payload.eventCount).toBe(1);
    expect(payload.truncated).toBe(true);
    expect(payload.events).toEqual(events);
    const text = JSON.stringify(payload);
    expect(text.toLowerCase()).not.toContain("password");
  });
});
