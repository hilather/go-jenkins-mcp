import { describe, expect, it } from "vitest";
import type { AuditEvent } from "../api/types";
import {
  AUDIT_TYPE_OPTIONS,
  buildAuditExportPayload,
  buildAuditQueryString,
  datetimeLocalToRfc3339,
  filterEventsByExternalSubject,
  formatAuditSubjectCell,
  normalizeAuditLimit,
  olderBeforeCursor,
  presentAuditFields,
} from "./auditQuery";

describe("buildAuditQueryString", () => {
  it("returns empty string with no params", () => {
    expect(buildAuditQueryString({})).toBe("");
  });

  it("includes limit, type, before, external_subject", () => {
    const qs = buildAuditQueryString({
      limit: 50,
      type: "tool_deny",
      before: "2026-01-01T00:00:00Z",
      externalSubject: "alice@idp",
    });
    const params = new URLSearchParams(qs);
    expect(params.get("limit")).toBe("50");
    expect(params.get("type")).toBe("tool_deny");
    expect(params.get("before")).toBe("2026-01-01T00:00:00Z");
    expect(params.get("external_subject")).toBe("alice@idp");
  });

  it("omits blank externalSubject; trims value", () => {
    expect(buildAuditQueryString({ externalSubject: "  " })).toBe("");
    expect(
      new URLSearchParams(
        buildAuditQueryString({ externalSubject: "  bob@idp  " }),
      ).get("external_subject"),
    ).toBe("bob@idp");
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

describe("AUDIT_TYPE_OPTIONS", () => {
  it("includes tool_deny, tool_error, tool_success, mutation_*", () => {
    const values = AUDIT_TYPE_OPTIONS.map((o) => o.value);
    expect(values).toContain("");
    expect(values).toContain("tool_deny");
    expect(values).toContain("tool_error");
    expect(values).toContain("tool_success");
    expect(values).toContain("mutation_preview");
    expect(values).toContain("mutation_confirm");
    expect(values).toContain("mutation_deny");
    // Metrics name tool_ok is not an audit type string.
    expect(values).not.toContain("tool_ok");
  });
});

describe("formatAuditSubjectCell", () => {
  it("returns em dash for empty", () => {
    expect(formatAuditSubjectCell(undefined)).toBe("—");
    expect(formatAuditSubjectCell("")).toBe("—");
    expect(formatAuditSubjectCell("   ")).toBe("—");
  });

  it("returns short values whole", () => {
    expect(formatAuditSubjectCell("alice@idp")).toBe("alice@idp");
    expect(formatAuditSubjectCell("a1b2c3d4e5f67890")).toBe("a1b2c3d4e5f67890");
  });

  it("truncates long values with ellipsis", () => {
    const long = "abcdefghijklmnopqrstuvwxyz";
    expect(formatAuditSubjectCell(long, 8)).toBe("abcdefgh…");
  });
});

describe("filterEventsByExternalSubject", () => {
  const events: AuditEvent[] = [
    {
      time: "t1",
      type: "tool_deny",
      schemaVersion: 1,
      externalSubject: "alice@corp",
      subjectKeyHash: "deadbeefcafebabe",
    },
    {
      time: "t2",
      type: "tool_error",
      schemaVersion: 1,
      externalSubject: "bob@corp",
    },
    { time: "t3", type: "login_success", schemaVersion: 1 },
  ];

  it("returns all when filter empty", () => {
    expect(filterEventsByExternalSubject(events, "")).toEqual(events);
    expect(filterEventsByExternalSubject(events, undefined)).toEqual(events);
  });

  it("exact match case-sensitive (aligns with BFF external_subject)", () => {
    const got = filterEventsByExternalSubject(events, "alice@corp");
    expect(got).toHaveLength(1);
    expect(got[0].externalSubject).toBe("alice@corp");
    // Wrong case / substring must not match
    expect(filterEventsByExternalSubject(events, "ALICE@corp")).toHaveLength(0);
    expect(filterEventsByExternalSubject(events, "alice")).toHaveLength(0);
    expect(filterEventsByExternalSubject(events, "corp")).toHaveLength(0);
  });

  it("excludes events without externalSubject when filter set", () => {
    expect(filterEventsByExternalSubject(events, "alice@corp")).toHaveLength(1);
    expect(filterEventsByExternalSubject(events, "missing@idp")).toHaveLength(0);
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

  it("includes multi-user correlation fields when present", () => {
    const fields = presentAuditFields({
      time: "t1",
      type: "tool_deny",
      schemaVersion: 1,
      externalSubject: "alice@idp",
      subjectKeyHash: "a1b2c3d4e5f67890",
    });
    const map = Object.fromEntries(fields.map((f) => [f.key, f.value]));
    expect(map.externalSubject).toBe("alice@idp");
    expect(map.subjectKeyHash).toBe("a1b2c3d4e5f67890");
  });

  it("skips secret-shaped extra keys (canary)", () => {
    const ev = {
      time: "t1",
      type: "x",
      schemaVersion: 1,
      password: "should-not-appear",
      access_token: "tok",
      Authorization: "Bearer x",
      // Canary: vault-shaped raw key must never be a detail field name we invent.
      vault_token: "CANARY_vault_must_not_appear",
    } as AuditEvent & Record<string, unknown>;
    const fields = presentAuditFields(ev as AuditEvent);
    const blob = JSON.stringify(fields);
    expect(blob).not.toContain("should-not-appear");
    expect(blob).not.toContain("Bearer");
    expect(blob).not.toContain("CANARY_vault");
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

  it("includes multi-user fields on events and client externalSubject filter meta", () => {
    const events: AuditEvent[] = [
      {
        time: "t1",
        type: "tool_error",
        schemaVersion: 1,
        externalSubject: "alice@idp",
        subjectKeyHash: "a1b2c3d4e5f67890",
        decision: "error",
      },
    ];
    const payload = buildAuditExportPayload(
      "corp",
      events,
      {
        truncated: false,
        filters: {
          limit: 50,
          type: "tool_error",
          externalSubject: "alice",
        },
      },
      "2026-01-01T00:00:00.000Z",
    );
    expect(payload.events).toEqual(events);
    const filters = payload.filters as Record<string, unknown>;
    expect(filters.externalSubject).toBe("alice");
    const text = JSON.stringify(payload);
    expect(text).toContain("externalSubject");
    expect(text).toContain("subjectKeyHash");
    expect(text).toContain("a1b2c3d4e5f67890");
    // Canary: never invent tokens into export.
    expect(text.toLowerCase()).not.toContain("bearer");
    expect(text.toLowerCase()).not.toContain("password");
  });
});
