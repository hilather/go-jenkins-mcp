import { describe, expect, it } from "vitest";
import { NAV_GROUPS, flatNavItems, navTo } from "./navGroups";

describe("NAV_GROUPS", () => {
  it("orders Status / Config / Ops with required routes", () => {
    expect(NAV_GROUPS.map((g) => g.id)).toEqual(["status", "config", "ops"]);
    expect(NAV_GROUPS[0].items.map((i) => i.to)).toEqual([
      "/",
      "/metrics",
      "/doctor",
    ]);
    expect(NAV_GROUPS[1].items.map((i) => i.to)).toEqual([
      "/profiles",
      "/policy",
      "/access",
    ]);
    expect(NAV_GROUPS[2].items.map((i) => i.to)).toEqual(["/audit", "/cache"]);
  });

  it("badges Metrics 15s and marks Overview end", () => {
    const metrics = NAV_GROUPS[0].items.find((i) => i.to === "/metrics");
    expect(metrics?.badge).toBe("15s");
    expect(NAV_GROUPS[0].items.find((i) => i.to === "/")?.end).toBe(true);
  });

  it("does not invent login or fleet routes", () => {
    const paths = flatNavItems().map((i) => i.to);
    expect(paths).not.toContain("/login");
    expect(paths.some((p) => p.includes("fleet") || p.includes("queue"))).toBe(
      false,
    );
  });
});

describe("navTo", () => {
  it("preserves profile search on every link", () => {
    expect(navTo("/metrics", "profile=corp")).toEqual({
      pathname: "/metrics",
      search: "profile=corp",
    });
  });
});
