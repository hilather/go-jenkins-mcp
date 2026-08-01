import { describe, expect, it } from "vitest";
import {
  chartAnimationDuration,
  chartThemeDark,
  chartThemeLight,
  navLinkClassName,
  prefersReducedMotion,
  resolveChartTheme,
} from "./uiTheme";

describe("resolveChartTheme", () => {
  it("returns light tokens when prefers light", () => {
    const t = resolveChartTheme((q) => q.includes("prefers-color-scheme: light"));
    expect(t.accent).toBe(chartThemeLight.accent);
    expect(t.text).toBe(chartThemeLight.text);
  });

  it("returns dark tokens otherwise", () => {
    const t = resolveChartTheme(() => false);
    expect(t.accent).toBe(chartThemeDark.accent);
  });
});

describe("prefersReducedMotion / chartAnimationDuration", () => {
  it("detects reduced motion", () => {
    expect(prefersReducedMotion((q) => q.includes("prefers-reduced-motion"))).toBe(
      true,
    );
    expect(prefersReducedMotion(() => false)).toBe(false);
  });

  it("zeros animation when reduced motion", () => {
    expect(
      chartAnimationDuration((q) => q.includes("prefers-reduced-motion")),
    ).toBe(0);
    expect(chartAnimationDuration(() => false)).toBe(200);
  });
});

describe("navLinkClassName", () => {
  it("marks active nav links", () => {
    expect(navLinkClassName(true)).toBe("nav-link active");
    expect(navLinkClassName(false)).toBe("nav-link");
  });
});
