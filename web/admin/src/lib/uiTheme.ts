/**
 * Shared UI theme helpers for admin SPA polish (UI-POLISH-001/006/007).
 * Pure browser-aware helpers; unit-tested with injectable matchMedia-like probes.
 */

export type ChartThemeTokens = {
  text: string;
  textMuted: string;
  border: string;
  accent: string;
  accentSoft: string;
  ok: string;
  warn: string;
  fail: string;
  bg: string;
  font: string;
  mono: string;
};

/** Dark theme (default) — matches styles.css :root. */
export const chartThemeDark: ChartThemeTokens = {
  text: "#e7ecf3",
  textMuted: "#9aa8bc",
  border: "#2d3a4d",
  accent: "#3d8bfd",
  accentSoft: "rgba(61, 139, 253, 0.35)",
  ok: "#3dd68c",
  warn: "#f5a524",
  fail: "#f31260",
  bg: "transparent",
  font: 'system-ui, "Segoe UI", sans-serif',
  mono: 'ui-monospace, "Cascadia Code", Menlo, monospace',
};

/** Light theme — matches styles.css prefers-color-scheme: light. */
export const chartThemeLight: ChartThemeTokens = {
  text: "#1a2332",
  textMuted: "#5c6b7f",
  border: "#d0d7e2",
  accent: "#006fee",
  accentSoft: "rgba(0, 111, 238, 0.18)",
  ok: "#12a150",
  warn: "#c4841d",
  fail: "#c20e4d",
  bg: "transparent",
  font: chartThemeDark.font,
  mono: chartThemeDark.mono,
};

export type MediaQueryProbe = (query: string) => boolean;

/**
 * Resolve chart tokens for light/dark. Injectable probe for unit tests
 * (avoids real matchMedia in jsdom).
 */
export function resolveChartTheme(
  probe: MediaQueryProbe = defaultMediaProbe,
): ChartThemeTokens {
  if (probe("(prefers-color-scheme: light)")) {
    return chartThemeLight;
  }
  return chartThemeDark;
}

/** True when user prefers reduced motion (UI-POLISH-006). */
export function prefersReducedMotion(
  probe: MediaQueryProbe = defaultMediaProbe,
): boolean {
  return probe("(prefers-reduced-motion: reduce)");
}

/** Animation duration ms for ECharts (0 when reduced motion). */
export function chartAnimationDuration(
  probe: MediaQueryProbe = defaultMediaProbe,
): number {
  return prefersReducedMotion(probe) ? 0 : 200;
}

function defaultMediaProbe(query: string): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
    return false;
  }
  try {
    return window.matchMedia(query).matches;
  } catch {
    return false;
  }
}

/** Nav active class helper (UI-POLISH-002) — pure for tests. */
export function navLinkClassName(isActive: boolean): string {
  return isActive ? "nav-link active" : "nav-link";
}
