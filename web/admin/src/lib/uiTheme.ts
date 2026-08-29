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

/** Dark lab (forced) — matches styles.css :root. */
export const chartThemeDark: ChartThemeTokens = {
  text: "#ecece8",
  textMuted: "#9aa3ad",
  border: "#2a2d33",
  accent: "#6ea8fe",
  accentSoft: "rgba(110, 168, 254, 0.35)",
  ok: "#3dd68c",
  warn: "#f5a524",
  fail: "#f31260",
  bg: "transparent",
  font: '"IBM Plex Sans", system-ui, sans-serif',
  mono: '"IBM Plex Mono", ui-monospace, monospace',
};

/** Unused fixture after force-dark (do not use in production builders). */
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
 * Forced dark-lab charts. Probe is accepted for call-site compatibility
 * but light OS preference must not paint light tokens on dark chrome.
 */
export function resolveChartTheme(
  _probe: MediaQueryProbe = defaultMediaProbe,
): ChartThemeTokens {
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
