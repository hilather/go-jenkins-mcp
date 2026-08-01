/**
 * Overview status chips + optional numeric health chart (UI-POLISH-003).
 * Pure builders — drive ECharts via metricCharts.snapshotBarOption.
 */

import type { AdminChartOption } from "../components/charts/EChart";
import { snapshotBarOption } from "./metricCharts";

export type StatusChipTone = "ok" | "warn" | "fail" | "neutral" | "residual";

export interface StatusChip {
  id: string;
  label: string;
  value: string;
  tone: StatusChipTone;
  title?: string;
}

export interface OverviewHealthInput {
  status?: string;
  multiUserEnabled?: boolean;
  gatewayReady?: boolean;
  haMultiReplica?: boolean;
  credentialMode?: string;
  /** Live pin flags from residual-status (always false offline). */
  modeALive?: boolean;
  modeBLive?: boolean;
  modeCLive?: boolean;
  residualAvailable?: boolean;
  apiReachable?: boolean;
}

/** Build operator-facing status chips from health/residual snapshot. */
export function buildOverviewStatusChips(input: OverviewHealthInput): StatusChip[] {
  const chips: StatusChip[] = [];

  if (input.apiReachable === false) {
    chips.push({
      id: "api",
      label: "BFF",
      value: "unreachable",
      tone: "warn",
      title: "Admin BFF not reachable — expected until admin serve is running",
    });
    return chips;
  }

  const st = (input.status || "").toLowerCase();
  chips.push({
    id: "health",
    label: "Health",
    value: input.status || "—",
    tone: st === "ok" || st === "healthy" ? "ok" : st ? "warn" : "neutral",
  });

  chips.push({
    id: "mode",
    label: "Credential mode",
    value: input.credentialMode || "—",
    tone: "neutral",
  });

  chips.push({
    id: "multi-user",
    label: "Multi-user",
    value: input.multiUserEnabled ? "on" : "off",
    tone: input.multiUserEnabled ? "residual" : "neutral",
    title: input.multiUserEnabled
      ? "Foundation residual — not multi-pod live GO"
      : undefined,
  });

  chips.push({
    id: "gateway-ready",
    label: "Gateway ready (BFF)",
    value: input.gatewayReady ? "yes" : "no",
    tone: input.gatewayReady ? "ok" : "residual",
    title: "Admin BFF residual; serve /readyz is authoritative",
  });

  chips.push({
    id: "ha",
    label: "HA multi-replica",
    value: input.haMultiReplica ? "yes" : "no",
    tone: input.haMultiReplica ? "warn" : "ok",
    title: "HOST-008 Tier A expects no (single-replica)",
  });

  if (input.residualAvailable !== false) {
    const liveA = Boolean(input.modeALive);
    const liveB = Boolean(input.modeBLive);
    const liveC = Boolean(input.modeCLive);
    chips.push({
      id: "live-pins",
      label: "Live pins A/B/C",
      value: `${liveA ? "A" : "—"}${liveB ? "B" : "—"}${liveC ? "C" : "—"}`,
      tone: liveA || liveB || liveC ? "ok" : "residual",
      title: "mode_*_live_*_qualified — false until production evidence",
    });
  }

  return chips;
}

/**
 * Numeric residual honesty chart: counts of live-qualified flags still false
 * vs true (ECharts only). Always returns an option (empty shell if no residual).
 */
export function overviewLivePinBarOption(input: {
  modeALive?: boolean;
  modeBLive?: boolean;
  modeCLive?: boolean;
  residualAvailable?: boolean;
}): AdminChartOption {
  if (input.residualAvailable === false) {
    return snapshotBarOption("Live pin flags", {});
  }
  const data: Record<string, number> = {
    mode_a_live_false: input.modeALive ? 0 : 1,
    mode_b_live_false: input.modeBLive ? 0 : 1,
    mode_c_live_false: input.modeCLive ? 0 : 1,
    mode_a_live_true: input.modeALive ? 1 : 0,
    mode_b_live_true: input.modeBLive ? 1 : 0,
    mode_c_live_true: input.modeCLive ? 1 : 0,
  };
  // Prefer showing residual false counts (typical offline: three 1s).
  const residualFacing: Record<string, number> = {
    "A not live-qualified": data.mode_a_live_false,
    "B not live-qualified": data.mode_b_live_false,
    "C not live-qualified": data.mode_c_live_false,
  };
  return snapshotBarOption("Live pin residual (1 = still residual)", residualFacing);
}
