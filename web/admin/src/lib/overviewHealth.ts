/**
 * Overview status chips (UI-POLISH-003). Live-pin 0/1 ECharts bar removed —
 * chips already show A/B/C.
 */

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
    label: "Gateway ready",
    value: input.gatewayReady ? "yes" : "no",
    tone: input.gatewayReady ? "ok" : "residual",
    title: "Admin BFF residual; serve /readyz is authoritative",
  });

  chips.push({
    id: "ha",
    label: "HA replica",
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

/** Live-pin card value: never claim "not live" before residual-status succeeds. */
export function livePinCardValue(
  residualReady: boolean,
  live?: boolean,
): "live" | "not live" | "—" {
  if (!residualReady) {
    return "—";
  }
  return live ? "live" : "not live";
}
