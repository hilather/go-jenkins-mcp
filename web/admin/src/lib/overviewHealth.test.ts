import { describe, expect, it } from "vitest";
import {
  buildOverviewStatusChips,
  overviewLivePinBarOption,
} from "./overviewHealth";

describe("buildOverviewStatusChips", () => {
  it("returns BFF unreachable chip only when API down", () => {
    const chips = buildOverviewStatusChips({ apiReachable: false });
    expect(chips).toHaveLength(1);
    expect(chips[0].id).toBe("api");
    expect(chips[0].tone).toBe("warn");
  });

  it("builds health and residual chips when online", () => {
    const chips = buildOverviewStatusChips({
      apiReachable: true,
      status: "ok",
      multiUserEnabled: true,
      gatewayReady: false,
      haMultiReplica: false,
      credentialMode: "api_token_vault",
      residualAvailable: true,
      modeALive: false,
      modeBLive: false,
      modeCLive: false,
    });
    const ids = chips.map((c) => c.id);
    expect(ids).toContain("health");
    expect(ids).toContain("live-pins");
    expect(chips.find((c) => c.id === "health")?.tone).toBe("ok");
    expect(chips.find((c) => c.id === "ha")?.value).toBe("no");
  });
});

describe("overviewLivePinBarOption", () => {
  it("returns bar series for residual false counts", () => {
    const opt = overviewLivePinBarOption({
      residualAvailable: true,
      modeALive: false,
      modeBLive: false,
      modeCLive: false,
    });
    const series = opt.series as { type: string; data: number[] }[];
    expect(series[0].type).toBe("bar");
    expect(series[0].data).toContain(1);
  });

  it("empty shell when residual unavailable", () => {
    const opt = overviewLivePinBarOption({ residualAvailable: false });
    expect(opt.series).toEqual([]);
  });
});
