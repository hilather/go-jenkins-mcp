import { describe, expect, it } from "vitest";
import { buildOverviewStatusChips, livePinCardValue } from "./overviewHealth";

describe("buildOverviewStatusChips", () => {
  it("returns BFF unreachable chip only when API down (not 401)", () => {
    const chips = buildOverviewStatusChips({ apiReachable: false });
    expect(chips).toHaveLength(1);
    expect(chips[0].id).toBe("api");
    expect(chips[0].tone).toBe("warn");
  });

  it("does not use unreachable when apiReachable is true (401 path)", () => {
    const chips = buildOverviewStatusChips({
      apiReachable: true,
      status: "ok",
      residualAvailable: false,
    });
    expect(chips.find((c) => c.id === "api")).toBeUndefined();
    expect(chips.find((c) => c.id === "health")?.value).toBe("ok");
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
    expect(chips.find((c) => c.id === "ha")?.label).toBe("HA replica");
    expect(chips.find((c) => c.id === "live-pins")?.value).toBe("———");
  });
});

describe("livePinCardValue", () => {
  it("does not claim not live until residual-status succeeds", () => {
    expect(livePinCardValue(false, false)).toBe("—");
    expect(livePinCardValue(false, true)).toBe("—");
    expect(livePinCardValue(true, false)).toBe("not live");
    expect(livePinCardValue(true, true)).toBe("live");
  });
});
