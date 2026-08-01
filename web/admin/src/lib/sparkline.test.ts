import { describe, expect, it } from "vitest";
import { barPercents, sparklinePoints } from "./sparkline";

describe("sparklinePoints", () => {
  it("returns empty for fewer than 2 points", () => {
    expect(sparklinePoints([])).toBe("");
    expect(sparklinePoints([{ t: 1, v: 1 }])).toBe("");
  });

  it("returns polyline coordinates for a rising series", () => {
    const pts = sparklinePoints(
      [
        { t: 1, v: 0 },
        { t: 2, v: 10 },
      ],
      100,
      20,
      0,
    );
    expect(pts).toBe("0.0,20.0 100.0,0.0");
  });

  it("handles flat series without NaN", () => {
    const pts = sparklinePoints(
      [
        { t: 1, v: 5 },
        { t: 2, v: 5 },
        { t: 3, v: 5 },
      ],
      100,
      20,
      0,
    );
    expect(pts.includes("NaN")).toBe(false);
    const ys = pts.split(" ").map((p) => p.split(",")[1]);
    expect(ys.every((y) => y === "10.0")).toBe(true);
  });
});

describe("barPercents", () => {
  it("scales to max abs value", () => {
    expect(barPercents([{ t: 1, v: 0 }, { t: 2, v: 50 }, { t: 3, v: 100 }])).toEqual([
      0, 50, 100,
    ]);
  });
});
