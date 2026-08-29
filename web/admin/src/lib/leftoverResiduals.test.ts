import { describe, expect, it } from "vitest";
import {
  ACCESS_RESIDUAL_CAVEAT,
  ACCESS_RESIDUAL_DETAILS,
  AUDIT_RESIDUAL_CAVEAT,
  AUDIT_RESIDUAL_DETAILS,
  CACHE_RESIDUAL_CAVEAT,
  CACHE_RESIDUAL_DETAILS,
  DOCTOR_RESIDUAL_CAVEAT,
  DOCTOR_RESIDUAL_DETAILS,
  POLICY_RESIDUAL_CAVEAT,
  POLICY_RESIDUAL_DETAILS,
  PROFILES_RESIDUAL_CAVEAT,
  PROFILES_RESIDUAL_DETAILS,
} from "./leftoverResiduals";

describe("leftover residual caveats", () => {
  it("Profiles mentions secret-free / never tokens", () => {
    expect(PROFILES_RESIDUAL_CAVEAT).toMatch(/secret-free/i);
    expect(PROFILES_RESIDUAL_CAVEAT).toMatch(/never/i);
    expect(PROFILES_RESIDUAL_DETAILS).toMatch(/hasCredential/);
  });

  it("Policy mentions lower-only HOST-006 / HOST-008", () => {
    expect(POLICY_RESIDUAL_CAVEAT).toMatch(/lower only/i);
    expect(POLICY_RESIDUAL_CAVEAT).toMatch(/HOST-006/);
    expect(POLICY_RESIDUAL_DETAILS).toMatch(/LowerRate/);
  });

  it("Access mentions break-glass / signed config", () => {
    expect(ACCESS_RESIDUAL_CAVEAT).toMatch(/break-glass/i);
    expect(ACCESS_RESIDUAL_CAVEAT).toMatch(/signed/);
    expect(ACCESS_RESIDUAL_DETAILS).toMatch(/basename/i);
  });

  it("Audit mentions no SSE / File-sink", () => {
    expect(AUDIT_RESIDUAL_CAVEAT).toMatch(/no SSE/);
    expect(AUDIT_RESIDUAL_DETAILS).toMatch(/type_filter/);
  });

  it("Doctor does not claim live GO", () => {
    expect(DOCTOR_RESIDUAL_CAVEAT).toMatch(/not production GO/);
    expect(DOCTOR_RESIDUAL_DETAILS).toMatch(/HOST-007/);
    expect(DOCTOR_RESIDUAL_DETAILS).not.toMatch(/live-pin-blockers\.md/);
  });

  it("Cache mentions CLI pin residual", () => {
    expect(CACHE_RESIDUAL_CAVEAT).toMatch(/CLI/);
    expect(CACHE_RESIDUAL_DETAILS).toMatch(/available:false/);
  });
});
