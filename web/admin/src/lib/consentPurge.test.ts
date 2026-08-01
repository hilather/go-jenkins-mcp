import { describe, expect, it } from "vitest";
import {
  CLEAR_ALL_CONFIRM_TOKEN,
  canSubmitConsentPurge,
} from "./consentPurge";

describe("canSubmitConsentPurge (HOST-007 clear_all confirm)", () => {
  it("allows purge_expired without confirm", () => {
    expect(canSubmitConsentPurge({ action: "purge_expired" })).toBe(true);
    expect(
      canSubmitConsentPurge({ action: "purge_expired", confirmDraft: "nope" }),
    ).toBe(true);
  });

  it("requires non-empty session_id for delete_session", () => {
    expect(canSubmitConsentPurge({ action: "delete_session" })).toBe(false);
    expect(
      canSubmitConsentPurge({ action: "delete_session", sessionId: "  " }),
    ).toBe(false);
    expect(
      canSubmitConsentPurge({
        action: "delete_session",
        sessionId: "sess-abc",
      }),
    ).toBe(true);
  });

  it("requires exact CLEAR_ALL for clear_all", () => {
    expect(canSubmitConsentPurge({ action: "clear_all" })).toBe(false);
    expect(
      canSubmitConsentPurge({ action: "clear_all", confirmDraft: "" }),
    ).toBe(false);
    expect(
      canSubmitConsentPurge({ action: "clear_all", confirmDraft: "clear_all" }),
    ).toBe(false);
    expect(
      canSubmitConsentPurge({ action: "clear_all", confirmDraft: "EVICT" }),
    ).toBe(false);
    expect(
      canSubmitConsentPurge({
        action: "clear_all",
        confirmDraft: " CLEAR_ALL ",
      }),
    ).toBe(false);
    expect(
      canSubmitConsentPurge({
        action: "clear_all",
        confirmDraft: CLEAR_ALL_CONFIRM_TOKEN,
      }),
    ).toBe(true);
    expect(CLEAR_ALL_CONFIRM_TOKEN).toBe("CLEAR_ALL");
  });
});
