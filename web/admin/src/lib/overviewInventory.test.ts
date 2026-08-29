import { describe, expect, it } from "vitest";
import {
  CONSENT_PURGE_INPUT_KEYS,
  CONSENT_PURGE_RESULT_KEYS,
  K8S_CHECKLIST_ITEMS,
  OVERVIEW_HEALTH_DL_KEYS,
  OVERVIEW_MODE_C_HONESTY_KEYS,
  OVERVIEW_RESIDUAL_STATUS_DL_KEYS,
  OVERVIEW_VAULT_UNIQUE_KEYS,
  OVERVIEW_VERSION_DL_KEYS,
  RESIDUALS_V1_TOPICS,
  SUBJECT_INVALIDATE_INPUT_KEYS,
  SUBJECT_INVALIDATE_RESULT_KEYS,
  VAULT_PUT_SNIPPET,
  formatBytesMiB,
  formatHealthRateCaption,
} from "./overviewInventory";

describe("overview inventories", () => {
  it("keeps Health + Version keys including buildTime and rate knobs", () => {
    expect(OVERVIEW_HEALTH_DL_KEYS).toContain("ratePerMinute");
    expect(OVERVIEW_HEALTH_DL_KEYS).toContain("sharedTokenCacheFile");
    expect(OVERVIEW_VERSION_DL_KEYS).toContain("buildTime");
    expect(OVERVIEW_VERSION_DL_KEYS).toContain("os/arch");
  });

  it("keeps vault-unique and residual-status rows that compact chrome drops easily", () => {
    expect(OVERVIEW_VAULT_UNIQUE_KEYS).toEqual(
      expect.arrayContaining([
        "enabledModes",
        "vaultConfigured",
        "entryCount",
        "subjects",
      ]),
    );
    for (const k of [
      "mode_matrix",
      "residual_ids",
      "principal_cache_entries",
      "shared_api_token_vault_file",
      "shared_jwt_vault_file",
      "gateway_ready",
      "multi_pod_residual_checklist",
      "residual_id (Mode B)",
      "doc",
    ] as const) {
      expect(OVERVIEW_RESIDUAL_STATUS_DL_KEYS).toContain(k);
    }
    expect(OVERVIEW_MODE_C_HONESTY_KEYS).toContain(
      "progressiveConsentStoresTokens",
    );
  });

  it("treats session_id as consent input only (never a result key)", () => {
    expect(CONSENT_PURGE_INPUT_KEYS).toContain("session_id");
    expect(CONSENT_PURGE_RESULT_KEYS).not.toContain("session_id");
    expect(CONSENT_PURGE_INPUT_KEYS).toContain("CLEAR_ALL");
    expect(SUBJECT_INVALIDATE_INPUT_KEYS).toContain("subject_key");
    expect(SUBJECT_INVALIDATE_RESULT_KEYS).toContain("principal_cleared");
  });

  it("keeps k8s checklist, residuals v1 topics, and vault-put snippet", () => {
    expect(K8S_CHECKLIST_ITEMS.length).toBeGreaterThanOrEqual(5);
    expect(RESIDUALS_V1_TOPICS).toContain("consent purge HOST-007 CLEAR_ALL");
    expect(VAULT_PUT_SNIPPET).toContain("vault-put");
    expect(VAULT_PUT_SNIPPET.toLowerCase()).not.toContain("password");
  });
});

describe("formatHealthRateCaption", () => {
  it("uses health numbers and never hardcodes 60/20", () => {
    expect(formatHealthRateCaption(30, 10)).toBe(
      "30 / min · burst 10 · process-local health (not a /metrics field)",
    );
    expect(formatHealthRateCaption(60, 20)).toContain("60 / min · burst 20");
    expect(formatHealthRateCaption(undefined, 10)).toBeNull();
    expect(formatHealthRateCaption(30, undefined)).toBeNull();
  });
});

describe("formatBytesMiB", () => {
  it("formats usage without inventing quota", () => {
    expect(formatBytesMiB(18 * 1024 * 1024)).toBe("18.0 MiB");
    expect(formatBytesMiB(Number.NaN)).toBe("—");
  });
});
