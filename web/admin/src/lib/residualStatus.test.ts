/**
 * HOST-007 residual-status field pick / honesty helpers.
 */

import { describe, expect, it } from "vitest";
import type { GatewayResidualStatusResponse } from "../api/types";
import {
  CONSENT_FILE_BACKED_HONESTY,
  CONSENT_MULTI_REPLICA_SHARED_HONESTY,
  CONSENT_SAME_HOST_RELOAD_HONESTY,
  CONSENT_STORES_TOKENS_HONESTY,
  formatPrincipalCacheHygiene,
  formatResidualBool,
  GATEWAY_READY_RESIDUAL_HONESTY,
  HA_MULTI_REPLICA_RESIDUAL_HONESTY,
  LIVE_PIN_RESIDUAL_HONESTY,
  pickProgressiveConsentFields,
  pickResidualLivePinFields,
  pickResidualRateCacheFields,
  PRINCIPAL_CACHE_PROCESS_HONESTY,
  SHARED_JWKS_FILE_HONESTY,
  SHARED_SUBJECT_RATE_FILE_HONESTY,
  SHARED_TOKEN_CACHE_FILE_HONESTY,
  SUBJECT_LIMITER_MAX_SUBJECTS_HONESTY,
  SUBJECT_SLOTS_PROCESS_LOCAL_HONESTY,
} from "./residualStatus";

describe("pickResidualRateCacheFields", () => {
  it("defaults shared_* flags false when payload missing", () => {
    expect(pickResidualRateCacheFields(undefined)).toEqual({
      shared_subject_rate_file: false,
      shared_principal_cache_file: false,
      shared_jwks_file: false,
      shared_token_cache_file: false,
      subject_slots_process_local: false,
    });
    expect(pickResidualRateCacheFields(null)).toEqual({
      shared_subject_rate_file: false,
      shared_principal_cache_file: false,
      shared_jwks_file: false,
      shared_token_cache_file: false,
      subject_slots_process_local: false,
    });
  });

  it("mirrors Wave 11 snake_case residual-status keys including shared_token_cache_file", () => {
    const data: GatewayResidualStatusResponse = {
      shared_subject_rate_file: true,
      shared_principal_cache_file: true,
      shared_jwks_file: true,
      shared_token_cache_file: true,
      subject_rate_max_subjects: 64,
      subject_limiter_max_subjects: 2048,
      subject_slots_process_local: true,
      principal_cache_entries: 3,
      principal_cache_max_entries: 256,
      principal_cache_ttl_seconds: 7200,
      principal_cache_process_note: "note",
      rateEnabled: true,
      ratePerMinute: 30,
      rateBurst: 10,
    };
    expect(pickResidualRateCacheFields(data)).toEqual({
      shared_subject_rate_file: true,
      shared_principal_cache_file: true,
      shared_jwks_file: true,
      shared_token_cache_file: true,
      subject_rate_max_subjects: 64,
      subject_limiter_max_subjects: 2048,
      subject_slots_process_local: true,
      principal_cache_entries: 3,
      principal_cache_max_entries: 256,
      principal_cache_ttl_seconds: 7200,
      principal_cache_process_note: "note",
    });
  });

  it("omits optional hygiene knobs when absent (unlimited / no TTL)", () => {
    const data: GatewayResidualStatusResponse = {
      shared_subject_rate_file: false,
      shared_jwks_file: false,
      shared_token_cache_file: false,
      subject_slots_process_local: true,
      principal_cache_entries: 0,
    };
    expect(pickResidualRateCacheFields(data)).toEqual({
      shared_subject_rate_file: false,
      shared_principal_cache_file: false,
      shared_jwks_file: false,
      shared_token_cache_file: false,
      subject_slots_process_local: true,
      principal_cache_entries: 0,
    });
    expect(pickResidualRateCacheFields(data).subject_limiter_max_subjects).toBeUndefined();
  });

  it("never invents subjects or path fields from residual map", () => {
    const data = {
      shared_subject_rate_file: true,
      shared_jwks_file: true,
      shared_token_cache_file: true,
      subject_slots_process_local: true,
      principal_cache_entries: 1,
      // adversarial noise — must not surface as typed rate/cache fields
      subject: "tenant|alice|profile",
      token: "canary-secret-token",
      path: "/tmp/jwks-cache.json",
      jwks_cache_path: "/secret/path/jwks.json",
      token_cache_path: "/secret/path/token.json",
    } as GatewayResidualStatusResponse;
    const picked = pickResidualRateCacheFields(data);
    expect(picked).toEqual({
      shared_subject_rate_file: true,
      shared_principal_cache_file: false,
      shared_jwks_file: true,
      shared_token_cache_file: true,
      subject_slots_process_local: true,
      principal_cache_entries: 1,
    });
    expect(JSON.stringify(picked)).not.toMatch(/canary|alice|secret-token|path|secret\/path/i);
  });

  it("only treats explicit boolean true as shared_*_file / subject_slots (never Boolean() truthy strings)", () => {
    // Regression: Boolean("false") === true; residual honesty must fail closed.
    const noisy = {
      shared_subject_rate_file: "false",
      shared_principal_cache_file: "true",
      shared_jwks_file: 1,
      shared_token_cache_file: "yes",
      subject_slots_process_local: "true",
    } as unknown as GatewayResidualStatusResponse;
    expect(pickResidualRateCacheFields(noisy)).toEqual({
      shared_subject_rate_file: false,
      shared_principal_cache_file: false,
      shared_jwks_file: false,
      shared_token_cache_file: false,
      subject_slots_process_local: false,
    });
  });
});

describe("formatPrincipalCacheHygiene", () => {
  it("returns null when both omitted", () => {
    expect(formatPrincipalCacheHygiene()).toBeNull();
    expect(formatPrincipalCacheHygiene(0, 0)).toBeNull();
  });

  it("formats max and ttl when positive", () => {
    expect(formatPrincipalCacheHygiene(256, 7200)).toBe(
      "max_entries=256 · ttl_seconds=7200",
    );
    expect(formatPrincipalCacheHygiene(100, undefined)).toBe("max_entries=100");
    expect(formatPrincipalCacheHygiene(undefined, 60)).toBe("ttl_seconds=60");
  });
});

describe("pickResidualLivePinFields", () => {
  it("defaults all live pins false when payload missing", () => {
    expect(pickResidualLivePinFields(undefined)).toEqual({
      mode_a_live_obtain_qualified: false,
      mode_b_live_rs_qualified: false,
      mode_c_live_agentcore_qualified: false,
      gateway_ready: false,
      ha_multi_replica: false,
    });
    expect(pickResidualLivePinFields(null)).toEqual({
      mode_a_live_obtain_qualified: false,
      mode_b_live_rs_qualified: false,
      mode_c_live_agentcore_qualified: false,
      gateway_ready: false,
      ha_multi_replica: false,
    });
  });

  it("mirrors residual-status live pin keys and defaults missing to false", () => {
    const data: GatewayResidualStatusResponse = {
      mode_a_live_obtain_qualified: false,
      mode_b_live_rs_qualified: false,
      mode_c_live_agentcore_qualified: false,
      gateway_ready: false,
      ha_multi_replica: false,
    };
    expect(pickResidualLivePinFields(data)).toEqual({
      mode_a_live_obtain_qualified: false,
      mode_b_live_rs_qualified: false,
      mode_c_live_agentcore_qualified: false,
      gateway_ready: false,
      ha_multi_replica: false,
    });
    // Partial payload: omitted keys stay false (fail-closed honesty).
    expect(
      pickResidualLivePinFields({
        mode_b_live_rs_qualified: false,
      }),
    ).toEqual({
      mode_a_live_obtain_qualified: false,
      mode_b_live_rs_qualified: false,
      mode_c_live_agentcore_qualified: false,
      gateway_ready: false,
      ha_multi_replica: false,
    });
  });

  it("only treats explicit true as true (never invent live GO from truthy noise)", () => {
    // Regression: residual-status always emits false; SPA must not claim GO from
    // adversarial/accidental truthy strings if a proxy rewrote JSON.
    const data = {
      mode_a_live_obtain_qualified: true,
      mode_b_live_rs_qualified: false,
      mode_c_live_agentcore_qualified: false,
      gateway_ready: false,
      ha_multi_replica: false,
      token: "canary-secret-token",
      subject: "tenant|alice|profile",
    } as GatewayResidualStatusResponse;
    const picked = pickResidualLivePinFields(data);
    expect(picked.mode_a_live_obtain_qualified).toBe(true);
    expect(picked.mode_b_live_rs_qualified).toBe(false);
    expect(JSON.stringify(picked)).not.toMatch(/canary|alice|token|secret/i);
  });
});

describe("formatResidualBool", () => {
  it("formats false as no/false and true as yes/true", () => {
    expect(formatResidualBool(false)).toBe("no/false");
    expect(formatResidualBool(true)).toBe("yes/true");
  });
});

describe("pickProgressiveConsentFields", () => {
  it("defaults all consent honesty false when payload missing", () => {
    expect(pickProgressiveConsentFields(undefined)).toEqual({
      metadata_path_done_star: false,
      browser_3lo_automated: false,
      stores_tokens: false,
      multi_replica_shared: false,
      file_backed: false,
      same_host_reload_before_persist: false,
    });
    expect(pickProgressiveConsentFields(null)).toEqual({
      metadata_path_done_star: false,
      browser_3lo_automated: false,
      stores_tokens: false,
      multi_replica_shared: false,
      file_backed: false,
      same_host_reload_before_persist: false,
    });
  });

  it("picks progressive_consent nest from residual-status (file_backed + same_host_reload)", () => {
    const data: GatewayResidualStatusResponse = {
      progressive_consent: {
        metadata_path_done_star: true,
        browser_3lo_automated: false,
        stores_tokens: false,
        multi_replica_shared: false,
        file_backed: true,
        same_host_reload_before_persist: true,
      },
    };
    expect(pickProgressiveConsentFields(data)).toEqual({
      metadata_path_done_star: true,
      browser_3lo_automated: false,
      stores_tokens: false,
      multi_replica_shared: false,
      file_backed: true,
      same_host_reload_before_persist: true,
    });
  });

  it("accepts progressive_consent map alone", () => {
    expect(
      pickProgressiveConsentFields({
        metadata_path_done_star: true,
        file_backed: true,
        same_host_reload_before_persist: true,
        stores_tokens: false,
        multi_replica_shared: false,
      }),
    ).toEqual({
      metadata_path_done_star: true,
      browser_3lo_automated: false,
      stores_tokens: false,
      multi_replica_shared: false,
      file_backed: true,
      same_host_reload_before_persist: true,
    });
  });

  it("only treats explicit true as true (never invent tokens / multi-pod / path noise)", () => {
    const noisy = {
      progressive_consent: {
        stores_tokens: "false",
        multi_replica_shared: "true",
        file_backed: 1,
        same_host_reload_before_persist: "yes",
        metadata_path_done_star: true,
        token: "canary-secret-token",
        path: "/tmp/consent-sessions.json",
      },
    } as unknown as GatewayResidualStatusResponse;
    const picked = pickProgressiveConsentFields(noisy);
    expect(picked).toEqual({
      metadata_path_done_star: true,
      browser_3lo_automated: false,
      stores_tokens: false,
      multi_replica_shared: false,
      file_backed: false,
      same_host_reload_before_persist: false,
    });
    // Must not surface adversarial noise; avoid matching metadata_path_* field names.
    expect(JSON.stringify(picked)).not.toMatch(/canary|secret-token|consent-sessions|\/tmp/i);
  });
});

describe("honesty constants", () => {
  it("rate file honesty is same-host lite not multi-pod", () => {
    expect(SHARED_SUBJECT_RATE_FILE_HONESTY).toMatch(/same-host/i);
    expect(SHARED_SUBJECT_RATE_FILE_HONESTY).toMatch(/not multi-pod/i);
    expect(SHARED_SUBJECT_RATE_FILE_HONESTY).not.toMatch(/token|secret/i);
  });

  it("JWKS file honesty is same-host FileJWKS lite not multi-pod", () => {
    expect(SHARED_JWKS_FILE_HONESTY).toMatch(/same-host/i);
    expect(SHARED_JWKS_FILE_HONESTY).toMatch(/FileJWKS/i);
    expect(SHARED_JWKS_FILE_HONESTY).toMatch(/not multi-pod/i);
    expect(SHARED_JWKS_FILE_HONESTY).toMatch(/path never shown/i);
    expect(SHARED_JWKS_FILE_HONESTY).not.toMatch(/token|secret|\/tmp|\/var/i);
  });

  it("token cache file honesty is same-host FileTokenCache lite not multi-pod", () => {
    expect(SHARED_TOKEN_CACHE_FILE_HONESTY).toMatch(/same-host/i);
    expect(SHARED_TOKEN_CACHE_FILE_HONESTY).toMatch(/FileTokenCache/i);
    expect(SHARED_TOKEN_CACHE_FILE_HONESTY).toMatch(/not multi-pod/i);
    expect(SHARED_TOKEN_CACHE_FILE_HONESTY).toMatch(/path never shown/i);
    expect(SHARED_TOKEN_CACHE_FILE_HONESTY).toMatch(/secrets never shown/i);
    expect(SHARED_TOKEN_CACHE_FILE_HONESTY).not.toMatch(/\/tmp|\/var|access_token/i);
  });

  it("principal cache honesty is admin BFF process-local", () => {
    expect(PRINCIPAL_CACHE_PROCESS_HONESTY).toMatch(/admin BFF/i);
    expect(PRINCIPAL_CACHE_PROCESS_HONESTY).toMatch(/not necessarily MCP serve/i);
  });

  it("live pin honesty never claims production GO or secrets", () => {
    expect(LIVE_PIN_RESIDUAL_HONESTY).toMatch(/offline residual/i);
    expect(LIVE_PIN_RESIDUAL_HONESTY).toMatch(/not production GO/i);
    expect(LIVE_PIN_RESIDUAL_HONESTY).not.toMatch(/token|secret|qualified=true/i);
    expect(GATEWAY_READY_RESIDUAL_HONESTY).toMatch(/readyz/i);
    expect(GATEWAY_READY_RESIDUAL_HONESTY).toMatch(/false/i);
    expect(HA_MULTI_REPLICA_RESIDUAL_HONESTY).toMatch(/HOST-008|single-replica/i);
  });

  it("subject slots honesty is process-local not multi-pod", () => {
    expect(SUBJECT_SLOTS_PROCESS_LOCAL_HONESTY).toMatch(/process-local/i);
    expect(SUBJECT_SLOTS_PROCESS_LOCAL_HONESTY).toMatch(/not multi-pod/i);
    expect(SUBJECT_SLOTS_PROCESS_LOCAL_HONESTY).not.toMatch(/token|secret/i);
    expect(SUBJECT_LIMITER_MAX_SUBJECTS_HONESTY).toMatch(/process-local/i);
    expect(SUBJECT_LIMITER_MAX_SUBJECTS_HONESTY).toMatch(/unlimited/i);
    expect(SUBJECT_LIMITER_MAX_SUBJECTS_HONESTY).not.toMatch(/token|secret/i);
  });

  it("consent store honesty is same-host lite not multi-pod / never tokens", () => {
    expect(CONSENT_FILE_BACKED_HONESTY).toMatch(/same-host/i);
    expect(CONSENT_FILE_BACKED_HONESTY).toMatch(/not multi-pod/i);
    expect(CONSENT_FILE_BACKED_HONESTY).toMatch(/path never shown/i);
    expect(CONSENT_FILE_BACKED_HONESTY).not.toMatch(/access_token|\/tmp|\/var/i);
    expect(CONSENT_SAME_HOST_RELOAD_HONESTY).toMatch(/reload-before-persist/i);
    expect(CONSENT_SAME_HOST_RELOAD_HONESTY).toMatch(/not multi-pod/i);
    expect(CONSENT_SAME_HOST_RELOAD_HONESTY).not.toMatch(/token|secret|\/tmp/i);
    expect(CONSENT_STORES_TOKENS_HONESTY).toMatch(/always false/i);
    expect(CONSENT_STORES_TOKENS_HONESTY).toMatch(/never tokens/i);
    expect(CONSENT_MULTI_REPLICA_SHARED_HONESTY).toMatch(/always false/i);
    expect(CONSENT_MULTI_REPLICA_SHARED_HONESTY).toMatch(/HOST-008|multi-pod/i);
  });
});
