/**
 * HOST-007 residual-status field pick / honesty helpers.
 */

import { describe, expect, it } from "vitest";
import type { GatewayResidualStatusResponse } from "../api/types";
import {
  formatPrincipalCacheHygiene,
  formatResidualBool,
  GATEWAY_READY_RESIDUAL_HONESTY,
  HA_MULTI_REPLICA_RESIDUAL_HONESTY,
  LIVE_PIN_RESIDUAL_HONESTY,
  pickResidualLivePinFields,
  pickResidualRateCacheFields,
  PRINCIPAL_CACHE_PROCESS_HONESTY,
  SHARED_JWKS_FILE_HONESTY,
  SHARED_SUBJECT_RATE_FILE_HONESTY,
  SUBJECT_LIMITER_MAX_SUBJECTS_HONESTY,
  SUBJECT_SLOTS_PROCESS_LOCAL_HONESTY,
} from "./residualStatus";

describe("pickResidualRateCacheFields", () => {
  it("defaults shared_* flags false when payload missing", () => {
    expect(pickResidualRateCacheFields(undefined)).toEqual({
      shared_subject_rate_file: false,
      shared_principal_cache_file: false,
      shared_jwks_file: false,
      subject_slots_process_local: false,
    });
    expect(pickResidualRateCacheFields(null)).toEqual({
      shared_subject_rate_file: false,
      shared_principal_cache_file: false,
      shared_jwks_file: false,
      subject_slots_process_local: false,
    });
  });

  it("mirrors Wave 11 snake_case residual-status keys including shared_jwks_file", () => {
    const data: GatewayResidualStatusResponse = {
      shared_subject_rate_file: true,
      shared_principal_cache_file: true,
      shared_jwks_file: true,
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
      subject_slots_process_local: true,
      principal_cache_entries: 0,
    };
    expect(pickResidualRateCacheFields(data)).toEqual({
      shared_subject_rate_file: false,
      shared_principal_cache_file: false,
      shared_jwks_file: false,
      subject_slots_process_local: true,
      principal_cache_entries: 0,
    });
    expect(pickResidualRateCacheFields(data).subject_limiter_max_subjects).toBeUndefined();
  });

  it("never invents subjects or path fields from residual map", () => {
    const data = {
      shared_subject_rate_file: true,
      shared_jwks_file: true,
      subject_slots_process_local: true,
      principal_cache_entries: 1,
      // adversarial noise — must not surface as typed rate/cache fields
      subject: "tenant|alice|profile",
      token: "canary-secret-token",
      path: "/tmp/jwks-cache.json",
      jwks_cache_path: "/secret/path/jwks.json",
    } as GatewayResidualStatusResponse;
    const picked = pickResidualRateCacheFields(data);
    expect(picked).toEqual({
      shared_subject_rate_file: true,
      shared_principal_cache_file: false,
      shared_jwks_file: true,
      subject_slots_process_local: true,
      principal_cache_entries: 1,
    });
    expect(JSON.stringify(picked)).not.toMatch(/canary|alice|token|path|secret\/path/i);
  });

  it("only treats explicit boolean true as shared_*_file / subject_slots (never Boolean() truthy strings)", () => {
    // Regression: Boolean("false") === true; residual honesty must fail closed.
    const noisy = {
      shared_subject_rate_file: "false",
      shared_principal_cache_file: "true",
      shared_jwks_file: 1,
      subject_slots_process_local: "true",
    } as unknown as GatewayResidualStatusResponse;
    expect(pickResidualRateCacheFields(noisy)).toEqual({
      shared_subject_rate_file: false,
      shared_principal_cache_file: false,
      shared_jwks_file: false,
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
});
