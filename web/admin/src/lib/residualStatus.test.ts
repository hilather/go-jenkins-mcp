/**
 * HOST-007 residual-status field pick / honesty helpers.
 */

import { describe, expect, it } from "vitest";
import type { GatewayResidualStatusResponse } from "../api/types";
import {
  formatPrincipalCacheHygiene,
  pickResidualRateCacheFields,
  PRINCIPAL_CACHE_PROCESS_HONESTY,
  SHARED_SUBJECT_RATE_FILE_HONESTY,
} from "./residualStatus";

describe("pickResidualRateCacheFields", () => {
  it("defaults shared_subject_rate_file false when payload missing", () => {
    expect(pickResidualRateCacheFields(undefined)).toEqual({
      shared_subject_rate_file: false,
    });
    expect(pickResidualRateCacheFields(null)).toEqual({
      shared_subject_rate_file: false,
    });
  });

  it("mirrors Wave 9 snake_case residual-status keys", () => {
    const data: GatewayResidualStatusResponse = {
      shared_subject_rate_file: true,
      principal_cache_entries: 3,
      principal_cache_max_entries: 256,
      principal_cache_ttl_seconds: 7200,
      rateEnabled: true,
      ratePerMinute: 30,
      rateBurst: 10,
    };
    expect(pickResidualRateCacheFields(data)).toEqual({
      shared_subject_rate_file: true,
      principal_cache_entries: 3,
      principal_cache_max_entries: 256,
      principal_cache_ttl_seconds: 7200,
    });
  });

  it("omits optional hygiene knobs when absent (unlimited / no TTL)", () => {
    const data: GatewayResidualStatusResponse = {
      shared_subject_rate_file: false,
      principal_cache_entries: 0,
    };
    expect(pickResidualRateCacheFields(data)).toEqual({
      shared_subject_rate_file: false,
      principal_cache_entries: 0,
    });
  });

  it("never invents subjects or path fields from residual map", () => {
    const data = {
      shared_subject_rate_file: true,
      principal_cache_entries: 1,
      // adversarial noise — must not surface as typed rate/cache fields
      subject: "tenant|alice|profile",
      token: "canary-secret-token",
      path: "/tmp/rate.json",
    } as GatewayResidualStatusResponse;
    const picked = pickResidualRateCacheFields(data);
    expect(picked).toEqual({
      shared_subject_rate_file: true,
      principal_cache_entries: 1,
    });
    expect(JSON.stringify(picked)).not.toMatch(/canary|alice|token|path/i);
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

describe("honesty constants", () => {
  it("rate file honesty is same-host lite not multi-pod", () => {
    expect(SHARED_SUBJECT_RATE_FILE_HONESTY).toMatch(/same-host/i);
    expect(SHARED_SUBJECT_RATE_FILE_HONESTY).toMatch(/not multi-pod/i);
    expect(SHARED_SUBJECT_RATE_FILE_HONESTY).not.toMatch(/token|secret/i);
  });

  it("principal cache honesty is admin BFF process-local", () => {
    expect(PRINCIPAL_CACHE_PROCESS_HONESTY).toMatch(/admin BFF/i);
    expect(PRINCIPAL_CACHE_PROCESS_HONESTY).toMatch(/not necessarily MCP serve/i);
  });
});
