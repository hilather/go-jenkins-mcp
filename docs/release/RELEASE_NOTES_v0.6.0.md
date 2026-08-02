# Release notes — v0.6.0 (fleet peer-cache offline GO pack)

**Date:** 2026-08-02  
**Tag:** `v0.6.0`  
**Baseline:** continues `v0.5.0`  
**FLC gate:** [shared-cache-release-gate.md](../fleet/shared-cache-release-gate.md) (**FLC-073 Done\*** offline)

> Absolute links preferred on the GitHub release page. Default fleet-cache mode remains **`off`**. This release ships an **opt-in** multi-fleet peer sealed-log library + operator canary docs — **not** a claim of live multi-host production GO without site evidence.

## Highlights

### Fleet peer shared cache (FLC epic — offline Done\*)

| Capability | Notes |
|------------|--------|
| Owner-directed peer read of **sealed completed console logs** | Pure zstd wire; local AEAD re-wrap |
| Fill leases + origin fallback | Concurrent miss single-flight residual honesty under partition |
| RF2 + repair/drain library | Mode off by default; near copies never count toward RF |
| Isolation / crypto proofs | Cross-tenant fail-closed; dual-key portability |
| Process-local metrics + status/doctor | Multi-member aggregation residual |
| Admin BFF + MCP fleet-cache ops | Status/doctor/purge (`PURGE`); **SPA page residual** |
| Canary criteria (shadow→read→full) | Rollback any→off without migration |
| Running frames + finalize without recompress | Library + store tests; multi-host stream residual |
| Object class default-deny | **`console_log` only** (FLC-082); unknown kinds fail closed |
| Operator canary runbook | [shared-cache-operator.md](https://github.com/hilather/go-jenkins-mcp/blob/master/docs/fleet/shared-cache-operator.md) |

Enable only explicitly: `--fleet-cache-mode=read|shadow|full` or `JENKINS_MCP_FLEET_CACHE_MODE` after reading the operator runbook.

### Security / residual honesty

| Residual | Status |
|----------|--------|
| Mode default **off** | Product default |
| Live multi-host LB canary soak | Operator residual (offline dual-dir + optional lab smoke) |
| Production mTLS peer identity | Residual beyond lab HTTP allowlist |
| Admin SPA fleet-cache page | Residual (BFF+MCP Done\*) |
| HOST-008 multi-pod HA | **Cancelled** |
| SIEM ship | Residual |
| Extra object classes | New class requires separate approval PR (FLC-082 framework) |

## Breaking / migration

| Change | Operator action |
|--------|-----------------|
| No default-on peer cache | Leave mode unset/`off` for prior local-only behavior |
| Unknown object_kind fail closed | Only `console_log` locators/publish paths succeed for peer cache |
| New admin MCP tools (opt-in) | Enable `--enable-admin-mcp` only when agents need fleet-cache ops |

## Verify

```bash
export PATH="$HOME/.local/go/bin:$PATH"
go test -race -count=1 ./internal/fleetcache/ ./internal/store/ ./internal/admin/ ./internal/adminops/ ./internal/fleetmcp/
# Operator: docs/fleet/shared-cache-operator.md § rollback
```

## See also

- [shared-cache-release-gate.md](../fleet/shared-cache-release-gate.md)  
- [shared-cache-architecture.md](../fleet/shared-cache-architecture.md)  
- [gates.md](gates.md)  
