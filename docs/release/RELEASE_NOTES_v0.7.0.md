# Release notes — v0.7.0 (typed resource cache + cache control plane)

**Date:** 2026-08-06  
**Tag:** `v0.7.0`  
**Baseline:** continues `v0.6.0`  
**Merge commits:** [PR #9](https://github.com/hilather/go-jenkins-mcp/pull/9) (resource cache), [PR #11](https://github.com/hilather/go-jenkins-mcp/pull/11) (cache control), docs cleanup [PR #6](https://github.com/hilather/go-jenkins-mcp/pull/6)

> Absolute HTTPS links only (pinned to this tag). Default pilot remains **read-only** local stdio. Admin MCP and mutations stay **opt-in**. This release does **not** claim live Entra pin, multi-pod HA, or production ratarmount dual-reader GO.

## Highlights

### Typed non-log resource cache (ADR 0017)

Separate data plane under each profile data dir (`resource-cache/resources.sqlite` + `objects/`) for approved tool sources — **not** repacked into progressive console-log frames:

| Kind | Tools / use |
|------|-------------|
| `artifact_blob` / `artifact_catalog` / `artifact_text` / `artifact_inspection` | Artifact list, text, inspection |
| `test_report` | JUnit / test summary |
| `pipeline_stages` | Pipeline stage graph |
| `build_changes` | SCM changesets |
| `stage_log` | Stage/node log text (structured; not progressive frames) |

- **Every hit re-authorizes** via `AccessContext` + live MCP/Jenkins policy (cache presence never grants access)
- Incomplete/partial results never sealed as complete; subject isolation (`subject_private`)
- Opened at serve when a profile data dir exists; tools use GetOrFetch when wired
- SoT: [ADR 0017](https://github.com/hilather/go-jenkins-mcp/blob/v0.7.0/docs/adr/0017-resource-cache.md) · [caching.md](https://github.com/hilather/go-jenkins-mcp/blob/v0.7.0/docs/caching.md)

### Unified cache control plane (ADR 0018)

Process-local control plane over specialized stores (`internal/cachecontrol`):

| Capability | Notes |
|------------|--------|
| Stable type IDs (12) | `console_log`, resource kinds, `diagnostic_fetch`, `survey_summary`, `ratarmount_index` |
| Modes | `off` · `read_only` · `write_only` · `read_write` — **disable never purges** |
| Config precedence | emergency/startup → runtime override → profile → server file → built-in |
| Absent config | Available types default `read_write` (pre-feature behavior); `ratarmount_index` `off`/unqualified |
| Runtime overrides | CAS revision DB `cache-control.sqlite`; audit-friendly patch |
| Purge epoch | Late-fill discard; epoch advances **only after successful** lifecycle execute |
| Telemetry | Low-cardinality hit/miss/fill (no job names, paths, subjects, free-form errors) |
| Admin MCP | `admin_cache_inventory`, `admin_cache_effective`, `admin_cache_patch_mode`, `admin_cache_plan`, `admin_cache_telemetry` (with `--enable-admin-mcp`) |
| Compatibility | Legacy `admin_cache_status` / `admin_cache_evict*` unchanged |

**Data-path enforcement:** modes gate console log (`logmirror`), resource cache, diagnostic process FetchCache, and survey **process L1 + durable** Meta.

SoT: [ADR 0018](https://github.com/hilather/go-jenkins-mcp/blob/v0.7.0/docs/adr/0018-cache-control-plane.md) · [caching.md § control plane](https://github.com/hilather/go-jenkins-mcp/blob/v0.7.0/docs/caching.md) · [mcp-ops-parity.md](https://github.com/hilather/go-jenkins-mcp/blob/v0.7.0/docs/admin/mcp-ops-parity.md)

### Documentation cleanup (PR #6)

Policy, information architecture, quick starts, and CI doc gates aligned with product SoT (absolute links, residual honesty). Free-lab smoke: `qs-live-smoke` residual path.

## Breaking / migration

| Change | Operator action |
|--------|-----------------|
| New optional profile data under `resource-cache/` and `cache-control/` | Older binaries ignore; no migration of log frames required |
| New admin MCP tools (opt-in) | Appear only when `--enable-admin-mcp` is set; default RO pilot unchanged |
| Mode API if adopted | Absent config ⇒ same open-cache behavior; setting `off` stops use but does not delete data — purge is a separate plan/confirm op |

## Security / residual honesty

| Residual | Status |
|----------|--------|
| Live Entra / production jwt-auth-filter / AgentCore | Operator site pin — not free-lab DoD |
| Multi-pod gateway HA | **Cancelled** (multi-fleet) |
| Fleet non-log object classes (protocol v2) | Default-off; [Issue #7](https://github.com/hilather/go-jenkins-mcp/issues/7) |
| ratarmount-rs dual L2 / FUSE | Optional/unqualified; [Issue #8](https://github.com/hilather/go-jenkins-mcp/issues/8); native Go L2 remains required |
| Admin HTTP BFF + SPA typed inventory; dump/purge body engines | [Issue #10](https://github.com/hilather/go-jenkins-mcp/issues/10); plan/confirm + epoch shipped |
| SIEM audit ship | AUD-T residual |
| Raw cache dump | Startup-gated **off** by default |

Pilot default remains **read-only** stdio + personal API token.

## Verify

```bash
export PATH="$HOME/.local/go/bin:$PATH"
make fmt && make lint && make test
go test -count=1 ./internal/cachecontrol/ ./internal/resourcecache/ ./internal/logmirror/ ./internal/adminops/ ./internal/tools/
# optional offline residual honesty (not part of default make test):
make residual-smoke
make build
./bin/jenkins-mcp version --json
```

## See also

- [ADR 0017 — resource cache](https://github.com/hilather/go-jenkins-mcp/blob/v0.7.0/docs/adr/0017-resource-cache.md)
- [ADR 0018 — cache control plane](https://github.com/hilather/go-jenkins-mcp/blob/v0.7.0/docs/adr/0018-cache-control-plane.md)
- [caching.md](https://github.com/hilather/go-jenkins-mcp/blob/v0.7.0/docs/caching.md)
- [gates.md](https://github.com/hilather/go-jenkins-mcp/blob/v0.7.0/docs/release/gates.md)
- Previous: [RELEASE_NOTES_v0.6.0.md](https://github.com/hilather/go-jenkins-mcp/blob/v0.7.0/docs/release/RELEASE_NOTES_v0.6.0.md)
