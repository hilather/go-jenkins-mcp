# Cache eviction CLI (ARC-007 track)

| Field | Value |
|-------|--------|
| **Task** | ARC-007 (eviction dry-run Wave 26 + offline apply Wave 29) |
| **Status** | Dry-run + confirm-gated apply implemented |
| **Store** | `store.QuotaManager.PlanEviction` / `NeedsEviction` / `Usage` / `RecoverEvictJournal` / `Evict` |
| **Primary reclaim** | Serve-time `app.Maintainer` (still the default production path) |
| **CLI role** | Offline dry-run + operator escape hatch with explicit `--confirm`/`--yes` |

## Operator commands

```bash
# Dry-run plan: what maintenance would reclaim (never deletes)
jenkins-mcp cache eviction-plan --profile <id> [--json] [--target-bytes N]

# Default dry-run (same as eviction-plan; never deletes without --confirm/--yes)
jenkins-mcp cache evict --profile <id> [--json] [--target-bytes N]
jenkins-mcp cache eviction-apply --profile <id> [--json] [--target-bytes N]

# Apply: recover journal + re-plan + Evict (destructive; requires confirm)
jenkins-mcp cache evict --profile <id> --confirm [--json] [--target-bytes N]
jenkins-mcp cache evict --profile <id> --yes [--json] [--target-bytes N]
jenkins-mcp cache eviction-apply --profile <id> --confirm [--json] [--target-bytes N]

# Usage / quota snapshot only
jenkins-mcp cache quota --profile <id> [--json]
```

| Flag | Detail |
|------|--------|
| `--profile` | Required; missing profile fails closed |
| `--json` | Secret-free structured output |
| `--target-bytes N` | Optional; additional reclaim goal beyond bringing usage under the **resolved** total quota (default 10 GiB). Non-negative integer. |
| `--cache-total-quota-bytes N` | Optional; same resolve as serve (`store.ResolveQuotaConfig`; env `JENKINS_MCP_CACHE_TOTAL_QUOTA_BYTES`; empty/0=default; min 64 MiB; max 1 TiB fail closed). |
| `--cache-low-disk-bytes N` | Optional; free-space plan threshold (env `JENKINS_MCP_CACHE_LOW_DISK_BYTES`; empty/0=default 1 GiB; min 16 MiB; max 1 TiB). Offline CLI usually has no DiskFree probe. |
| `--confirm` / `--yes` | **Required to apply**. Without either flag, `cache evict` / `eviction-apply` are dry-run only and never call `Evict`. |
| **Data dir** | Must already exist (serve or prior cache open); CLI does **not** create an empty tree |

## Output (secret-free)

| Field | Meaning |
|-------|---------|
| `needs_eviction` | Over total quota and/or low-disk (when free-space probe is configured) |
| `usage` | Physical/logical L1+L2 bytes, generation/pack counts, quota, over_quota |
| `bytes_needed` / `total_reclaim_bytes` | Plan target and sum of candidate reclaim estimates |
| `candidates` | Ordered list: `kind` (`l1`/`l2`), `id` (generation or pack id), `bytes`, optional `age` / `reason` |
| `pins_skipped` | Durable pin row count (pinned objects are omitted from candidates) |
| `dry_run` | `true` for plan / unconfirmed `evict`; `false` on confirmed apply path |
| `applied` | `true` when `Evict` finished the plan (confirm path) |
| `evicted` / `failed` / `reclaimed_bytes` | Apply counts (confirm path) |
| `interrupted` / `journal_consistent` | Cancel/partial apply + journal integrity |
| `journal_recovered` / `journal_reclaimed_bytes` | Items finished from leftover journal before re-plan |

No credentials, tokens, job log bodies, frame payloads, or absolute secret-bearing paths appear in text or JSON. Candidate ids are generation/pack identifiers only.

## Semantics

### Dry-run (`eviction-plan`, or `evict` / `eviction-apply` without confirm)

- Calls **`PlanEviction` only** — never `Evict`.
- Eviction order matches serve-time maintenance: oldest sealed unpinned L1 first, then unpinned L2 packs (oldest mtime). Unsealed/running generations and pins are never candidates.

### Apply (`evict` / `eviction-apply` with `--confirm` or `--yes`)

1. Fail closed if profile or data directory is missing.
2. **`RecoverEvictJournal`** (same journal lite as serve-time Maintainer).
3. **Re-plan** with `PlanEviction` immediately before apply (pins/leases/usage current).
4. **`Evict`** the plan. Store re-checks pins/leases/unsealed on each L1/L2 delete; journal keeps metadata consistent on interrupt.
5. Context cancel returns `cancelled` and may leave a journal for later recover (serve tick or next apply).

Default quota config matches serve via `store.ResolveQuotaConfig` (empty/0 → 10 GiB total / 1 GiB low-disk). Offline CLI does not apply a free-space probe unless `DiskFree` is wired (serve/tests); low-disk flag still sets the threshold when a probe exists.

## Serve vs offline

| Path | Role |
|------|------|
| **Serve-time `app.Maintainer`** | Primary automatic reclaim when over quota (interval default 5m) |
| **`cache evict --confirm`** | Operator escape hatch when serve is down or immediate reclaim is needed |
| **`cache eviction-plan`** | Safe inspection only |

## Residuals

| Residual | Notes |
|----------|--------|
| **Manual delete-all** | Plan/pins do not protect against `rm -rf` of the profile data directory |
| **Retention knobs on CLI** | Per-outcome success/failed retention durations are store config for serve/tests; not CLI flags in this track |
| **MCP tool surface** | Eviction plan/apply via MCP tools not in this track |
| **Interactive prompt** | No tty “type yes” prompt; flags only (`--confirm` / `--yes`) |

Related: pins CLI [`cache-pins.md`](cache-pins.md); unified operator guide [`caching.md`](../caching.md).

## Verify

```bash
export PATH="$HOME/.local/go/bin:$PATH"
go test ./cmd/jenkins-mcp/ -count=1 -run 'CacheEviction|CacheEvict'
make test && make lint
```
