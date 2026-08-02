# Caching mechanisms and configuration

**Audience:** operators, platform engineers, agents configuring Cursor stdio, admin Docker, gateway, or multi-fleet hosts  
**Platforms:** Rocky Linux + Ubuntu only (ADR 0008)  
**Related:** [arc/eviction.md](arc/eviction.md) · [arc/cache-pins.md](arc/cache-pins.md) · [security/cache-encryption.md](security/cache-encryption.md) · [arc/pack-format-v1.md](arc/pack-format-v1.md) · [gateway/README.md](gateway/README.md) · [deploy/local/README.md](../deploy/local/README.md) · ADR [0005](adr/0005-independent-zstd-frames-l1.md) / [0007](adr/0007-seekable-multiframe-tar-zst-l2.md)

This page is the **operator SoT** for *what* is cached, *where* it lives, and *how* to size and configure it per deployment type. Deep CLI semantics stay in the linked arc/* docs.

---

## 1. Two cache planes (do not conflate)

| Plane | Purpose | Isolation unit | Default home |
|-------|---------|----------------|--------------|
| **A. Profile data-plane (log/artifact store)** | Durable L1 progressive-log frames, L2 packs, SQLite indexes, survey summaries | **Per profile** under XDG data | `$XDG_DATA_HOME/jenkins-mcp/profiles/<id>/` |
| **B. Process / gateway caches** | Obtain tokens, Jenkins principal map, JWKS public keys, subject rate state | **Per process** (optional same-host file share) | Memory, or explicit path env vars |

Secrets (API tokens, AEAD keys) never live in plane A trees — only in **keyring** / `JENKINS_MCP_KEYRING_FILE` (headless residual). See [security/cache-encryption.md](security/cache-encryption.md) and [security/operator-guide.md](security/operator-guide.md).

---

## 2. Profile data-plane cache (plane A)

### 2.1 What is stored

```text
$XDG_DATA_HOME/jenkins-mcp/profiles/<profile-id>/
  metadata.sqlite          # indexes, pins, generation/pack catalog (no log bodies)
  frames/<generation>/…zst # L1 independent Zstandard frames (STO-003/004)
  archives/                # L2 multi-frame seekable packs (ARC / pack-format-v1)
  evict-journal.json       # interrupt-safe eviction journal
  release-journal.json     # L1-release-after-pack journal
```

| Layer | Content | Access model |
|-------|---------|--------------|
| **L1 frames** | Progressive log chunks as **independent** zstd frames | Bounded range/line/tail reads; no unbounded `ReadAll` |
| **L2 packs** | Related sealed generations in multi-frame `.tar.zst` | Seekable members; native Go reader required path |
| **SQLite meta** | Offsets, hashes, pins, collection catalog, survey summary cache | Recovery + eviction decisions |
| **Survey cache** | Compact signature summaries for recent-failure survey | TTL + max entries; never full log tails |

**Rules of thumb**

- Download each remote log **once per generation**; subsequent tools hit local cache.
- A single-frame whole-log blob is **not** random-access (ADR 0005).
- Cache is **per profile** (and thus per Jenkins URL / auth method in multi-fleet).

### 2.2 Paths and XDG

| Path | Default | Override |
|------|---------|----------|
| Config (profiles JSON) | `$XDG_CONFIG_HOME/jenkins-mcp/` | `XDG_CONFIG_HOME` |
| Data (cache trees) | `$XDG_DATA_HOME/jenkins-mcp/` | `XDG_DATA_HOME` |
| Cache (policy last-good, etc.) | `$XDG_CACHE_HOME/jenkins-mcp/` | `XDG_CACHE_HOME` |
| Per-profile data root | `…/profiles/<id>/` | Profile field `dataDir` (absolute path) when set |

If `HOME` / XDG are unset, resolution follows the Go `os.UserHomeDir` + XDG defaults used by `config.Resolve()` (see packaging).

**Multi-fleet:** each host may share the **same** signed **policy** overlay, but each member’s **data dir** is local unless you deliberately share a volume (usually wrong for multi-host). Prefer one data dir per machine/profile.

### 2.3 Quota and automatic maintenance

| Knob | Default | Meaning |
|------|---------|---------|
| Total physical L1+L2 quota | **10 GiB** per profile (`store.DefaultTotalQuotaBytes`) | Operator-tunable; over-quota triggers reclaim planning |
| Low-disk free threshold | **1 GiB** (`store.DefaultLowDiskBytes`) | Triggers plan when free-space probe is wired (`DiskFree`); offline CLI often skips probe |
| Total quota flag / env | `--cache-total-quota-bytes` / `JENKINS_MCP_CACHE_TOTAL_QUOTA_BYTES` | Integer **bytes**; empty/`0` = default; min **64 MiB**; max **1 TiB** fail closed (flag wins) |
| Low-disk flag / env | `--cache-low-disk-bytes` / `JENKINS_MCP_CACHE_LOW_DISK_BYTES` | Integer **bytes**; empty/`0` = default; min **16 MiB**; max **1 TiB** fail closed (flag wins) |
| Maintenance tick | **5m** | `--cache-maintenance-interval` / `JENKINS_MCP_CACHE_MAINTENANCE_INTERVAL` |
| Absolute interval bounds | **30s–1h** | Fail closed outside range |
| Disable maintenance | off | `--no-cache-maintenance` or `JENKINS_MCP_NO_CACHE_MAINTENANCE=1` (tests/smoke) |

Serve maintenance, offline `cache quota` / `eviction-plan` / confirm-gated `evict`, and admin BFF/MCP ops share `store.ResolveQuotaConfig` (same budget).

**Serve-time `app.Maintainer`** (primary production path when a profile data dir is open):

1. Measure usage vs quota (and optional low-disk).  
2. Plan eviction: oldest sealed **unpinned** L1 first, then unpinned L2 packs.  
3. Optionally compact L1 → L2 packs; after verified pack, release L1 (ARC-005 residual path).  
4. Journal + recover so crash mid-evict stays consistent.

**What is never auto-evicted**

- **Pinned** generations/packs ([cache-pins.md](arc/cache-pins.md))  
- **Unsealed / running** generations (still writing)  
- Active reader **leases** (in-process)

### 2.4 Operator CLI (offline escape hatch)

```bash
export PATH="$HOME/.local/go/bin:$PATH"

jenkins-mcp cache status --profile corp
jenkins-mcp cache quota --profile corp [--json] [--cache-total-quota-bytes N]
jenkins-mcp cache verify --profile corp [--full] [--sample N]

# Dry-run only (never deletes)
jenkins-mcp cache eviction-plan --profile corp [--json] [--target-bytes N] [--cache-total-quota-bytes N]
jenkins-mcp cache evict --profile corp [--json]

# Destructive — requires explicit confirm
jenkins-mcp cache evict --profile corp --confirm [--json] [--target-bytes N] [--cache-total-quota-bytes N]

# Pins (survive quota eviction)
jenkins-mcp cache pin generation --profile corp --generation <id>
jenkins-mcp cache pins --profile corp [--json]
```

| Command family | Doc |
|----------------|-----|
| Eviction plan/apply/quota | [arc/eviction.md](arc/eviction.md) |
| Pins | [arc/cache-pins.md](arc/cache-pins.md) |
| AEAD encryption keys | [security/cache-encryption.md](security/cache-encryption.md) |

Admin console **Cache** page and MCP `admin_cache_*` mirror status / plan / confirm-gated evict when admin MCP is enabled (operator role + confirm token).

### 2.5 Optional frame encryption (ARC-009)

Default **off**. When enabled:

1. `jenkins-mcp cache key init --profile <id>` stores AES-256 material in **keyring**.  
2. Profile flags `cacheEncryption` + `cacheKeyVersion` (non-secret).  
3. L1 frames sealed with AEAD; loss of keys ⇒ unreadable frames (fail closed).

Do **not** enable for multi-process share of the same data dir unless every process can load the same keyring material (usually impractical across containers without a shared secret store). Prefer OS volume encryption + ACL for lab Docker.

---

## 3. Process / gateway caches (plane B)

These are **not** the log store. They speed multi-user HTTP/gateway identity and JWKS.

| Cache | Default | Optional same-host file | Env (path never dumped in residual JSON) |
|-------|---------|-------------------------|------------------------------------------|
| **Token / Obtain** | Process `MemoryTokenCache` | `FileTokenCache` | `JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH` |
| **Principal map** | Process memory | `FilePrincipalCache` | `JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH` |
| **JWKS (public keys)** | Process memory + TTL refresh | File snapshot | `JENKINS_MCP_HTTP_JWKS_CACHE_PATH` |
| **Subject rate** | Process limiter | `FileSubjectRateLimiter` | `JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH` |

| Hygiene | Env | Notes |
|---------|-----|--------|
| Principal max entries | `JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_MAX` | Empty/`0` = unlimited; LRU when full |
| Principal TTL | `JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_TTL` | Go duration; empty = no expiry |
| Subject rate max subjects | `JENKINS_MCP_GATEWAY_SUBJECT_RATE_MAX_SUBJECTS` | Empty = unlimited |
| Subject limiter max subjects | `JENKINS_MCP_GATEWAY_SUBJECT_LIMITER_MAX_SUBJECTS` | Map hygiene; fail closed if all hold slots |
| JWKS refresh TTL | `JENKINS_MCP_HTTP_JWKS_REFRESH_TTL` | Default 5m; min 30s max 1h |
| JWKS max stale | `JENKINS_MCP_HTTP_JWKS_MAX_STALE` | Empty/0 = unlimited stale-if-error |

**Important**

- File caches are **HOST-008 lite**: same host / shared FS + flock + mode 0600. **Not** multi-pod Redis HA.  
- Admin BFF and MCP serve are **separate processes** — memory caches are **not** shared unless you set the file paths.  
- Residual-status exposes **bools only** (`shared_token_cache_file`, …) — never path values or tokens.  
- `gateway subject-invalidate` clears principal/token only for **this** process **or** shared file caches when paths are set.

Full tables: [gateway/README.md](gateway/README.md), [gateway/deployment.md](gateway/deployment.md).

---

## 4. Configuration by deployment type

### 4.1 Local Cursor stdio (default pilot — ADR 0002)

| Setting | Recommendation |
|---------|----------------|
| Profile | `login --profile <id>` then `serve --profile <id> --read-only --stdio` |
| XDG | Host defaults under `$HOME` |
| Quota | Default 10 GiB usually enough for pilot; monitor `cache quota` |
| Maintenance | Leave **enabled** (default 5m) |
| Encryption | Optional; only if policy requires beyond FDE |
| Gateway file caches | **Off** (not multi-user gateway) |

```json
// Cursor mcp.json (no tokens)
{
  "mcpServers": {
    "jenkins": {
      "command": "jenkins-mcp",
      "args": ["serve", "--profile", "corp", "--read-only", "--stdio"],
      "env": { "JENKINS_MCP_READ_ONLY": "true" }
    }
  }
}
```

### 4.2 Multi-fleet laptop / workstation fleet

| Setting | Recommendation |
|---------|----------------|
| Policy | **Shared signed overlay** ([fleet/multi-fleet-rollout.md](fleet/multi-fleet-rollout.md)) |
| Cache | **Local by default** per host under each user’s XDG — do not NFS-share profile data dirs between laptops |
| Peer shared cache (FLC) | **Planned residual** (ADR [0016](adr/0016-fleet-p2p-shared-cache.md)) — optional pure-Go owner-directed peer read of **sealed completed console logs** for LB multi-member deploys; default **off**; **not Done**; ops `fleet_*` fan-out is a **different plane** ([fleet-mcp-ops.md](fleet/fleet-mcp-ops.md)) |
| MVP A (when implemented) | Peer **read** of sealed logs + origin fallback first; fill-lease and RF2/repair are **later** gates — [shared-cache-architecture.md](fleet/shared-cache-architecture.md) |
| Quota | Raise only if users keep large progressive logs; pin critical generations |
| Encryption | Per-user keyring keys; do not share data dirs across OS users; peer path must re-wrap AEAD locally (never share ciphertext as portable) |

### 4.3 Local Docker admin support stack (`deploy/local`)

Three models (see [deploy/local/README.md](../deploy/local/README.md)):

| Model | Cache behavior | When |
|-------|----------------|------|
| **1. Default named volumes** | Docker-only cache; **host Cursor stdio cannot see it** | Admin UI only |
| **2. Shared XDG** | Bind-mount lab XDG; host + container share plane A | Warm agent cache + admin |
| **3. HTTP profile** | Container HTTP MCP; cache still in container XDG unless shared | Experiments only |

**Model 2 (warm cache)** — configure deliberately:

```bash
cp deploy/local/docker-compose.shared-xdg.example.yml \
   deploy/local/docker-compose.override.yml
# Set absolute XDG_* on host mcp.json and in compose to the same lab dirs
```

Do **not** point production home XDG at throwaway lab dirs. Tear-down with volume wipe destroys cache.

### 4.4 Gateway / team-hosted single replica (`deploy/gateway`, `serve --gateway`)

| Setting | Recommendation |
|---------|----------------|
| Plane A | Persistent volume for `$XDG_DATA_HOME` (or profile `dataDir`) **per replica** |
| Plane B file caches | Optional same-host multi-process (sidecar + serve) via path envs |
| Multi-pod shared vault/session/rate | **Out of scope** (HOST-008 cancelled) — one data dir per fleet member for plane A; do **not** NFS-share store trees |
| Optional peer log cache (FLC) | **Planned** only — ADR [0016](adr/0016-fleet-p2p-shared-cache.md); not multi-pod HA; not shipped |
| Quota | Size volume ≥ expected concurrent subjects × log retention; set pins for critical incident packs |
| Maintenance | Keep enabled; shorter interval only under measured pressure (still ≥ 30s) |
| Subject rate / limiter | Tune `JENKINS_MCP_GATEWAY_SUBJECT_*` after load tests; process-local slots always |

**Tier A honesty:** kustomize `replicas: 1`; `ha_multi_replica=false` until multi-pod vault/rate/token/JWKS are designed.

### 4.5 Admin BFF only (`jenkins-mcp admin serve`)

- Does **not** open the full log store for MCP tools.  
- Cache page acts on **profile data dir** when present (status/plan/evict).  
- Gateway residual cards report **file-backed** plane B bools for the **admin process env** — set the same path envs as serve if you need CLI/admin invalidate to hit the same file maps.

### 4.6 CI / smoke / labs

| Lab | Cache note |
|-----|------------|
| `make test` | Offline; no Docker; no durable cache required |
| `make stdio-smoke` | Temp XDG + `JENKINS_MCP_NO_CACHE_MAINTENANCE=1` |
| `live-jenkins-*` / `live-oauth-*` / `live-jwt-rs-*` | Ephemeral containers; destroy with `down -v` |
| `JENKINS_MCP_KEYRING_FILE` | Headless file keyring residual (not Secret Service) |

---

## 5. Quick configuration reference

### 5.1 Plane A (profile store)

| Control | Flag / env | Default / notes |
|---------|------------|-----------------|
| Disable background maintenance | `--no-cache-maintenance` / `JENKINS_MCP_NO_CACHE_MAINTENANCE=1` | Off |
| Maintenance interval | `--cache-maintenance-interval` / `JENKINS_MCP_CACHE_MAINTENANCE_INTERVAL` | 5m (30s–1h) |
| Force encryption process-wide | `JENKINS_MCP_CACHE_ENCRYPTION=1` | Still needs key init |
| Profile data root | profile `dataDir` | Else `ProfileDataDir(id)` under XDG data |
| Total physical quota | `--cache-total-quota-bytes` / `JENKINS_MCP_CACHE_TOTAL_QUOTA_BYTES` | Default **10 GiB**; min 64 MiB; max 1 TiB; empty/0 = default |
| Low-disk threshold | `--cache-low-disk-bytes` / `JENKINS_MCP_CACHE_LOW_DISK_BYTES` | Default **1 GiB**; min 16 MiB; max 1 TiB; empty/0 = default |

### 5.2 Plane B (gateway / HTTP)

| Control | Env | Default |
|---------|-----|---------|
| Token Obtain cache file | `JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH` | Memory |
| Principal map file | `JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH` | Memory |
| Subject rate file | `JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH` | Process |
| JWKS snapshot file | `JENKINS_MCP_HTTP_JWKS_CACHE_PATH` | Memory |
| Principal max / TTL | `…_PRINCIPAL_CACHE_MAX` / `_TTL` | Unlimited / none |
| JWKS refresh / max stale | `JENKINS_MCP_HTTP_JWKS_REFRESH_TTL` / `_MAX_STALE` | 5m / unlimited |

---

## 6. Day-2 operations checklist

1. **Status:** `cache status` + `cache quota` (or admin Cache page).  
2. **Integrity:** `cache verify` after crashes or disk full.  
3. **Protect evidence:** `cache pin generation|pack` before large reclaim.  
4. **Reclaim:** prefer serve maintenance; use `cache evict --confirm` when offline.  
5. **Keys:** if encryption on, rotate with `cache key rotate`; never commit keys.  
6. **Gateway:** after subject revoke, `gateway subject-invalidate` with shared principal/token paths if multi-process.  
7. **Support:** support-bundle excludes cache key material and raw logs by design.

---

## 7. Residuals (honest)

| Residual | Notes |
|----------|--------|
| Multi-pod shared Obtain / principal / rate / JWKS | **Out of scope** (HOST-008 cancelled); same-host file lite only; scale via multi-fleet |
| Multi-fleet **peer** sealed-log cache (FLC) | **Planned** — audit [fleet/shared-cache-current-state.md](fleet/shared-cache-current-state.md); ADR [0016](adr/0016-fleet-p2p-shared-cache.md); MVP A = peer read first; **not** claimed Done |
| Per-outcome success-vs-failed retention knobs | Store fields exist; not full operator product surface beyond total-quota/low-disk |
| ratarmount-rs FUSE dual reader | Optional after ARC-000 production go; native Go L2 required |
| Full rewrite on encryption rotate | Lite rotation keeps last 2 key versions only |
| Cross-user shared laptop data dir | Unsupported — isolate OS users and profiles |

---

## 8. Related commands (cheat sheet)

```bash
# Plane A
jenkins-mcp cache status|quota|verify|pins|pin|unpin|eviction-plan|evict|key …

# Plane B residual honesty
jenkins-mcp gateway residual-status
jenkins-mcp gateway subject-invalidate --tenant T --subject-id S [--profile P]

# Admin (loopback)
jenkins-mcp admin serve --admin-role operator …
# SPA Cache page + GET/POST …/cache*
```

---

## 9. See also

| Doc | Topic |
|-----|--------|
| [packaging.md](packaging.md) | XDG layout, serve flags |
| [user/README.md](user/README.md) | Pilot Cursor path |
| [admin/README.md](admin/README.md) | Admin env tables |
| [observability.md](observability.md) | `cache_*` metrics |
| [fleet/shared-cache-current-state.md](fleet/shared-cache-current-state.md) | FLC-000 audit (peer cache Planned) |
| [adr/0016-fleet-p2p-shared-cache.md](adr/0016-fleet-p2p-shared-cache.md) | Peer shared-cache decision + MVP cut |
| [security/product-residuals.md](security/product-residuals.md) | Residual honesty |
