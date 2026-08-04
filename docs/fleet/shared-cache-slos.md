# Fleet shared-cache SLOs, budgets, and fallback (FLC-002)

**Status:** Defaults **shipped** in `internal/fleetcache`; FLC epic **implemented offline; default mode **off**; live multi-host production GO residual (see [shared-cache-release-gate.md](shared-cache-release-gate.md))  
**Related:** [shared-cache-operator.md](shared-cache-operator.md) · [shared-cache-architecture.md](shared-cache-architecture.md) · [shared-cache-current-state.md](shared-cache-current-state.md) · ADR [0016](../adr/0016-fleet-p2p-shared-cache.md)

These limits keep multi-fleet peer cache from delaying authorized Jenkins origin work or unbounded peer fan-out. Empty/zero operator overrides restore product defaults; out-of-range values **fail closed** (no silent unsafe clamp).

---

## 1. Mode default

| Mode | Meaning | Peer payload I/O |
|------|---------|------------------|
| **`off` (default)** | Local plane A only | No |
| `shadow` | Placement/metrics only | No |
| `read` | MVP A owner-directed peer read | Yes (read path) |
| `full` | Fill + RF2 later gate | Yes |

**Config:** `JENKINS_MCP_FLEET_CACHE_MODE` or serve `--fleet-cache-mode` (FLC-060) → `off` when unset.

Cursor stdio / single-member pilots must leave mode **off**.

---

## 2. Budgets (process ceilings)

| Budget | Default | Min | Absolute max | Env |
|--------|---------|-----|--------------|-----|
| Peer **lookup** timeout before origin fallback | **750ms** | 50ms | 5s | `JENKINS_MCP_FLEET_CACHE_PEER_LOOKUP_TIMEOUT` (`200ms` or integer ms) |
| Max concurrent peer **frame streams** | **4** | 1 | 32 | `JENKINS_MCP_FLEET_CACHE_MAX_PEER_STREAMS` |
| Max concurrent owner **lookups** per request | **2** | 1 | 16 | `JENKINS_MCP_FLEET_CACHE_MAX_PEER_LOOKUPS` |

**Origin fallback:** always **on** when config resolves. Setting `JENKINS_MCP_FLEET_CACHE_ORIGIN_FALLBACK=false` is **rejected** (availability non-negotiable).

Empty or `0` at a layer means the product default for that field.

---

## 3. Fallback behavior

```text
local mapping miss
  → peer owner lookup (≤ PeerLookupTimeout, ≤ MaxPeerLookups)
  → on timeout / all owners fail / mode off
  → authorized Jenkins origin via existing logmirror (within tool budgets)
```

A degraded or misconfigured peer plane **must not** indefinitely delay origin. Repair/replication traffic (when implemented) is lower priority than request-path lookup and must not steal the full stream budget from user reads.

---

## 4. Measurement methods

| Target | How to measure |
|--------|----------------|
| Lookup timeout / fallback | Unit: `fleetcache.ResolveConfig`; integration: lab injects slow peer, assert origin path within timeout + ε |
| Stream/lookup caps | Unit tests on resolve bounds; later peer handler tests reject over-admission |
| Origin bytes avoided | **implemented library — process-local `OriginBytesAvoided()` / local_hit + peer_hit decoded counters (FLC-061); multi-member aggregation residual FLC-062+ |
| Pure-zstd wire ≤ compressed frames | **implemented offline gates (FLC-070) — `TestWireBytes_*` / `TestSLO_*`; multi-member HTTP lab residual |
| Bounded ReadRange memory | **implemented offline gate (FLC-070) — mid-window read not O(whole log) |
| Shadow mode | Placement computed, zero peer payload bytes |

Default `make test` stays offline; multi-node lab is opt-in (`make fleet-cache-lab-*`).

---

## 5. What is not in this document

- Operator canary walkthrough — see [shared-cache-operator.md](shared-cache-operator.md) (FLC-064 **implemented)  
- Admin SPA fleet-cache page (FLC-063 SPA residual; BFF+MCP implemented)  
- Live multi-host canary orchestration (FLC-072 offline criteria implemented; live residual)  
- **Live multi-host production peer-cache GO** — offline gate pack **FLC-073 implemented ([shared-cache-release-gate.md](shared-cache-release-gate.md)); site canary residual  


Go API: `fleetcache.ResolveConfig` · constants `DefaultPeerLookupTimeout`, `DefaultMaxPeerStreams`, `DefaultMaxPeerLookups`.
