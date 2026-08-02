# ADR 0016: Pure-Go peer-to-peer shared cache coordination (multi-fleet)

- **Status:** Accepted  
- **Date:** 2026-08-02  
- **Owner:** engineering + security + operations  
- **Related:** FLC-000…FLC-082 · HOST-008 (cancelled) · ADR 0002 · ADR 0004 · ADR 0005 · ADR 0014 · [shared-cache-current-state.md](../fleet/shared-cache-current-state.md) · [shared-cache-architecture.md](../fleet/shared-cache-architecture.md) · [caching.md](../caching.md) · [fleet-mcp-ops.md](../fleet/fleet-mcp-ops.md)

## Context

Enterprise multi-fleet deploys **N independent** single-replica `jenkins-mcp` members with shared **signed policy** (gitops). **HOST-008 multi-pod HA** (shared vault, Obtain, rate, sticky multi-replica gateway) is **cancelled**; multi-fleet *is* the scale model.

Plane A log cache remains **per profile data dir on each host**. When members sit behind a load balancer without stickiness, requests for the same user/job land on different members, so a warm local cache on one node is cold on another → repeated Jenkins progressive downloads.

Operators want optional **cache reuse across members** without:

- external cache middleware / Redis / shared filesystem,
- a second embedded database or new compressed object format,
- reopening multi-pod shared session/vault state,
- broadcasting every cache miss to all peers via `fleet_*` ops fan-out.

The tree already has local L1 independent Zstd frames (`internal/store`), progressive mirror (`internal/logmirror`), and fleet roster/mesh peer plumbing (`internal/fleetmcp`).

## Decision

1. **In-process coordination, not a new cache product.**  
   Add an optional pure-Go coordination layer (target package name `internal/fleetcache` when implemented) that reuses `store` + `logmirror` for durable bytes. **No** second DB, **no** sidecar daemon, **no** external cache appliance, **no** shared multi-pod vault/session/rate store.

2. **Default remains local-only.**  
   Fleet cache mode is **off** unless explicitly enabled (`off|shadow|read|full` planned). Cursor stdio single-member pilots must not enable peer cache by surprise.

3. **Separate planes.**  
   - Operator aggregation (`fleet_*` tools, `/fleet/v1` JSON, 1 MiB caps) stays the **ops plane**.  
   - Cache payload traffic uses a **dedicated streaming protocol** path; cache lookup queries **deterministic owners only**, never full-member broadcast fan-out.

4. **First production object class:** sealed **completed** Jenkins **console logs** only.  
   Running logs, arbitrary artifacts, and peer L2 pack replication are **out of first slice** (FLC-080+).

5. **HOST-008 stays cancelled.**  
   Peer cache does **not** share credentials, Obtain tokens, subject rate, or admin sessions across pods. Members remain independent processes with local keyrings and local AEAD keys.

6. **Wire format and encryption.**  
   Peers transfer **pure compressed Zstandard frames** (existing L1 frame codec). Receivers **re-encrypt** with local `FrameCrypto` when encryption is enabled. Sender ciphertext and local generation AAD are not portable.

7. **Authorization.**  
   A cache hit is **not** authorization. Entry node applies trusted subject, Jenkins authorization evidence, and deny-only MCP policy before returning local or peer bytes. Peer requests carry short-lived **scoped assertions** (opaque subject hash, locator, op, byte caps, policy epoch)—never raw Jenkins/OAuth credentials.

8. **Availability.**  
   Peer/cache failure **fails open** to the authorized Jenkins origin path within existing budgets. Cache never elevates access.

9. **Read-only.**  
   Global `--read-only` continues to allow internal cache fills used by read tools. Destructive purge/rebalance remain independently role/confirm gated.

10. **MVP cut line (binding for release planning):**  
    | Gate | Scope | Required for first useful peer-cache release? |
    |------|--------|-----------------------------------------------|
    | **MVP A** | Owner-directed peer **read** of sealed completed console logs + origin fallback | **Yes** |
    | **Fill** | Fill lease / fencing for one-origin body under concurrent miss | **No** (next gate) |
    | **RF2 / repair / drain** | Multi-replica durability and membership handoff | **No** (later gate) |

    Shadow mode may land before MVP A for placement metrics without peer I/O.

11. **Rollback.**  
    Setting mode `off` (or unsetting fleet-cache config) restores current local-only behavior. Incomplete imports must remain unpublished; recovery must not serve unverified bytes.

12. **Production peer identity residual.**  
    Fleet-wide mesh token is acceptable for **controlled pilot/lab** on private TLS networks and must be reported as residual. Production write/import paths should add unique node identity (mTLS or per-node signing) before claiming production GO.

## Alternatives considered

| Option | Why rejected |
|--------|----------------|
| Shared NFS/S3 for plane A | Cross-host SQLite/frame races; encryption/ACL pain; not multi-fleet model |
| Redis / external cache appliance | New middleware; secret/ACL surface; contradicts pure-Go process preference |
| Multi-pod HA shared store (HOST-008) | Explicitly cancelled; wrong blast radius for vault/session |
| Reuse `fleet_*` fan-out for log bodies | Wrong plane; 1 MiB JSON; O(N) broadcast; not owner-directed |
| Full RF2 + fill + repair in first release | Excess risk; delays LB cold-miss relief from peer **read** alone |
| Sidecar cache daemon | Extra process/deploy surface; rejected planning constraint |

## Consequences

**Benefits:** Optional LB-friendly reuse of sealed logs; reuses hard local cache work; preserves multi-fleet independence; clear MVP gates; honest residual for mesh-token pilot.

**Costs:** Peer protocol, placement, authz assertions, schema extensions, multi-node lab, and security review load. Disk may hold owner copies longer when RF2 ships. SQLite writer contention under import/repair must be measured.

**Residuals:** Runtime not shipped until FLC tasks land; production mTLS/signing; admin SPA/MCP parity (FLC-063); SIEM; running-log classes (FLC-080+).

## Owner

Engineering (implementation) · security (peer authz / assertion design) · operations (roster, TLS, mode rollout)
