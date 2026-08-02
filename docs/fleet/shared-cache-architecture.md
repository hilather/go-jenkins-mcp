# Fleet shared cache — target architecture (summary)

**Status:** Foundation **Done\*** (budgets, identity, wire validation, placement, managed peer server); owner-directed **peer-read handlers still Planned** (FLC-030…032)  
**Audience:** implementers, security, operators  
**SoT decision:** [ADR 0016](../adr/0016-fleet-p2p-shared-cache.md)  
**Audit:** [shared-cache-current-state.md](shared-cache-current-state.md)  
**Backlog:** `FLC-*` in [agent-todo](../jenkins-mcp-enterprise-agent-todo.md) + [task-index](../jenkins-mcp-enterprise-task-index.json)

This page is the **operator/implementer summary**. Full protocol detail lives in the ADR and FLC task contracts; do not treat this page as a claim that peer cache is shipped.

---

## 1. Problem

Multi-fleet members are independent processes (HOST-008 multi-pod HA **cancelled**). Behind a load balancer without stickiness, consecutive requests hit different members; each member’s **plane A** log cache is local, so warm data on member A is a miss on member B → repeated Jenkins origin pulls.

Optional **in-process pure-Go peer coordination** lets a request that lands on any member reuse a **sealed completed console log** already stored on a deterministic owner, without shared disk, external cache middleware, or reopening multi-pod vault/session state.

---

## 2. Planes (do not conflate)

| Plane | Role | Status |
|-------|------|--------|
| **A — profile store** | Local L1/L2 logs under XDG per profile | **Done** |
| **B — gateway caches** | Obtain/principal/JWKS/rate (process or same-host file) | **Done\*** lite |
| **Ops — `fleet_*` / `/fleet/v1` JSON** | Request-time fan-out of health/metrics/doctor | **Done\***; **not** log bodies |
| **FLC — cache payload peer protocol** | Owner-directed HEAD/manifest/bounded read (+ later fill/RF2) | **Planned**; default **off** |

Cache lookup **must not** broadcast through `fleetmcp.FanOut` to every member.

---

## 3. High-level shape

```text
                    load balancer (optional)
               /            |            \
          member A      member B      member C
          store L1      store L1      store L1
          logmirror     logmirror     logmirror
          fleetcache?   fleetcache?   fleetcache?   (Planned; mode off|shadow|read|full)
               \____________|____________/
                 authenticated owner-directed peer traffic
                              |
                     authorized Jenkins origin when needed
```

- Local store remains SoT for bytes on disk.  
- Coordinator decides owners, lookup order, and when to fall back to origin.  
- Local encryption stays node-local; wire format is **pure Zstandard frames** with re-wrap on import.

---

## 4. Identity (planned)

- **Locator** (canonical): fleet + cache pool + controller + `console_log` + normalized job + build + schema version — **not** local profile ID or SQLite generation ID.  
- **Sealed version:** manifest digest over ordered frame ranges and content hashes.  
- **Placement:** weighted rendezvous over eligible members (matching controller/pool/protocol); epoch from roster `bundle_seq`.  
- **v1 RF target (post–MVP A):** replication factor 2; near-cache copies do not count as replicas.

---

## 5. MVP cut line (binding)

| Gate | Scope | First useful release? |
|------|--------|------------------------|
| **MVP A** | Owner-directed peer **read** of sealed completed console logs; miss → authorized Jenkins origin via existing `logmirror` | **Yes — first useful** |
| **Fill** | Primary fill lease / fencing so healthy concurrent misses do one origin body | Later |
| **RF2+** | Replicate compressed frames, repair, drain | Later |
| **FLC-080+** | Running logs / other object classes | Later |

Do not block MVP A on admin SPA parity, RF2, or production mTLS if pilot mesh + residual honesty is accepted for lab/canary only.

---

## 6. Security (non-negotiable)

1. Cache hit is not authorization.  
2. No Jenkins/OAuth credentials on peer requests.  
3. Scoped short-lived peer assertions (subject hash, locator, op, byte caps, policy epoch).  
4. Fail closed on auth/crypto; fail open to origin within budget.  
5. Secret-free metrics/audit/MCP.  
6. HOST-008 remains cancelled (no shared vault/session/rate multi-pod).

---

## 7. Rollout modes (planned config)

| Mode | Behavior |
|------|----------|
| `off` (default) | Current local-only plane A |
| `shadow` | Placement/metrics only; no peer read/write |
| `read` | MVP A peer lookup/read |
| `full` | Fill + RF2 + repair (later gate) |

Cursor **stdio** single-member pilots stay `off`. Do not enable by surprise.

---

## 8. Foundation landed vs residuals

| Piece | Status |
|-------|--------|
| SLOs / budgets / mode default off | **Done\*** — `internal/fleetcache` + [shared-cache-slos.md](shared-cache-slos.md) |
| Canonical locator + sealed manifest identity | **Done\*** — pure API + golden tests (FLC-010) |
| Wire protocol v1 validation | **Done\*** — `ParseWireManifestJSON` / bounds / forbidden local fields (FLC-011) |
| Weighted rendezvous placement | **Done\*** — `OwnerOrder` / `SelectPrimaryOwners` golden vectors (FLC-014) |
| Managed peer HTTP server | **Done\*** — `fleetmcp.ListenPeer` / `StartPeerServer` timeouts + shutdown (FLC-015) |
| Roster cache eligibility fields | **Done\*** — optional `cache` on roster v1 (FLC-012) |
| 3-member lab scaffold | **Done\*** offline — `testdata/fleet-cache-lab/` + `make fleet-cache-lab-*` (FLC-003) |
| Peer streaming read / logmirror hook | **Planned** (FLC-030…032) — **not** peer-read Done |
| Fill lease / RF2 | **Planned** (later gates) |
| Production per-node identity | mTLS or signing beyond mesh token |
| Admin BFF/SPA/MCP full parity | FLC-063 residual |
| Shared NFS/S3 log store | Non-goal |
| Multi-pod HA | HOST-008 cancelled |

Absolute link: [shared-cache-architecture.md](https://github.com/hilather/go-jenkins-mcp/blob/master/docs/fleet/shared-cache-architecture.md)
