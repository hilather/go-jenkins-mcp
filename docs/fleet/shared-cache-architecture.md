# Fleet shared cache — target architecture (summary)

**Status:** FLC epic **Done\*** offline (through FLC-073 release gate pack + FLC-082 object-class default-deny); mode default **off**; SPA/live multi-host/mTLS residual; **not** site production GO without canary  
**Audience:** implementers, security, operators  
**SoT decision:** [ADR 0016](../adr/0016-fleet-p2p-shared-cache.md)  
**Operator canary runbook:** [shared-cache-operator.md](shared-cache-operator.md)  
**Audit:** [shared-cache-current-state.md](shared-cache-current-state.md)  
**Backlog:** `FLC-*` in [agent-todo](../jenkins-mcp-enterprise-agent-todo.md) + [task-index](../jenkins-mcp-enterprise-task-index.json)

This page is the **implementer summary**. Operators configuring a three-member canary should start at [shared-cache-operator.md](shared-cache-operator.md). Full protocol detail lives in the ADR and FLC task contracts; default mode remains **off** — offline release gate is **FLC-073 Done\*** ([shared-cache-release-gate.md](shared-cache-release-gate.md)); do **not** claim **site** production peer-cache GO without a live multi-host canary.

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
| **FLC — cache payload peer protocol** | Owner-directed HEAD/manifest/bounded decoded read + fill/RF2 library | **Done\*** library; default **off** |

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
| **RF2+** | Replicate compressed frames (library **Done\*** FLC-043); repair, drain later | Partial (043); 044 later |
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
| Atomic roster hot-reload + LKG | **Done\*** — `RosterSnapshot` bundle_seq fail-closed (FLC-013) |
| Peer URL HTTPS non-loopback + trust residual | **Done\*** — default `ParseRoster`/`ResolveConfig` reject non-loopback `http://`; lab residual `JENKINS_MCP_FLEET_ALLOW_INSECURE_HTTP`; mesh pilot / mTLS **not Done** (FLC-016) |
| Pure zstd wire size/hash schema | **Done\*** — chunks.zstd_size / zstd_sha256 + backfill (FLC-020) |
| Scoped peer assertions + replay | **Done\*** — `IssueAssertion`/`VerifyAssertion` HMAC + nonce store (FLC-017) |
| Pure zstd export helpers | **Done\*** — `ExportPureZstd` / `ExportPureZstdEnsured` (FLC-021) |
| Fleet-cache mode flags on serve | **Done\*** — default off; `StatusSummary` reports lookup+decoded-read live (FLC-060) |
| Authz freshness gate | **Done\*** — `FreshnessGate` deny-only probe + TTL; fail closed; no elevation (FLC-018) |
| Sealed → wire manifest publish | **Done\*** — `PublishSealed` idempotent (FLC-042) |
| Owner-directed manifest lookup | **Done\*** — `/fleet/cache/v1/objects/{lh}/manifest` + client (FLC-030) |
| Bounded decoded peer-read | **Done\*** — POST `.../read` + `ServeDecodedRead` + client (FLC-031) |
| Logmirror peer→origin coordinator | **Done\*** — `ResolveAndReadRange`/`Tail` + `PeerLogCoordinator` (FLC-032) |
| Roster cache eligibility fields | **Done\*** — optional `cache` on roster v1 (FLC-012) |
| 3-member lab scaffold | **Done\*** offline — `testdata/fleet-cache-lab/` + `make fleet-cache-lab-*` (FLC-003) |
| One-frame pure-zstd export/transfer | **Done\*** — GET `.../frames/{seq}` + `ServeFrameExport` + admission (FLC-022) |
| Crash-safe peer import + local re-wrap | **Done\*** — schema v9 mapping/journal + `RunImport` + `ImportPureZstdFrame` (FLC-023) |
| Startup recovery + quarantine | **Done\*** — `RecoverFleetImports` abort staging + quarantine unhealthy mappings; complete re-import UPSERT replaces quarantined (FLC-024) |
| Primary fill leases + fence | **Done\*** — in-memory `FillLeaseAuthority` Join/Complete/Status (FLC-040); partition may duplicate origin safely |
| Fill + logmirror single-flight | **Done\*** — `CoordinateOriginFill` + `Access.Fill` after local/peer miss (FLC-041); waiters skip origin body |
| RF2 compressed-frame replication | **Done\*** — `PlanRF2Replication` + `ReplicateSealed`/`ReplicateWave`; `StagingLookupSink` resume transfers **only missing frames** (`FramesTransferred` = missing count); dual-dir LogReader parity; skip verified; partial invisible (FLC-043); not auto-enabled in mode=read |
| Repair / drain / previous-owner grace | **Done\*** — `PlanRepair`/`RunRepair`; drain refuses new primary; MaxConcurrentCopies budget; idempotent when RF healthy (FLC-044); not default-on |
| Fill partition conflict matrix | **Done\*** — same-digest converge; different digest residual + no overwrite; stale fence fail-closed; no mixed-manifest content (FLC-045) |
| Isolation proofs | **Done\*** — `IsolationCheck` + cross-user/controller/fleet/pool matrix (FLC-052); cache hit ≠ authz |
| Crypto portability / key isolation | **Done\*** — dual-key LogReader parity; cross-key fail closed; wire pure-zstd identity stable under rotation (FLC-053) |
| Metrics / audit-style residuals | **Done\*** — process-local `FleetCacheMetrics` + scrubbed security ring (FLC-061); multi-member aggregation residual **FLC-062+** |
| Owner-aware quota / L1 release roles | **Done\*** — `OrderEvictCandidates` / `ShouldSkipL1Release`; hard safety wins; mode-off ignores roles (FLC-050); QuotaManager auto-wire residual |
| Purge + tombstone | **Done\*** — `PlanPurge` / `ActiveTombstones` block import/replicate/repair resurrection (FLC-051); multi-member HTTP purge residual |
| Status / doctor residuals | **Done\*** — `BuildFleetCacheStatus` / `DoctorFleetCache` (FLC-062); BFF+MCP ops **FLC-063** (SPA residual) |
| Near-cache promotion | **Done\*** — `AdmitNearCache` default **off**; `FilterRFObservations` so near never counts toward RF (FLC-033); serve auto-promote residual |
| Offline SLO / bench gates | **Done\*** — pure-zstd wire vs decoded, frame-at-a-time import, bounded ReadRange (FLC-070); multi-member lab residual |
| Offline chaos / race qual | **Done\*** — member-loss RF, partial invisible, isolation, drain (FLC-071); live Docker multi-host residual |
| Admin BFF + MCP fleet-cache ops | **Done\*** — status/doctor/purge (`PURGE`); SPA page residual (FLC-063) |
| Canary stage criteria / rollback | **Done\*** — offline shadow/read/full ladder; live multi-host residual (FLC-072) |
| Running-log durable frames | **Done\*** — progressive ranges + durable prefix plan; multi-host stream residual (FLC-080) |
| Finalize running without recompress | **Done\*** — `PlanFinalizeFromDurable` / `FinalizeSealed`; FramesReused; crash-invisible (FLC-081); multi-host residual |
| Production per-node identity | mTLS or signing beyond mesh token (residual) |
| Operator canary docs pack | **Done\*** — [shared-cache-operator.md](shared-cache-operator.md) (FLC-064) |
| Offline production release gate pack | **Done\*** — [shared-cache-release-gate.md](shared-cache-release-gate.md) + RELEASE_NOTES_v0.6.0 (FLC-073 offline); live multi-host residual |
| Object class default-deny | **Done\*** — `AdmitObjectClass`; **console_log** only (FLC-082); new class = separate PR |
| Shared NFS/S3 log store | Non-goal |
| Multi-pod HA | HOST-008 cancelled |

**Isolation honesty:** with mode **off**, multi-fleet plane A stays **local per member**. With mode **`read`/`full`**, sealed completed console logs for a matching **fleet + pool + controller** **may be shared** across eligible members (owner-directed). Do **not** claim multi-fleet caches are **always isolated** after optional peer rollout. Boundaries remain fleet/pool/controller + authz (FLC-052), not “every host forever independent.”

**FLC IDs remaining Planned:** none. Ops residuals: live multi-host canary, SPA page, mTLS, signed packaging. Mode remains **off** by default.

Absolute link: [shared-cache-architecture.md](https://github.com/hilather/go-jenkins-mcp/blob/master/docs/fleet/shared-cache-architecture.md)
