# Current-state audit: pure-Go peer-to-peer shared cache (FLC-000)

**Repository:** `github.com/hilather/go-jenkins-mcp`  
**Audited snapshot (SoT):** `0bde63662ebaa4783a14663346ab4b44f44f90d2`  
**Re-verified against live tree:** same commit (Phase 0 land date 2026-08-02)  
**Go toolchain required:** `go 1.25.12` (`go.mod`)  
**Status of this document:** **historical Phase 0 audit** (snapshot below) plus a **live capability matrix** (§7) kept current as FLC tasks land  
**Related:** [ADR 0016](../adr/0016-fleet-p2p-shared-cache.md) · [shared-cache-architecture.md](shared-cache-architecture.md) · **[shared-cache-operator.md](shared-cache-operator.md)** (operator canary) · [caching.md](../caching.md) · [fleet-mcp-ops.md](fleet-mcp-ops.md) · HOST-008 **cancelled**

---

## 1. Scope and verification

Static review covered:

| Area | Packages / paths |
|------|------------------|
| Agent / platform policy | `AGENTS.md`, `go.mod` |
| Fleet membership + peer ops | `internal/fleetmcp` (roster, mesh token, `/fleet/v1` fan-out) |
| Plane A local cache | `internal/store` (SQLite Meta, Frames, LogReader, crypto, Recover, quota) |
| Progressive mirror | `internal/logmirror` (Machine, Access, singleflight, seal) |
| Serve lifecycle | `cmd/jenkins-mcp` |
| Authz / audit / metrics | `internal/policy`, `internal/audit`, `internal/telemetry` |
| Operator docs | `docs/caching.md`, `docs/fleet/*`, gateway residual notes |

**Live tree spot-check (Phase 0):** packages above exist; `store.CurrentSchemaVersion` migrations present; fleetmcp roster schema v1 and mesh-token peer auth present. Full `go test ./...` is the implementer gate for runtime FLC tasks (not claimed by this audit).

Planning-pack provenance: adapted from the offline planning pack audited at the same commit (planner env lacked Go 1.25.12 and could not run tests).

---

## 2. Executive conclusion

The repository already has a **mature node-local log cache** and a **basic multi-fleet control plane**. Shared cache work must **not** invent a second database, frame format, sidecar, external cache appliance, or membership system.

Correct product direction (ADR 0016):

```text
reuse
  internal/store.{Meta,Frames,LogReader,OpenFrameCompressed,FrameCrypto,Recover,Quota…}
  internal/logmirror.{Machine,Access}
  internal/fleetmcp roster + mesh trust + managed peer HTTP lifecycle (harden)
  policy, audit, telemetry, admin frameworks

new work (Planned — FLC-* backlog; not shipped)
  canonical cross-node locator + sealed manifest identity
  deterministic owner placement (not broadcast fan-out)
  streaming cache peer protocol (separate from fleet_* ops JSON)
  optional fill coordination, RF2/repair (post–MVP A)
  scoped peer assertions + authz freshness
```

**First production slice (when implemented):** sealed **completed** Jenkins console logs only. Running logs, arbitrary artifacts, and peer L2 packs are later (FLC-080+).

**Default today:** plane A remains **local per profile/host**. Optional peer coordination library is **Done\*** with mode default **off** until explicitly enabled. Offline release gate **FLC-073 Done\***; **live multi-host production GO residual**. Operator canary: [shared-cache-operator.md](shared-cache-operator.md).

---

## 3. Reuse / extend / avoid

| Area | Current state | Decision for FLC |
|------|---------------|------------------|
| Metadata DB | pure-Go SQLite WAL (`store.Meta`) | **Reuse/extend** schema; no second DB |
| Frame format | independent Zstd frames (8 MiB target / 16 MiB cap) | **Reuse** on the wire as pure compressed frames |
| Bounded reads | byte/line/tail via intersecting frames | **Reuse** local + owner-side decoded reads |
| Local AEAD | per-node key; generation/seq AAD | **Keep local**; transfer pure zstd; re-wrap on receiver |
| Progressive acquire | `logmirror` + local singleflight | **Hook**; do not replace |
| Roster | schema v1 GitOps; stable member IDs; `bundle_seq` | **Version** with cache eligibility (Planned) |
| Peer auth | fleet-wide mesh token (constant-time) | **Pilot OK**; production needs unique node identity residual |
| `/fleet/v1` JSON | 1 MiB GET fan-out for ops | **Keep ops plane**; **do not** use for cache bodies |
| `fleet_*` tools | request-time aggregation | **Separate** from cache lookup |
| HOST-008 multi-pod vault/rate | **Cancelled** | **Do not reopen**; multi-fleet stays independent members |
| L2 packs | local only | **Out of v1 peer replication** |

---

## 4. Fleet plane today (verified)

**Config (fail closed):** `JENKINS_MCP_FLEET_MODE`, `…_MEMBER_ID`, `…_ROSTER`, `…_MESH_TOKEN`, `…_PEER_LISTEN`.

**Roster v1 fields:** `schema_version`, `fleet_id`, `bundle_seq`, members with `id`, `peer_url`, `profile_id`, `region`, labels.

**Gaps for shared cache (absent / partial — not Done):**

- controller/cache-pool eligibility, capacity weight, drain, protocol capability
- atomic hot-reload + last-known-good placement epoch
- streaming payload protocol under a dedicated path
- managed peer server timeouts/TLS/mTLS appropriate for large frames
- per-node cryptographic identity (mTLS or signing) beyond shared mesh token

---

## 5. Node-local cache today (verified)

| Concern | Notes |
|---------|--------|
| Identity | Local generation IDs and profile IDs are **not** fleet-global |
| Encryption portability | On-disk ciphertext must not be replicated as-is across nodes |
| Wire metadata | Need pure-zstd size/hash columns for export (schema extension Planned) |
| Quota / eviction | No owner-replica vs near-cache roles yet |
| Recovery | Import journal + committed mapping (FLC-023); startup abort/quarantine **Done\*** (FLC-024) |

---

## 6. Authorization and security (product constraints)

1. **Cache hit ≠ authorization** — apply Jenkins evidence + deny-only MCP policy before returning local or peer bytes.  
2. **No credentials on peer path** — Jenkins/OAuth tokens never sent to cache peers.  
3. **Secret-free** audit/metrics/MCP — no log bodies, tokens, or raw subject keys.  
4. **Fail open to origin** — degraded peer plane must not block authorized Jenkins progressive fetch within budget.  
5. **Read-only** — global RO continues to allow cache fills used by read tools; destructive purge remains gated.

---

## 7. Capability claim matrix (honesty)

| Capability | Status |
|------------|--------|
| Local plane A L1/L2 cache | **Done** (existing) |
| Multi-fleet independent members + signed policy | **Done\*** (existing) |
| `fleet_*` ops fan-out | **Done\*** vertical slice |
| Peer owner-directed sealed-log read/import | **Done\*** library (FLC-022/023, 030…032); default mode **off** |
| Fill lease / one-origin coordination | **Done\*** in-memory leases (FLC-040) + `CoordinateOriginFill` / logmirror FillBridge (FLC-041); partition matrix **Done\*** FLC-045 |
| RF2 compressed-frame replication | **Done\*** library (FLC-043 planner + dual-dir import + missing-frame resume); not default-on |
| Repair / drain / previous-owner grace | **Done\*** library (FLC-044 PlanRepair/RunRepair + drain budget); not default-on |
| Partition / duplicate-fill / conflict | **Done\*** library (FLC-045); split-primary may still duplicate origin (safe residual) |
| Isolation proofs | **Done\*** (FLC-052) — cross-user/controller/fleet/pool; bytes ≠ authz |
| Crypto portability / key isolation | **Done\*** (FLC-053) — dual-key parity; cross-key fail closed |
| Metrics / audit-style residuals | **Done\*** (FLC-061) process-local; multi-member aggregation residual **FLC-062+** |
| Owner-aware quota / L1 roles | **Done\*** (FLC-050 library; QuotaManager wire residual) |
| Purge + tombstone | **Done\*** (FLC-051 process-local; multi-member HTTP residual) |
| Status / doctor | **Done\*** (FLC-062 library; admin SPA residual FLC-063) |
| Near-cache promotion | **Done\*** (FLC-033 library; default off; never RF; serve wire residual) |
| Offline SLO / bench gates | **Done\*** (FLC-070 unit gates; multi-member lab residual) |
| Offline chaos / race qual | **Done\*** (FLC-071; live multi-host Docker residual) |
| Admin BFF + MCP fleet-cache | **Done\*** (FLC-063; SPA residual; process-local purge) |
| Canary criteria / rollback | **Done\*** (FLC-072 offline; live multi-host residual) |
| Operator docs / canary runbook | **Done\*** (FLC-064 — [shared-cache-operator.md](shared-cache-operator.md)) |
| Offline release gate pack | **Done\*** (FLC-073 — [shared-cache-release-gate.md](shared-cache-release-gate.md); live multi-host residual) |
| Running-log durable frames | **Done\*** (FLC-080 library; multi-host stream residual) |
| Finalize running without recompress | **Done\*** (FLC-081 library; multi-host residual) |
| Object class default-deny | **Done\*** (FLC-082 — console_log only; unknown fail closed) |
| HOST-008 multi-pod shared vault/session | **Cancelled** |

**Isolation honesty:** mode **off** → local plane A only. Mode **`read`/`full`** → eligible members **may share** sealed completed console logs for matching fleet/pool/controller; not “always isolated after full rollout.” Authz + locator isolation (FLC-052) still apply.

**FLC task IDs remaining Planned:** none. Mode default remains **off**. Live multi-host/mTLS/SPA residuals remain.

---

## 8. MVP cut line (planning)

See [ADR 0016](../adr/0016-fleet-p2p-shared-cache.md) § MVP cut line:

1. **MVP A** — owner-directed peer **read** of sealed completed console logs + origin fallback (**Done\*** library; mode default **off**)  
2. **Fill** — fill lease / origin dedup (**Done\*** FLC-040/041) + partition matrix (**Done\*** FLC-045)  
3. **RF2** — compressed-frame replication (**Done\*** FLC-043) + repair/drain library (**Done\*** FLC-044); near-cache library **Done\*** default off (FLC-033)

Library Done\* + offline release gate (**FLC-073**) ≠ automatic site production GO: mode remains **off** until operator canary; live multi-host soak residual.

---

## 9. See also

| Doc | Role |
|-----|------|
| [shared-cache-operator.md](shared-cache-operator.md) | **Operator canary runbook** (FLC-064) |
| [shared-cache-architecture.md](shared-cache-architecture.md) | Target architecture summary |
| [shared-cache-slos.md](shared-cache-slos.md) | Budgets / origin fallback |
| [ADR 0016](../adr/0016-fleet-p2p-shared-cache.md) | Binding decision |
| [jenkins-mcp-enterprise-agent-todo.md](../jenkins-mcp-enterprise-agent-todo.md) | FLC backlog SoT |
| [jenkins-mcp-enterprise-task-index.json](../jenkins-mcp-enterprise-task-index.json) | Machine graph |
| Absolute (GitHub): [shared-cache-current-state.md](https://github.com/hilather/go-jenkins-mcp/blob/master/docs/fleet/shared-cache-current-state.md) | Landing/link surface |
