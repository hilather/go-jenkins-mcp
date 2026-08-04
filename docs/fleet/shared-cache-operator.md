# Fleet shared cache — operator canary runbook (FLC-064)

**Audience:** platform operators standing up a multi-member peer cache canary  
**Status:** Operator documentation **implemented (FLC-064); FLC epic **implemented offline (FLC-073 gate pack + FLC-082 class deny); mode default **off**; **live multi-host production GO still requires site canary** — see [shared-cache-release-gate.md](shared-cache-release-gate.md)  
**SoT decision:** [ADR 0016](../adr/0016-fleet-p2p-shared-cache.md)  
**Architecture:** [shared-cache-architecture.md](shared-cache-architecture.md)  
**Budgets / SLOs:** [shared-cache-slos.md](shared-cache-slos.md)  
**Ops plane (different):** [fleet-mcp-ops.md](fleet-mcp-ops.md)  
**Plane A operator cache guide:** [caching.md](../caching.md)  
**Admin HTTP contract:** [admin/api-v1.md](../admin/api-v1.md) § Fleet-cache  
**Lab:** [testdata/fleet-cache-lab/README.md](../../testdata/fleet-cache-lab/README.md)

This runbook is the **navigable operator home** for configuring a three-member fleet-cache canary from repository docs alone. Offline release-gate pack is **FLC-073 implemented ([shared-cache-release-gate.md](shared-cache-release-gate.md)); **live multi-host site production GO** still requires a real canary + packaging residual.

---

## 0. Honesty first (read before enable)

| Claim | Reality |
|-------|---------|
| Default mode | **`off`** — local plane A only until you set mode |
| Library path | Peer lookup/read/fill/RF2/repair libraries **implemented under `internal/fleetcache` |
| Production GO | **Not** automatic — offline **FLC-073 implemented; live multi-host canary + site packaging residual before calling site production GO |
| HOST-008 multi-pod HA | **Cancelled** — peer cache does **not** share vault/session/rate |
| Isolation after enable | Matching **fleet + cache pool + controller** sealed logs **may be shared** across eligible members; caches are **not** “always isolated” once mode is `read`/`full`. Isolation is by locator identity + authz (user/controller/fleet/pool), not by “every member always independent forever.” |
| Cursor stdio pilots | Leave fleet-cache mode **off** |
| SPA fleet-cache page | **Residual** (BFF + MCP implemented — FLC-063) |
| Production mTLS / unique node identity | **Residual** — mesh token OK for controlled lab/pilot; not production pin |
| Live multi-host canary orchestration | FLC-072 criteria library implemented; live multi-host residual |

---

## 1. Planes (do not conflate)

| Plane | What it is | Cache bodies? |
|-------|------------|---------------|
| **A — profile store** | Local L1/L2 under XDG per profile | Yes — **local only** by default |
| **B — gateway caches** | Obtain / principal / JWKS / rate | No log bodies |
| **Ops — `fleet_*` / `/fleet/v1`** | Request-time health/metrics/doctor fan-out | **No** log bodies; 1 MiB JSON |
| **FLC — peer cache protocol** | Owner-directed HEAD/manifest/bounded read (+ fill/RF2 when mode full) | Sealed completed console logs (MVP A) |

Cache lookup **must not** broadcast through `fleetmcp.FanOut`. Ops aggregation and FLC payload paths are separate.

```text
                    load balancer (optional, no stickiness for canary)
               /            |            \
          member A      member B      member C
          plane A       plane A       plane A     (distinct XDG data dirs)
          fleetcache?   fleetcache?   fleetcache? (mode off|shadow|read|full)
               \____________|____________/
                 authenticated owner-directed peer traffic
                              |
                     authorized Jenkins origin on miss / timeout
```

---

## 2. Prerequisites

1. **Three independent multi-fleet members** (not multi-pod HA). Distinct data dirs / XDG volumes.  
2. **Shared gitops roster** with optional `cache` eligibility blocks (see §4).  
3. **Fleet peer mesh trust** (mesh token for lab/pilot; mTLS residual for production).  
4. **Fleet mode** plumbing for peer listen (`--fleet-mode` + roster + member id + mesh token) — see [fleet-mcp-ops.md](fleet-mcp-ops.md) §3.  
5. **Fleet-cache mode** set explicitly (`off` default).  
6. **Read-only pilot posture** remains default for Jenkins tools; global RO still allows **read-path cache fills**; destructive purge is separately gated.

HOST-008 remains cancelled: never share vault, Obtain, subject rate, or admin sessions across pods.

---

## 3. Enable flags and environment

### 3.1 Fleet-cache mode and budgets

| Knob | Flag | Env | Default |
|------|------|-----|---------|
| Mode | `--fleet-cache-mode` | `JENKINS_MCP_FLEET_CACHE_MODE` | **`off`** |
| Peer lookup timeout | `--fleet-cache-peer-lookup-timeout` | `JENKINS_MCP_FLEET_CACHE_PEER_LOOKUP_TIMEOUT` | **750ms** |
| Max peer streams | `--fleet-cache-max-peer-streams` | `JENKINS_MCP_FLEET_CACHE_MAX_PEER_STREAMS` | **4** |
| Max peer lookups | `--fleet-cache-max-peer-lookups` | `JENKINS_MCP_FLEET_CACHE_MAX_PEER_LOOKUPS` | **2** |
| Origin fallback | *(not disableable)* | `JENKINS_MCP_FLEET_CACHE_ORIGIN_FALLBACK` | **always true**; `false` is **rejected** |

Flag wins over env when both are set at the serve layer. Empty / `0` budgets restore product defaults. Out-of-range values **fail closed** (see [shared-cache-slos.md](shared-cache-slos.md)).

### 3.2 Fleet membership (peer listen / trust)

| Knob | Flag / env | Notes |
|------|------------|-------|
| Fleet mode | `--fleet-mode` / `JENKINS_MCP_FLEET_MODE=1` | Opt-in; fail closed without full set |
| Member id | `--fleet-member-id` / `JENKINS_MCP_FLEET_MEMBER_ID` | Must match roster `members[].id` |
| Roster path | `--fleet-roster` / `JENKINS_MCP_FLEET_ROSTER` | Gitops JSON (lab: `testdata/fleet-cache-lab/roster.json`) |
| Mesh token | `--fleet-mesh-token-file` / `JENKINS_MCP_FLEET_MESH_TOKEN` | Disposable for lab; never commit production secrets |
| Peer listen | `--fleet-peer-listen` / `JENKINS_MCP_FLEET_PEER_LISTEN` | Private/loopback bind for peer HTTP |
| Lab cleartext HTTP | `JENKINS_MCP_FLEET_ALLOW_INSECURE_HTTP=1` | Lab residual only; production `ParseRoster` **rejects** non-loopback `http://` without it (FLC-016) |

### 3.3 Modes

| Mode | Behavior | Peer payload I/O |
|------|----------|------------------|
| **`off` (default)** | Local plane A only | No |
| **`shadow`** | Placement/metrics only | No |
| **`read`** | MVP A owner-directed peer **read** of sealed completed console logs | Yes (read path) |
| **`full`** | Fill + RF2 + repair (later gate; accepted in config) | Yes |

Cursor **stdio** single-member pilots stay **`off`**.

### 3.4 Example member env (canary sketch)

```bash
# Member lab-a — distinct XDG; shared roster file content
export XDG_DATA_HOME=/var/lib/jenkins-mcp/lab-a
export JENKINS_MCP_FLEET_MODE=1
export JENKINS_MCP_FLEET_MEMBER_ID=lab-a
export JENKINS_MCP_FLEET_ROSTER=/etc/jenkins-mcp/fleet/roster.json
export JENKINS_MCP_FLEET_PEER_LISTEN=0.0.0.0:9443
export JENKINS_MCP_FLEET_MESH_TOKEN="$(cat /etc/jenkins-mcp/fleet/mesh-token)"  # secret material; file preferred
export JENKINS_MCP_FLEET_CACHE_MODE=off   # promote deliberately: shadow → read → full

jenkins-mcp serve --profile lab-a --read-only --stdio \
  --fleet-mode \
  --fleet-member-id lab-a \
  --fleet-roster /etc/jenkins-mcp/fleet/roster.json \
  --fleet-cache-mode off \
  --enable-admin-mcp --admin-role operator   # optional day-2 admin_* tools
```

Repeat for `lab-b` / `lab-c` with unique `XDG_DATA_HOME`, `MEMBER_ID`, and peer listen ports. Prefer private TLS networks; set `JENKINS_MCP_FLEET_ALLOW_INSECURE_HTTP=1` **only** for the disposable lab compose residual.

---

## 4. Roster and cache eligibility

Roster schema v1 (secret-free) plus optional per-member **`cache`** block (FLC-012):

| Field | Role |
|-------|------|
| `schema_version` | `1` |
| `fleet_id` | Fleet identity in locators |
| `bundle_seq` | Placement epoch / hot-reload LKG (monotonic) |
| `members[].id` | Stable member id |
| `members[].peer_url` | Peer base URL (HTTPS outside lab residual) |
| `members[].profile_id` | Local profile mapping |
| `members[].cache.enabled` | Eligible for placement when true |
| `members[].cache.controller_id` | Jenkins controller identity for pool match |
| `members[].cache.pool` | Cache pool id (locator dimension) |
| `members[].cache.capacity_weight` | Weighted rendezvous weight |
| `members[].cache.failure_domain` | Prefer RF diversity across domains |
| `members[].cache.protocols` | e.g. `["fleet-cache/1"]` |

Lab fixture: [testdata/fleet-cache-lab/roster.json](../../testdata/fleet-cache-lab/roster.json) — three members, same `controller_id` + `pool`, distinct failure domains, capacity weights 100/100/50.

**Eligibility filter:** only members with matching controller/pool/protocol and `cache.enabled=true` enter owner order. Drain (when used) refuses new primary ownership.

**Locator identity (canonical):** fleet + cache pool + controller + `console_log` + normalized job + build + schema version — **not** local profile ID or SQLite generation ID.

---

## 5. Lab: offline smoke and optional Docker

Default `make test` / `make ci` stay offline. Fleet-cache lab is **opt-in**.

```bash
# Offline smoke (roster parse, eligibility, locator goldens, distinct data dirs)
make fleet-cache-lab-smoke

# Optional Docker: 3 members + nginx LB (no stickiness) on 127.0.0.1:19080
make fleet-cache-lab-up
make fleet-cache-lab-down   # down -v destroys independent volumes
```

| Target | Role |
|--------|------|
| `make fleet-cache-lab-smoke` | Offline validation gate |
| `make fleet-cache-lab-up` | Compose 3 members + LB |
| `make fleet-cache-lab-down` | Tear-down + volume destroy |
| Peer host ports | `19443`–`19445` (lab) |
| LB | `19080` round-robin (exercises multi-member routing) |

Details and residuals: [testdata/fleet-cache-lab/README.md](../../testdata/fleet-cache-lab/README.md).

---

## 6. Canary stages (FLC-072 criteria codes)

Promotion is **adjacent-only** on the ladder `off → shadow → read → full`.  
**Rollback any → off is always allowed** and requires **no data migration** (`rollback_no_migration`).  
Non-adjacent promotions (e.g. `off → read`, `off → full`) are **denied** (`transition_adjacent_only`).

Library: `internal/fleetcache` — `CriteriaFor`, `ValidateTransition`, `CheckCanaryPreconditions`, `RollbackToOff`.

### 6.1 Preconditions (read / full)

| Mode | Preconditions residual codes |
|------|------------------------------|
| `off` | `precond_mode_off` |
| `shadow` | `precond_shadow_no_peer_io` (no peer I/O wiring required) |
| `read` / `full` | Handlers live + origin fallback on → `precond_ok`; else `precond_handlers_not_live` / `precond_origin_fallback_required` |

### 6.2 Stage checklists (stable criteria codes)

#### `off` (baseline)

| Class | Codes |
|-------|-------|
| Entry | `entry_mode_off_local_only` |
| Exit | `exit_n_a_default` |
| Rollback | `rollback_n_a_already_off` |

#### `shadow`

| Class | Codes |
|-------|-------|
| Entry | `entry_mode_off_or_prior_shadow`, `entry_placement_library_live`, `entry_metrics_process_local_ok`, `entry_operator_approval_shadow` |
| Exit | `exit_placement_predictions_match`, `exit_zero_peer_payload_bytes`, `exit_no_auth_denial_spikes` |
| Rollback | `rollback_set_mode_off`, `rollback_no_data_migration`, `rollback_local_plane_a_unchanged` |

**Operator actions**

1. Obtain explicit approval for shadow.  
2. Set `--fleet-cache-mode=shadow` (or env) on all canary members.  
3. Confirm placement predictions agree across members for sample locators.  
4. Confirm **zero** peer payload bytes (metrics only).  
5. Watch auth denial metrics for spikes.

#### `read` (MVP A)

| Class | Codes |
|-------|-------|
| Entry | `entry_shadow_exit_criteria_met`, `entry_peer_read_handlers_live`, `entry_origin_fallback_on`, `entry_small_controller_pool`, `entry_operator_approval_read` |
| Exit | `exit_source_metadata_parity`, `exit_origin_fallback_proven`, `exit_no_corruption_alerts` |
| Rollback | `rollback_set_mode_off`, `rollback_no_data_migration`, `rollback_local_cache_intact` |

**Operator actions**

1. Exit shadow criteria met.  
2. Restrict to a **small controller/pool** (lab roster pattern).  
3. Promote to `--fleet-cache-mode=read`.  
4. Prove peer hit returns sealed completed console log ranges that match origin metadata.  
5. Inject slow/unreachable peer → origin fallback within lookup timeout (default 750ms).  
6. No corruption / unexplained auth alerts.

#### `full` (fill + RF2 + repair gate)

| Class | Codes |
|-------|-------|
| Entry | `entry_read_exit_criteria_met`, `entry_peer_read_handlers_live`, `entry_origin_fallback_on`, `entry_rf2_repair_library_live`, `entry_strict_budget_limits`, `entry_operator_approval_full` |
| Exit | `exit_replica_health_ok`, `exit_measured_savings_justify`, `exit_no_unexplained_auth_or_corruption` |
| Rollback | `rollback_set_mode_off`, `rollback_no_data_migration`, `rollback_local_behavior_restored` |

**Operator actions**

1. Exit read criteria met; keep **strict** peer stream/lookup budgets.  
2. Promote to `--fleet-cache-mode=full` only with approval.  
3. Confirm fill single-flight (waiters skip origin body) and RF2/repair health.  
4. Measured origin-byte savings justify continued rollout.  
5. **Still not automatic site production GO** — offline FLC-073 pack implemented; complete a live multi-member canary before calling production GO.

### 6.3 Recommended ladder

```text
off  →  shadow  →  read  →  full
 ↑_______________________________|
        any stage → off (rollback, no migration)
```

Live multi-host orchestration dashboards remain residual (FLC-072 honesty residual). Offline unit transitions cover the criteria library.

---

## 7. Origin fallback

Always **on** when config resolves successfully.

```text
local mapping miss
  → peer owner lookup (≤ PeerLookupTimeout, ≤ MaxPeerLookups)
  → timeout / all owners fail / mode off
  → authorized Jenkins origin via existing logmirror (within tool budgets)
```

- Peer/cache failure **must not** indefinitely delay authorized origin.  
- Setting `JENKINS_MCP_FLEET_CACHE_ORIGIN_FALLBACK=false` is **rejected**.  
- Cache hit is **never** authorization — entry node still applies Jenkins evidence + deny-only MCP policy.

---

## 8. Quotas, owner roles, near-cache

| Topic | Default / residual |
|-------|--------------------|
| Plane A total quota | **10 GiB** per profile (see [caching.md](../caching.md)); flags `--cache-total-quota-bytes` / env |
| Owner-aware eviction roles | Library implemented (FLC-050) — prefer reclaim near/non-required copies first; hard safety wins; mode-off ignores fleet roles |
| QuotaManager auto-wire | Residual note on FLC-050 |
| Near-cache promotion | Library implemented (FLC-033); **default off** (`Enabled=false`); near never counts toward RF |
| Purge / tombstone | Process-local implemented (FLC-051); multi-member HTTP purge residual |

Near-cache is **not** required for MVP A peer read.

---

## 9. Status, doctor, purge (admin BFF + MCP)

**FLC-063 implemented:** process-local BFF routes + `admin_fleet_cache_*` MCP tools.  
**SPA dedicated fleet-cache page:** residual.  
**Multi-member HTTP purge fan-out:** residual.

### 9.1 HTTP (admin serve)

| Path | Method | Role |
|------|--------|------|
| `/admin/v1/fleet-cache/status` | GET | viewer+ |
| `/admin/v1/fleet-cache/doctor` | GET | viewer+ |
| `/admin/v1/fleet-cache/purge` | POST | operator + body `confirm: "PURGE"` |

Status fields (secret-free): `mode`, `active`, `local_healthy` / `replica_healthy`, aggregation residual, `spa_residual`, mode_default_off when off.

Purge does **not** delete Jenkins origin data; does **not** fan out purge over HTTP to peers (`http_peer_prop: false`). Audit type `admin_fleet_cache_purge` (locator as `TargetHash` only).

Contract detail: [admin/api-v1.md](../admin/api-v1.md) § Fleet-cache.

### 9.2 MCP (`--enable-admin-mcp`)

| Tool | Role |
|------|------|
| `admin_fleet_cache_status` | Read status snapshot |
| `admin_fleet_cache_doctor` | Doctor checks envelope |
| `admin_fleet_cache_purge` | Operator; confirm string **`PURGE`** |

Shared libraries with BFF (not HTTP proxy). Secret-free; same confirm string.

### 9.3 Related fleet ops tools (different plane)

`fleet_cache_status` / `fleet_doctor` (when `--fleet-mode`) are **ops fan-out**, not the FLC payload protocol — [fleet-mcp-ops.md](fleet-mcp-ops.md).

---

## 10. Rollback to off

1. Set mode to **`off`** on every canary member (`--fleet-cache-mode=off` or unset env → default off).  
2. **No data migration** required (`rollback_no_migration`).  
3. Local plane A frames/SQLite remain intact; incomplete peer imports stay unpublished / quarantined by recovery rules.  
4. Behavior returns to current local-only caching ([caching.md](../caching.md)).  
5. Optional: leave fleet ops mode on for health fan-out without peer log cache.

Rollback is allowed from **any** known stage (`shadow`/`read`/`full` → `off`).

---

## 11. Troubleshooting residuals

| Symptom / topic | Guidance |
|-----------------|----------|
| Mode stays off | Unset or empty `JENKINS_MCP_FLEET_CACHE_MODE` defaults to **off** (by design) |
| Serve rejects mode | Must be exact `off\|shadow\|read\|full` |
| Non-loopback `http://` peer URLs rejected | Set lab residual `JENKINS_MCP_FLEET_ALLOW_INSECURE_HTTP=1` **only** in lab; production needs HTTPS / private mesh |
| mTLS / unique node identity | Mesh token pilot residual; production pin residual before site production GO |
| Origin slow under peer outage | Lower/keep lookup timeout (default 750ms); origin fallback is mandatory |
| Unexpected peer share | Enabled `read`/`full` **does share** sealed logs for matching fleet/pool/controller — not “always isolated”; use pools/controller ids to scope |
| Cross-user / cross-controller bleed | Fail closed by isolation proofs (FLC-052); report as bug if observed |
| Purge only local | Expected — multi-member HTTP purge residual; tombstones process-local |
| No SPA page | Residual — use BFF HTTP or `admin_fleet_cache_*` MCP |
| Live multi-host chaos | Offline FLC-071 implemented; Docker multi-host residual |
| Production GO questions | Offline **FLC-073 implemented; use this runbook for canary; site production GO needs live multi-host residual closed |
| HOST-008 / shared vault requests | Cancelled — multi-fleet independent members only |

---

## 12. Security non-negotiables (operator checklist)

1. Cache hit ≠ authorization.  
2. No Jenkins/OAuth credentials on peer requests.  
3. Scoped short-lived peer assertions only.  
4. Fail closed on auth/crypto; fail open to origin within budget.  
5. Secret-free metrics, audit, MCP, admin JSON.  
6. Never bake production mesh tokens into git or images.  
7. Global RO pilots: leave mode **off** unless canary approved.

---

## 13. What is not in this runbook

| Residual / out of runbook | Note |
|---------------------------|------|
| Offline release gate pack | **FLC-073 implemented — [shared-cache-release-gate.md](shared-cache-release-gate.md); live multi-host residual |
| Finalize running without recompress | **FLC-081 implemented library |
| Object class default-deny | **FLC-082 implemented — `console_log` only; new class = separate PR |
| Admin SPA fleet-cache page | Residual on FLC-063 (BFF+MCP implemented) |
| SIEM ship of fleet-cache audit | AUD-T residual |
| Shared NFS/S3 log store | Non-goal |
| Multi-pod HA | HOST-008 cancelled |

---

## 14. See also

| Doc | Role |
|-----|------|
| [shared-cache-architecture.md](shared-cache-architecture.md) | Target architecture summary |
| [shared-cache-current-state.md](shared-cache-current-state.md) | Capability honesty matrix |
| [shared-cache-slos.md](shared-cache-slos.md) | Budgets / origin fallback |
| [multi-fleet-rollout.md](multi-fleet-rollout.md) | Shared policy multi-fleet scale |
| [fleet-mcp-ops.md](fleet-mcp-ops.md) | Ops fan-out plane |
| [caching.md](../caching.md) | Plane A operator guide |
| [adr/0016-fleet-p2p-shared-cache.md](../adr/0016-fleet-p2p-shared-cache.md) | Binding ADR |
| Absolute (GitHub): [shared-cache-operator.md](https://github.com/hilather/go-jenkins-mcp/blob/master/docs/fleet/shared-cache-operator.md) | Landing/link surface |
