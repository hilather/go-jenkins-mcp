# Fleet MCP ops — design plan (aggregation without multi-pod HA)

**Status:** **Done\* vertical slice** (2026-08-02) — `internal/fleetmcp` + `fleet_*` MCP tools; mesh-token peer auth; mTLS residual  
**Audience:** product, security, implementers, operators  
**Package:** `internal/fleetmcp` · tools: `internal/tools/fleet_ops.go` · serve flags `--fleet-mode` / roster / member-id / mesh token  
**Related:** [multi-fleet-rollout.md](multi-fleet-rollout.md) · [admin/mcp-ops-parity.md](../admin/mcp-ops-parity.md) · [caching.md](../caching.md) · HOST-008 **cancelled** · ADR 0002 (stdio default) · ADR 0014 (admin ≠ MCP discovery)

---

## 0. Problem statement

Today:

| Surface | Scope |
|---------|--------|
| Multi-fleet | **N independent** single-replica members; shared **signed policy** (gitops) |
| `admin_*` MCP | **This process only** (opt-in `--enable-admin-mcp`) |
| Metrics / doctor / residual | **Process-local** |
| Multi-pod HA | **Out of scope** (HOST-008 cancelled) |

Operators and agents want: *ask any one fleet node* for a **fleet-wide** read of health/metrics/doctor/residual — without building multi-replica shared vault/rate HA, and without collapsing multi-fleet into a SaaS control plane.

This plan defines a **separate** tool family, gated on explicit **fleet mode**, plus a sketch of **fan-out aggregation** to peer members.

---

## 1. Goals / non-goals

### Goals

1. **Opt-in fleet mode** — tools only register when fleet mode is explicitly configured and valid (fail closed otherwise).  
2. **Namespace isolation** — `fleet_*` tools distinct from `jenkins_*` (data plane) and `admin_*` (single-node day-2).  
3. **Any-node entry** — agent may attach to **any** member; that member fans out and returns a **composed** secret-free view.  
4. **Partial honesty** — unreachable peers appear as structured residuals, not silent under-count.  
5. **Same deny-only / secret-free rules** as admin MCP (no tokens, no vault material, no raw logs).  
6. **Roster as SoT** — membership from **gitops fleet roster** (signed or require-signed path), not free-form tool args inventing peers.

### Non-goals (v1)

| Non-goal | Why |
|----------|-----|
| Multi-pod HA / shared Obtain/rate/vault | HOST-008 cancelled; multi-fleet remains independent processes |
| Cross-member mutation fan-out (start job, evict, policy apply) | Blast radius; v1 is **read-mostly** |
| SPA as fleet SoT | Policy remains signed config |
| Agent SAML login for fleet tools | Admin MCP remains process role; fleet peer auth is **mesh**, not browser SSO |
| Unbounded full audit merge | AUD-T SIEM residual; optional later with hard caps |
| Auto-discovery of peers via mDNS / Jenkins | Spoofable; roster only |

---

## 2. Conceptual model

```text
                    ┌─────────────────────────────────────┐
                    │  Gitops fleet pack                  │
                    │  - signed policy overlay            │
                    │  - fleet roster (member endpoints)  │
                    │  - peer trust (mTLS CA / mesh keys)  │
                    └─────────────────────────────────────┘
                                      │
          ┌───────────────────────────┼───────────────────────────┐
          ▼                           ▼                           ▼
   Member A (stdio MCP)        Member B                    Member C
   serve --fleet-mode          serve --fleet-mode          serve --fleet-mode
   fleet_* tools               peer listen                 peer listen
          │
          │  agent calls fleet_metrics on A
          ▼
   A = coordinator for this request
          │
          ├─ local snapshot (A)
          ├─ HTTPS GET peer B /fleet/v1/metrics  (bounded, mTLS)
          └─ HTTPS GET peer C /fleet/v1/metrics
          │
          ▼
   fleet_metrics result:
     members[] + aggregate_lite + residuals[]
```

**Key idea:** Aggregation is **request-time fan-out**, not shared memory or multi-pod HA. Each member keeps its own cache, vault, audit file, and metrics registry.

---

## 3. Fleet mode (when tools appear)

### 3.1 Enablement (fail closed)

Tools register **only** when **all** of the following hold:

| Requirement | Example |
|-------------|---------|
| Explicit flag/env | bare `--fleet-mode` (bool) or `JENKINS_MCP_FLEET_MODE=1` |
| Valid roster path | `--fleet-roster` / `JENKINS_MCP_FLEET_ROSTER` → JSON (or signed envelope) |
| Peer trust configured | **Shipped:** mesh shared secret (`JENKINS_MCP_FLEET_MESH_TOKEN` or `--fleet-mesh-token-file`) — empty trust ⇒ **no** `fleet_*` tools. **mTLS residual** |
| Local member id | `--fleet-member-id` / `JENKINS_MCP_FLEET_MEMBER_ID` must match a roster entry |
| Optional: require signed roster | Residual (unsigned roster JSON for free-lab; sign like policy later) |

If any check fails: **do not register** `fleet_*` (log secret-free residual). Never half-enable with open peer fan-out.

**Default pilot RO stdio remains non-fleet** (ADR 0002). Fleet mode is a managed/operator profile.

### 3.2 Relationship to admin MCP

| Flag | Tools |
|------|--------|
| (default) | `jenkins_*` only |
| `--enable-admin-mcp` | + `admin_*` (this node) |
| `--fleet-mode` + valid roster/trust | + `fleet_*` (fan-out) |
| Both admin + fleet | Both namespaces; fleet does **not** replace admin |

`fleet_*` must **not** proxy through admin HTTP on peers as “curl localhost admin with shared token” unless that is an **explicit residual** design. Prefer a **dedicated peer surface** (§5).

---

## 4. Roster format (membership SoT)

Gitops next to multi-fleet pack:

```text
fleet/
  policy/overlay.bundle.json
  roster/
    roster.json              # or roster.bundle.json (signed)
    trusted_peer_keys/       # optional Ed25519 for roster envelope
```

### 4.1 `roster.json` (sketch)

```json
{
  "schema_version": 1,
  "fleet_id": "corp-jenkins-mcp",
  "bundle_seq": 12,
  "members": [
    {
      "id": "edge-a",
      "display_name": "Edge A",
      "peer_url": "https://edge-a.mcp.svc:9443",
      "profile_id": "site-a",
      "region": "us-east",
      "labels": { "tier": "pilot" }
    },
    {
      "id": "edge-b",
      "peer_url": "https://edge-b.mcp.svc:9443",
      "profile_id": "site-b"
    }
  ]
}
```

| Rule | Detail |
|------|--------|
| **No secrets** | No tokens, vault paths with credentials, or private keys in roster |
| **peer_url** | HTTPS only; host allow-list / pin residual like HOST-002 |
| **id** | Stable; used in responses and residual rows |
| **Self** | Local process must find itself by `fleet-member-id` |
| **Signed** | Prefer same Ed25519 envelope pattern as policy bundles (MGR-001 lite) |

Roster hot-reload: same last-good / bundle_seq downgrade refuse pattern as policy.

---

## 5. Peer protocol (how one node reaches others)

### 5.1 Dedicated peer API (recommended)

Each fleet-mode process listens on a **peer port** (not Cursor stdio; not public Jenkins):

| Item | Recommendation |
|------|----------------|
| Bind | Loopback or private network only; non-local requires mTLS |
| Path prefix | `/fleet/v1/...` |
| Auth | **mTLS** (preferred) or static mesh token in header from file (pilot); never Jenkins API token |
| Body | Secret-free JSON only; same scrubbing as admin |
| Timeouts | Per-peer deadline (e.g. 2s) + overall fan-out budget (e.g. 5s) |
| Concurrency | Max parallel peers (e.g. 8–16); rest queued or residual “skipped_budget” |

### 5.2 Endpoints (v1 read set)

| Peer route | Mirrors | Notes |
|------------|---------|--------|
| `GET /fleet/v1/health` | admin health lite | version, ready residual, mode flags |
| `GET /fleet/v1/version` | version/commit | secret-free |
| `GET /fleet/v1/residual-status` | gateway residual-status map | bools/counts only |
| `GET /fleet/v1/metrics` | process metrics snapshot | counters/gauges only |
| `GET /fleet/v1/doctor?offline=1` | doctor offline summary | no raw logs |
| `GET /fleet/v1/cache-status` | cache quota/usage lite | bytes + needs_eviction; no paths with home |
| `GET /fleet/v1/member` | self identity | id, profile_id, roster bundle_seq |

**No v1 peer writes** (evict, policy apply, vault, subject-invalidate). Those stay single-node `admin_*` / CLI so blast radius is intentional.

### 5.3 Why not “stdio to every peer”?

Cursor/agent is attached to **one** stdio process. Fan-out must be **server-side** from that coordinator. Peers expose a small HTTPS surface; the coordinator is the only MCP-facing process for that agent session.

### 5.4 Trust boundaries

```text
Agent ──stdio──► Member A (fleet_* coordinator)
                      │ mTLS
                      ├──► Member B /fleet/v1/*
                      └──► Member C /fleet/v1/*

Jenkins credentials never leave each member's keyring.
Peer calls never carry Jenkins tokens.
```

---

## 6. MCP tool surface (`fleet_*`)

Register **only** in fleet mode. Suggest process role gate parallel to admin: `viewer` can read; no fleet writes in v1.

| Tool | Behavior | Status |
|------|----------|--------|
| `fleet_list_members` | Roster + peer `/member` reachability | **Done\*** |
| `fleet_health` | Fan-out health; per-member + summary counts | **Done\*** |
| `fleet_metrics` | Fan-out metrics; per-member snapshots + allowlisted counter sums | **Done\*** |
| `fleet_residual_status` | Fan-out residual maps; never claim live GO from union | **Done\*** |
| `fleet_doctor` | Fan-out offline doctor summaries | **Done\*** |
| `fleet_cache_status` | Fan-out quota usage lite | **Done\*** |
| `fleet_version` | Fan-out version/commit matrix | **Done\*** |

### 6.1 Common result envelope (sketch)

```json
{
  "schema": "jenkins-mcp.fleet-aggregate.v1",
  "fleet_id": "corp-jenkins-mcp",
  "coordinator_id": "edge-a",
  "roster_bundle_seq": 12,
  "queried_at": "2026-08-02T00:00:00Z",
  "members": [
    {
      "id": "edge-a",
      "source": "local",
      "ok": true,
      "payload": { }
    },
    {
      "id": "edge-b",
      "source": "peer",
      "ok": true,
      "latency_ms": 42,
      "payload": { }
    },
    {
      "id": "edge-c",
      "source": "peer",
      "ok": false,
      "error_code": "timeout",
      "residual": "peer unreachable within deadline"
    }
  ],
  "summary": {
    "members_total": 3,
    "members_ok": 2,
    "members_failed": 1
  },
  "aggregate": { },
  "incomplete": true,
  "residual_notes": ["partial fleet view; do not treat as HA single-system"]
}
```

Rules:

- **Never** invent missing members as healthy.  
- **incomplete=true** if any peer fails or is skipped.  
- **Secret canaries** on all peer payloads and coordinator output.  
- **Budgets:** max members in roster (e.g. 64); max response bytes; truncate with residual.

### 6.2 Aggregation semantics (metrics example)

| Field type | Aggregate? | How |
|------------|------------|-----|
| Counter (e.g. `mcp_tool_ok`) | Optional sum | Only **allowlisted** names; document non-comparability across restarts |
| Gauge (e.g. cache bytes) | Per-member only or sum with residual | Sum can mislead across profiles — prefer per-member + optional sum_with_caveat |
| Bool residual flags | Logical OR of “badness” | e.g. any `gateway_ready=false` → summary `any_not_ready=true` |
| Version strings | Drift set | `{ "versions": {"v0.4.0": ["a","b"], "v0.3.0": ["c"]} }` |

Do **not** average latencies without recording sample counts.

---

## 7. Request path (sequence)

```text
1. Agent → MCP CallTool fleet_metrics on Member A
2. A: RequirePermission(viewer+); require fleet mode loaded
3. A: Load roster (memory, hot-reload); resolve peer list excluding self
4. A: Local metrics snapshot → members[A]
5. A: For each peer (bounded parallel):
      - Dial peer_url with mTLS / mesh auth
      - GET /fleet/v1/metrics with deadline
      - Map transport/auth errors → residual row (no raw TLS secrets)
6. A: Build envelope (summary, optional aggregate, incomplete)
7. A: Enforce MCP result budget / redact
8. Return to agent
```

**Partial failure:** still return 200-level tool success with `incomplete=true` and per-member errors (unless local snapshot itself fails closed).

**Auth failure to peer:** count as failed member; do not retry with weaker auth.

---

## 8. Security model

| Threat | Mitigation |
|--------|------------|
| Agent invents peer URLs | Peers **only** from roster; tool args cannot add hosts |
| Rogue peer spoofing | mTLS or mesh secret + optional response signing residual |
| Token leak via fan-out | Peer handlers reuse secret-free admin/lib views; canaries |
| SSRF via peer_url | Roster validation: HTTPS, deny link-local/metadata ranges residual, private-net allow policy |
| Cross-tenant data | Fleet roster is **operator** plane; still deny-only MCP policy on coordinator; no Jenkins job data in `fleet_*` v1 |
| Confused deputy (admin role) | `fleet_*` default read-only; process role still required; separate from Jenkins subject |
| Amplification | Max peers, max concurrency, per-request timeout, rate limit fan-out |

**SAML:** remains browser admin SSO on a node. It does **not** authenticate fleet peer mesh. Fleet peer identity is **machine/mesh**, not end-user browser.

---

## 9. Phased delivery (suggested task IDs)

| Phase | ID (proposed) | Deliverable |
|-------|---------------|-------------|
| **F** | **FLEET-MCP-000** | ADR: fleet mode, roster, peer surface, non-goals vs HOST-008 |
| **F** | **FLEET-MCP-001** | Roster schema + load/validate + signed envelope lite + tests |
| **F** | **FLEET-MCP-002** | Peer HTTP server `/fleet/v1/*` read handlers + mTLS/mesh auth + canaries |
| **F** | **FLEET-MCP-003** | Coordinator fan-out client + budgets + incomplete envelope |
| **F** | **FLEET-MCP-004** | Register `fleet_*` tools only when fleet mode valid; catalog + MCP-OPS matrix row |
| **F** | **FLEET-MCP-005** | Docker lab: 2–3 members + roster + opt-in `make live-fleet-mcp-*` (not default `make test`) |
| **F** | **FLEET-MCP-006** | Docs: multi-fleet-rollout § fleet MCP; agent-usage; residual honesty |
| **Later** | **FLEET-MCP-010** | Optional allowlisted counter sums; doctor SPA fleet panel residual |
| **Later** | **FLEET-MCP-011** | Write tools (explicit deny by default) — only with security go |
| **Out** | — | Multi-pod HA, shared vault, auto-install upgrade fan-out |

Prefer **one task ID per PR**. Pair 002+003 only if needed for a vertical slice.

### Definition of done (first vertical slice)

- [ ] Without fleet mode: zero `fleet_*` in ListTools  
- [ ] With broken roster/trust: fail closed, no tools  
- [ ] With 2-node lab: `fleet_health` shows local + peer; kill peer → incomplete residual  
- [ ] Secret canaries on peer JSON and MCP result  
- [ ] No Jenkins tokens in peer auth  
- [ ] Docs state: not multi-pod HA; not full fleet metrics product pin  

---

## 10. Config sketch (operator)

```bash
# Member edge-a
export JENKINS_MCP_FLEET_MODE=1
export JENKINS_MCP_FLEET_MEMBER_ID=edge-a
export JENKINS_MCP_FLEET_ROSTER=/etc/jenkins-mcp/fleet/roster.json
export JENKINS_MCP_FLEET_PEER_LISTEN=127.0.0.1:9443   # or private IP + mTLS
export JENKINS_MCP_FLEET_MTLS_CERT=...
export JENKINS_MCP_FLEET_MTLS_KEY=...
export JENKINS_MCP_FLEET_MTLS_CA=...

jenkins-mcp serve --profile site-a --read-only --stdio \
  --fleet-mode \
  --fleet-member-id edge-a \
  --fleet-roster /etc/jenkins-mcp/fleet/roster.json \
  --enable-admin-mcp --admin-role operator   # optional single-node admin_*
# bare --fleet-mode is a Bool flag (does not consume the next argv token)
```

Cursor `mcp.json` still points at **one** command (edge-a). That process is the coordinator for `fleet_*` calls.

---

## 11. Alternatives considered

| Option | Verdict |
|--------|---------|
| Extend `admin_metrics` to auto-fan-out | **Reject** — breaks process-local contract; surprises non-fleet deploys |
| External Prometheus only | Valid ops residual; does not give agent MCP tools |
| Shared Redis metrics | Smells like HA; out of scope |
| Agent opens N MCP connections | Possible but poor UX; product still needs roster/trust |
| stdio hop via SSH | Residual ops pattern; not product MCP |

---

## 12. Open decisions (for ADR FLEET-MCP-000)

1. **Peer auth:** mTLS-only for production vs mesh token pilot?  
2. **Roster signing:** mandatory when `REQUIRE_SIGNED_POLICY` already on?  
3. **Max fleet size** product limit (32 vs 64 vs 128)?  
4. **Include multi-profile hosts** (one OS user, many Jenkins profiles) as one member or N logical members?  
5. **Admin SPA fleet page** same change or residual after MCP?  
6. **Metrics allowlist** ownership (security vs platform)?  

---

## 13. Summary

| Question | Plan answer |
|----------|-------------|
| Separate fleet MCP options? | Yes — **`fleet_*`**, only if **fleet mode** + roster + trust |
| Available in normal pilot? | **No** — default off |
| Any node returns all fleet? | **Yes (read path)** — coordinator fans out to roster peers over authenticated peer API; partial failures explicit |
| Shared multi-pod state? | **No** — still independent members; aggregation is live fan-out |
| Metrics from all nodes? | **Yes for snapshots** when peers reachable; incomplete otherwise; careful aggregate sums |
| SAML for agents? | **No** — process/mesh auth; SAML stays browser admin |
| Writes across fleet? | **Not in v1** |

This preserves multi-fleet as the scale model (HOST-008 stays cancelled) while giving agents a deliberate, fail-closed way to see **fleet-shaped** ops data from a single MCP attachment.
