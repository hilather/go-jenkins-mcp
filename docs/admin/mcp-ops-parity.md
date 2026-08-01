# Admin console ↔ MCP ops parity (management tools)

**Audience:** implementers, agents, security  
**Related:** [api-v1.md](api-v1.md), [ADR 0014](../adr/0014-admin-console-reactive-spa.md), [AGENTS.md](../../AGENTS.md)  
**Status:** Gap analysis + backlog (2026-08-01). Local admin BFF/SPA is first-class for **operators in a browser**; **agent-facing management** via MCP is incomplete and is a first-class product requirement going forward.

---

## 1. Why this exists

Operators use `jenkins-mcp admin serve` + SPA. **Agents** (Cursor MCP stdio) must not depend on scraping the admin HTTP API. The MCP server is the **first-class control plane for agents**: anything an operator can do on an admin page for day-2 management should be available as an **MCP tool** (or an explicit residual with id), with the same secret-free, fail-closed semantics as the BFF.

**Separation that remains:**

| Surface | Transport | Audience |
|---------|-----------|----------|
| Admin BFF + SPA | HTTP `/admin/v1` (loopback, optional token, console RBAC) | Human operators |
| MCP `serve` | stdio (default) / optional Streamable HTTP | Agents / Cursor |
| Shared libraries | `internal/policy`, `diagnostics`, `audit`, `gateway`, `store` | **No second policy engine** — both call the same libs |

Admin HTTP is **not** MCP discovery (ADR 0014). MCP tools **wrap the same libraries** the BFF uses; they do not call admin HTTP from inside `serve`.

---

## 2. Current admin surface (SPA pages → BFF)

| SPA page | Primary BFF routes | Writes? |
|----------|-------------------|---------|
| **Overview** | `GET /health`, `/version`, `/me`, `/gateway/vault`, `/gateway/residual-status`; `POST` subject-invalidate, consent-purge | operator / policy_admin for gateway ops |
| **Profiles** | `GET /profiles`, `/profiles/{id}`, security-selfcheck; `POST` support-bundle | support-bundle: operator |
| **Policy** | `GET` effective + overlay; `POST` validate/apply | policy_admin |
| **Metrics** | `GET /metrics` | read |
| **Audit** | `GET /profiles/{id}/audit` | read |
| **Doctor** | `GET /profiles/{id}/doctor` | read (offline default) |
| **Cache** | `GET` cache; `POST` evict-plan / evict | plan: read; evict: operator |

Console RBAC: `viewer` / `operator` / `policy_admin` (never widens enterprise `force_read_only`).

---

## 3. Current MCP surface (agent tools)

**Default RO seed (Jenkins triage):** job/build/log/queue/node/view tools — **not** day-2 ops.

**Optional / flag-gated today:**

| Tool / area | Register path | Covers admin? |
|-------------|---------------|---------------|
| `jenkins_doctor` | RegisterOptions.Doctor | Partial doctor only |
| Log search / mirror | RegisterOptions | Not admin cache UI |
| Mutations (start/stop/…) | allow-mutations | Jenkins writes, not admin BFF |
| External logs / adapters | enable-adapter | Not admin SPA |

**Gap:** Almost the entire admin console (profiles list, effective policy show, policy apply, metrics snapshot, audit tail, cache status/evict, residual-status, vault inventory, consent purge, subject-invalidate, support-bundle) is **CLI and/or admin HTTP only** — agents cannot manage those via MCP tools today.

---

## 4. Parity matrix (target)

Proposed tool namespace: **`admin_*`** (or `mcp_admin_*`) — distinct from `jenkins_*` Jenkins data tools.  
Registration: **opt-in** `RegisterOptions.EnableAdminOps` / serve flag `--enable-admin-mcp` (default **off** for pure pilot RO triage; on for managed/agent-ops profiles).  
Authz: process **admin role** (same as console) or stricter serve-time gate; destructive tools require explicit **confirm** strings matching BFF.

| Admin capability | Target MCP tool(s) | Priority | Notes |
|------------------|-------------------|----------|--------|
| Health / version / me | `admin_health`, `admin_version`, `admin_me` | P0 | Secret-free; me never returns token |
| Residual status | `admin_gateway_residual_status` | P0 | Same map as residual-status CLI |
| Profiles list/show | `admin_list_profiles`, `admin_get_profile` | P0 | No credentials |
| Effective policy | `admin_policy_effective` | P0 | Mirror show-effective |
| Policy overlay get | `admin_policy_overlay_get` | P1 | |
| Policy validate/apply | `admin_policy_validate`, `admin_policy_apply` | P1 | policy_admin + confirm on apply |
| Metrics snapshot | `admin_metrics` | P0 | Counters/gauges only; residual note |
| Audit list | `admin_audit_list` | P0 | limit/before/type/external_subject caps |
| Doctor | `admin_doctor` (or extend `jenkins_doctor` with profile parity) | P0 | Prefer one doctor path + document alias residual |
| Security self-check | `admin_security_selfcheck` | P1 | Offline default |
| Cache status | `admin_cache_status` | P0 | |
| Cache evict-plan / evict | `admin_cache_evict_plan`, `admin_cache_evict` | P1 | confirm `EVICT` |
| Support bundle | `admin_support_bundle` | P1 | preview/create; secret-free |
| Vault inventory (Mode A) | `admin_gateway_vault_status` | P1 | No tokens; same as BFF vault GET |
| Subject invalidate | `admin_subject_invalidate` | P1 | gateway_ops + confirm |
| Consent purge | `admin_consent_purge` | P1 | CLEAR_ALL confirm parity |
| SPA static only | — | N/A | No MCP equivalent required |

**Coverage rule:** every new **BFF route** that is operator-actionable gets a row here and an MCP tool (or residual id) in the same change.

---

## 5. Task backlog (MCP-OPS / ADM-MCP)

| ID | Task | Size | Acceptance |
|----|------|------|------------|
| **MCP-OPS-001** | Design: `admin_*` tool schemas, RegisterOptions flag, role gate, deny interaction with force_read_only | M | ADR amend or this doc § accepted; no secrets in schemas |
| **MCP-OPS-002** | Implement read tools: health, version, me, residual-status, profiles list/show, policy effective, metrics, audit list, doctor, cache status | L | Unit + MCP smoke list tools; secret canaries |
| **MCP-OPS-003** | Implement write tools: policy validate/apply, cache plan/evict, support-bundle, subject-invalidate, consent-purge | L | Confirm tokens; RBAC fail-closed; AUD-001 emit on writes |
| **MCP-OPS-004** | Wire serve: `--enable-admin-mcp` / profile flag; default off; docs packaging | S | `make` help + user docs |
| **MCP-OPS-005** | Admin SPA residual note: “also available via MCP when admin-mcp enabled” | S | Overview or docs |
| **MCP-OPS-006** | Parity test: every BFF route in api-v1 has MCP tool name or residual marker in this matrix | M | CI test or generate table from registry |
| **MCP-OPS-007** | Agent usage guide: Cursor ops profile using admin_* tools | S | docs/agent-usage or user README |
| **MCP-OPS-008** | Audit: every admin_* write emits AUD-001 | S | Align AGENTS audit non-negotiable |

---

## 6. Agent non-negotiable (summary)

See root **AGENTS.md** → *Non-negotiable: admin MCP ops parity*.

When adding or changing **admin BFF/SPA** functionality:

1. Prefer implementing the capability in **shared library** code first.  
2. Expose via **admin HTTP** (existing).  
3. Expose via **`admin_*` MCP tool** in the same change (or **MCP-OPS-*** residual).  
4. Never teach agents to call loopback admin HTTP as the primary ops path.  
5. Secret-free + fail-closed + audit on writes.

---

## 7. Explicit non-goals

- Replacing the browser admin SPA with MCP-only UX.  
- Putting Jenkins API tokens in MCP tool results.  
- Auto-enabling admin MCP on default pilot RO stdio (opt-in).  
- Using Streamable admin HTTP as MCP transport without a new ADR.

---

## 8. Document history

| Date | Note |
|------|------|
| 2026-08-01 | Initial gap analysis + MCP-OPS backlog; agent parity rule |
