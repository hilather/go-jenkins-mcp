# Admin console ↔ MCP ops parity (management tools)

**Audience:** implementers, agents, security  
**Related:** [api-v1.md](api-v1.md), [ADR 0014](../adr/0014-admin-console-reactive-spa.md), [AGENTS.md](../../AGENTS.md)  
**Status:** **Done\* foundation (MCP-OPS-001…008)** — `admin_*` tools via
`--enable-admin-mcp` (default **off**); shared library `internal/adminops`;
process role `viewer|operator|policy_admin`. Local admin BFF/SPA remains
first-class for browser operators. POL-006/007 RBAC user/group + SAML tools
remain residual.

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

**Done\* lite:** With `--enable-admin-mcp`, agents get `admin_*` tools covering
health/version/me, residual-status, profiles, policy effective/overlay/validate/apply
(apply durable residual when signed bundles), metrics, audit list/settings, doctor,
security self-check, cache status/plan/evict, support-bundle, vault status,
subject-invalidate, consent-purge. Default pilot RO stdio keeps admin tools **off**.

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
| User/group RBAC bindings (POL-006) | `admin_rbac_list_bindings`, `admin_rbac_put_binding`, `admin_rbac_delete_binding` | P1 | Policy language **Done\*** (`subjects.users`/`subjects.groups`); **admin_* CRUD residual** until UI-011 |
| SAML SP / attribute map (POL-007) | `admin_saml_status`, `admin_saml_config_get` (write residual) | P2 | Secret-free metadata only; residual until POL-007 |
| Metrics snapshot | `admin_metrics` | P0 | Counters/gauges only; residual note |
| Audit list | `admin_audit_list` | P0 | limit/before/type/external_subject caps |
| Audit type settings | `admin_audit_settings_get`, `admin_audit_settings_put` | P1 | Mirror GET/PUT `…/audit/settings`; gateway_ops on put; catalog from KnownEventTypes |
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

| ID | Task | Size | Acceptance | Status |
|----|------|------|------------|--------|
| **MCP-OPS-001** | Design: `admin_*` tool schemas, RegisterOptions flag, role gate | M | This doc + `internal/adminops` | **Done\*** |
| **MCP-OPS-002** | Read tools: health, version, me, residual-status, profiles, policy effective, metrics, audit list, doctor, cache status | L | Unit + MCP list/call; secret canaries | **Done\*** |
| **MCP-OPS-003** | Write tools: policy validate/apply, cache plan/evict, support-bundle, subject-invalidate, consent-purge, audit settings | L | Confirm tokens; RBAC fail-closed; AUD-001 | **Done\*** (policy apply durable residual) |
| **MCP-OPS-004** | Wire serve: `--enable-admin-mcp` / `--admin-role`; default off | S | usage + log line | **Done\*** |
| **MCP-OPS-005** | Admin SPA residual note | S | docs + Overview residual | **Done\*** docs |
| **MCP-OPS-006** | Parity catalog + residual map | M | `adminops.ToolCatalog` + tests | **Done\*** |
| **MCP-OPS-007** | Agent usage guide | S | docs/agent-usage | **Done\*** (this section + agent-usage note) |
| **MCP-OPS-008** | Audit on admin_* writes | S | emitWriteAudit | **Done\*** |

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
