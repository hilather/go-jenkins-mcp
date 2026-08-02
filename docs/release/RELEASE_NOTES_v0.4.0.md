# Release notes — v0.4.0

**Date:** 2026-08-01  
**Tag:** `v0.4.0`  
**Baseline:** continues `v0.3.0` (mutations, gateway residual honesty, admin UI polish foundations)

## Highlights

### Admin MCP ops parity (MCP-OPS-001…008)

Agents can manage day-2 operator surfaces via opt-in **`admin_*` MCP tools** (shared libraries with the admin BFF — not HTTP proxy to `admin serve`).

| Enable | `jenkins-mcp serve --enable-admin-mcp --admin-role operator` (default **off**) |
|--------|--------------------------------------------------------------------------------|

**Reads (when enabled):** `admin_health`, `admin_version`, `admin_me`, `admin_gateway_residual_status`, `admin_list_profiles`, `admin_get_profile`, `admin_policy_effective`, `admin_policy_overlay_get`, `admin_metrics`, `admin_audit_list`, `admin_audit_settings_get`, `admin_doctor`, `admin_security_selfcheck`, `admin_cache_status`, `admin_gateway_vault_status`, `admin_cache_evict_plan`

**Writes (role + confirm):** `admin_audit_settings_put`, `admin_cache_evict` (`EVICT`), `admin_support_bundle`, `admin_subject_invalidate`, `admin_consent_purge` (`CLEAR_ALL`), `admin_policy_validate` / `admin_policy_apply` (`APPLY`)

Shared package: `internal/adminops`. Parity matrix: [`docs/admin/mcp-ops-parity.md`](../admin/mcp-ops-parity.md). Agent guide: [`docs/agent-usage.md`](../agent-usage.md) §12.

### Audit type catalog + operator enable/disable

- `audit.KnownEventTypes()` catalog SoT; File sink **ReloadingFilterSink** + `type_filter.json`
- Admin BFF `GET`/`PUT …/audit/settings` (`gateway_ops` on write); SPA **Event type settings** (enable all / disable all / save)
- New AUD-001 types for admin/MCP writes: `policy_validate`, `policy_apply`, `admin_cache_evict`, `admin_support_bundle`, `admin_subject_invalidate`, `admin_consent_purge` (plus existing `audit_settings`)
- Agent non-negotiable: security-relevant paths emit AUD-001; new types must join the catalog + defaults + SPA/docs (`AGENTS.md`)

### POL-006 — per-user and per-group MCP deny bindings

Enterprise overlay `subjects.users[]` / `subjects.groups[]` attach the same deny patterns and lower-only budgets as global fields.

- Effective access = force RO ∧ global denials ∧ matching user ∧ matching group bindings (most restrictive)
- List-row privacy uses subject-aware patterns; `max_result_bytes` applied per request at dispatch
- SoT: [`docs/policy-rbac.md`](../policy-rbac.md)

**Residual:** admin SPA Access CRUD (**UI-011**); SAML group source (**POL-007**); process-wide rate maps for per-subject `max_tools_*`.

### Gateway Mode B JWT vault CLI (HOST-010)

`jenkins-mcp gateway jwt-vault put|delete|list|status` — Jenkins-audience access tokens only; token from env (never argv/stdout). Production jwt-auth-filter pin remains residual.

### Admin console + agent policy

- **Admin users (v1 design):** shared secret + **one process-wide role** — no local admin user directory ([`docs/admin/README.md`](../admin/README.md))
- **SAML multi-fleet design:** SP settings, group→role maps, and POL-006 bindings managed via **versioned/signed configuration**, not a per-pod user DB (POL-007 backlog)
- Agent rules: audit emits, admin console currency, MCP-OPS parity, RBAC user+group targets, **release notes on every release**, Docker labs, ECharts-only metrics charts
- Admin UI polish (landed earlier on master): ECharts metrics + UI-POLISH-001…008

### Labs / residual honesty

- Mode A vault Obtain live lab against disposable Jenkins (`make live-jenkins-test`)
- OAuth mock labs Mode B/C (`make live-oauth-test`); production Entra / jwt-auth-filter still residual
- CI: gofmt fix for live sweep tests; race/SDK pin hardening on master

## Breaking / migration

| Change | Operator action |
|--------|-----------------|
| New audit types default **on** in `DefaultTypeFilter` | Operators may disable high-volume or noisy types via Audit settings / `type_filter.json` |
| Admin MCP tools default **off** | Enable explicitly with `--enable-admin-mcp` (and set `--admin-role`) when agents need day-2 ops |
| Overlay may include `subjects` (POL-006) | Optional; omit for unchanged global-only behavior. Invalid binding schema fails load closed |

No forced renames of existing tools or remove of CLI flags in this release.

## Security / residual honesty

| Residual | Status |
|----------|--------|
| Live Entra / production jwt-auth-filter / AgentCore Identity vault | **Not** production GO |
| Multi-pod HA / multi-replica admin (HOST-008) | **Cancelled / out of scope** — multi-fleet scale model |
| Admin multi-operator named accounts / SAML SSO | Residual (shared secret + process role today) |
| `admin_policy_apply` durable write under signed enterprise bundles | Partial residual (validate + role gate Done*) |
| `admin_rbac_*` / SAML SP management tools | Residual until UI-011 / POL-007 |
| SIEM/syslog ship of audit | AUD-T residual |
| MUT-ADMIN (config.xml, credentials, script console, …) | Still residual |

Pilot default remains **read-only** stdio + personal API token; admin MCP and mutations stay opt-in.

## Verify

```bash
export PATH="$HOME/.local/go/bin:$PATH"
make lint
go test -count=1 ./...
# optional race (longer):
# go test -count=1 -race ./...
make residual-smoke   # offline residual honesty; not live GO
./bin/jenkins-mcp -version
```

Package (Linux tarball / optional deb/rpm helpers):

```bash
make admin-ui   # optional; embeds SPA when dist exists
make package VERSION=v0.4.0
```

## Docs index (this release)

| Doc | Topic |
|-----|--------|
| [`docs/admin/mcp-ops-parity.md`](../admin/mcp-ops-parity.md) | `admin_*` tool matrix |
| [`docs/admin/api-v1.md`](../admin/api-v1.md) | BFF contract + audit settings |
| [`docs/admin/README.md`](../admin/README.md) | Operator enablement + admin-user design |
| [`docs/policy-rbac.md`](../policy-rbac.md) | POL-006 + SAML multi-fleet design |
| [`docs/observability.md`](../observability.md) | AUD-001 catalog + type filter |
| [`AGENTS.md`](../../AGENTS.md) | Agent non-negotiables (audit, admin, MCP-OPS, release notes) |
