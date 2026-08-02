# Agent instructions — go-jenkins-mcp

You are working in **go-jenkins-mcp**, an enterprise Jenkins MCP for Cursor
(local per-user stdio) with an optional managed-gateway path. The seed is
`simonfxr/go-jenkins-mcp`; treat it as a behavioral reference, not the long-term
architecture.

This file is **mandatory policy** for every coding agent session in this repo
(Grok, Claude, Codex, Cursor, and subagents). Global rules still apply; this
file is repo-specific and must not be ignored.

## Sources of truth

| Surface | Source |
|---------|--------|
| Architecture & decisions | `docs/jenkins-mcp-enterprise-architecture.md` |
| Architecture decision records | `docs/adr/README.md` (FND-006 / FND-008) |
| Implementation backlog (task SoT) | `docs/jenkins-mcp-enterprise-agent-todo.md` |
| Machine-readable task graph | `docs/jenkins-mcp-enterprise-task-index.json` |
| Planning pack overview | `docs/README-jenkins-mcp-enterprise-planning-pack.md` |
| Phase 0 progress | `docs/phase0-progress.md` |
| Operator admin console (BFF + SPA) | ADR 0014; `docs/admin/api-v1.md`; `internal/admin/`; `web/admin/` |
| Server/team-hosted roadmap | `docs/roadmap/server-team-hosted.md` |
| Release notes (per version) | `docs/release/RELEASE_NOTES_v*.md` · gates: `docs/release/gates.md` · REL-001/002 |
| Agent policy (this file) | `AGENTS.md` |
| Implemented code (when present) | `cmd/`, `internal/`, `pkg/` |

Do not invent decisions that contradict the architecture Key Decisions, the
platform matrix, or the backlog task contracts. Prefer **one task ID per PR**
unless a task explicitly permits pairing.

**Platform matrix (summary):** Tier 1 = Rocky Linux + Ubuntu; Tier 2 = macOS
nice-to-have; **Windows out of scope** (no native FUSE). See architecture §19.

---

## Non-negotiable: tests for every feature

**Every feature and behavior change must land with automated tests in the same
change** (same commit preferred; same PR required).

| Rule | Detail |
|------|--------|
| **New features** | Unit tests for pure logic **and**, when applicable, package/integration or MCP contract tests for the public path. |
| **Success + failure** | Cover success, failure, cancellation/context, and limit/budget paths. |
| **Security-sensitive paths** | Auth, policy/RBAC, redaction, URL/origin, storage ACL, secret handling — canary tests that secrets never appear in logs/errors/MCP output. |
| **Storage / formats** | Crash/recovery, corruption, compatibility, and bounded-read tests (see backlog DoD). |
| **No “manual only”** | Manual repro does not replace automated tests for shippable behavior. |
| **Skips** | Do not skip core-path tests without a documented environment gate (e.g. no FUSE, no keyring); skipped tests do not count as coverage unless gated and explained. |
| **Docs-only / comment-only** | New tests not required; still re-read for accuracy. |

When code exists, run the project test entrypoint (e.g. `make test` / `go test ./...`
with race where applicable) and keep it green before claiming done.

---

## Non-negotiable: Docker integration scaffolds where possible

**Prefer Docker Compose (or equivalent disposable containers) for integration
labs** whenever a feature talks to an external or multi-process system that can
be faked or pinned offline. Offline pure-Go unit tests remain the default
`make test` gate; containers are **opt-in** unless the task explicitly requires
them in CI.

| Expectation | Detail |
|-------------|--------|
| **When required** | Network clients, HTTP peers, IdP/JWT RS, Jenkins controller, gateway, DB-like peers, reverse proxies, multi-container deploys — add or extend a scaffold under `testdata/` or `deploy/` in the **same change** (or leave an explicit residual TODO). |
| **Existing pattern** | `testdata/jenkins-compose/` + `make live-jenkins-up/test/down` (TST-001); OAuth mock lab `testdata/oauth-lab/` + `make live-oauth-*` (HOST-012…015). Reuse/extend these rather than inventing one-off scripts. |
| **First-class local admin/support deploy** | **`deploy/local/`** + `make local-docker-up/down/doctor/smoke` is the **first-class local MCP admin/support Docker stack** (admin BFF/SPA on loopback, optional `http` / `with-jenkins` profiles via `LOCAL_COMPOSE_PROFILES=http,with-jenkins`). SoT: `deploy/local/README.md`. **Cursor MCP stdio remains host-native** (ADR 0002). For a **warm shared log/cache** between Cursor and Docker, document **Model 2 shared XDG** (`docker-compose.shared-xdg.example.yml` + host `XDG_*` in mcp.json) — do not assume default named volumes are visible to host stdio. Opt-in only; **not** in default `make test`. |
| **OAuth / JWT labs** | Plan and scaffold: mock OIDC IdP + Jenkins RS path for mode B; mock token/3LO endpoint for mode C — see **HOST-012…HOST-015** / `docs/roadmap/server-team-hosted.md`. Real Entra remains residual; mocks must still enforce audience/iss/exp fail-closed. |
| **Secrets** | Ephemeral only; never bake production tokens/passwords into images or compose files. Use generated disposable secrets written into the container volume at boot (same as API-token lab). `deploy/local/.env` is gitignored. |
| **Makefile** | Document `make …-up` / `…-test` / `…-down` (or equivalent); keep default `make test` / `make ci` offline. Local Docker group is listed under **Local Docker (support / admin UI)** in `make help`. |
| **Docs** | README next to the compose file: ports, env vars, tear-down, what is residual (e.g. “not production Entra”). For `deploy/local/`, keep operator quick start + troubleshooting current. |
| **Fail closed** | Lab profiles must not teach shared Jenkins SAs or Jenkins-as-AS. |
| **When Docker is wrong** | Pure algorithm/format/crypto unit tests; no need for a container. Say so briefly if a reviewer might expect one. |

**Do not** claim live OAuth/JWT/gateway integration is “done” without either a
Docker (or documented equivalent) lab path **or** an explicit residual naming
the missing harness.

---

## Non-negotiable: regression tests for every fix

**Every bug fix must include a regression test that fails before the fix and
passes after** (red–green), in the same change.

| Requirement | Detail |
|-------------|--------|
| **Reproduce the failure mode** | Assert the fixed behavior; name or comment with `Regression:` and a short symptom. |
| **Lowest useful layer** | Prefer unit tests; add integration/contract tests if the bug only appears there. |
| **Do not land** | Fix commits without new/updated tests unless the user **explicitly** waived tests for that change. |
| **Keep green** | After the fix, re-run the full relevant suite, not only the new test. |

Performance or network-sensitive fixes also attach before/after measurements
when the backlog or architecture requires them.

---

## Non-negotiable: code review every change set

**Do not treat implementation as done until the change set has been
code-reviewed.**

| Expectation | Detail |
|-------------|--------|
| **How** | Prefer the Grok **`/review`** skill (local mode for uncommitted work; branch/PR mode for shared work). Prefer a reviewer subagent; do not self-declare “looks fine” without a structured pass. |
| **When** | After tests and docs for the change are in place; **before commit/push** unless the user asked for draft-only or waived review. |
| **Scope** | Full change set: implementation + tests + docs + scripts/CI. Read surrounding code, not only the diff. |
| **Act on findings** | Fix **bug**-severity issues in the same effort. Address suggestions when cheap; note residual risk if deferred. Re-test after substantial fixes. |
| **Trivial exceptions** | Pure typos or one-line doc wording may use a careful self-re-read; still re-read the edit. |
| **User override** | “Skip review” / “draft only” applies to that turn only — not a permanent waiver. |

Do **not** commit or push large behavioral changes with open **bug**-severity
review findings unless the user explicitly accepts them.

### Minimum review checklist

- Correctness vs architecture decisions and the task’s acceptance criteria  
- Missing tests / missing docs / stale backlog status  
- Fail-closed auth, policy, budgets, and secret handling  
- Bounds: network, disk, memory, MCP response size, fan-out  
- No secrets in logs, errors, fixtures, CLI args, or MCP output  
- Package boundaries (Jenkins client must not import MCP; tools must not raw-HTTP)  
- Platform claims match the Tier-1 matrix (no accidental Windows support claims)  
- **Admin console parity:** operator-relevant changes update BFF/SPA/api-v1 (or document residual)  
- **Admin MCP ops parity:** same capabilities as `admin_*` MCP tools (or MCP-OPS residual) — agents manage via MCP  
- **Audit trail:** security-relevant actions emit AUD-001 events (or explicit residual) — see audit section below  
- **Docker lab residual:** integration-facing work has compose/Makefile/docs scaffold or an explicit residual  
- **Release notes (on release):** version `RELEASE_NOTES_v*.md` covers new features and high-level changes — see release notes section  

---

## Non-negotiable: documentation stays current

**Every change that affects behavior, surfaces, or operator/agent guidance must
update documentation in the same change** (same commit preferred; same PR
required before treating work done).

| Change type | Update these |
|-------------|--------------|
| Tool schemas, defaults, budgets, CLI flags/env | Architecture and/or tool-contract docs; user/admin guidance when present; backlog notes if contracts change |
| Auth, policy, platform matrix, packaging | `docs/jenkins-mcp-enterprise-architecture.md`, packaging notes, `AGENTS.md` if agent policy changes |
| Storage/format/index behavior | Architecture storage sections + task acceptance evidence notes |
| Operator-visible day-2 surfaces (policy, metrics, audit, doctor/cache, profiles, support-bundle, security self-check, budgets/caps) | **Admin console** — see next section (`internal/admin`, `web/admin`, `docs/admin/api-v1.md`) |
| Task completion / partial work | Backlog checkboxes and task status (see next section) |
| ADRs / irreversible choices | New or updated ADR per backlog FND-008 / task requirements |
| Docs-only polish | No extra churn; fix anything you know is wrong |

**Do not** claim a capability is done in docs or backlog without code and tests
that implement it. Do not ship behavior without updating the docs that are the
source of truth for that surface.

If documentation is intentionally deferred, say so in the session response and
leave an explicit TODO with an owner/next step — never imply docs are current
when they are not.

---

## Non-negotiable: keep the admin console current

The **operator admin console** (`jenkins-mcp admin serve` + SPA under `web/admin/`,
BFF in `internal/admin/`, contract in `docs/admin/api-v1.md`, ADR 0014) is a
**first-class surface**. It must not lag product behavior.

**When you implement or change any operator-relevant feature, update the admin
interface in the same change** (or leave an explicit residual TODO with task ID
if intentionally deferred — never silent drift).

**Also expose the same capability via MCP** for agent management (see *Admin MCP
ops parity* below) — browser BFF alone is not enough for first-class agent ops.

| Product change | Admin follow-through (as applicable) |
|----------------|--------------------------------------|
| New/changed **policy / RO / deny-lists / signed bundles** | Effective/overlay APIs; Policy page; validate/apply rules; docs; **`admin_*` MCP tools**; **user + group** binding targets when POL-006 lands (see RBAC section) |
| New/changed **SAML / IdP group / user RBAC management** | POL-006/007 model; UI-011 Access/user-group UI; BFF + **`admin_rbac_*` / policy binding MCP** (or residual) |
| New/changed **metrics / telemetry / budgets / caps** | `GET /admin/v1/metrics` (or residual note); Metrics page; **ECharts** visualization; **`admin_metrics` MCP** |
| New/changed **audit event types or fields** | **Emit sites** + **`KnownEventTypes` catalog** + type filter defaults + Audit list/filter **and Event type settings** toggles; SPA; canary tests; **`admin_audit_list` / `admin_audit_settings` MCP** (or residual) |
| New/changed **doctor / support-bundle / security self-check** | Doctor/ops endpoints; SPA; **`admin_doctor` / selfcheck / support-bundle MCP** |
| New/changed **cache / pin / quota / eviction** | Cache APIs; Cache page; **`admin_cache_*` MCP** |
| New/changed **profiles / config paths / packaging** | Profile list/show; **`admin_list_profiles` / get MCP** |
| New/changed **gateway residual / vault inventory / consent / subject-invalidate** | BFF routes + SPA; **`admin_gateway_*` / consent / invalidate MCP** |
| New **CLI day-2 commands** operators will use | BFF + **MCP** parity preferred; residual if deferred |
| Authn/z for **admin itself** (roles, tokens, CSP) | `rbac`, `/me`, middleware, SPA; MCP admin tools respect same role/confirm gates |

**Rules**

| Rule | Detail |
|------|--------|
| **Same change preferred** | BFF + SPA + `docs/admin/api-v1.md` (+ short admin README note) land with the feature when the console already exposes that domain. |
| **No second policy engine** | Admin BFF **wraps** existing libraries/CLI semantics; do not re-implement policy, budgets, or auth differently. |
| **Secret-free forever** | Never return tokens, keyring material, Authorization headers, raw logs, or job parameters in admin JSON/SPA. Canary tests when touching responses. |
| **Fail closed** | New write/destructive admin routes require console RBAC (`viewer` / `operator` / `policy_admin`); confirm tokens for destructive ops; cannot widen enterprise `force_read_only`. |
| **Tests** | Extend `internal/admin` tests (and SPA unit tests when UI changes). Prefer `TestUI009_*` patterns for authz/XSS canaries on new write surfaces. |
| **Honest residuals** | If SPA/BFF parity is deferred, say so on the page + API doc + session next steps — do not imply the console manages a feature that only exists on CLI. |
| **Not MCP** | Admin is operator-only and separate from Cursor tool discovery / stdio serve (ADR 0002 / 0014). |

**Quick map for agents**

| Path | Role |
|------|------|
| `internal/admin/` | Admin BFF handlers, RBAC, assets/CSP |
| `web/admin/src/` | React SPA pages and API client |
| `web/admin/src/components/charts/EChart.tsx` | **Only** chart host (Apache ECharts) |
| `web/admin/src/lib/metricCharts.ts` | ECharts option builders for metrics |
| `docs/admin/api-v1.md` | HTTP contract SoT |
| `docs/admin/README.md` | Operator enablement |
| `cmd/jenkins-mcp/admin_cmd.go` | `admin serve` CLI |
| `make admin-ui` / `make admin-e2e` | Build SPA; opt-in e2e smoke |

### Admin SPA charts and metrics visualization (non-negotiable)

| Rule | Detail |
|------|--------|
| **Charts = ECharts only** | All charts in `web/admin` **must** use **Apache ECharts** (`echarts` + `echarts-for-react` via `components/charts/EChart`). **Do not** add Recharts, Chart.js, Plotly, Visx, Nivo, Highcharts, or ad-hoc SVG/canvas chart shells for dashboards. Deprecated pure SVG helpers under `lib/sparkline.ts` are **not** for UI charts. |
| **Metrics always visualized** | Any operator-facing **metrics / counters / gauges / rates / budgets / quota totals** exposed on the Metrics page (or new metrics surfaces) must ship with **at least one basic ECharts visualization** (bar, line, or area) in addition to tables when tables exist. Empty snapshots still mount an ECharts empty-state shell — not table-only. |
| **New metric fields** | When BFF adds metric keys or maps, extend Metrics page charts (snapshot bar and/or history line) and option builders in `lib/metricCharts.ts` in the **same change**. |
| **Theme** | Prefer colors from `lib/metricCharts.ts` `chartTheme` aligned with `styles.css` tokens; keep dark/light readable. |
| **Secret-free** | Never chart or label raw subject keys, tokens, or secret-shaped strings. |
| **Tests** | Unit-test option builders (`metricCharts.test.ts`); run `npm test` / `make admin-ui` when touching SPA charts. |

**Admin UI polish backlog (UI-POLISH-001…008) — closed 2026-08-01:**

| ID | Status | Shipped |
|----|--------|---------|
| **UI-POLISH-001** | Done | Design tokens + density (`styles.css` space/elevation scale; `PageHeader`) |
| **UI-POLISH-002** | Done | Sticky topbar + sticky desktop sidebar; active nav border; mobile horizontal-nav residual note |
| **UI-POLISH-003** | Done | Overview status chips + ECharts live-pin residual bar (`overviewHealth.ts`) |
| **UI-POLISH-004** | Done | Sticky table headers (`.table-scroll`); Audit/Metrics empty states |
| **UI-POLISH-005** | Done | Doctor residual badge + check-pill hierarchy |
| **UI-POLISH-006** | Done | Focus rings; chart aria-labels; reduced-motion CSS + ECharts animation 0 |
| **UI-POLISH-007** | Done | Light theme CSS + `chartThemeLight` for ECharts options |
| **UI-POLISH-008** | Done\* residual | Tree-shaken ECharts; prod JS ~887 kB min / ~287 kB gzip — further code-split optional residual |

Before claiming a feature “done for operators,” ask: *Can an operator see or safely act on this from `admin serve` if we already have that surface — and if not, is the residual documented? If metrics/charts: is it ECharts with at least a basic viz? Can an **agent** do the same via MCP `admin_*` tools (or is MCP-OPS residual explicit)?*

---

## Non-negotiable: admin MCP ops parity (agent management)

The product MCP server must grow **first-class management tools** for day-2
operations that the admin console exposes. Agents must not rely on calling
loopback admin HTTP.

**SoT gap analysis + backlog:** [docs/admin/mcp-ops-parity.md](docs/admin/mcp-ops-parity.md)
(**MCP-OPS-001…008**). Tool namespace target: **`admin_*`** (distinct from
`jenkins_*` triage tools). Registration opt-in (`--enable-admin-mcp` /
RegisterOptions residual until implemented).

### When MCP tools are required (same change as admin BFF/SPA)

| Admin / ops change | MCP requirement |
|--------------------|-----------------|
| New **BFF route** under `/admin/v1` that is operator-actionable | Matching **`admin_*` tool** (or **MCP-OPS-*** residual id on api-v1 + mcp-ops-parity matrix) |
| New **SPA page/section** that invokes BFF | Same as BFF route — tools follow API, not only UI chrome |
| New **destructive** admin action | MCP tool with same **confirm** string + role gate; **AUD-001** emit |
| Read-only ops snapshot (health, metrics, audit, doctor, residual, profiles, policy effective, cache status) | Prefer **P0** tools first (MCP-OPS-002) |

### Rules

| Rule | Detail |
|------|--------|
| **Shared libraries, not HTTP proxy** | MCP tools call `internal/policy`, `diagnostics`, `audit`, `store`, `gateway`, etc. — same as BFF. Do **not** implement tools as “HTTP client to admin serve”. |
| **Secret-free** | Same scrubbing as admin JSON / support-bundle. Canary tests on new tools. |
| **Fail closed** | Respect enterprise `force_read_only` / deny lists; console role (or equivalent serve gate); destructive confirms (`EVICT`, `CLEAR_ALL`, …). |
| **Opt-in default** | Admin MCP tools default **off** for pure pilot RO triage until flag enabled — document residual. When building managed/agent-ops profiles, enable and test. |
| **Namespace** | `admin_*` for management; `jenkins_*` for Jenkins data plane. Do not overload job tools for policy/cache/audit. |
| **Docs matrix** | Update [mcp-ops-parity.md](docs/admin/mcp-ops-parity.md) parity table when adding routes/tools. |
| **Audit** | Admin MCP writes emit AUD-001 (see audit non-negotiable). |
| **Not replacing SPA** | Browser console remains for humans; MCP is for agents. Both must stay capable. |

### Pre-done checklist

1. New admin capability exists in **shared lib**?  
2. Exposed on **BFF + SPA** (or residual)?  
3. Exposed as **`admin_*` MCP tool** (or **MCP-OPS-*** residual)?  
4. Secret-free + confirm + role tests?  
5. Matrix row in mcp-ops-parity.md updated?

---

## Non-negotiable: RBAC controls definable per user and per group

**MCP and admin authorization must remain addressable at both individual-user
and group granularity.** Agents must not ship new deny-lists, resource patterns,
budgets, mutation gates, or admin permissions that can only be expressed as a
single global/profile blob with no path to **user** or **group** targets.

Backlog: **POL-006** (binding model), **POL-007** (SAML identity + groups),
**UI-011** (admin console management). Deny-only foundation: **POL-001…005**,
`docs/policy-rbac.md`. JWT group overage fail-closed: **OAUTH-006**.

### Rules (always)

| Rule | Detail |
|------|--------|
| **User and group targets** | When adding or extending an RBAC control, design (and prefer implement) bindings for **verified individual subjects** *and* **groups** (IdP/SAML/OIDC/Entra group claims or approved aliases). If group or user binding is deferred, leave an explicit **POL-006** residual — never silent “global only forever.” |
| **Deny-only / most restrictive** | MCP policy only **reduces** access. Multi-group membership → **most restrictive** effective set (adding a group deny never elevates). Never invent group membership (overage / missing claims fail closed). |
| **Trusted identity only** | Subject and groups come from verified authn (API-token principal, OIDC/JWT claims, SAML assertion map, gateway bind) — **never** tool arguments or free-form MCP params. |
| **SAML is SP + attribute map** | SAML work is **service provider** + attribute→subject/groups mapping for RBAC (POL-007). Stock Jenkins is **not** a SAML IdP/AS for MCP (ADR 0003). |
| **Admin + MCP parity** | Operator-facing user/group binding CRUD updates BFF/SPA (`UI-011`) and `admin_*` tools (or MCP-OPS residual) in the same change set as the policy model. |
| **Audit** | Binding create/update/delete and authz denials emit AUD-001 (secret-free; no assertion XML, tokens, or raw oversize NameIDs). |
| **Tests** | User-only deny, group-only deny, both, group membership change, unknown group fail closed; canaries that secrets never appear. |

### Pre-done checklist (agents)

When touching authorization / policy surfaces:

1. Can an operator attach this control to a **user** and to a **group** (or is POL-006 residual stated)?  
2. Does effective access remain **Jenkins ∧ RO ∧ MCP denials** with no elevation?  
3. Are subject/groups from **verified identity** only?  
4. Admin console / MCP management path updated or residualed?  
5. AUD-001 + secret-free canaries?

---

## Non-negotiable: audit trails when security-relevant (AUD-001)

Privacy-preserving **security audit** is a first-class product control (`internal/audit`,
[docs/observability.md](docs/observability.md), industry gaps/backlog in
[docs/security/audit-trail-review.md](docs/security/audit-trail-review.md)).
Agents **must** wire or extend audit when the change is security-relevant — not
as a follow-up “nice to have.”

### When an audit event is required (same change)

Emit (or extend) an `audit.Event` via `audit.Emit` / the package’s wired helpers
for **any new or changed path** that is security- or compliance-relevant, including:

| Category | Examples (non-exhaustive) |
|----------|---------------------------|
| **Authentication / identity** | Login success/fail; serve bind; mid-serve re-verify fail; gateway subject bind fail; token/session invalidation |
| **Authorization / policy** | Tool deny (RO, deny-lists, signed policy); admin RBAC deny; mutation preview/confirm/deny |
| **Handler / safety failures** | Tool errors that are security-relevant (budget, subject limiter, invalid identity) — use `tool_error` / stable `reasonCode`, not free text |
| **Mutations** | Start/stop/cancel and other write tools after policy allows — preview/confirm/deny already pattern |
| **Admin / operator writes** | Policy validate/apply; cache destructive evict; vault put/delete/revoke; consent purge/clear_all; subject-invalidate; destructive admin confirm tokens |
| **Serve lifecycle** | Serve start (and stop/shutdown if added) |

If emit is **intentionally deferred**, leave an explicit residual with task id
(**AUD-T-*** or AUD-001 coverage matrix) on the emit site comment + docs — **never
silent omission** of security-relevant actions.

### Rules (always)

| Rule | Detail |
|------|--------|
| **Use the audit package** | Prefer `audit.Emit(ctx, sink, Event{...})` or existing wrappers (`internal/tools/audit_emit.go`, mutation manager, `cmd/.../audit_wire.go`). Do not invent parallel “security log” formats. |
| **Stable types + reason codes** | Use `Type*` constants (`login_*`, `tool_deny`, `tool_error`, `auth_fail`, …) or add a new **low-cardinality** type in `event.go` + docs. `reasonCode` is machine-stable (policy reason, `apperr` code) — not user/error strings. |
| **Catalog + type filter (same change)** | Every new type string **must** be added to `audit.KnownEventTypes()` (`internal/audit/types_catalog.go`), appear in admin **Event type settings** via GET/PUT `…/audit/settings`, and have a sensible `DefaultTypeFilter` entry. SPA list filter options come from the catalog API (static `AUDIT_TYPE_OPTIONS` is offline fallback only — update both). High-volume types default **off** unless product decision says otherwise. |
| **Secret-free forever** | Never put tokens, passwords, Authorization headers, prompts, full job parameters, log excerpts, or vault material in any Event field. Use `principalId` / redacted `externalSubject` / `subjectKeyHash` (`audit.HashOpaque`) / `targetHash`. Run or extend **canary** tests when adding fields or emit sites. |
| **Best-effort emit** | Audit failures **must not** authorize work or fail-open security checks. Ignore or log emit errors without elevating privileges (existing pattern: `_ = audit.Emit(...)`). |
| **Identity attribution** | Prefer effective multi-user identity on the event (`profileId`, `principalId`, optional `externalSubject` + `subjectKeyHash`) when SubjectKey / Binding is available — same as tool_deny/mutation patterns. |
| **Sink wiring** | New long-lived processes (serve, admin serve, gateway) must have a sink when a profile data dir exists (`OpenProfileSink` wraps File with `ReloadingFilterSink`). Tests may use `Memory` / `Nop` (Memory does **not** apply type filter unless you wrap it). Do not claim SIEM/syslog/Splunk ship without implementing **AUD-T-010…012**. |
| **Schema / SPA / docs** | New event **types** or **fields** update: `event.go` constants, **`KnownEventTypes`**, [docs/observability.md](docs/observability.md), admin Audit page filters **and** settings toggles / hints, `docs/admin/api-v1.md`, canary/unit tests — **same change**. |
| **Not a substitute for ext-logs** | Querying external log backends (INT-003) is not AUD-001. Shipping audit to SIEM is residual — see audit-trail-review. |

### Adding a new audit event type (agent checklist)

When introducing a **new** `type` string (not only a new emit of an existing type):

1. Add `Type*` constant in `internal/audit/event.go` (if applicable) and append to **`KnownEventTypes()`**.
2. Emit from the security-relevant path (`audit.Emit` / wrappers) — secret-free fields only.
3. Set default enabled/disabled in **`DefaultTypeFilter()`** (high-volume → default off).
4. Admin SPA: type appears via settings API catalog (no hard-coded-only catalog); add `AUDIT_TYPE_HINTS` / static `AUDIT_TYPE_OPTIONS` fallback entry.
5. Document in [docs/observability.md](docs/observability.md) + [docs/admin/api-v1.md](docs/admin/api-v1.md); extend canary/unit tests.
6. MCP-OPS: row for `admin_audit_settings` if not present (or residual).

Skipping the catalog leaves the type **fail-closed** at the File filter (`AllowUnknown` false) and hidden from admin toggles — treat that as a **bug** in the change, not a residual, unless documented.

### Quick map for agents

| Path | Role |
|------|------|
| `internal/audit/` | Event schema, File/Memory/Multi sinks, **`KnownEventTypes` / TypeFilter / ReloadingFilterSink**, sanitize, HashOpaque |
| `internal/audit/types_catalog.go` | **Catalog SoT** for admin settings + filter defaults |
| `internal/admin/audit_settings.go` | GET/PUT `…/audit/settings` (gateway_ops on write) |
| `internal/tools/audit_emit.go` | Tool deny / error / success emit (success persistence via filter) |
| `internal/mutation/manager.go` | Mutation preview/confirm/deny audit |
| `cmd/jenkins-mcp/audit_wire.go` | Login / auth_fail wire helpers |
| `web/admin/src/pages/AuditPage.tsx` | Event list + **type enable/disable** panel |
| `docs/observability.md` | AUD-001 SoT for operators |
| `docs/security/audit-trail-review.md` | Standards mapping + **AUD-T-*** backlog (SIEM residual) |

### Pre-done checklist (agents)

Before marking security-relevant work complete, answer **yes** or document residual:

1. Does every **deny / fail-closed / destructive / auth** path emit an audit event (or residual id)?  
2. Are events **secret-free** (canary or review of fields)?  
3. Are **type** + **reasonCode** stable and documented?  
4. Is a **new type** registered in **`KnownEventTypes`** + admin settings catalog + DefaultTypeFilter?  
5. Can an operator **see** the event via admin audit list when the console covers that domain (or residual stated)?  
6. Can an operator **enable/disable** the type via Audit settings (or residual stated)?  
7. Did emit **failure** leave authorization fail-closed?

---

## Non-negotiable: release notes stay current on every release

**When performing a release** (version tag, release package, REL-002 evidence pack,
or publishing artifacts), agents **must** write or update **versioned release notes**
so operators and agents can see **what changed** at a high level — not only a
git tag and binary.

**SoT location:** `docs/release/RELEASE_NOTES_vX.Y.Z.md` (see existing
`RELEASE_NOTES_v0.1.0.md` / `RELEASE_NOTES_v0.3.0.md` for shape). Cross-link from
release evidence / gates when applicable ([docs/release/gates.md](docs/release/gates.md),
REL-001/002).

### When release notes are required

| Trigger | Expectation |
|---------|-------------|
| Cutting a **version tag** / release branch | New or updated `docs/release/RELEASE_NOTES_vX.Y.Z.md` in the **same** change set (or immediately before tag) |
| **REL-002** / `release-evidence` / pilot-evidence pack for a version | Release notes path recorded or linked; content matches shipped features |
| **Package** publish (tar/rpm/deb) for a version | Notes list user-visible / operator-visible changes for that version |
| Hotfix / patch release | Notes still required: security/fix highlights + residual honesty |

Day-to-day feature PRs **should** keep docs current (`AGENTS.md` documentation
rules) so release-note drafting is summarization, not archaeology. Still, **the
release step itself** must produce complete notes for the version.

### What the notes must contain (high level)

| Section | Include |
|---------|---------|
| **Identity** | Version, date, tag, baseline / previous version |
| **Highlights** | New features and major behavior changes in plain language (tools, admin, auth modes, MCP-OPS, audit, storage, mutations, gateway, …) |
| **Breaking / migration** | Schema, flag, env, policy, tool renames — anything operators must act on |
| **Security / residual honesty** | Fail-closed defaults; what is **not** production GO (live Entra, multi-pod, etc.) |
| **Verify** | Commands operators/agents can run (`make lint`, tests, residual-smoke, …) |

### Rules (always)

| Rule | Detail |
|------|--------|
| **Up to date with the release** | Notes cover **all** material features/high-level changes **in that version**, not only the last PR. Diff against previous tag / prior RELEASE_NOTES when drafting. |
| **Operator-readable** | Prefer highlights and tables over dump of every commit subject. Link deeper docs (`api-v1`, observability, mcp-ops-parity, live-pin-blockers) instead of pasting secrets or full logs. |
| **No silent capability claims** | Do not mark live GO / Entra pin / multi-pod Done unless evidence exists. Residual stays residual. |
| **Secret-free forever** | Never put tokens, vault material, private URLs with credentials, or raw subject keys in release notes. |
| **Same change as tag/package when practical** | Prefer notes + version bump + evidence in one PR; never ship a public tag with empty or stale notes. |
| **Match reality** | If a feature is residual or flag-gated, say so (e.g. `--enable-admin-mcp`, `--allow-mutations`). |

### Pre-release checklist (agents)

Before treating a **release** as done:

1. Is there a `docs/release/RELEASE_NOTES_vX.Y.Z.md` for this version?  
2. Do **highlights** cover new tools, admin/MCP ops, auth/gateway, audit, policy, storage, and packaging changes since the previous release?  
3. Are **breaking** changes and operator actions called out?  
4. Are **residuals** honest (live pins, multi-pod, deferred MCP rows)?  
5. Is content **secret-free** and consistent with code/docs (no invented Done claims)?  
6. Are **verify** commands present and known-good for this tree?

### Quick map

| Path | Role |
|------|------|
| `docs/release/RELEASE_NOTES_v*.md` | Per-version release notes SoT |
| `docs/release/gates.md` | REL-002 gate checklist |
| `docs/release/evidence-template.md` | Evidence pack form |
| `jenkins-mcp release-evidence --offline` | Offline evidence JSON (does not replace notes) |

---

## Non-negotiable: todo / backlog tracking and next steps

**Work is tracked against the backlog.** Incomplete work must never be left
ambiguous.

| Rule | Detail |
|------|--------|
| **Pick a task** | Prefer a single task ID from `docs/jenkins-mcp-enterprise-agent-todo.md` (and the JSON index for dependencies). |
| **In-session todos** | Maintain a live todo list for multi-step work; mark items `in_progress` / `completed` as you go. |
| **Partial completion** | If a task, PR, or session ends incomplete: leave clear **next steps** (what remains, blockers, suggested follow-up task IDs, and how to verify). |
| **Do not false-complete** | Do not check backlog acceptance criteria or DoD boxes unless they were demonstrated (tests run, evidence attached). |
| **Carry forward** | When resuming, read existing next-step notes before inventing a new plan. |
| **Session summary** | End incomplete work with: done / not done / next steps / residual risk. |

Suggested next-step note shape (in PR description, session reply, or backlog
comment):

```text
## Next steps
- [ ] <concrete action> (task ID if known)
- [ ] <test or verification command>
- Blockers: <none | description>
```

---

## Before-done / before-commit procedure

```text
1. Identify task ID(s) and re-read architecture + dependency tasks
2. Implement within task scope
3. Add/update tests (features + regression tests for fixes)
4. If security-relevant: wire **audit emit** (AUD-001) or explicit AUD-T residual — see audit section
5. If operator-relevant: update admin BFF/SPA/api-v1 **and** `admin_*` MCP tools (or MCP-OPS residual) — see admin MCP parity
6. If external-system/integration: add or extend Docker compose lab (opt-in Makefile) or residual TODO
7. Update documentation and backlog/todo status
8. Run lint/tests/race as applicable; attach perf evidence if required
9. Structured code review (/review); fix bug findings; re-test
10. If **releasing** a version: write/update docs/release/RELEASE_NOTES_vX.Y.Z.md (features + high-level deltas + residuals) — see release notes section
11. If incomplete: write next steps; do not mark DoD complete
12. Commit code + tests + docs (+ admin + lab scaffolds + release notes when releasing) together when practical
```

---

## Security and product constraints (always on)

- Fail closed: effective access is Jenkins allow **AND** global read-only **AND**
  MCP policy **AND** operation budgets. MCP policy never elevates.
- No secrets in CLI args, config committed to git, logs, MCP results, or support
  bundles. Credentials live in OS secret stores on Tier-1 Linux (Secret Service).
- Jenkins is not a native 3LO authorization server; do not document or code it
  as one.
- Progressive logs: no unbounded `ReadAll`; stream into bounded independent
  Zstandard frames. L2 seekable multi-frame `.tar.zst` only — never call a
  single-frame `.tar.zst` “random access.”
- Mutations only after policy, audit, preview/confirmation epics allow them.
- Treat Jenkins data, logs, artifacts, and model-facing text as untrusted.

See also the full agent rules in
`docs/jenkins-mcp-enterprise-agent-todo.md` (“How an implementation agent must
use this backlog”).
