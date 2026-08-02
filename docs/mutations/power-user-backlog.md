# Mutations & power-user backlog (opt-in)

**Status:** Planning SoT for remaining Jenkins **write / power-user** MCP surface  
**Audience:** implementers, security, product  
**Related:** architecture §11.12 · [agent-usage § Mutations](../agent-usage.md#5-mutations-and-confirmation) · [user guide § Mutations](../user/README.md#7-mutations-usually-disabled) · MUT-001…003 in [agent todo](../jenkins-mcp-enterprise-agent-todo.md) · [tool-contracts](../tool-contracts.md)

---

## 0. Non-negotiables (every epic)

| Rule | Detail |
|------|--------|
| **Off by default** | Mutation tools are **not** registered under pilot RO / without explicit host enablement |
| **Enablement** | `--allow-mutations` (or future profile/policy capability) **and** no stronger RO (`--read-only`, `JENKINS_MCP_READ_ONLY`, enterprise `force_read_only`, profile RO) |
| **MUT-001 gate** | Every new mutate tool: dry-run **preview** → short-lived bound token → single-use **confirm**; cooldown + preview rate; audit; no auto-retry POST |
| **Classifier** | New Jenkins write paths added to request classifier allowlist; **unclassified POST fails closed** |
| **Secret-free** | No secrets in previews, audit, logs, support bundles, admin JSON |
| **Jenkins remains authoritative** | MCP deny-only + RO; Job/Build permissions still enforced by controller |
| **Subject bind** | Confirm tokens bound to principal / ExternalSubject (multi-user gateway residual already partially done) |
| **Docs in same change** | `tool-contracts.md`, `agent-usage.md`, user guide, route matrix cell, agent-todo checkbox |

Architecture §11.12 allows: trigger, cancel queue, stop, **replay/rebuild where safe**.  
**Administrative** surfaces (config.xml, credentials, nodes, plugins, script console, global settings) stay **out of scope** unless a future security **go** decision (same bar as OAUTH-011).

---

## 1. Already shipped (baseline — do not re-implement)

| Tool | Epic | Notes |
|------|------|-------|
| `jenkins_start_job` | MUT-002 Done\* | Preview/confirm; param defs; secret types blocked; no POST auto-retry |
| `jenkins_stop_build` | MUT-003 Done\* | `/stop`; wrong-state fail-closed |
| `jenkins_cancel_queue_item` | MUT-003 Done\* | Queue only; assigned → use stop |

Framework: `internal/mutation` Manager, RO registration, doctor `mutations` check, audit `mutation_*`.

---

## 2. Epic map (implementation order)

```text
MUT-0xx  Foundation closure (formal MUT-001 ACs + classifier hygiene)
   │
   ├─ MUT-010  Interrupt escalation (term / kill)
   ├─ MUT-011  Rebuild last parameters
   ├─ MUT-012  Pipeline replay (safe subset)
   ├─ MUT-013  Job buildable toggle (enable / disable)
   ├─ MUT-014  Build keep-forever + description
   ├─ MUT-015  start_job residual hardening
   ├─ MUT-016  Queue power-user (cancel-by-job, optional stuck-only)
   └─ MUT-017  Policy allowlists (per-job / per-action) for mutations

Parallel (docs/tests only): MUT-DOC, MUT-TST (live smoke matrix cells)
Explicitly deferred: MUT-ADMIN (see §8)
```

Priority legend: **P0** = safety/foundation before expanding surface · **P1** = architecture-named power-user · **P2** = common ops · **P3** = nice-to-have / high blast radius.

---

## 3. Foundation — close the gate before growing the set

### MUT-001F — Formalize MUT-001 acceptance (P0)

**Goal:** Treat MUT-001 as Done\* with checkboxes that match code + residual honesty.

| # | Task | Acceptance |
|---|------|------------|
| F1 | Default RO registers **no** mutation tools; classifier blocks mutation POSTs without opt-in | Conformance + RO tests green; doctor `mutations` skip when RO |
| F2 | Confirm token binds exact action + normalized target + params; cannot authorize another job/build | Cross-target / cross-param replay tests |
| F3 | Secret parameters blocked (types + name heuristics); never in preview text | Canary tests |
| F4 | Denial, expiry, replay, race, cooldown, preview-rate tests | Existing suite expanded if gaps |
| F5 | Enterprise `force_read_only` cannot be weakened by user `--allow-mutations` alone | Existing force tests; doc pointer |
| F6 | Agent-todo MUT-001 ACs checked only with evidence | Update `jenkins-mcp-enterprise-agent-todo.md` |

**Depends on:** none (code mostly present).  
**Deliverable:** closed MUT-001 boxes + any missing tests.

### MUT-001C — Classifier & crumb matrix expansion (P0)

| # | Task | Acceptance |
|---|------|------------|
| C1 | Route matrix documents every planned write path (term/kill/rebuild/replay/toggle/keep/description) as **auth/mutate** | `docs/tst/route-matrix.json` cells |
| C2 | Request classifier allowlists only MUT-gated tools; `/scriptText`, `config.xml` POST, pluginManager write remain **denied** | Negative tests (already partial for scriptText) |
| C3 | Crumb attached on all new write POSTs; crumb-disabled controllers still work | Client tests |

---

## 4. Interrupt & rebuild family (architecture §11.12)

### MUT-010 — Build interrupt escalation: term / kill (P1)

Jenkins often exposes progressive interrupt: **stop → term → kill**.

| Item | Spec |
|------|------|
| Tools | `jenkins_term_build`, `jenkins_kill_build` **or** single `jenkins_interrupt_build` with `mode=stop\|term\|kill` (prefer **one tool + mode** to keep catalog small) |
| Client | POST `…/job/…/<n>/term`, `…/kill` (and keep existing `/stop`) |
| Preview | Job full name, build #, building state, chosen mode, controller identity |
| Wrong state | Finished / not building → clear non-success (parity with stop) |
| Policy | EffectMutate; optional deny more dangerous modes via overlay |
| Tests | RO omit; force RO deny; wrong-state; no POST retry; audit secret-free |
| Docs | agent-usage escalation order: cancel queue → stop → term → kill |

**Residual honesty:** not all executors honor term/kill the same way; report Jenkins HTTP outcome, not “agent is dead.”

### MUT-011 — Rebuild with last parameters (P1)

| Item | Spec |
|------|------|
| Tool | `jenkins_rebuild_build` |
| Semantics | Rebuild a **completed** (or policy-allowed) build using parameters **from that build**, not free-form model invention |
| Client | Prefer Jenkins rebuild plugin endpoint **if** capability detected; else re-fetch params from build + `buildWithParameters` (document which path) |
| Preview | Source build #, job, redacted params that will run, “same as build N” claim |
| Guards | Secret params still blocked; unknown rebuild plugin → capability error; no silent fallthrough to wrong job |
| Tests | Param snapshot matches execute; secret scrub; RO; no auto-retry |

**Residual:** rebuild plugin absent; multibranch edge cases; “rebuild failed build only” policy residual.

### MUT-012 — Pipeline replay (P1, careful)

| Item | Spec |
|------|------|
| Tool | `jenkins_replay_pipeline` (Pipeline jobs only) |
| Semantics | Replay run with **same** or **explicitly reviewed** Jenkinsfile text only if API supports safe replay; **reject** arbitrary model-authored Jenkinsfile by default |
| Default | Replay **without** script edit (re-run same definition) if API allows; script-edit mode **off** unless `allow_replay_script_edit` policy residual |
| Preview | Job, build #, pipeline type, script-edit=false |
| Out | Freestyle/matrix without Pipeline REST |
| Tests | Non-pipeline → clear error; RO; no secret in script body audit |

**Security bar:** edited Jenkinsfile is near-admin power — keep behind extra policy flag, not default `--allow-mutations` alone if feasible.

---

## 5. Job & build power-user (non-admin)

### MUT-013 — Enable / disable job (buildable) (P2)

| Item | Spec |
|------|------|
| Tools | `jenkins_enable_job`, `jenkins_disable_job` **or** `jenkins_set_job_buildable` with `buildable=bool` |
| Client | POST `…/enable`, `…/disable` (standard Jenkins) |
| Preview | Job full name, current buildable state, new state |
| Guards | Folder-only paths rejected; cannot enable if policy `deny_job_prefixes`; never recursive mass-enable |
| Tests | State flip offline fixture; RO; audit |

**Not in scope:** delete job, create job, move/rename, config.xml replace.

### MUT-014 — Build keep-forever & description (P2)

| Item | Spec |
|------|------|
| Tools | `jenkins_set_build_keep_forever` (`keep: bool`), `jenkins_set_build_description` (`description: string`, length-capped) |
| Client | `…/<n>/toggleLogKeepForever` (or keepLog API), `…/<n>/submitDescription` |
| Preview | Job, build #, current keep flag / description hash or truncated text |
| Guards | Description max length (e.g. 4 KiB); strip control chars; no HTML exec claims |
| Tests | Cap enforced; secret-like description canary scrubbed in audit |

### MUT-015 — `jenkins_start_job` residual hardening (P1)

Close MUT-002 residuals without new tools:

| # | Task | Acceptance |
|---|------|------------|
| S1 | Document / improve “required without default” best-effort (when Jenkins exposes it) | Fail closed when known required missing; honest residual when unknown |
| S2 | Active Choices / dynamic params: reject unsupported with stable reason; no half-execute | Tests + tool-contracts residual note |
| S3 | Optional client correlation param **only** when job policy / explicit allowlist says so | Off by default |
| S4 | Capability probe: job not buildable → clear error before preview token mint | |

### MUT-016 — Queue power-user (P2)

| Item | Spec |
|------|------|
| Tool A | `jenkins_cancel_queue_items_for_job` — cancel **waiting** items for one full job name (bounded: max N items per confirm, e.g. 20) |
| Tool B (optional) | `jenkins_cancel_stuck_queue_items` — only items with `stuck=true`, same cap |
| Preview | List of queue ids + why snippets (redacted), count, cap |
| Guards | Never cancel “all queue on controller”; require job name or stuck filter; confirm lists exact ids |
| Tests | Cap; partial failure reporting; RO |

### MUT-017 — Mutation policy allowlists (P1)

Today: RO + deny_tools. Power-user needs finer control:

| # | Task | Acceptance |
|---|------|------------|
| P1 | Overlay / enterprise fields: `allow_mutation_tools: []` (when allow-mutations on, only these register) | Default empty = all classified mutations when opt-in **or** default = seed three only until allowlist set (pick one; document) |
| P2 | Optional `allow_mutation_job_prefixes` / reuse deny prefixes for mutate class | Evaluate on preview **and** confirm |
| P3 | Optional per-action severity: `allow_interrupt_modes: [stop]` excludes term/kill | |
| P4 | Admin SPA residual: show mutation posture (registered vs executable) — doctor already has check | |

**Recommendation:** default opt-in still registers **only seed + newly enabled families** via explicit flags later if catalog grows large (`--mutation-family=interrupt,rebuild`).

---

## 6. Enablement model (product)

| Mode | Behavior |
|------|----------|
| **Pilot default** | RO; zero mutation tools |
| **`--allow-mutations`** | Register classified mutation set subject to force RO / deny_tools / future allowlists |
| **Future (optional)** | `--mutation-families=core,interrupt,rebuild,job-toggle,build-meta,queue-bulk` so sites can enable subsets without full surface |
| **Enterprise** | Signed policy may force RO forever; may allowlist tools/jobs; cannot be weakened by CLI alone |

All new tools: add to `policy.MutationToolNames` / `IsMutationTool` / seed classification **before** registration.

---

## 7. Cross-cutting DoD (every tool epic)

Standing gates for **new** mutation tools (not a session todo queue — all of these must remain true):

- Client method in `internal/jenkins` (crumb, no POST auto-retry, secret-free errors)
- Tool handler via MUT-001 Manager (preview/confirm)
- `policy` classification + RO registration
- Unit + RO/force + wrong-state + replay + audit canary tests
- Route-matrix / classifier entry
- `tool-contracts.md` + `agent-usage.md` + user mutations section
- Doctor still honest (mutations register vs executable)
- No admin SPA requirement for v1 (CLI/MCP only)

---

## 8. Explicitly out of scope (MUT-ADMIN — not scheduled)

Do **not** implement under this backlog without a separate security **go**:

| Surface | Why |
|---------|-----|
| Job create / delete / copy / rename / move | Admin blast radius; config injection |
| `config.xml` GET/POST as write tool | Full job takeover |
| Credentials store, secrets, certificates | Secret exfil / inject |
| Nodes / agents offline-online, launch | Infra control |
| Plugin install/update/disable | Supply chain |
| Script console / `scriptText` / Groovy | Arbitrary code on controller |
| Quiet-down / cancel quiet-down / safe-restart | Controller-wide availability |
| User/security realm changes | IdP/admin |
| Arbitrary generic `jenkins_http_post` | Classifier bypass |

These remain **classifier-denied** and undocumented as agent tools.

---

## 9. Suggested implementation waves

| Wave | Epics | Outcome |
|------|-------|---------|
| **M0** | MUT-001F, MUT-001C | Gate closed; checklist honest |
| **M1** | MUT-010, MUT-015 | Safer interrupt + start_job residual |
| **M2** | MUT-011, MUT-012 (replay no script-edit) | Rebuild/replay power-user |
| **M3** | MUT-013, MUT-014 | Job toggle + build meta |
| **M4** | MUT-016, MUT-017 | Bulk queue + allowlists / families |
| **M5** | Live smoke cells (opt-in `make live-jenkins-*`) | Evidence pack residual |

Estimate: M0 small; M1–M2 medium; M3–M4 medium; each tool ~1–3 days with tests/docs if MUT-001 is solid.

---

## 10. Open checklist (copyable)

Shipped MUT-001F/C and MUT-010…017 — **removed from this working list** (see §1 / status boards). Open residual only:

### Always / residual
- [ ] Standing gates remain true on every new mutation tool (off by default; force RO wins; preview/confirm/cooldown/rate/audit/no-retry; docs + contracts + agent-usage)
- [ ] **No** MUT-ADMIN surfaces without security go

---

## 11. First sprint recommendation

Foundation + MUT-010…017 are **Done\***. Next product residual:

1. **MUT-ADMIN** — only if security explicitly goes (out of scope by default).  
2. Live smoke cells for mutations (opt-in `make live-jenkins-*`) when site evidence is required.
