# Server Tier A critical path — JWT / OAuth (all modes)

**Status:** Offline + **free-lab** Tier A **Done\*** (product bar — see [free-lab-qualification.md](../gateway/free-lab-qualification.md)). Mode A disposable Jenkins vault Obtain **Done\***; Mode B mock RS + Mode C mock-token **Done\*** (`make live-oauth-test`). **Site production** Entra / jwt-auth-filter pins remain **operator-owned residual** (`mode_*_live_*_qualified=false` until **that site** attaches evidence). Free labs do **not** flip production-qualified flags.  
**Audience:** implementers, security, platform  
**Defer:** multi-node / multi-pod HA (**HOST-008** Tier B) — same-host flock lite already Done\*  
**Related:** [server-team-hosted.md](server-team-hosted.md) · [live-pin-blockers.md](../gateway/live-pin-blockers.md) · [oauth-capability-matrix.md](../auth/oauth-capability-matrix.md) · [auth-architecture.md](../auth-architecture.md) · [jwt-auth-filter-qualification.md](../auth/jwt-auth-filter-qualification.md) · code `internal/gateway/critical_path_tier_a_test.go`

---

## 0. Goal and honesty

**Goal:** Ship a **Tier A (replicas: 1)** managed gateway that can enable **any or all** of the three designed credential modes without silent fallthrough, with **live lab evidence** for each mode the site turns on.

| Mode | ID | Jenkins wire | Identity / obtain |
|------|-----|--------------|-------------------|
| **A** | `api_token_vault` | Basic `user:api_token` | Per-user vault on gateway (never shared SA) |
| **B** | `jwt_rs_bearer` | `Authorization: Bearer` Jenkins-audience JWT | External IdP issues token; Jenkins is **RS only** (`jwt-auth-filter` or approved proxy) |
| **C** | `agentcore_3lo_obo` | Bearer (typical) | AgentCore **3LO and/or OBO** against **Entra AS** → Jenkins-audience token |

**Non-negotiables**

- Stock Jenkins is **not** an OAuth authorization server (ADR 0003 / OAUTH-011 default no-go).
- AgentCore discovery/authorize/token → **Entra** (or approved AS), never stock Jenkins.
- Invalid Bearer never falls through to Basic/session/anonymous on OAuth-required routes.
- No shared service account for interactive users.
- Offline qualify / residual-smoke green ≠ production GO.
- Local Cursor **stdio + personal API token** remains default pilot (ADR 0002).

**Out of this list:** multi-pod vault HA, multi-replica session store, fleet admin multi-operator OIDC, MUT-ADMIN.

---

## 1. Workstreams (do all three mode tracks in parallel after shared foundation)

```text
  ┌─────────────────────────────────────────────────────────┐
  │  S0 Shared foundation (HTTP subject + bind + edge)     │
  └───────────────────────────┬─────────────────────────────┘
           ┌──────────────────┼──────────────────┐
           ▼                  ▼                  ▼
      S1 Mode A            S2 Mode B          S3 Mode C
   API token vault      JWT RS bearer      AgentCore 3LO/OBO
           └──────────────────┼──────────────────┘
                              ▼
                 S4 Mode matrix + live qualify
                              ▼
                 S5 Single-replica deploy + REL evidence
```

Estimated size: **S** days · **M** 1–2 weeks · **L** multi-week.

---

## 2. Task checklist

### S0 — Shared foundation (all modes) · P0

| ID | Task | Size | Status offline | Live still needed |
|----|------|------|----------------|-------------------|
| **S0.1** | **HOST-001** Streamable HTTP multi-user: RequireSubject, session fingerprint, mid-session rebind fail-closed | M | Done\* offline + lab JWT Alice/Bob | Live Entra JWKS under load; path-prefix pin with real edge |
| **S0.2** | **HOST-002** Reverse-proxy Host/Origin matrix; TrustedProxy honesty; dual health/ready | S–M | Offline fixtures Done\* | Live edge container matrix (X-Forwarded ignore) |
| **S0.3** | **GWY-002** HTTP/gateway identity → `policy.Subject` (claims/principal); no tool-arg identity | M | Bind helpers + offline | Live claim → subject end-to-end |
| **S0.4** | **HOST-003** Serve Obtain wire: credential mode → Jenkins client; Ready fail-closed; Live only when explicit | M | Done\* offline modes | Live Obtain for each enabled mode |
| **S0.5** | **HOST-004** Cache/archive partition by tenant/profile/subject on multi-user host | M | Done\* offline (SubjectKey + token/principal/vault partition; `TestCriticalPath_HOST004_*`) | Live concurrent two-user load under real edge |
| **S0.6** | **HOST-006** Per-subject rate + concurrency (process-local + same-host file lite OK) | S | Done\* process/file lite | Measure under live multi-user load |
| **S0.7** | Doctor / residual-status / residual-smoke honesty: `mode_*_live_*_qualified=false` until pins | S | Done\* | Never flip live flags without evidence |

**Exit S0:** Non-loopback (or reverse-proxied) HTTP can authenticate **individual** subjects offline+lab; tool args cannot spoof identity; Ready never claims live GO falsely.

---

### S1 — Mode A: API token vault · P0 (fastest team path)

| ID | Task | Size | Notes |
|----|------|------|-------|
| **S1.1** | **HOST-009** Vault lifecycle: put/list/status/delete/revoke CLI; Obtain returns **only** bound subject token | M | Offline Done\*; admin vault **write** residual |
| **S1.2** | Obtain isolation canaries: cross-subject read fail closed; no process-wide default token | S | Done\* file vault + multi-user HTTP tools/call Alice/Bob |
| **S1.3** | Secret-free: no token in logs, admin JSON, MCP, support bundle | S | Done\* canaries; keep green |
| **S1.4** | Live lab: multi-user HTTP + vault subjects against real Jenkins Basic ACL | M | Done\* lab: offline multi-user HTTP+vault + `TestLive_ModeAVaultObtain_WhoAmI` (`make live-jenkins-test`, `-tags=live_jenkins`). Production multi-user load residual |
| **S1.5** | RO pilot + optional mutations still fail closed per subject | S | MUT already subject-bound offline Done\* |

**Exit S1:** Offline Mode A complete. **Disposable Jenkins vault Obtain lab Done\*** (`make live-jenkins-test`). Production multi-user load + pin flag flip still residual.

---

### S2 — Mode B: JWT resource-server bearer (all RS implementations)

Design allows **either** plugin or edge RS — implement qualification for **both** paths until site picks one.

| ID | Task | Size | Notes |
|----|------|------|-------|
| **S2.1** | **OAUTH-009** product free-lab + offline RS contracts; checklist for **site** pin (live-pin-blockers §2) | L | Product Done\*; site LTS/plugin/JCasC fill-in = operator residual |
| **S2.2** | Required MCP route inventory offline + free mock re-prove | M | `auth.RequiredMCPRoutes`; site controller re-prove = operator residual |
| **S2.3** | Invalid Bearer matrix: offline + mock RS Done\* | M | `make live-oauth-test`; real jwt-auth-filter on site = operator residual |
| **S2.4** | JWKS outage + rotation contracts offline | M | Fail closed; site concurrent load = operator residual |
| **S2.5** | Entra group overage fail-closed (no invent membership); Graph expansion residual noted | S | OAUTH-006 foundation Done\* |
| **S2.6** | **Approved reverse-proxy RS path** documented as first-class option | M | Site chooses plugin vs proxy |
| **S2.7** | **HOST-010** Gateway Mode B Bearer-only | M | Offline + mock-rs Done\* |
| **S2.8** | Local/gateway OIDC PKCE → Jenkins-audience token path secret-free | M | OAUTH-001…005 foundations |
| **S2.9** | Operator go/no-go template (fill when site pins Mode B production) | S | Does **not** block product free-lab GO |

**Exit S2 (product):** Mode B Obtain + free mock RS + residual honesty. **Site** production RS pin optional ([free-lab-qualification.md](../gateway/free-lab-qualification.md)).

---

### S3 — Mode C: AgentCore 3LO / OBO (both obtain shapes)

Ship **both** user-delegated 3LO and OBO/token-exchange shapes; site enables one or both.

| ID | Task | Size | Notes |
|----|------|------|-------|
| **S3.1** | **OAUTH-010 / GWY-001** Entra app registration template (exact Jenkins API resource) | M | **Operator-owned** when site uses Entra; product free-lab uses mock AS |
| **S3.2** | Authorization-code **3LO** Obtain: consent metadata only (never tokens in SPA/audit) | L | Progressive consent Done\* metadata; browser 3LO against Entra = operator residual |
| **S3.3** | **OBO / RFC 8693 / RFC 7523** exchange path shape → short-lived Jenkins-audience access token | L | Fail closed without exact aud; free mock-token lab Done\* |
| **S3.4** | `HTTPTokenFetcher` Live=true only under explicit config; https-only; no redirects; body caps | M | Offline + mock-token lab Done\* (`make live-oauth-test` HOST-015). Site Entra = operator residual |
| **S3.5** | Consent session store: file-backed reload-before-persist lite; purge CLI/admin; CLEAR_ALL confirm | S | Offline Done\* |
| **S3.6** | Force re-auth / revoke window: subject-invalidate + principal/token cache clear (not multi-pod fan-out) | M | Offline Done\*; live IdP revoke residual |
| **S3.7** | Conditional Access / CA policies lab matrix (interactive vs OBO) | M | Site-specific |
| **S3.8** | AgentCore / managed runtime pin: binary or deployment reference + SBOM residual | L | GWY-003/004 |
| **S3.9** | Never AS-to-Jenkins: config + doctor reject Jenkins as token endpoint | S | Done\* offline (`ValidateProviderConfig` + critical-path canary); keep green |

**Exit S3:** Live Entra 3LO **or** OBO (preferably both) obtains Jenkins-audience token; Mode C Ready honest; progressive consent never leaks tokens.

---

### S4 — Mode matrix (HOST-011) · P0

| ID | Task | Size | Notes |
|----|------|------|-------|
| **S4.1** | Config enum: enable modes independently (`api_token_vault`, `jwt_rs_bearer`, `agentcore_3lo_obo`) | S | Offline Done\* |
| **S4.2** | No silent fallthrough: failed Mode B never becomes another subject’s Mode A token | S | Offline Done\* (qualify + `TestCriticalPath_*`); live re-prove |
| **S4.3** | LIVE env only legal on Mode C; reject on A/B | S | Offline Done\* |
| **S4.4** | GWY-003 offline qualify floors stay green; add **live** qualify rows per enabled mode | M | Attach evidence packs |
| **S4.5** | Signed mode-selection record for site (which modes piloted / production) | S | REL-002 residual honesty |
| **S4.6** | Latency/isolation notes per enabled mode (single replica OK) | S | No multi-pod claim |

**Exit S4:** Site can document “we run A+B” or “C only” with fail-closed switch evidence.

---

### S5 — Single-replica deploy + REL (no multi-node) · P1

| ID | Task | Size | Notes |
|----|------|------|-------|
| **S5.1** | **HOST-005 / GWY-004** Deploy scaffold: compose/kustomize `replicas: 1`, probes, resource limits | S | Done\* scaffold |
| **S5.2** | Sticky session optional honesty only (do not claim HA) | S | Done\* |
| **S5.3** | Env completeness: modes, vault paths, JWKS, multi-user, consent path | S | Partial |
| **S5.4** | `make residual-smoke` + pilot-evidence pack still list residual ids | S | Done\* offline |
| **S5.5** | REL evidence template filled for modes piloted (secret-free) | M | Not production GO alone |
| **S5.6** | Operator runbook: enable Mode A vs B vs C; emergency disable RS → Mode A only | S | live-pin-blockers tree |

**Exit S5:** Documented single-replica install path for chosen mode set; residual ids still honest.

---

### S6 — Labs (opt-in; supports all implementations) · P0 for velocity

| ID | Task | Size | Notes |
|----|------|------|-------|
| **S6.1** | **HOST-012…014** Mock IdP + mock JWT RS + route fallthrough lab | M | Done\* (`make live-oauth-*` + Mode B live_oauth tests); production plugin residual |
| **S6.2** | **HOST-015** Mock token peer for Mode C Obtain shape | S | Done\* scaffold + Mode C live_oauth; Entra residual |
| **S6.3** | Free: Keycloak OIDC + Jenkins + real jwt-auth-filter | L | **Done\*** opt-in `make live-jwt-rs-*` (`testdata/jwt-rs-lab/`); site Entra residual |
| **S6.4** | Entra lab tenant checklist (dev app regs for 3LO and OBO) | M | Org |
| **S6.5** | Evidence pack script: secret-free curl/probe outputs → `dist/` | S | Align pilot-evidence |

---

## 3. Explicitly deferred (after Tier A JWT/OAuth)

| Item | Why later |
|------|-----------|
| **HOST-008** multi-pod vault / shared Obtain cache / multi-replica rate | User deferral; same-host flock lite sufficient for Tier A |
| Multi-replica session store | Same |
| Admin multi-operator cookie/OIDC | HOST-007 residual; not mode identity |
| OAUTH-011 / JAS-* Jenkins-as-AS | Default **no-go** |
| MUT-ADMIN config/script | Separate security go |

---

## 4. Suggested execution order (when staffing is limited)

1. **S0** shared (especially S0.1–S0.4) — blocks every mode.  
2. **S1 Mode A live lab** — fastest end-to-end team gateway.  
3. **S2 Mode B** in parallel tracks: **plugin RS pin** and **proxy RS pin** (pick later).  
4. **S3 Mode C** 3LO and OBO tracks in parallel after Entra app reg.  
5. **S4** matrix + live qualify rows for whatever is enabled.  
6. **S5** packaging/runbook; **S6** labs continuously.

---

## 5. Definition of done (Tier A JWT/OAuth critical path)

**Product free-lab DoD** (this section) is met without corporate Entra / customer RS labs.
**Site production pin** remains optional operator residual ([live-pin-blockers.md](../gateway/live-pin-blockers.md)).

- [x] S0 exit met **offline** (HTTP subject + bind + Ready honesty; HOST-001…006/GWY-002 foundations + residual honesty). Site Entra/edge load = operator residual.  
- [x] **Each** of modes A, B, C has offline foundation **and** free lab path (Mode A `live-jenkins-*`; B/C `live-oauth-*`).  
- [x] Mode B **product**: offline Bearer matrix + mock RS lab Done\* (`make live-oauth-test`). **Site** production jwt-auth-filter/proxy pin = operator residual (checklist in live-pin-blockers / jwt-auth-filter-qualification).  
- [x] Mode C **product**: offline mock AS + mock-token lab Done\* + Jenkins-as-AS reject. **Site** Entra/AgentCore pin = operator residual.  
- [x] HOST-011: no silent cross-mode fallthrough **offline** (qualify + `TestCriticalPath_*` / mode matrix).  
- [x] residual-smoke residual ids still present; no false `mode_*_live_*_qualified=true` (enforced by residual-smoke + `TestCriticalPath_ResidualStatusNeverLiveQualified`).  
- [x] HOST-008 multi-pod **not** required for this DoD (Tier A `replicas: 1`).  
- [x] Free-lab qualification policy documented ([free-lab-qualification.md](../gateway/free-lab-qualification.md)).

---

## 6. Cross-links (implementer entry points)

| Topic | Doc / code |
|-------|------------|
| Mode A vault | `docs/gateway/README.md` Mode A · `jenkins-mcp gateway vault` |
| Mode B RS | `docs/auth/jwt-auth-filter-qualification.md` · qualify `oauth009_offline_bearer_matrix` |
| Mode C Obtain | `docs/auth/oauth-capability-matrix.md` §4 · `internal/gateway` |
| Free-lab product bar | `docs/gateway/free-lab-qualification.md` |
| Operator production pin | `docs/gateway/live-pin-blockers.md` |
| Deploy single replica | `docs/gateway/deployment.md` §9 |
| Offline honesty | `make residual-smoke` · `make pilot-evidence` |
| Agent backlog IDs | HOST-001…011, OAUTH-009/010, GWY-001…004 in `docs/jenkins-mcp-enterprise-agent-todo.md` |
