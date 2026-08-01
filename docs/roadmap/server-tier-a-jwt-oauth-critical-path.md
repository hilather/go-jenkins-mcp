# Server Tier A critical path — JWT / OAuth (all modes)

**Status:** Planning SoT for **single-replica** team/server-hosted gateway identity  
**Audience:** implementers, security, platform  
**Defer:** multi-node / multi-pod HA (**HOST-008** Tier B) — same-host flock lite already Done\*  
**Related:** [server-team-hosted.md](server-team-hosted.md) · [live-pin-blockers.md](../gateway/live-pin-blockers.md) · [oauth-capability-matrix.md](../auth/oauth-capability-matrix.md) · [auth-architecture.md](../auth-architecture.md) · [jwt-auth-filter-qualification.md](../auth/jwt-auth-filter-qualification.md)

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
| **S0.5** | **HOST-004** Cache/archive partition by tenant/profile/subject on multi-user host | M | Partial | Concurrent two-user isolation evidence |
| **S0.6** | **HOST-006** Per-subject rate + concurrency (process-local + same-host file lite OK) | S | Done\* process/file lite | Measure under live multi-user load |
| **S0.7** | Doctor / residual-status / residual-smoke honesty: `mode_*_live_*_qualified=false` until pins | S | Done\* | Never flip live flags without evidence |

**Exit S0:** Non-loopback (or reverse-proxied) HTTP can authenticate **individual** subjects offline+lab; tool args cannot spoof identity; Ready never claims live GO falsely.

---

### S1 — Mode A: API token vault · P0 (fastest team path)

| ID | Task | Size | Notes |
|----|------|------|-------|
| **S1.1** | **HOST-009** Vault lifecycle: put/list/status/delete/revoke CLI; Obtain returns **only** bound subject token | M | Offline Done\*; admin vault **write** residual |
| **S1.2** | Obtain isolation canaries: cross-subject read fail closed; no process-wide default token | S | Expand if any gap |
| **S1.3** | Secret-free: no token in logs, admin JSON, MCP, support bundle | S | Existing canaries; keep green |
| **S1.4** | Live lab: multi-user HTTP + vault subjects against real Jenkins Basic ACL | M | Docker or site lab |
| **S1.5** | RO pilot + optional mutations still fail closed per subject | S | MUT already subject-bound offline |

**Exit S1:** Site can run gateway Mode A only (personal tokens in vault) with live multi-user evidence.

---

### S2 — Mode B: JWT resource-server bearer (all RS implementations)

Design allows **either** plugin or edge RS — implement qualification for **both** paths until site picks one.

| ID | Task | Size | Notes |
|----|------|------|-------|
| **S2.1** | **OAUTH-009** Live **jwt-auth-filter** pin checklist (live-pin-blockers §2) | L | LTS + plugin version, JCasC, iss/aud/JWKS, principal map |
| **S2.2** | Required MCP route re-prove live (whoami, job/build API, progressive, artifact, wfapi, …) | M | `auth.RequiredMCPRoutes` |
| **S2.3** | Invalid Bearer matrix live: wrong aud/iss/exp/alg/type → 401/403; **no** Basic/session/anonymous fallthrough | M | `oauth probe-rs` + curl pack |
| **S2.4** | JWKS outage + rotation under concurrent clients | M | Fail closed; document TTL/stale |
| **S2.5** | Entra group overage fail-closed (no invent membership); Graph expansion residual noted | S | OAUTH-006 foundation Done\* |
| **S2.6** | **Approved reverse-proxy RS path** (alternative to plugin): same fallthrough + route matrix | M | Document as first-class option in pin table |
| **S2.7** | **HOST-010** Gateway Mode B: present Bearer only (no mixed Basic); JWT vault / claim helpers | M | Offline Done\*; live Obtain residual |
| **S2.8** | Local/gateway OIDC PKCE → Jenkins-audience token path (stdio/gateway peer) still secret-free | M | OAUTH-001…005; pairs with RS pin |
| **S2.9** | Security go/no-go record: filled §2.1 table + residual exceptions | S | Blocks “Mode B production” claim |

**Exit S2:** At least one of {jwt-auth-filter, approved proxy RS} live-qualified; Mode B Obtain wire proven; residual honesty if only one path pinned.

---

### S3 — Mode C: AgentCore 3LO / OBO (both obtain shapes)

Ship **both** user-delegated 3LO and OBO/token-exchange shapes; site enables one or both.

| ID | Task | Size | Notes |
|----|------|------|-------|
| **S3.1** | **OAUTH-010 / GWY-001** Entra app registration: exact Jenkins API resource, scopes, redirect | M | Org-owned |
| **S3.2** | Authorization-code **3LO** Obtain: browser consent → auth URL + session_id only in metadata (never tokens in SPA/audit) | L | Progressive consent Done\* metadata; browser 3LO automation residual |
| **S3.3** | **OBO / RFC 8693 / RFC 7523** exchange path → short-lived Jenkins-audience access token | L | Fail closed without exact aud |
| **S3.4** | `HTTPTokenFetcher` Live=true only under explicit config; https-only; no redirects; body caps | M | Offline Done\*; live Entra residual |
| **S3.5** | Consent session store: file-backed reload-before-persist lite; purge CLI/admin; CLEAR_ALL confirm | S | Offline Done\* |
| **S3.6** | Force re-auth / revoke window: subject-invalidate + principal/token cache clear (not multi-pod fan-out) | M | Offline Done\*; live IdP revoke residual |
| **S3.7** | Conditional Access / CA policies lab matrix (interactive vs OBO) | M | Site-specific |
| **S3.8** | AgentCore / managed runtime pin: binary or deployment reference + SBOM residual | L | GWY-003/004 |
| **S3.9** | Never AS-to-Jenkins: config + doctor reject Jenkins as token endpoint | S | Done\* offline; keep canary |

**Exit S3:** Live Entra 3LO **or** OBO (preferably both) obtains Jenkins-audience token; Mode C Ready honest; progressive consent never leaks tokens.

---

### S4 — Mode matrix (HOST-011) · P0

| ID | Task | Size | Notes |
|----|------|------|-------|
| **S4.1** | Config enum: enable modes independently (`api_token_vault`, `jwt_rs_bearer`, `agentcore_3lo_obo`) | S | Offline Done\* |
| **S4.2** | No silent fallthrough: failed Mode B never becomes another subject’s Mode A token | S | Offline Done\*; live re-prove |
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
| **S6.1** | **HOST-012…014** Mock IdP + mock JWT RS + route fallthrough lab | M | `make live-oauth-*` residual |
| **S6.2** | **HOST-015** Mock token peer for Mode C Obtain shape | S | Offline/live tags residual |
| **S6.3** | Disposable Jenkins + jwt-auth-filter image for OAUTH-009 | L | Real plugin pin path |
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

- [ ] S0 exit met (HTTP subject + bind + Ready honesty).  
- [ ] **Each** of modes A, B, C has offline foundation **and** a live lab plan; production claim only for modes with attached live evidence.  
- [ ] Mode B: at least one RS implementation (filter **or** proxy) live-qualified; other path residual documented.  
- [ ] Mode C: 3LO and/or OBO live against Entra; AS endpoints never Jenkins.  
- [ ] HOST-011: no silent cross-mode fallthrough under live load for enabled set.  
- [ ] residual-smoke residual ids still present; no false `mode_*_live_*_qualified=true`.  
- [ ] HOST-008 multi-pod **not** required for this DoD.

---

## 6. Cross-links (implementer entry points)

| Topic | Doc / code |
|-------|------------|
| Mode A vault | `docs/gateway/README.md` Mode A · `jenkins-mcp gateway vault` |
| Mode B RS | `docs/auth/jwt-auth-filter-qualification.md` · qualify `oauth009_offline_bearer_matrix` |
| Mode C Obtain | `docs/auth/oauth-capability-matrix.md` §4 · `internal/gateway` |
| Live blockers | `docs/gateway/live-pin-blockers.md` |
| Deploy single replica | `docs/gateway/deployment.md` §9 |
| Offline honesty | `make residual-smoke` · `make pilot-evidence` |
| Agent backlog IDs | HOST-001…011, OAUTH-009/010, GWY-001…004 in `docs/jenkins-mcp-enterprise-agent-todo.md` |
