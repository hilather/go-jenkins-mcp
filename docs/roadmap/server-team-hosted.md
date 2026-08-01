# Server / team-hosted roadmap

**Status:** Planning SoT for optional **team/server-hosted** Jenkins MCP  
**Audience:** engineering leads, security, platform operators, implementation agents  
**Not a claim of production readiness:** local Cursor stdio pilot remains the default product path (ADR 0002).  
**Related SoT:** [architecture](../jenkins-mcp-enterprise-architecture.md) (§§1–2, §6.6, §19.7, Phase 4), [agent todo](../jenkins-mcp-enterprise-agent-todo.md) (GWY/MGR/OAUTH/REL/UI/**HOST**), [task index](../jenkins-mcp-enterprise-task-index.json), [gateway](../gateway/README.md), [auth-architecture](../auth-architecture.md), ADRs 0002 / 0003 / 0004 / 0013 / 0014  

**Auth decision for Tier A (binding):** implement **all three** Jenkins credential paths as first-class, tested gateway modes — sites pick the default; engineering does **not** pick only one:

| Mode ID | Name | Jenkins wire | How credential is obtained |
|---------|------|--------------|----------------------------|
| **A** `api_token_vault` | Personal API token (per-user vault) | Basic `user:api_token` | User-provisioned personal token in vault/keyring (never shared SA) |
| **B** `jwt_rs_bearer` | External IdP JWT resource server | Bearer Jenkins-audience JWT | Entra (or approved IdP) PKCE / issued access token; Jenkins **`jwt-auth-filter`** (or proxy RS) validates |
| **C** `agentcore_3lo_obo` | AgentCore / gateway 3LO + OBO | Bearer Jenkins-audience JWT (typical) | AgentCore user-delegated 3LO and/or OBO/token exchange against **Entra AS** (not stock Jenkins) |

JWT on Jenkins (**mode B/C**) and “OAuth” (**Entra AS + obtain path**) are **complements**, not alternatives. Mode A needs neither JWT nor OAuth. See [auth-architecture.md](../auth-architecture.md).

---

## 1. Current state (honest inventory)

### 1.1 What works today (local pilot / foundations)

| Area | State | Evidence |
|------|-------|----------|
| **Default transport** | **Done** — Cursor stdio per-user process | ADR 0002; `jenkins-mcp serve --stdio` |
| **Personal API token + Secret Service** | **Done** (Tier-1) | ADR 0009; `internal/keyring`; auth path 2.1 |
| **Global RO + deny-only MCP RBAC** | **Done** (local) | ADR 0004; `internal/policy`; tool AuthGate |
| **Local OIDC PKCE → Jenkins-audience token** | **Partial** — offline claim validation, refresh, epoch, whoAmI re-verify landed; **live Entra / jwt-auth-filter lab residual** | OAUTH-001…008 foundations; OAUTH-003/004/006/007 lite; OAUTH-009 residual |
| **Tool contracts, budgets, progressive logs, L2 multi-frame** | **Done*** (MVP) | Phase 0–2 waves; native Go L2 required path |
| **Signed policy bundles (Ed25519)** | **Partial / lite** — envelope verify + multi-sig lite + ForceOff lite offline | MGR-001 lite; `docs/security/policy-bundles.md`; fleet ForceOff residual pin |
| **Fleet telemetry** | **Partial** — opt-in queue/export schema; force-off lite; privacy pack | MGR-002 lite; `docs/security/fleet-telemetry.md` |
| **Admin console** | **Partial (Phase 6 mid-flight)** — SPA + loopback BFF + RBAC roles + CSP/packaging | UI-000…UI-008; ADR 0014; multi-user residual |
| **Package / pilot evidence** | **Partial** — RPM/DEB/tar, offline release-evidence, pilot kit | PKG-001 lite; REL-001/002 lite |
| **Adapters framework** | **Partial** — INT-001 MVP offline; production SaaS clients residual | `docs/adapters/` |

### 1.2 Gateway / server path (stubs vs residual)

| Component | Implemented | Residual / not started |
|-----------|-------------|------------------------|
| `internal/gateway` provider config | AS URL / audience / mode validation; **Jenkins-as-AS rejected** | Live Entra discovery pin |
| `CredentialProvider.Obtain` | Fail-closed default (`Live=false`, `Fetcher=nil` → `not_configured`) | Production Live + durable vault |
| Pluggable `TokenFetcher` / `HTTPTokenFetcher` | Offline mock + HTTPS-shaped POST (tests) | Serve does **not** inject live fetcher |
| Token cache | In-memory keyed by `(user, workload, profile)` | Not a multi-instance vault |
| Consent metadata | Auth URL + session id only (no tokens) | Live consent UX end-to-end |
| Identity binding (`BindSubject` / env) | Tenant/workload/subject/profile/Jenkins principal fail-closed; group overage; reject tool-args identity | **Live Entra claim extraction** (not process env labels) |
| `serve --gateway` | Requires provider config; logs not-ready; **still uses local keyring Jenkins session** until live Obtain | Wire Obtain → Jenkins AuthProvider |
| `gateway qualify --offline` | GWY-003 **lite** offline suite (isolation, wrong audience, IdP mock chaos) | Live AgentCore pin + SLOs |
| Streamable HTTP (`--http`) | Loopback default, body/Host/Origin caps, optional shared-secret | **Not multi-tenant session auth**; loopback deny-anonymous **opt-in default off** (KD-008) |
| `deploy/gateway/` | Non-root, limits, probes, secret-free compose/kustomize (**HOST-005** envelope) | Signed image, AgentCore sidecar, HA runtime |
| Multi-user cache/audit isolation on one process | Docs recommend **one logical user per process** for MVP | True multi-tenant process isolation |
| Admin for gateway operators | Loopback SPA + HOST-007 residual docs; secret-free `enabledModes` | Non-loopback mTLS/OIDC multi-operator sessions |

**Bottom line:** the repo has a **credible foundation and offline contracts** for managed gateway, not a shippable multi-user server. Local stdio + personal credentials is the production-shaped pilot. Team-hosted requires finishing **all three auth modes**, HTTP multi-user authn, isolation, packaging, and REL gates — primarily by **executing existing GWY/OAUTH/MGR tasks plus HOST-***, not inventing a parallel product.

### 1.3 Code / deploy map (for agents)

| Path | Role |
|------|------|
| `deploy/local/` | **Local Docker support stack** (admin BFF, optional HTTP + lab Jenkins) — `make local-docker-up` |
| `internal/gateway/` | Credential provider, bind, cache, fetcher, qualify |
| `cmd/jenkins-mcp/main.go` | `--gateway` serve wiring (foundation) |
| `cmd/jenkins-mcp/gateway_cmd.go` | `gateway qualify --offline` |
| `cmd/jenkins-mcp/serve_http_token.go` | HTTP shared-secret residual (KD-008) |
| `internal/mcpserver/` | Streamable HTTP loopback / origin / body |
| `internal/admin/` + `web/admin/` | Operator console (loopback BFF + SPA) |
| `deploy/gateway/` | Optional container/kustomize scaffold |
| `docs/gateway/*` | Gateway operator/security narrative |

---

## 2. Target end-states (two tiers)

### Tier A — Team shared MCP gateway (primary “server hosted” goal)

**Near Jenkins**, multi-user, optional Streamable HTTP (or reverse-proxy terminated), **per-user tokens**, partitioned cache/audit.

```text
  Cursor / agent (remote or site network)
        │  Streamable HTTP (hardened) or approved reverse-proxy path
        ▼
  jenkins-mcp serve --gateway --read-only   [Rocky/Ubuntu near controller]
        │  Entra/AgentCore subject → policy.Subject
        │  Obtain per-user Jenkins-audience credential (3LO / OBO / exact JWT)
        │  cache + audit + continuations namespaced by user/tenant/profile
        ▼
  Jenkins (resource server: jwt-auth-filter or approved RS)
```

| Property | Requirement |
|----------|-------------|
| Identity | Every call = authenticated individual **and** verified Jenkins principal |
| Credentials | No shared Jenkins SA for interactive users |
| Policy | Same as local: `Jenkins allow ∧ global RO ∧ MCP deny-only ∧ budgets` |
| Placement | Same site / low-latency path to controller (bandwidth savings measurable) |
| Transport | Explicit server mode; **stdio remains default for local Cursor** |
| Admin | Operator console for the **gateway host** (not end-user SaaS control plane) |
| Platforms | Tier-1 Rocky + Ubuntu; **Windows out of scope** |

**Success definition (Tier A GA-lite):** A small team can point approved clients at a near-Jenkins gateway; each user sees only their Jenkins visibility; tokens/cache never cross subjects; RO default holds; **modes A, B, and C are all implementable and qualified** (site enables one or more); offline + live qualify evidence exists per mode; container/systemd deploy documented for operators.

### Tier B — Enterprise fleet (later)

Builds on Tier A:

| Capability | Notes |
|------------|-------|
| Signed policy distribution at fleet scale | MGR-001 production pin (not just lite offline) |
| Privacy-preserving fleet telemetry | MGR-002 + privacy board |
| Multi-controller residual | Live chaos/network matrix; profile-per-controller still primary |
| HA / multi-replica gateway | Sticky session or external vault; no shared memory token cache as sole store |
| Optional multi-operator admin | OIDC/mTLS, no localStorage bearer residual |
| Controlled mutations under policy | Only after MUT + REL security gates; never enabled merely because hosted |

Tier B is **not** required to call the product “team hosted.” Prefer shipping Tier A honestly.

---

## 3. Non-goals / anti-patterns

| Anti-pattern | Why forbidden |
|--------------|---------------|
| **Shared Jenkins bot / service account** for interactive users | Collapses subjects; violates architecture §1–2 and AUTH shared-account ban |
| **Jenkins as 3LO authorization server by default** | ADR 0003 / 0011 / 0013; OAUTH-011 default **no-go** |
| Claiming **stock Jenkins** is OAuth AS in docs/code | Terminology canaries fail; misleads security review |
| **Admin SPA as multi-tenant SaaS control plane** without mTLS/OIDC + multi-session design | ADR 0014 v1 is loopback BFF; residual is explicit |
| **localStorage tokens** as production admin auth | Pilot-only residual |
| **Streamable HTTP without subject binding** as “multi-user ready” | Shared-secret ≠ per-user identity (KD-008) |
| **Mutations enabled because hosted** | Gateway must default RO; mutations only after MUT epic + policy |
| **Windows gateway image** | ADR 0008 platform matrix |
| **Single-frame `.tar.zst` called random access** | Architecture storage rules (L2 multi-frame only) |
| Parallel epic that **rewrites** GWY/MGR instead of finishing them | Prefer existing task IDs |
| Elevating MCP policy above Jenkins deny | Deny-only forever |

---

## 4. Capability gap matrix

Legend: **Done** / **Partial** / **Not started** relative to Tier A needs.

| Capability | Local today | Needed for Tier A | Task IDs (existing or NEW) | Priority | Notes |
|------------|-------------|-------------------|----------------------------|----------|-------|
| Transport (stdio default) | **Done** | Keep default; server mode optional | ADR 0002, MCP-001 | P0 | Do not flip product default |
| Streamable HTTP hardened multi-user | **Partial*** (RequireSubject + session fingerprint offline; HOST-002 matrix docs) | Live Entra/JWKS rotation, path-prefix pin, mTLS residual | GWY-004, MCP-001 residual, **HOST-001**, **HOST-002** | P0 | Mid-session subject swap fail-closed offline |

| Authn (Entra/OIDC, gateway subject) | **Partial** (local OIDC; gateway env labels) | Live inbound claims → `policy.Subject` | OAUTH-001…003, GWY-002, OAUTH-010 | P0 | Env binding is foundation only |
| Authz (deny-only + Jenkins AND) | **Done** local | Same contracts on gateway path | POL-*, GWY-002 | P0 | Tool args never set identity |
| Token acquisition **mode A** API token vault | Local keyring **Done** | Per-user vault on gateway host; Obtain path | **HOST-009**, HOST-003 | P0 | Never shared SA |
| Token acquisition **mode B** JWT RS bearer | OIDC offline **Partial**; RS live residual | Live jwt-auth-filter + claim matrix + bearer wire | **OAUTH-009**, OAUTH-003/005, **HOST-010** | P0 | JWT = Jenkins half |
| Token acquisition **mode C** 3LO/OBO Obtain | Gateway Obtain **stub** | Live Entra 3LO + OBO + vault | **OAUTH-010**, **GWY-001**, HOST-003 | P0 | AS = Entra, not Jenkins |
| Mode matrix / fail-closed switch | N/A | Config selects modes; no silent cross-mode fallthrough | **HOST-011**, GWY-003 | P0 | Qualify all three |
| Session/subject binding | Local re-verify **Done***; HTTP `Mcp-Session-Id` fingerprint **Done*** offline | Continuous JWKS rotation; durable multi-replica session store | AUTH-004, GWY-002, **HOST-001**, **HOST-003** | P0 | Mid-session subject swap → 401 offline; live Entra residual |
| Cache isolation by user/tenant/profile | Local XDG per OS user **Partial** | Namespace + ACL on multi-user host | GWY-004, STO-*, **HOST-004** | P0 | MVP: one process per subject OK |
| Audit isolation + correlation | Local audit **Done*** | Per-subject + correlation ID across hops | AUD-001, GWY-004, OBS-* | P1 | No secrets in events |
| Network placement near Jenkins | N/A (local) | Deploy next to controller; measure bytes | GWY-004, PERF-* | P1 | Prove near-source benefit |
| Packaging (container, non-root, health) | Scaffold envelope **Done*** | Signed image + live AgentCore | GWY-004, PKG-001, **HOST-005** | P1 | limits+probes; signing residual |
| Rate limits / multi-tenant budgets | Process budgets **Done*** | Per-subject quotas + fan-out caps | MCP-001, GWY-004, **HOST-006** | P1 | Mutations multi-tenant residual |
| Policy distribution (signed bundles) | **Partial** lite | Enforce on gateway host | MGR-001 | P1 | ForceOff enterprise pin residual |
| Observability / correlation | Metrics/doctor **Partial** | Jenkins↔gateway vs gateway↔client byte metrics | OBS-*, GWY-004, MGR-002 | P2 | Fleet export privacy board |
| Admin console multi-operator | Loopback SPA **Partial** + HOST-007 docs | Cookie/OIDC multi-operator | UI-003…010, **HOST-007** | P2 | enabledModes secret-free; not SaaS |
| jwt-auth-filter / RS pin | Offline **Done***; mock lab scaffold | Live plugin pin + Entra | OAUTH-009 | P0 for OAuth path | `make live-oauth-*` ≠ production |
| Docker OAuth/JWT labs | Mode A compose **Done*** (jenkins-compose) | Mock IdP + JWT RS + token peer scaffolds | **HOST-012…015** | P0 | Opt-in; not default make test |
| HA / multi-replica | **Docs residual Done*** | Runtime multi-replica | Tier B: **HOST-008** | P3 | Single-replica Tier A default documented |
| Multi-controller chaos | **Not started** | Live matrix residual | NET-*, TST-* | P3 | Tier B / REL |
| Full Jenkins AS plugin | **No-go default** | Only if OAUTH-011 **go** | OAUTH-011, JAS-* | — | Do not schedule unless go |

---

## 5. Phased program (ordered workstreams)

Relative size: **S** ≈ days, **M** ≈ 1–2 weeks, **L** ≈ multi-week. Parallel tracks noted.

### P0 — Foundations already done (cite; no rework)

**Entry:** repo as of Phase 0–2 / waves through admin UI-008.  
**Exit:** leadership agrees Tier A is optional path; local pilot remains SoT.

| Deliverable | Size | Status |
|-------------|------|--------|
| Stdio local pilot, RO, deny-only, keyring API token | L (done) | Done |
| Gateway package contracts + Jenkins-as-AS reject | M (done) | Done foundation |
| Offline qualify suite | S (done) | Done lite |
| Deploy scaffold compose/kustomize | S (done) | Scaffold only |
| Admin loopback BFF + SPA | L (mid-flight) | UI-000…008 Done*; residual UI-009+ |

### P1 — Gateway identity + HTTP + **all three auth modes** (Tier A critical path)

**Entry:** OAUTH-005 foundations + POL-003 available; security engaged on RS.  
**Exit:** Non-loopback (or reverse-proxy) HTTP authenticates **individual** subjects; **modes A, B, and C** each have an Obtain path + fail-closed switch; tool identity cannot be spoofed; shared secret alone is never multi-user identity.

| Track | Work | Size | Deps | Tasks | Mode |
|-------|------|------|------|-------|------|
| HTTP | Multi-user Streamable HTTP authn + reverse-proxy | M | POL-003 | **HOST-001**, **HOST-002** | all |
| Bind | Live claims → `policy.Subject` (not env-only) | M | POL-003 | **GWY-002** | all |
| **A** | Per-user **API token vault** Obtain + Basic to Jenkins | M | HOST-001, GWY-002 | **HOST-009**, **HOST-003** | A |
| **B** | Live **jwt-auth-filter** RS + claim/bearer wire | M–L | lab Jenkins | **OAUTH-009**, **HOST-010** | B |
| **C** | Entra **3LO/OBO** prototype + production provider | L | security | **OAUTH-010**, **GWY-001**, HOST-003 | C |
| Matrix | Mode switch; no silent A↔B↔C fallthrough; qualify all three | M | A–C tracks | **HOST-011**, GWY-003 | all |

**Parallel:** admin polish (UI-009 residual / HOST-007) without blocking Tier A identity.

### P2 — Durable vault / refresh / consent (modes B & C; vault also backs A)

**Entry:** P1 mode stubs green offline; at least one live lab path started.  
**Exit:** Refresh/revoke/consent isolated per user/workload for B/C; API-token vault isolated for A; canaries prove no token leakage.

| Work | Size | Tasks | Mode |
|------|------|-------|------|
| Durable vault (API tokens + OAuth refresh material) | L | GWY-001, **HOST-009** | A, C (B local refresh may use existing OIDC store) |
| Consent URL propagation without token exposure | M | GWY-001, OAUTH-010 | C |
| Force re-auth / revocation window | M | GWY-002, OAUTH-006/007 | B, C |
| Serve Live=true only under explicit operator config + health | S | **HOST-003** | all |

### P3 — Isolation (cache / audit / namespace)

**Entry:** subject identity stable end-to-end.  
**Exit:** two concurrent users cannot share cache hits, continuation tokens as auth, or archive handles.

| Work | Size | Tasks |
|------|------|-------|
| Cache root partition by tenant/profile/user | M | **HOST-004**, GWY-004 ACs |
| Audit events include subject + correlation; no secret fields | S | AUD-*, GWY-004 |
| Mutation preview/confirm scoped per subject (if mutations ever on) | M | MUT-*, HOST-006 |
| MVP ops guidance: one process/namespace per subject until multi-tenant quotas green | S | docs (deployment.md already) |

### P4 — Packaging + deploy

**Entry:** P1–P3 offline + lab green.  
**Exit:** Non-root container/systemd unit with health/readiness, resource limits, secret-free compose examples.

| Work | Size | Tasks |
|------|------|-------|
| Harden `deploy/gateway` to operator-runbook quality | M | **GWY-004**, **HOST-005** |
| Health/readiness + bounded resources | S | GWY-004 |
| SBOM/provenance/signing residual (org-owned) | M | PKG-001, REL-002 |
| Near-source bandwidth measurement harness | M | PERF / GWY-004 AC |

### P5 — Policy / fleet (MGR)

**Entry:** Tier A single-site works with local overlays.  
**Exit:** Signed bundles constrain gateway fleet; telemetry privacy-approved or off.

| Work | Size | Tasks |
|------|------|-------|
| MGR-001 enterprise pin (expiry, rollback, cannot weaken) | M | **MGR-001** |
| MGR-002 export + force-off via signed policy | M | **MGR-002** |
| Effective policy explainable on gateway host | S | POL / admin UI-004 |

### P6 — Admin console for operators of the gateway (not end-users)

**Entry:** Tier A process stable; admin UI-008 packaging exists.  
**Exit:** Operators can inspect effective policy, metrics, audit, doctor for gateway profiles without browser secrets for Jenkins.

| Work | Size | Tasks |
|------|------|-------|
| Finish UI-009 adversarial + residual polish | M | **UI-009**, UI-004/007 writes |
| Document reverse-proxy + CSP for admin (same-origin preferred) | S | UI-008 residual, **HOST-007** |
| Multi-operator sessions only after auth design (OIDC/mTLS) | L | **HOST-007** (gated) |
| Explicit non-goal: multi-tenant SaaS admin | — | ADR 0014 |

### P7 — Pilot + REL gates

**Entry:** P1–P4 complete for chosen site; security review scheduled.  
**Exit:** Limited team pilot evidence; REL checklist rows for gateway filled or excepted.

| Work | Size | Tasks |
|------|------|-------|
| GWY-003 **live** qualify (not only offline) | L | **GWY-003** |
| REL-001 limited pilot (include gateway cohort if in scope) | M | **REL-001** |
| REL-002 gates + evidence pack | M | **REL-002** |
| OAUTH-011 formal no-go (or go with funding) after prototypes | S | **OAUTH-011** |
| Independent security review | M | QA-005 / org process |

```text
P0 (done foundations)
  │
  ├─► P1 identity + HTTP ──► P2 vault ──► P3 isolation ──► P4 package ──► P7 pilot/REL
  │                              │
  │                              └─► P5 MGR (parallel after P1 policy subject stable)
  │
  └─► P6 admin residual (parallel; does not unblock Tier A MCP path)
```

---

## 6. New task backlog proposals

Prefer **existing** IDs. New `HOST-*` tasks only fill gaps not spelled as standalone ACs.

### 6.1 Existing + HOST tasks — prioritize next (top 18 ordered)

Implement **all three auth modes** (A/B/C); tracks can run in parallel after HOST-001 + GWY-002 foundations.

| # | Task ID | Mode | Why next |
|---|---------|------|----------|
| 1 | **HOST-001** | all | Multi-user Streamable HTTP subject authn |
| 2 | **GWY-002** | all | Live claim → Subject; kill env-label-only trust |
| 3 | **HOST-009** | **A** | Per-user API token vault Obtain (no OAuth required) |
| 4 | **OAUTH-009** | **B** | Live jwt-auth-filter / RS pin |
| 5 | **HOST-010** | **B** | End-to-end Jenkins-audience JWT bearer path on gateway |
| 6 | **OAUTH-010** | **C** | AgentCore/Entra 3LO/OBO prototype matrix |
| 7 | **GWY-001** | **C** | Production 3LO/OBO credential provider |
| 8 | **HOST-003** | all | Serve wiring: Obtain → Jenkins client (all modes) |
| 9 | **HOST-011** | all | Auth mode matrix + fail-closed switch (A/B/C) |
| 10 | **HOST-002** | all | Non-local HTTP + reverse-proxy matrix |
| 11 | **HOST-004** | all | Cache/audit namespace isolation |
| 12 | **GWY-003** | all | Live qualify **per mode** (A, B, and C) |
| 13 | **MGR-001** | all | Signed policy enterprise pin |
| 14 | **GWY-004** | all | Package + near-source deploy |
| 15 | **HOST-005** | all | Health/readiness/resource envelope |
| 16 | **HOST-006** | all | Per-subject rate/budget isolation |
| 17 | **HOST-012** | lab | Docker lab umbrella + opt-in Makefile (all modes) |
| 18 | **HOST-013** / **HOST-014** | **B** lab | JWT RS Jenkins/mock + mock OIDC IdP Compose |
| 19 | **HOST-015** | **C** lab | Mock AgentCore/token-exchange Compose |
| 20 | **HOST-007** | ops | Gateway operator admin residual |
| 21 | **REL-001** / **REL-002** | all | Pilot + release evidence (all enabled modes) |

Also keep **OAUTH-011** as a scheduled decision gate after OAUTH-010/009 evidence (default **no-go** for Jenkins-as-AS). Do **not** start JAS-* without go.

**Lab note:** Real Entra is residual; Docker mocks (HOST-013–015) are **required scaffolds** for integration confidence. Extend `testdata/jenkins-compose/` pattern (`make live-jenkins-*`); never put labs on default `make test`.

### 6.2 New proposed tasks

---

#### HOST-001 — Harden Streamable HTTP for multi-user gateway authn

**Priority:** P0  
**Dependencies:** GWY-002 (subject binding), MCP-001 HTTP guards  
**Maps to:** GWY-004 transport AC; KD-008 residual  
**Status:** **Partial Done*** offline (not live Entra production)

**Objective**

Replace “optional shared secret on loopback” as the multi-user story with **authenticated individual subjects** on the MCP HTTP path (gateway mode).

**Acceptance criteria**

- [x] Non-local bind always requires authenticated subject (not anonymous).
- [x] Shared-secret alone is **not** documented as multi-user identity; if retained, it is transport gate only and still requires per-user token/OIDC.
- [x] Session or request credentials bind to identity fingerprint; mid-session subject change fails closed (`Mcp-Session-Id` + `IdentityFingerprint` in `internal/mcpserver`; gateway `Binding.Revalidate` for policy.Subject).
- [x] Tokens never appear in logs, errors, metrics labels, or support bundles (canary tests).
- [x] Regression: loopback pilot without gateway may keep KD-008 residual **explicitly documented**; gateway mode cannot enable anonymous multi-user.

**Residual (do not claim Done):** multi-instance / under-load JWKS HA (process-local `RefreshingJWKS` TTL refresh + stale-if-error + optional `JENKINS_MCP_HTTP_JWKS_MAX_STALE` fail-closed landed; multi-instance shared JWKS still residual); live Entra / jwt-auth-filter production pin; multi-replica durable session store (HOST-008).

---

#### HOST-002 — Reverse-proxy and non-loopback deployment matrix

**Priority:** P1  
**Dependencies:** HOST-001, NET-001 origin pin  
**Maps to:** GWY-004 deployment  
**Progress:** **Partial / Done*** — docs matrix + fail-closed tests + `PathPrefix` strip/`--http-path-prefix`; live edge origin pin residual  

**Objective**

Prove safe placement behind site reverse-proxy (TLS terminate, path prefix, Host/Origin).

**Acceptance criteria**

- [x] Documented allowed deployment shapes (TLS at proxy vs app; no CORS wildcard).
- [x] Empty AllowedHosts / AllowedOrigins fail closed for non-local.
- [ ] Live or fixture matrix for path-prefix origin pin (extends NET-001 residual).
- [x] Health endpoints do not leak secrets or broad tool inventory without auth.

---

#### HOST-003 — Gateway serve wiring: live Obtain to Jenkins client

**Priority:** P0  
**Dependencies:** GWY-001, GWY-002  
**Maps to:** GWY-001 ACs “attributable to validated caller”  

**Objective**

When `--gateway` and provider Ready, Jenkins HTTP credentials come from `CredentialProvider.Obtain` for the bound subject — **not** a silent keyring shared path, and **never** a static SA.

**Acceptance criteria**

- [ ] Gateway mode + not Ready → fail closed or explicit degraded mode that cannot serve interactive multi-user traffic with wrong identity.
- [ ] Obtain failure does not fall through to another user’s token or anonymous.
- [ ] ConsentRequired surfaces authorization URL metadata only.
- [ ] Unit/integration tests with mock Fetcher prove per-subject credential selection.
- [ ] Docs update: `docs/gateway/README.md` residuals closed for wiring.

---

#### HOST-004 — Multi-tenant cache and continuation isolation

**Priority:** P0  
**Dependencies:** GWY-002, STO cache layout  
**Maps to:** GWY-004 isolation ACs  

**Objective**

Ensure derived cache, L1/L2 handles, and list continuations cannot cross users/policies on a shared host.

**Acceptance criteria**

- [x] Cache key material includes subject/tenant/profile (or process isolation enforced and tested).
- [x] Continuation tokens are not an auth boundary; when multi-tenant, they fail closed across subjects.
- [x] Two-user offline test: no shared archive handle / cache hit leakage.
- [x] Support-bundle and doctor remain secret-free under multi-user layout.

**Foundation (done):** `CacheKey.Tenant`, `Caller.CacheKey`/`SubjectKey`,
`jenkins.*WithSubject` page tokens, offline Alice/Bob tests,
`docs/gateway/README.md` §3c. **Serve wire Done*:** `tools.RegisterOptions.SubjectKey`
+ list tools subject-bound pagination when `--gateway`. **Residual:**
per-HTTP-request SubjectKey rebind; durable L1/L2 namespace; multi-replica (HOST-008).

---

#### HOST-005 — Gateway health, readiness, and resource envelope

**Priority:** P1  
**Dependencies:** GWY-004 scaffold  
**Maps to:** GWY-004 packaging ACs  
**Progress:** **Done*** scaffold (probes + limits); live AgentCore residual  

**Objective**

Production-shaped liveness/readiness and cgroup/memory limits for container/systemd.

**Acceptance criteria**

- [x] Readiness fails when provider not configured in gateway mode (or reports residual clearly).
- [x] Non-root image runs with read-only root where practical; writable only cache/config volumes.
- [x] Documented CPU/memory/file descriptor limits for pilot.
- [x] Compose/kustomize examples remain secret-free (`.env.example` only).

---

#### HOST-006 — Per-subject rate limits and multi-tenant budgets

**Priority:** P1  
**Dependencies:** MCP-001 budgets, HOST-001  
**Maps to:** architecture concurrent clients; mutation multi-tenant residual  

**Objective**

Prevent one user from exhausting process-wide budgets for others.

**Acceptance criteria**

- [x] Per-subject concurrent tool / preview rate caps (config via policy, not elevation).
- [x] Process absolute ceilings still apply (fail closed).
- [x] Tests: subject A spam does not starve subject B below documented floor (or fair-share policy documented).
- [x] Mutation confirm cooldown tokens cannot be replayed across subjects.

**Foundation (done):** `gateway.SubjectLimiter` + fair-share tests; mutation
`Binding` = profile + principal + ExternalSubject + tenant with multi-user
`BindingFromContext` (Alice/Bob tests). **Token-bucket rate Done* foundation:**
`gateway.SubjectRateLimiter` (30/min + burst 10 default; process ceiling).
**Serve wire Done*:** `SubjectSlotLimiter` + `SubjectRateLimiter`; Allow then Hold;
`MutationBindingFromContext` prefers Valid PolicySubject PrincipalID (HTTP claim)
else Caller + PrincipalCache (Obtain) else process principal. **Done\*** Obtain→
Binding principal via PrincipalCache. **Residual:** HOST-008 multi-replica; policy
overlay rate reduction; Obtain still does not rewrite policy.Subject on ctx mid-call.

---

#### HOST-007 — Gateway operator admin path (non-SaaS)

**Priority:** P2  
**Dependencies:** UI-003…UI-008, ADR 0014  
**Maps to:** Phase 6 residual; architecture admin  
**Progress:** **Done*** residual docs + secret-free `enabledModes`; cookie multi-op residual  

**Objective**

Operators of a **team gateway** can use admin BFF safely; still **not** a multi-tenant end-user control plane.

**Acceptance criteria**

- [x] Document when admin may bind non-loopback (token required; prefer reverse-proxy mTLS/OIDC residual design).
- [x] No Jenkins API tokens or gateway vault material in browser responses.
- [x] Multi-user admin sessions: either explicit residual “single process role” or designed session table with CSRF for cookies.
- [x] Remove or quarantine localStorage token UX for non-pilot (httpOnly cookie or OS-broker residual).
- [x] CSP remains fail-closed; reverse-proxy guidance updated.

---

#### HOST-008 — HA / multi-replica residual (Tier B)

**Priority:** P3  
**Dependencies:** HOST-003, HOST-004, durable vault  
**Maps to:** architecture HA session notes  
**Progress:** **Done*** as documentation residual only (no multi-replica runtime)  

**Objective**

Define when multi-replica is allowed (external vault, sticky sessions, no split-brain token cache).

**Acceptance criteria**

- [x] Architecture note: single-replica Tier A default.
- [x] Checklist for multi-replica: shared vault, session affinity, audit aggregation.
- [x] Explicit non-goal until vault exists.

---

#### HOST-009 — Mode A: per-user personal API token vault (gateway)

**Priority:** P0  
**Dependencies:** HOST-001, GWY-002, ADR 0009  
**Maps to:** auth path `api_token`; gateway without IdP  

**Objective**

Ship multi-user gateway using **personal Jenkins API tokens** only: each subject has an isolated vault entry; Jenkins wire is Basic; no shared SA; no JWT required on Jenkins for this mode.

**Acceptance criteria**

- [ ] Operator can provision/rotate/revoke a per-user API token into vault (CLI and/or approved control plane residual).
- [ ] Obtain for mode A returns credentials only for the bound subject; cross-subject read fails closed.
- [ ] Gateway mode never falls back to a process-wide or “default” API token.
- [ ] Tokens never appear in logs, admin JSON, MCP results, or support bundles (canaries).
- [ ] Works with global RO + deny-only RBAC unchanged.
- [ ] Documented as first-class Tier A mode (not a temporary hack).

---

#### HOST-010 — Mode B: Jenkins JWT resource-server bearer path (gateway + live RS)

**Priority:** P0  
**Dependencies:** OAUTH-009, OAUTH-003/005, HOST-001, GWY-002  
**Maps to:** auth path `external_idp_jwt_bearer`; `jwt-auth-filter`  

**Objective**

End-to-end **Bearer Jenkins-audience JWT** from gateway/MCP to Jenkins where Jenkins is **only** a resource server (jwt-auth-filter or approved proxy). Complements IdP issuance; does **not** make Jenkins an AS.

**Acceptance criteria**

- [ ] Live OAUTH-009 pin: invalid Bearer does not fall through to Basic/session/anonymous on OAuth-required routes.
- [ ] Access-token claim validation (iss/aud/exp/nbf) enforced; ID tokens never used as Jenkins API credentials.
- [ ] Graph / generic gateway / wrong-audience tokens rejected.
- [ ] Gateway (or local OIDC store) can present Bearer without mixing Basic on the same call.
- [ ] Doctor/self-check residual honest when RS not qualified.
- [ ] Docs: mode B requirements (Entra app + jwt-auth-filter version pin).

---

#### HOST-011 — Auth mode matrix and fail-closed mode switch (A + B + C)

**Priority:** P0  
**Dependencies:** HOST-009, HOST-010, GWY-001 (or mocks), HOST-003  
**Maps to:** architecture multi-path auth; GWY-003 comparison ACs  

**Objective**

Configure and qualify **all three** modes as first-class. Site enables one or more; process documents default. **No silent fallthrough** between modes (e.g. failed JWT must not become another user’s API token).

**Acceptance criteria**

- [ ] Explicit config enum/flags for enabled modes: `api_token_vault`, `jwt_rs_bearer`, `agentcore_3lo_obo`.
- [ ] At least one offline test matrix row per mode for Obtain → Jenkins auth header shape (Basic vs Bearer).
- [ ] Cross-mode fail-closed tests: disabled mode returns clear error; failed mode does not try another user’s credential.
- [ ] GWY-003 (or host qualify) documents latency/isolation evidence for each enabled mode.
- [ ] Operator guide: when to choose A vs B vs C; never shared SA.
- [ ] Admin console residual note listing which modes the process has enabled (secret-free).

---


---

#### HOST-012 — Docker lab umbrella for server-side auth (opt-in Makefile)

**Priority:** P0  
**Dependencies:** TST-001 jenkins-compose pattern  
**Maps to:** AGENTS.md Docker scaffolds; modes A/B/C labs  

**Objective**

Single documented entry point for disposable Docker labs for auth modes without default CI.

**Acceptance criteria**

- [ ] Opt-in Makefile targets (`live-oauth-*` or `live-auth-lab-*`); not in `make test`/`ci`.
- [ ] Documented compose profiles; mode A reuses jenkins-compose.
- [ ] Tear-down removes volumes; no secrets committed.
- [ ] README cross-links HOST-013…015 and OAUTH-009.
- [ ] No shared SA / Jenkins-as-AS guidance.

---

#### HOST-013 — Docker scaffold: Jenkins JWT RS lab (mode B)

**Priority:** P0  
**Dependencies:** HOST-012, OAUTH-009 offline  
**Maps to:** mode B; jwt-auth-filter qualification  

**Objective**

Compose lab for Bearer JWT validation (real jwt-auth-filter when practical, else mock RS proxy).

**Acceptance criteria**

- [ ] Healthy `make …-up` path; residual documented if plugin pin deferred.
- [ ] Opt-in tests: valid JWT ok; wrong aud/exp/iss denied.
- [ ] Invalid Bearer no Basic/session/anonymous success on OAuth-required routes.
- [ ] Lab-only keys; destroyed on tear-down.

---

#### HOST-014 — Docker scaffold: mock OIDC IdP

**Priority:** P0  
**Dependencies:** HOST-012  
**Maps to:** mode B token mint without real Entra  

**Acceptance criteria**

- [ ] Discovery + JWKS on loopback.
- [ ] Mint tokens with configurable aud/iss/exp for HOST-013.
- [ ] Wrong-audience/expired fail closed.
- [ ] No production secrets; opt-in only.

---

#### HOST-015 — Docker scaffold: mock AgentCore / token-exchange (mode C)

**Priority:** P0  
**Dependencies:** HOST-012, GWY-001 offline  
**Maps to:** mode C Obtain integration  

**Acceptance criteria**

- [ ] Obtain Live against mock returns Jenkins-audience credential.
- [ ] Wrong audience/errors fail closed without shared SA.
- [ ] ConsentRequired metadata only; no tokens in logs.
- [ ] Residual vs real AgentCore vault documented.
- [ ] Opt-in Makefile; secret-free compose.


### 6.3 Mapping new ↔ existing

| New ID | Primarily extends | Auth mode |
|--------|-------------------|-----------|
| HOST-001 / HOST-002 | GWY-004, MCP-001, KD-008 | all |
| HOST-003 | GWY-001 serve wiring | all |
| HOST-004 / HOST-006 | GWY-004 isolation ACs | all |
| HOST-005 | GWY-004 packaging | all |
| HOST-007 | UI-009+ / ADR 0014 residual | ops |
| HOST-008 | Tier B only | all |
| **HOST-009** | ADR 0009, keyring/vault | **A** |
| **HOST-010** | OAUTH-009, OAUTH-005 | **B** |
| **HOST-011** | GWY-003 mode matrix | **A+B+C** |
| **HOST-012** | TST-001 jenkins-compose | lab umbrella |
| **HOST-013** | OAUTH-009 live lab | **B** Docker RS |
| **HOST-014** | OAUTH-001…003 | **B** mock IdP |
| **HOST-015** | GWY-001, OAUTH-010 | **C** mock token peer |

When implementing, agents may **close ACs on GWY-*/OAUTH-*** and mark HOST-* as documentation split for roadmap clarity — avoid duplicate PRs that implement the same code twice.

---

## 7. Decision gates

| Gate | Blocking? | Default | Owner | Notes |
|------|-----------|---------|-------|-------|
| **OAUTH-011** Jenkins-as-AS | Yes for JAS epic only | **No-go** (formal residual log) | Security + eng | Enforced in code (ADR 0013); decision log [`docs/auth/jas-no-go.md`](../auth/jas-no-go.md) §4.1; do not build JAS-* without go |
| **OAUTH-009** RS production pin | Yes for **mode B** (and C when Bearer to Jenkins) | Open until lab | Platform + security | Fallthrough risk |
| **Ship all three modes A/B/C** | Yes for Tier A “complete” claim | **Implement all**; site picks default | Eng + security | HOST-011 matrix; no silent fallthrough |
| **Within mode C:** 3LO vs OBO vs exact JWT passthrough | Yes for GWY-003 close | Prefer OBO/3LO; passthrough most restricted | Security | Document residuals |
| **Non-loopback admin** | Yes for remote admin | Loopback only v1 | Security | Token required; OIDC residual |
| **Cookie sessions for admin** | Yes if leaving Bearer | Not in v1 | Security | CSRF + httpOnly required (ADR 0014) |
| **Multi-tenant single process vs process-per-user** | Ops choice for Tier A MVP | Process-per-user OK | Eng | Isolation tests still required for shared process claims |
| **Mutations on gateway** | Yes | Off / RO | Security | Never enable for “hosted convenience” |
| **Telemetry export destination** | Privacy board | Off default | Privacy | MGR-002 |
| **Windows support** | N/A | Out of scope | — | ADR 0008 |

---

## 8. Risk register

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Shared SA shortcut under delivery pressure | Critical identity collapse | Med | Code reject + review checklist + canaries; no undocumented fallthrough |
| HTTP multi-user with only shared secret | Lateral movement on LAN | High today | HOST-001; gateway mode requires subject auth |
| Token/cache cross-user leakage | Data exposure | Med | HOST-004 tests; qualify cross-user cases |
| Live Entra never pinned; ship scaffold as “done” | False readiness | High | Residual honesty; REL blocks; docs |
| Admin SPA localStorage / loopback residual treated as production | Token theft | Med | HOST-007; pilot labels |
| Scope creep to multi-controller HA SaaS | Delay Tier A | Med | Tier A vs B split; HOST-008 P3 |
| JAS plugin restarted without OAUTH-011 | Security debt | Low | ADR 0013 enforcement |
| Mutations enabled on central host | Blast radius | Med | RO default; MUT gates |
| Bandwidth benefit unproven | Business case fails | Med | GWY-004 measurement AC |
| Process memory vault lost on restart / multi-replica split brain | Auth outages / wrong subject | Med | Durable vault before HA |

---

## 9. Immediate next 30 / 60 / 90 days

Assumptions: local pilot largely green; Phase 6 admin mid-flight (UI-008/009 adversarial foundations landed; HOST-007 residual for non-loopback multi-operator). Leadership wants a **path** to team-hosted without pausing local value.

**Honesty (2026-08):** Offline **foundations landed** for modes A/B/C Obtain, multi-user opt-in, JWKS process-local refresh, packaging scaffold, doctor/admin residual fields, REL lite residual ids (`multi_user_offline`, `oauth009_offline`, `host008_single_replica`). **Live pins remain residual** — do not treat offline Done\* as live Entra / AgentCore / multi-replica GO.

### Days 0–30 (foundations — largely Done\*)

| Item | State | Residual |
|------|-------|----------|
| Socialize Tier A ships modes A+B+C (site chooses) | **Ongoing** | Site enablement evidence |
| **HOST-012…015** Docker lab umbrella + mock IdP/RS/token peers | **Done\*** opt-in (`make live-oauth-*`, jenkins-compose) | Not production Entra |
| **HOST-001** Streamable HTTP subject + JWKS refresh | **Done\*** process-local | Multi-instance JWKS HA; live Entra under load |
| **HOST-009** Mode A vault Obtain | **Done\*** offline + CLI vault | Live multi-user personal-token lab cohort |
| **HOST-010** Mode B JWT vault + **OAUTH-009** offline matrix | **Done\*** | **Live** jwt-auth-filter / Entra pin |
| **GWY-001** Mode C Live opt-in foundation | **Done\*** Live=false + mock Fetcher | Live AgentCore / Entra Obtain |
| **HOST-011** mode matrix + no fallthrough | **Done\*** | Ops mode-switch evidence |
| Anti-patterns freeze (no shared SA, no Jenkins-as-AS) | **Done** ADR 0003/0013 | OAUTH-011 formal sign-off residual |

### Days 31–60 (live pins + pilot path)

1. **Live OAUTH-009** pin: jwt-auth-filter version + JCasC + route re-prove (wrong aud/exp/iss, no Basic fallthrough).  
2. **Live HOST-009** multi-user Mode A cohort on lab Jenkins (personal tokens; no shared SA).  
3. **OAUTH-010** / **GWY-001** Live against mock peer first, then real AgentCore residual.  
4. **HOST-001/002** reverse-proxy path-prefix + mTLS non-local production pin.  
5. **MGR-001** enterprise `REQUIRE_SIGNED_POLICY` roll-out with trusted keys (gateway hosts).  
6. Team pilot checklist §0 mode matrix filled (REL-001); `release-evidence --offline` residual ids reviewed.

### Days 61–90 (package + dual-mode pilot)

1. **HOST-004** isolation green under live multi-user load for enabled modes.  
2. **GWY-003** live qualify rows for **A, B, and/or C** (or residual honesty per mode — never invent GO).  
3. **GWY-004** + **HOST-005** package runbook for one team (`deploy/gateway/` scaffold → signed image residual).  
4. Team pilot enabling ≥2 modes (recommend A + B or A + C); record evidence paths.  
5. **OAUTH-011** formal no-go (expected) for Jenkins-as-AS.  
6. REL-001/002 evidence pack lists which modes were piloted; **host008_single_replica** residual explicit until durable vault HA.

---

## 10. Mapping to admin console (Phase 6 residual)

| Concern | Local pilot (today) | Server / team-hosted change |
|---------|---------------------|----------------------------|
| Bind address | Loopback default | Still prefer loopback + SSH tunnel **or** reverse-proxy with auth; non-local requires token (existing residual) |
| Authn | Optional shared secret; localStorage SPA UX | HOST-007: no localStorage for production; prefer httpOnly cookie + CSRF or mTLS/OIDC |
| RBAC | Process-wide `viewer` / `operator` / `policy_admin` | Multi-operator only after session design; still **cannot** widen `force_read_only` |
| Multi-tenant SaaS | Out of scope | **Remains out of scope** for v1 console |
| Data | Secret-free BFF | Same; must not expose gateway vault or per-user Jenkins tokens |
| CSP | UI-008 headers | Preserve under reverse-proxy; same-origin SPA+API preferred |
| Metrics/audit | Process-local | Fleet aggregation = MGR-002 residual; admin shows residual notes |
| Policy apply | UI-004 residual | Signed-bundle apply remains host-side keys; browser never holds private keys |
| Coupling to MCP HTTP | Separate `admin serve` | **Keep separate** from Streamable HTTP agent path (ADR 0014) |

**Admin does not replace GWY identity work.** Shipping a prettier SPA does not make multi-user MCP safe.

---

## Appendix A — Architecture alignment (Key Decisions)

| KD / ADR | Roadmap stance |
|----------|----------------|
| ADR 0002 stdio default | Unchanged; server mode optional explicit |
| ADR 0003 / 0013 Jenkins not AS | Enforced; OAUTH-011 no-go path |
| ADR 0004 RO + deny-only | Identical on gateway |
| ADR 0008 platforms | Rocky/Ubuntu; no Windows gateway |
| ADR 0009 personal token | Local pilot primary; gateway uses per-user OAuth/vault |
| ADR 0012 signed policy | MGR-001 for fleet constrain |
| ADR 0014 admin SPA | Operator tool; not multi-tenant SaaS |
| Architecture §6.6 qualification order | 3LO → OBO → exact JWT → narrow broker → full AS last |

---

## Appendix B — Verification commands (agents)

```bash
export PATH="$HOME/.local/go/bin:$PATH"
go test ./internal/gateway/ ./internal/gateway/qualify/ ./internal/auth/ ./internal/mcpserver/ -count=1
jenkins-mcp gateway qualify --offline
jenkins-mcp security self-check --json
jenkins-mcp release-evidence --offline
docker compose -f deploy/gateway/docker-compose.yml config
```

Do not mark GWY-001…004 DoD complete without live evidence called out in backlog ACs.

---

## Appendix C — Document maintenance

| Change | Update |
|--------|--------|
| This roadmap | `docs/roadmap/server-team-hosted.md` |
| Gateway residuals | `docs/gateway/README.md`, `deployment.md`, `qualification.md` |
| Phase board pointer | `docs/phase2-progress.md` residual line |
| Docs index | `docs/README.md` |
| Task graph | Prefer existing IDs; add HOST-* to todo/index when implementation starts |

**Last updated:** 2026-08-01 — foundations landed offline; live pins residual; no gateway production claim.
