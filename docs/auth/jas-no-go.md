# JAS-001 — Jenkins authorization-server threat model (default **no-go**)

**Status:** Binding product decision for MCP profiles and gateway config  
**Decision:** **Default no-go** for treating stock Jenkins (or an unapproved Jenkins-hosted plugin) as an OAuth **authorization server**  
**Related:** [ADR 0003](../adr/0003-jenkins-not-oauth-authorization-server.md), [ADR 0011](../adr/0011-custom-jenkins-authz-plugin-gated.md), [ADR 0013](../adr/0013-jas-default-no-go-enforcement.md), [oauth-capability-matrix.md](oauth-capability-matrix.md), [auth-architecture.md](../auth-architecture.md), [threat-model.md](../security/threat-model.md)  
**Code:** `auth.RejectJenkinsAsAuthorizationServer` · profile OIDC validation · gateway `ValidateProviderConfig` · doctor check `jenkins_as_as`  
**Epic residual:** JAS-002…JAS-005 implement a full AS **only after** an OAUTH-011 **go** decision — not started by default

---

## 1. Explicit prohibition (always on)

| Rule | Enforcement |
|------|-------------|
| Stock Jenkins **must never** be configured as the OAuth **authorize**, **token**, **issuer**, or **JWKS** endpoint for MCP OIDC profiles or AgentCore/gateway AS settings | Fail-closed validation + doctor note |
| `oidc.issuer` host must not equal the profile Jenkins controller host | Profile validate + `auth.RejectJenkinsAsAuthorizationServer` |
| Gateway `AuthorizationServerBaseURL` / authz / token endpoints must not share Jenkins origin | `gateway.ValidateProviderConfig` |
| Product language must not claim stock Jenkins is a native 3LO AS | Terminology walk tests + capability matrix `custom_jenkins_as_plugin` = `no_go_default` |

**Preferred paths (in order):** personal API token → external IdP (Entra or approved AS) + Jenkins JWT **resource server** → AgentCore 3LO/OBO against that **external** AS → narrow broker/filter → **only then** a funded full Jenkins AS plugin (ADR 0011).

---

## 2. Threat model: running an OAuth AS on Jenkins

Running consent, authorization codes, and token minting **on the Jenkins controller** expands the trust boundary of an already high-value CI system. Actors, assets, and failure modes differ from Jenkins-as-**resource-server** (which only **validates** externally issued tokens).

### 2.1 Assets introduced by a Jenkins-hosted AS

| Asset | Sensitivity | Notes |
|-------|-------------|-------|
| Authorization codes | High | One-time, bound to client/redirect/PKCE/user |
| Access / refresh tokens | Secret | Minted by Jenkins; audience must be exact |
| AS signing keys (JWT) | Secret | HSM/credentials store; rotation/overlap required |
| Client registry (redirects, PKCE policy) | Integrity-critical | Mis-registration → open redirect / mix-up |
| Consent / session state | High | CSRF and fixation targets |
| Admin “emergency revoke” controls | Integrity | Missing revoke = long-lived blast radius |

### 2.2 Core threats

| Threat | Description | Why Jenkins-as-AS amplifies it |
|--------|-------------|-------------------------------|
| **Token minting abuse** | Attacker obtains codes/tokens for scopes beyond user intent or Jenkins ACL | AS co-resident with job control plane; plugin bugs become identity bugs |
| **Session fixation / consent replay** | Fixate login/consent session; replay consent across clients | Jenkins UI session cookies + crumb model are not an OAuth consent surface by default |
| **CSRF on authorize/consent** | Cross-site trigger of authorization without user intent | Must bind `state`, session, and exact redirect; Jenkins form crumbs alone are insufficient |
| **Privilege escalation** | Map OAuth scopes above the user’s Jenkins permissions or MCP policy | AS must ∩ Jenkins ACL ∧ MCP deny-only; easy to mis-map |
| **Shared identity collapse** | Many gateway users collapse to one Jenkins principal / service account | Violates per-user identity (architecture KD); AS “client credentials” or shared refresh is a failure mode |
| **Open redirect / client mix-up** | Loose redirect URI matching; wrong client receives codes | Public MCP/local clients need exact redirects + PKCE S256 |
| **Key/revocation failure** | Lost rotation, no emergency revoke, keys in logs/bundles | Jenkins credential stores and support-bundle hygiene become AS operational burden |
| **Confused deputy / SSRF** | AS metadata or token endpoints reachable in unsafe ways | Controller already a high-value SSRF/pivot target |
| **Audit gap** | Tokens issued without correlation to person + client + workload | Incident response cannot attribute MCP actions |

### 2.3 Why external IdP / AgentCore is preferred

| Approach | Role of Jenkins | AS surface on Jenkins |
|----------|-----------------|----------------------|
| Personal API token | Protected API (Basic) | None |
| External IdP + JWT RS (`jwt-auth-filter` / proxy) | Resource server only | None (IdP mints) |
| AgentCore 3LO/OBO → Entra | Downstream resource; vault binds user+workload | None on Jenkins |
| Full Jenkins AS plugin | AS **and** API host | Full (consent, codes, tokens, JWKS, revoke) |

External IdP / AgentCore keep **token minting**, **consent**, and **key lifecycle** with identity systems that already own MFA, Conditional Access, DCR/app registration, and revocation. Jenkins remains a **resource server** for an exact audience.

A Jenkins-hosted AS is justified **only** when a recorded OAUTH-011 decision proves those alternatives cannot meet a **specific, funded** gateway contract requirement — not because “OIDC login” exists in the Jenkins UI (`oic-auth` is a **browser security realm**, not an API AS).

---

## 3. Protocol profile (conditional — **if** OAUTH-011 ever goes **go**)

> **Label: CONDITIONAL.** Do not implement or advertise as baseline. Required **if** a security-owned go decision funds a Jenkins-hosted AS. Prefer OAuth 2.1 authorization-code + PKCE.

| Area | Required profile (if go) |
|------|---------------------------|
| Grant | Authorization code only; **prohibit** implicit and resource-owner password |
| PKCE | **Mandatory** S256 for public clients; reject plain |
| Redirect URIs | **Exact** string match; no wildcards; loopback rules documented |
| DCR | Dynamic client registration **off** by default; admin-approved clients only unless separately approved |
| Issuer / metadata | Stable issuer; OIDC discovery; **JWKS** published with cache/availability SLOs |
| Tokens | Short-lived access JWT; exact **audience** = Jenkins API resource; subject = person |
| Rotation | Signing-key rotation with overlap; refresh rotation + reuse detection |
| Revocation | Per-user/client revoke + admin emergency path; logout coupling as approved |
| Scopes | Map ≤ current Jenkins permissions ∩ MCP policy; never elevate |
| Audit | Issue/refresh/revoke events with principal, client_id, correlation — no secrets |
| Excluded | Device code unless approved; client-credentials for interactive users; shared SA tokens |

Detailed build-out is **JAS-002** (clients/consent/PKCE) → **JAS-003** (tokens/JWKS) → **JAS-004** (refresh/revoke) → **JAS-005** (ops/hardening). None of those land under the default no-go posture.

---

## 4. Default decision and ownership

| Item | Decision |
|------|----------|
| Default | **no-go** (ADR 0011 / path `custom_jenkins_as_plugin` = `no_go_default`) |
| Gate | OAUTH-011 written go with blocker, evidence, funding, owners |
| Long-term AS ownership (if go) | Named security + platform owners for keys, revoke, incidents (JAS-001 AC residual until go) |
| MCP release path | Must not depend on JAS-002…005 |

---

## 4.1 OAUTH-011 formal residual decision log (default **no-go**)

**Status:** Residual formalization of the product default — **not** a production
“shipped AS” claim. **Decision: default no-go** after prototype posture review.

| Field | Record |
|-------|--------|
| Decision | **NO-GO** (default; remains until an explicit funded **go** packet) |
| Date (UTC) | 2026-08-01 (repo residual formalization) |
| Criteria (go would require) | Named blocker that Entra/AgentCore RS, filter/proxy, token exchange, or narrow broker **cannot** solve safely; funded threat model, keys, revoke, conformance, pen-test, owners |
| Evidence considered | ADR 0003 / 0011 / 0013; capability matrix `custom_jenkins_as_plugin=no_go_default`; gateway `ValidateProviderConfig` rejects Jenkins-as-AS; doctor `jenkins_as_as`; offline oauth labs (mock IdP/JWT RS) prove **external** AS paths only |
| Prototypes residual | Live Entra + AgentCore pin still open (OAUTH-009/010 / GWY-003) — absence of those pins does **not** justify Jenkins-as-AS |
| Approvers | Engineering + security co-owners (org sign-off residual for any future **go**) |
| Funding / support horizon | **None** allocated for JAS-002…005 under default no-go |
| Effect on conditional epic | JAS-002…005 **deprioritized / closed until go**; MCP local + Mode A/B/C release paths **must not** depend on Jenkins-hosted AS |
| Code enforcement | `auth.RejectJenkinsAsAuthorizationServer`; `gateway.ValidateProviderConfig`; profile OIDC issuer host check; qualify case `jenkins_as_as_rejected` |
| Related | [ADR 0013](../adr/0013-jas-default-no-go-enforcement.md), [oauth-capability-matrix](oauth-capability-matrix.md), [server-team-hosted §7](../roadmap/server-team-hosted.md) |

**Re-open only** via written OAUTH-011 **go** packet (blocker, evidence, funding,
owners). Desire for Jenkins-branded OAuth endpoints is insufficient.

Regression canaries (must stay green):

```bash
go test ./internal/auth -count=1 -run 'RejectJenkins|JASNoGo|Capability'
go test ./internal/gateway -count=1 -run 'JenkinsAsAS|ValidateProviderConfig_Rejects'
```

---

## 5. Operator checklist (fail closed)

1. Profile `authMethod: oidc_bearer` → `oidc.issuer` is Entra/approved IdP, **not** the Jenkins URL.  
2. Gateway AgentCore AS base URL is Entra/approved AS, **not** the Jenkins origin.  
3. `jenkins-mcp doctor --profile <id> --offline` → check `jenkins_as_as` is OK (or skipped for non-OIDC).  
4. Capability matrix still lists custom Jenkins AS as **default no-go**.  
5. Never point discovery `authorization_endpoint` / `token_endpoint` / `jwks_uri` at the controller host.

---

## 6. Residuals (honest)

| Item | Status |
|------|--------|
| This threat model + enforcement helpers/tests | **This pack (JAS-001 MVP)** |
| OAUTH-011 formal default no-go decision log (§4.1) | **implemented residual formalization (not a live pen-test sign-off) |
| Org security “approval” signature for a future plugin **go** | Residual until funded OAUTH-011 **go** packet |
| JAS-002…005 implementation | **Not started** (correct under default no-go) |
| Live jwt-auth-filter lab / AgentCore pin | Separate OAUTH-009 / GWY residuals |
