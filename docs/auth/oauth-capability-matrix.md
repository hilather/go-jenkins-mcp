# Jenkins OAuth capability matrix (OAUTH-008)

**Status:** Binding classification for MCP auth path selection  
**Related:** [ADR 0003](../adr/0003-jenkins-not-oauth-authorization-server.md), [ADR 0011](../adr/0011-custom-jenkins-authz-plugin-gated.md), [ADR 0013](../adr/0013-jas-default-no-go-enforcement.md), [jas-no-go.md](jas-no-go.md) (JAS-001 threat model), [auth-architecture.md](../auth-architecture.md), [operator-guide](../security/operator-guide.md)  
**Code contract:** `internal/auth/capability_matrix.go` (`go test ./internal/auth -run Capability`); AS co-host reject: `auth.RejectJenkinsAsAuthorizationServer`

This matrix prevents selecting plugins or product language that treat stock
Jenkins as a three-legged OAuth (3LO) **authorization server** for MCP clients
(it is **not** a native 3LO AS — ADR 0003). Jenkins is a **resource server** /
protected API for scripted access.

Machine-readable path levels and plugin roles live in package `auth` as named
constants so tests fail if classifications drift.

---

## 1. Auth path matrix

| Path ID | Description | Level | Notes |
|---------|-------------|-------|-------|
| `api_token` | Personal Jenkins `username:api_token` (Basic) via Linux Secret Service | **supported** | Pilot default (AUTH / ADR 0009) |
| `external_idp_jwt_bearer` | Authorization Code + PKCE at **external IdP**; access token audience = exact Jenkins API resource; Jenkins validates bearer as RS | **conditional** | OAUTH-001 profile/discovery; OAUTH-002+ login/token; needs `jwt-auth-filter` or approved proxy |
| `agentcore_3lo_obo` | Managed-gateway AgentCore 3LO/OBO against **Entra (or approved AS)** → Jenkins-audience token | **residual** | GWY-* / OAUTH-010+; AS endpoints are never stock Jenkins |
| `custom_jenkins_as_plugin` | Full Jenkins-hosted OAuth authorization server (consent, codes, tokens) | **no_go_default** | ADR 0011/0013; threat model [jas-no-go.md](jas-no-go.md); JAS-002…005 only after OAUTH-011 **go** |
| `jwt_auth_filter` | Bearer JWT **resource-server** filter (not an AS) | **conditional** | OAUTH-009: offline contracts + `oauth probe-rs`; **live lab residual** |

### Level definitions

| Level | Meaning |
|-------|---------|
| `supported` | Baseline pilot path |
| `conditional` | Allowed only when external IdP + exact Jenkins audience + qualified RS controls |
| `residual` | Designed; not local-stdio MVP |
| `no_go_default` | Out of baseline; requires funded security decision |
| `not_applicable` | Wrong protocol role for MCP API auth |

---

## 2. Plugin / mechanism classification

| Plugin / mechanism | Actual role | MCP API auth alone? | Stance |
|--------------------|-------------|---------------------|--------|
| **Jenkins core API token** | Scripted Basic API (`scripted_basic_api`) | **Yes** | Preferred pilot path |
| **`oic-auth`** | Browser **security realm** (UI OIDC login) | **No** | Not MCP 3LO; deployments with only `oic-auth` **fall back to `api_token`** |
| **`oidc-provider`** | Outbound workload issuer **from builds** | **No** | Opposite direction; exclude from user→Jenkins MCP auth |
| **`github-oauth`** | GitHub-specific UI realm | **No** | Not general enterprise 3LO |
| **`oauth-credentials`** | Credentials framework for other plugins | **No** | Not a delegated AS |
| **`jwt-auth-filter`** | Bearer JWT **resource server** | Conditional (needs external token) | In-scope for RS qualification; not an AS; harden fallthrough + full MCP route coverage |
| **Approved reverse proxy JWT RS** | Same RS role as filter, at proxy | Conditional | Acceptable when filter is insufficient |
| **Custom Jenkins AS plugin** | Full **authorization server** | Decision-gated | Default **no-go** (ADR 0011) |

### Explicit rule (OAUTH-008 acceptance)

> **A deployment with only `oic-auth` must use the API-token provider** — never attempt bearer API calls as if UI OIDC supplied MCP 3LO tokens.

Code constant: `auth.FallbackAuthMethodWhenOnlyOICAuth == MethodAPIToken`.

---

## 3. External IdP JWT bearer (conditional detail)

| Requirement | Detail |
|-------------|--------|
| Authorization server | Entra or other **approved external IdP** |
| Client | Public client + PKCE (no client secret in profile JSON) |
| Audience | **Exact** Jenkins API resource / `jenkinsAudience` (never Graph-only or generic gateway) |
| Jenkins role | Resource server via `jwt-auth-filter` or approved proxy |
| Discovery | `/.well-known/openid-configuration`; issuer match; reject AS endpoints co-hosted with Jenkins controller |
| CLI | `jenkins-mcp oauth validate-profile --profile <id> [--offline]` (OAUTH-001) |

**Landed (MVP slice):** OIDC token blob store + single-flight refresh (OAUTH-004); logout / status `has_refresh` / recovery hints (OAUTH-007); bearer wire (OAUTH-005 MVP); jwt-auth-filter **offline** qualification matrix + probes (OAUTH-009 docs/contracts); **OAUTH-003 offline** access-token claim matrix + ID-token reject ([oauth-003-claim-validation.md](oauth-003-claim-validation.md)).  
**Residual:** durable discovery/JWKS cache; **live** jwt-auth-filter lab version pins and security go/no-go (OAUTH-005/009).

---

## 4. AgentCore 3LO/OBO (gateway residual — OAUTH-010)

| Item | Decision |
|------|----------|
| AS discovery/authorize/token | **Entra or approved AS**, not stock Jenkins |
| Resource / audience | Dedicated Jenkins API |
| Flows | User-delegated auth code, then OBO/exchange as needed |
| Full Jenkins AS | Only after ADR 0011 go decision |

### Offline / mock vs live (OAUTH-010 honesty)

| Path | Status | Evidence |
|------|--------|----------|
| Gateway Obtain contract (`Live=false` fail-closed) | **Done*** foundation | `internal/gateway` unit tests; no shared SA |
| Offline mock `TokenFetcher` + consent URL metadata | **Done*** offline | Mock AS / `HTTPTokenFetcher` https-only tests |
| Docker mock token peer (HOST-015) | **Scaffold** opt-in | `testdata/oauth-lab/` `mock-token`; `make live-oauth-*` |
| Live Entra 3LO + OBO + durable vault | **Residual** | OAUTH-010 / GWY-001 / GWY-003 production pin |
| AgentCore production binary pin | **Residual** | GWY-003 / GWY-004 |

Cross-links: [gateway/README.md](../gateway/README.md), [jwt-auth-filter-qualification.md](jwt-auth-filter-qualification.md) §9, HOST-012…015 in [roadmap](../roadmap/server-team-hosted.md), lab [`testdata/oauth-lab/README.md`](../../testdata/oauth-lab/README.md).

---

## 5. `jwt-auth-filter` residual checklist (OAUTH-009)

**Full qualification write-up:** [jwt-auth-filter-qualification.md](jwt-auth-filter-qualification.md)  
**Code:** `internal/auth/rs_qualification.go` · `go test ./internal/auth -run 'RS|Fallthrough|JWKSOutage|RequiredMCP|ProtectedResource|Classify'`  
**CLI:** `jenkins-mcp oauth probe-rs --profile <id> [--offline]` · doctor check `rs_auth` · security self-check `rs_qualification`

| Topic | Offline status | Live lab |
|-------|----------------|----------|
| Role | RS only — validates externally issued JWTs | — |
| Does **not** | Issue codes, host consent, or act as 3LO AS | — |
| `invalid_bearer_fallthrough` | `Done*` offline classifier (`OfflineFallthroughFixtures` + simulated RS); Wave 33 empty/HTML error/Bearer WWW-Authenticate | Must re-prove on real plugin |
| `incomplete_route_coverage` | **contract_tested** (`RequiredMCPRoutes`, inventory completeness, progressive OutsideAPIGlob) | Path includes in JCasC |
| `multi_issuer` / `alg_none` | **contract_tested** (`ValidateAccessToken`) | RS must match |
| `jwks_outage` | **contract_tested** (MCP fail-closed); **live residual** for Jenkins RS cache TTL | Fail-closed + cache TTL on controller |
| RFC 9728 PRM | **parser + edge validation** (fixture only; no live fetch) | Publication path residual |
| Doctor / self-check / probe | Matrix + classifier fixture count + `live_lab_still_required` (secret-free); optional online sample | Plugin version auto-detect residual |
| Production go/no-go | **Not claimed offline** (classifier Done* only) | Security sign-off residual |

### Tested versions / endpoints (living table)

Lab version pins remain **unqualified** until TST-001 / operator evidence:

| Component | Version under test | Expected headers / endpoints | Evidence |
|-----------|--------------------|------------------------------|----------|
| Jenkins LTS | *TBD (TST-001)* | REST + progressive text + Pipeline + artifacts | residual |
| `jwt-auth-filter` | *TBD* | `Authorization: Bearer <JWT>`; JWKS from IdP | residual |
| API token path | Jenkins core | Basic `user:token`; `/whoAmI/api/json` | AUTH-004 |
| Offline contracts | N/A (httptest) | Fallthrough deny; route inventory; JWT iss/aud/alg; JWKS outage; RFC 9728 parser | OAUTH-009 tests |

---

## 6. Consistency checklist

1. Never label `oic-auth` / UI OIDC as “MCP 3LO” or “Jenkins OAuth provider.”  
2. Name the **external IdP** as the authorization server for PKCE/3LO.  
3. Custom Jenkins AS remains **default no-go**.  
4. Run `go test ./internal/auth -run 'Capability|Terminology'` after doc edits.  
5. Prefer updating this file + `capability_matrix.go` together.
