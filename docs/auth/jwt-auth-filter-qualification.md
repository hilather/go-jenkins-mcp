# jwt-auth-filter qualification (OAUTH-009)

**Status:** Offline classifier + Bearer claim matrix + free mock RS lab `implemented` (product free-lab bar). **Site** production Jenkins / Entra / jwt-auth-filter pin = **operator residual** — [free-lab-qualification.md](../gateway/free-lab-qualification.md); **do not claim site Entra implemented  
**Related:** [oauth-capability-matrix.md](oauth-capability-matrix.md), [auth-architecture.md](../auth-architecture.md), [../gateway/qualification.md](../gateway/qualification.md) (GWY-003), **[../gateway/live-pin-blockers.md](../gateway/live-pin-blockers.md)** (consolidated live production GO residual), architecture §6.8  
**Code:** `internal/auth/rs_qualification.go` (+ `rs_fallthrough.go`, `rs_jwks_contract.go`, `rs_inventory.go`, `rs_prm.go`); `internal/gateway/oauth009_offline_test.go`; `internal/gateway/qualify` case `oauth009_offline_bearer_matrix`  
**Tests:** `go test ./internal/auth ./internal/gateway ./internal/gateway/qualify -count=1` · `-run 'OAUTH009|Fallthrough|RS|OfflineFallthrough|ModeB'`  
**CLI:** `jenkins-mcp oauth probe-rs --profile <id> [--offline]` · doctor check `rs_auth` · `jenkins-mcp security self-check` item `rs_qualification` · `jenkins-mcp gateway qualify --offline` (GWY-003)

This document qualifies **Jenkins as a bearer JWT resource server (RS)** for the
MCP. Stock Jenkins is **not** a three-legged OAuth authorization server
([ADR 0003](../adr/0003-jenkins-not-oauth-authorization-server.md)). The closest
in-tree option is the
[`jwt-auth-filter`](https://plugins.jenkins.io/jwt-auth-filter/) plugin (or an
approved reverse-proxy JWT RS, or a hardened fork).

> **Go/no-go residual:** Offline contracts, classifier fixtures, claim
> fail-closed matrix, and operator probes are shippable now (`implemented` for the
> offline path). Production **go** still requires live lab evidence
> (plugin/Jenkins LTS pins, JCasC, security review) — see §8. Offline `implemented`
> **never** closes live Entra / jwt-auth-filter pin.
>
> A worked **optional operator** Entra + jwt-rs-lab walkthrough lives at
> [../testing/entra-jwt-rs-lab.md](../testing/entra-jwt-rs-lab.md). That page is
> **not** a production pin and does not flip `mode_*_live_*_qualified`.
>
> **HOST-010 / Mode B note:** Gateway Mode B offline path (`JWTRSBearerProvider`
> + `JWTVault` under `internal/gateway`) can Obtain → Bearer for lab tokens
> keyed by subject. That is **not** a live jwt-auth-filter production pin.
> Access tokens only (**never** ID tokens as Jenkins API credentials). Doctor /
> self-check elevate **warn** when Mode B is enabled (`jwt_rs_bearer`) and set
> `mode_b_live_rs_qualified=false`. See [../gateway/README.md](../gateway/README.md)
> Mode B and GWY-003 [qualification.md](../gateway/qualification.md).

### Offline-automated vs live-lab residual (matrix)

| Surface | Offline-automated | Live-lab residual |
|---------|-------------------|-------------------|
| Fallthrough deny (status + WWW-Authenticate + body class) | `implemented` — `ClassifyFallthroughProbe`, `OfflineFallthroughFixtures`, simulated RS | Re-prove on real plugin / all §3 paths |
| Empty body / HTML error page / Bearer WWW-Authenticate | `implemented` Wave 33 fixture rows | Real Stapler/proxy pages may differ |
| Invalid-bearer success as authenticated | `implemented` fail closed (`FallthroughDetected`) | Must re-prove on controller |
| **Invalid Bearer never succeeds as Basic/anonymous** | `implemented` — OAuth-required route fixtures on `RequiredMCPRoutes` + mock RS classifier matrix (`TestOAUTH009_InvalidBearerMustNotSucceedAsBasicOrAnonymous`, `TestMockRS_OAuthRequiredRouteFallthroughMatrix`); Basic+authn and anonymous 2xx fixture rows | Must re-prove on controller (live Entra **not** Done) |
| **Wrong `aud` / `exp` / `iss` on Jenkins-shaped paths** | `implemented` — `ValidateAccessToken` + simulated JWT RS on `RequiredMCPRoutes` (`TestOAUTH009_OfflineBearerClaimMatrix_*`) | Re-prove on controller with real filter + Entra-issued tokens |
| **ID token never as API credential** | `implemented` — MCP validator + Mode B `JWTVault` Put reject + qualify `mode_b_jwt_vault_bearer` | Live RS must not treat `token_use=id_token` as API principal |
| **Mode B Obtain never Basic fallthrough** | `implemented` — HOST-011 / `oauth009_offline_bearer_matrix` / `TestOAUTH009_ModeB_*` (Obtain+Basic never mixed table) | Production mode switch ops evidence |
| Route inventory (unique IDs, `progressive_text` OutsideAPIGlob) | **Yes** — `ValidateRequiredMCPRoutesInventory` | JCasC path includes on controller |
| JWKS outage fail-closed (MCP client) | **Yes** — `EvaluateJWKSOutage*`, nil/empty JWKS + `FetchJWKS` errors | Jenkins RS cache TTL / rotation under load |
| Multi-issuer / `alg=none` | **Yes** — `ValidateAccessToken` | RS plugin must match |
| RFC 9728 protected resource metadata | **Parser + edge validation** (fixture JSON; no live fetch) | Controller publication + discovery path |
| Mock OIDC + mock RS Docker lab | Opt-in `make live-oauth-*` (HOST-012…014); `-tags=live_oauth` mock-rs health | **Not** production Entra / jwt-auth-filter |
| **Free real plugin lab** (Keycloak + `jwt-auth-filter`) | Opt-in `make live-jwt-rs-*` · `testdata/jwt-rs-lab/` | **Not** site Entra / production controller pin |
| Plugin/LTS version pins, go/no-go sign-off | No | **Required** before production `oidc_bearer` / Mode B live |

### Offline Bearer claim matrix (Jenkins-shaped paths)

Contract tests (no network) that fail closed for OAuth-required MCP routes:

| Case ID | Token / request shape | Expected offline outcome |
|---------|----------------------|--------------------------|
| `wrong_aud` | Signed JWT, `aud` ≠ Jenkins audience (e.g. Graph) | `ValidateAccessToken` fail; simulated RS **401** on every `RequiredMCPRoutes` example path |
| `wrong_iss` | Signed JWT, foreign `iss` | Same — fail closed |
| `expired` | Signed JWT, `exp` in the past | Same — fail closed |
| `id_token` | `token_use=id_token` (or ID-token shape) | Rejected as **API credential** (MCP + Mode B vault) |
| `garbage` / empty Bearer | Non-JWT / empty | Simulated RS **401**; classifier `Denied` |
| `invalid_bearer_plus_session` | Invalid Bearer + `JSESSIONID` | Still **401** (no session fallthrough) |
| `mode_b_empty_vault` | Mode B Obtain, empty JWT vault, Mode A vault co-resident | Obtain error; **no** Basic / Mode A token |
| `mode_b_hit` | Mode B vault hit | `HTTPAuth` scheme **Bearer** only (never Basic) |
| `invalid_bearer_basic_alone_oauth_required` | Invalid Bearer **or** Basic alone on OAuth-required routes | Simulated/mock RS **401**; classifier `Denied` (no Basic/anon success) |
| `unqualified_basic_fallthrough` | Anti-pattern: invalid Bearer → 200 authenticated Basic principal | Classifier `FallthroughDetected` (probe fail) |

Live residual checklist for the **same** rows is in §4 / §8 — re-prove with
real plugin version pins before production go. **Do not claim live Entra Done.**

---

## 1. Threat model (RS-specific)

| Threat ID | Symptom | Required control | Offline status |
|-----------|---------|------------------|----------------|
| `invalid_bearer_fallthrough` | Client sends `Authorization: Bearer <invalid>`; Jenkins answers **200** via Basic, UI `JSESSIONID`, or **anonymous** | When Bearer is present and invalid → **401/403**; no alternate authenticator success | **contract_tested** / offline-automated (simulated RS + `ClassifyFallthroughProbe`) |
| `incomplete_route_coverage` | Filter matches only `/**/api/**` or `/mcp/**`; progressive logs / artifacts / wfapi remain open | Cover **all** MCP route inventory (§3), especially non-`api` globs | **contract_tested** / offline-automated (`RequiredMCPRoutes` + inventory completeness) |
| `jwks_outage` | IdP JWKS unreachable → tokens accepted without signature check, or forever-stale cache | **Fail closed** for new verifications; bounded cache + rotation-aware refresh | **contract_tested** (MCP client); **live-lab residual** for Jenkins RS cache TTL |
| `multi_issuer` | Shared JWKS / multi-tenant keys accept foreign `iss` or wrong `kid` | Exact `iss` + audience; kid selection; signature alone insufficient | **contract_tested** (JWT validator) |
| `alg_none` | Compact JWT with `alg=none` (or empty) accepted | Reject `none` and non-allowlisted algs (MVP: RS256, ES256) | **contract_tested** |

Machine-readable checklist: `auth.DefaultRSThreatChecklist()`  
Contract: `auth.FallthroughMustDeny == true`, `auth.RequiredJWKSOutageBehavior == "fail_closed"`.

### Fallthrough (must deny)

OAuth-required controllers **must not** implement “try Bearer, then Basic, then
session, then anonymous” success for a request that already carried an invalid
Bearer. Evaluation helpers:

```text
EvaluateInvalidBearerResponse(status, authenticated, anonymous)
  → thin wrapper over ClassifyFallthroughProbe

ClassifyFallthroughProbe(status, WWW-Authenticate, body class)
  401/403        → Denied (pass); Bearer WWW-Authenticate noted when present
  2xx + auth/anon/HTML login/error JSON → FallthroughDetected (fail)
  0 / 5xx / other → inconclusive (not a pass)
```

Body classes: `whoami_authenticated`, `whoami_anonymous`, `error_json`,
`html_login`, `html_error`, `empty`, `unknown` (`ClassifyResponseBodyClass`).

Offline fixture table (Wave 33 + OAUTH-009 Basic/anon expand):
`auth.OfflineFallthroughFixtures()` and `FormatFallthroughClassifierMatrix()`
(printed by `oauth probe-rs --offline`). Includes Basic+authenticated 2xx fail,
anonymous 2xx fail, and 401 status-wins rows. Doctor / self-check / support-bundle
expose `fallthrough_fixture_count`, `classifier_matrix_done_star=true`,
`live_lab_still_required=true` (secret-free). Mode B elevates **warn** with
`residual_id=oauth009_offline`.

---

## 2. Plugin / proxy version fields (TBD template)

Fill during live lab (TST-001). Until filled, treat as **unqualified**.

| Field | Value | Evidence |
|-------|-------|----------|
| Jenkins LTS | *TBD* | `X-Jenkins` header / `/api/json` |
| `jwt-auth-filter` version | *TBD* | `/pluginManager/api/json` shortName `jwt-auth-filter` |
| Approved proxy (if used) | *TBD name + version* | edge config hash / change ticket |
| IdP (issuer) | *TBD* | profile `oidc.issuer` |
| Exact Jenkins audience | *TBD* | profile `oidc.jenkinsAudience` |
| JWKS URI | *TBD* | discovery `jwks_uri` |
| Path include patterns | *TBD* | JCasC / plugin UI export |
| Path exclude patterns | *TBD* | must not punch holes in §3 |
| Claim → principal mapping | *TBD* | e.g. `preferred_username` / `sub` |
| Group claim / overage | *TBD* | Entra overage residual if used |
| RFC 9728 metadata path | *TBD* | if published |
| Lab date / approver | *TBD* | security sign-off |

### Config checklist (operator)

- [ ] External IdP issues access tokens with **exact** Jenkins API audience (never Graph-only).
- [ ] RS plugin/proxy validates signature via JWKS; **alg allow-list** excludes `none` / HS*.
- [ ] Exact **issuer** allow-list; multi-issuer only when every issuer is approved.
- [ ] Protected paths include progressive log, artifact, and Pipeline REST (wfapi) — not only `/**/api/**`.
- [ ] Invalid Bearer → 401/403 with **no** session cookie / Basic fallthrough success.
- [ ] JWKS outage → fail closed; document cache TTL and key-rotation overlap window.
- [ ] Principal/group mapping reviewed; overage path documented or groups unused for authz.
- [ ] Emergency disable / rollback plan (disable filter → temporary API-token-only pilot).
- [ ] Audit identity visible as individual principal (no shared bot account for interactive users).
- [ ] Performance spot-check under concurrent MCP clients (no catastrophic JWKS fetch-per-request without cache).

### JCasC / proxy sketch (illustrative — not production-approved)

```yaml
# ILLUSTRATIVE ONLY — replace with lab-approved values.
# jwt-auth-filter configuration shape varies by plugin version; verify against
# the exact version under test before production.
unclassified:
  # Pseudocode keys — map to real JCasC attributes in lab.
  jwtAuthFilter:
    issuer: "https://login.microsoftonline.com/<tenant>/v2.0"
    audience: "api://jenkins-corp-resource"
    jwksUrl: "https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys"
    # MUST include non-api routes used by MCP (see §3).
    pathIncludes:
      - "/**"
    # Prefer deny-by-default with explicit includes over broad excludes.
```

Approved reverse proxy (alternative): terminate JWT at the edge with the same
audience/issuer/JWKS rules and inject a trusted identity to Jenkins only after
validation — still subject to full route coverage and fallthrough tests.

---

## 3. MCP route inventory (must be RS-covered)

Constants: `auth.RequiredMCPRoutes`. Protecting **only** `/mcp/**` or only
`/**/api/**` is **insufficient** — the local MCP calls classic Jenkins REST,
progressive text, artifacts, and Pipeline REST.

| ID | Pattern | Outside `/**/api/**`? | Why (MCP) |
|----|---------|----------------------|-----------|
| `whoami` | `/whoAmI/api/json` | no | Identity bind (AUTH-004), doctor |
| `root_api` | `/api/json` | no | Health / roots |
| `job_api` | `/**/job/*/api/json` | no | Jobs / builds |
| `build_api` | `/**/job/*/<n>/api/json` | no | Build detail |
| `progressive_text` | `/**/logText/progressiveText` | **yes** | LOG-001 logs |
| `artifact_download` | `/**/artifact/**` | **yes** | ART-001/002 |
| `wfapi_describe` | `/**/wfapi/describe` | **yes** | PIPE-001 stages |
| `wfapi_node_log` | `/**/execution/node/*/wfapi/log` | **yes** | PIPE-002 stage log |
| `queue_api` | `/queue/api/json` | no | Queue pressure |
| `queue_item` | `/queue/item/*/api/json` | no | Queue item wait |
| `computer_api` | `/computer/api/json` | no | Nodes |
| `crumb_issuer` | `/crumbIssuer/api/json` | no | Mutations (when enabled) |
| `plugin_manager` | `/pluginManager/api/json` | no | Capability / plugin detect |

Seed tools map primarily to job/build/queue/log routes; enterprise tools add
pipeline, artifacts, test reports, and controller health — all still Jenkins
HTTP paths on the same origin.

---

## 4. Fail-closed operator tests (live lab)

Run against a **real** Jenkins with the candidate filter/proxy. Record status
codes and (non-secret) `whoAmI` fields. Never paste access tokens into tickets.

### 4.1 Invalid bearer fallthrough

For **each** example path in §3 (or at minimum all `OutsideAPIGlob=true`):

1. `Authorization: Bearer not-a-valid-jwt`  
2. Repeat with a garbage JWT shape (`eyJ…` three segments, bad signature).  
3. Repeat with a **validly signed** token for **wrong audience**.  
4. Repeat with expired token.  
5. Optionally attach a leftover `JSESSIONID` from a browser UI login.

**Pass:** HTTP **401 or 403** every time.  
**Fail:** HTTP **200** (especially authenticated or anonymous whoAmI).

CLI assist (when network allowed):

```bash
jenkins-mcp oauth probe-rs --profile <oidc-profile>
```

### 4.2 Valid bearer identity

With a user logged in via `jenkins-mcp login --profile <id> --oidc` (or lab token):

```bash
jenkins-mcp status --profile <id>
jenkins-mcp doctor --profile <id>   # identity + rs_auth checks
```

**Pass:** bearer `whoAmI` returns the **expected individual** principal (not anonymous, not a shared bot).

### 4.3 oic-auth only (negative)

If the controller has **only** `oic-auth` (browser realm) and **no** bearer RS:

- Doctor / probe **warn**: browser realm is not MCP 3LO.  
- Use **api_token** for scripted MCP (`FallbackAuthMethodWhenOnlyOICAuth`).  
- Do **not** send IdP access tokens expecting Jenkins API auth.

### 4.4 JWKS outage

1. Block network path to JWKS (or point filter at a dead URL in a **lab** controller).  
2. Present a previously unseen token (or after cache flush).  

**Pass:** authentication denied (fail closed).  
**Fail:** tokens accepted without signature verification.

### 4.5 Multi-issuer / alg=none

- Token `iss=A` signed by keys for `iss=B` → deny.  
- `alg=none` compact JWT → deny at RS and in MCP `ValidateAccessToken`.

---

## 5. MCP-side contracts (already enforced offline)

| Control | Location |
|---------|----------|
| Reject `alg=none` / HS256 / non-RS256-ES256 | `internal/auth/jwt.go` |
| Exact issuer + Jenkins audience | `ValidateAccessToken` |
| ID token / Graph / known-bad audiences | `jwt_test.go` completeness table + `oauth-003-claim-validation.md` |
| Wrong issuer / kid / exp / nbf / azp / tid | `jwt_test.go` fail-closed cases |
| Multi-key JWKS without kid | fail closed (`KeyByID`) |
| Login + serve wire | `LoginOIDC`, `ValidateServeAccessToken` |
| Bearer wire (no Basic mix-up) | `internal/jenkins` bearer tests |
| Fallthrough evaluator + route inventory | `rs_qualification.go` / `rs_fallthrough.go` (`ClassifyFallthroughProbe`) |
| Offline fixture matrix (empty / HTML error / Bearer WWW-Authenticate) | `OfflineFallthroughFixtures` (Wave 33) |
| Simulated RS: invalid Bearer + session → 401 | `rs_qualification_test.go` |
| JWKS outage fail-closed (nil/empty/fetch error) | `EvaluateJWKSOutage*`, `ValidateAccessToken`, `FetchJWKS` |
| Route inventory completeness | `ValidateRequiredMCPRoutesInventory` |
| RFC 9728 PRM fixture parser + edge validation | `ParseProtectedResourceMetadata` / `ValidateProtectedResourceMetadata` |

---

## 6. Decision tree (go / no-go / replace)

```text
1. Can jwt-auth-filter (version pin) cover §3 routes + fallthrough deny?
   yes → lab sign-off → conditional production with monitoring
   no  → approved reverse-proxy JWT RS with same contracts?
         yes → proxy go (document ownership)
         no  → hardened fork / companion filter (security review + rollback plan)
              or defer oidc_bearer; remain on api_token pilot
```

Default without lab evidence: **no production go** for `oidc_bearer` against that
controller. API token pilot remains supported (`api_token`).

---

## 7. CLI / doctor / security self-check

| Command | Behavior |
|---------|----------|
| `jenkins-mcp oauth probe-rs --profile <id> --offline` | Print matrix, **classifier fixture table**, routes, threats, offline_automated, residuals (no network; secret-free) |
| `jenkins-mcp oauth probe-rs --profile <id>` | Offline report + when possible bearer whoAmI and invalid-bearer sample probes (WWW-Authenticate + body class) |
| `jenkins-mcp doctor --profile <id> [--offline]` | Check `rs_auth`: inventory_ok, jwks_outage_acceptable, `classifier_matrix_done_star`, `live_lab_still_required`, offline_automated; **warn** when gateway Mode B enabled |
| `jenkins-mcp security self-check [--json] [--profile <id>]` | Item `rs_qualification` (OAUTH-009): residual summary without secrets; warn on `oidc_bearer` **or** Mode B (`jwt_rs_bearer`) |
| `jenkins-mcp gateway qualify --offline` | GWY-003 suite including `oauth009_offline_bearer_matrix` + Mode A/B/C (not live Entra) |
| `jenkins-mcp oauth validate-profile` | OIDC profile + discovery (OAUTH-001); not a full RS lab |

All of the above remain **offline-friendly** (`--offline` / no network for self-check).

### Mode B residual honesty (doctor / self-check)

When `JENKINS_MCP_GATEWAY_CREDENTIAL_MODE=jwt_rs_bearer` (or Mode B in
`JENKINS_MCP_GATEWAY_ENABLED_MODES`):

| Field / surface | Offline value | Meaning |
|-----------------|---------------|---------|
| `gateway_mode_b_enabled` | `true` | Mode B primary or enabled |
| `mode_b_live_rs_qualified` | **`false` always offline** | Never claim live pin |
| `residual_id` | **`oauth009_offline`** | REL lite / pilot checklist residual id link |
| `oauth009_offline` | **`true`** | Same residual id as boolean flag (doctor `rs_auth` + self-check `rs_qualification`) |
| `gateway_mode_matrix_residual` | HOST-010 / OAUTH-009 residual string | Operator-visible residual |
| `id_jwt_never_api_credential` | `true` | Contract reminder (ID JWT never API cred; key avoids scrubbed `token` substring) |
| `live_lab_still_required` | `true` | Production pin open |
| status | **warn** (unless contracts broken → fail) | Honest residual elevation |

Offline JWT vault **Ready** does **not** clear these residuals. Doctor
`gateway_status` also sets `oauth009_offline_only=true` (unified residual honesty).

---

## 8. Residuals (explicit)

**Consolidated operator runbook** (version/JCasC/routes/evidence + residual-smoke
honesty + Mode C / multi-pod neighbors):
[../gateway/live-pin-blockers.md](../gateway/live-pin-blockers.md) §2 (OAUTH-009).

### Live lab (not offline-automated) — still required for production pin

- [ ] Live Jenkins LTS + `jwt-auth-filter` (or proxy) version pins in §2 table  
- [ ] Security-approved JCasC/proxy config and written go/no-go  
- [ ] Lab evidence for **Jenkins RS** JWKS outage, rotation, and concurrent load  
- [ ] Live invalid-bearer fallthrough on all `RequiredMCPRoutes` (especially OutsideAPIGlob)  
- [ ] RFC 9728 metadata publication path on controller (parser only offline)  
- [ ] Group overage / large-group resolution if groups drive Jenkins authz  
- [ ] Performance and audit-identity evidence under pilot load  
- [ ] Emergency disable runbook signed by ops  

### Offline-automated — checked when tests green

**Wave 19**

- [x] `ClassifyFallthroughProbe` status / WWW-Authenticate / body-class matrix  
- [x] JWKS outage fail-closed pure contracts + `ValidateAccessToken` nil/empty JWKS  
- [x] `RequiredMCPRoutes` inventory completeness (unique IDs, progressive_text OutsideAPIGlob)  
- [x] RFC 9728 protected resource metadata **parser** (fixture JSON)  
- [x] doctor `rs_auth` + security self-check `rs_qualification` residual summary  

**Wave 33 (`implemented` for classifier only)**

- [x] Expanded body classes: empty, `html_error`, HTML login, Bearer `WWW-Authenticate`  
- [x] `OfflineFallthroughFixtures` + `FormatFallthroughClassifierMatrix` in `oauth probe-rs --offline`  
- [x] Invalid-bearer authenticated success → always `FallthroughDetected` (fail closed)  
- [x] PRM edge validation (relative/ftp/empty AS/scopes, jwks_uri credentials)  
- [x] Online probe path uses body class + WWW-Authenticate (not whoAmI flags alone)  
- [x] Secret-free matrix fields on doctor / self-check / support-bundle (`live_lab_still_required=true`)  

**OAUTH-009 expand (offline foundations — still not live Entra Done)**

- [x] Wrong `aud` / `exp` / `iss` + ID-token reject on Jenkins-shaped `RequiredMCPRoutes` (`TestOAUTH009_OfflineBearerClaimMatrix_*`)  
- [x] Mode B Obtain never falls through to Basic (`TestOAUTH009_ModeB_*` Obtain+Basic never-mixed table, qualify `oauth009_offline_bearer_matrix`)  
- [x] Doctor `rs_auth` + self-check `rs_qualification` **warn** when Mode B enabled (`mode_b_live_rs_qualified=false`; `residual_id=oauth009_offline`)  
- [x] Invalid Bearer never succeeds as Basic/anonymous on OAuth-required route fixtures (`TestOAUTH009_InvalidBearerMustNotSucceedAsBasicOrAnonymous`)  
- [x] Mock RS classifier matrix + OfflineFallthroughFixtures Basic/anon rows (`internal/authlab` `TestMockRS_*`)  
- [x] Expanded fixture rows: `200_whoami_authenticated_basic_www`, anonymous Bearer remnant, 401 status-wins  
- [x] Cross-links: oauth-lab + `make live-oauth-*` + `-tags=live_oauth` mock-rs health + GWY-003 qualify residuals  

Offline **contract tests do not replace** live lab. Do not mark architecture
acceptance criteria complete until live-lab §8 items have evidence.
**Do not claim live Entra / jwt-auth-filter implemented from this offline expand.

## 9. Offline qualification vs live residual (OAUTH-009 honesty)

| Path | What it proves | What it does **not** prove |
|------|----------------|----------------------------|
| **Default `make test` / pure-Go** | Classifier fixtures, wrong aud/exp/iss, ID-token reject, Mode B no Basic fallthrough, JWKS outage, route inventory | Real Jenkins plugin behavior under load |
| **`jenkins-mcp oauth probe-rs --offline`** | Secret-free matrix + fixture table operators can archive | Plugin version pin / JCasC go |
| **`jenkins-mcp gateway qualify --offline` (GWY-003)** | Modes A/B/C Obtain matrix + `oauth009_offline_bearer_matrix` | Live AgentCore / Entra / jwt-auth-filter pin |
| **Docker mock lab (`make live-oauth-*`)** | Mock OIDC mint + mock RS fail-closed + mock token peer (HOST-012…015) | Real `jwt-auth-filter` plugin, real Entra |
| **Live Jenkins + plugin / proxy + Entra** | Production-shaped RS pin | — (**required** for OAUTH-009 go; still open) |

### Mock lab + GWY-003 cross-links (HOST-012…015)

| Task | Lab surface | Makefile / command |
|------|-------------|--------------------|
| HOST-012 umbrella | `testdata/oauth-lab/` | `make live-oauth-up` / `live-oauth-test` / `live-oauth-down` |
| HOST-014 mock OIDC IdP | `mock-oidc` :18081 | discovery, JWKS, token mint scenarios |
| HOST-013 mock JWT RS | `mock-rs` :18082 | Bearer whoAmI; **no** Basic/session fallthrough; wrong aud/exp/iss → 401 |
| HOST-015 mock token / 3LO peer | `mock-token` :18083 | HTTPTokenFetcher-shaped JSON; wrong-aud / consent fixtures |
| GWY-003 offline qualify | `internal/gateway/qualify` | `jenkins-mcp gateway qualify --offline` · `go test ./internal/gateway/qualify` |
| HOST-011 Mode B offline | `internal/gateway` JWT vault | package `TestHOST011_*` / `TestOAUTH009_ModeB_*` |

```bash
# Opt-in only — never part of default make test / make ci
export PATH="$HOME/.local/go/bin:$PATH"
make live-oauth-test          # up + smoke + down -v
go test -count=1 ./internal/authlab/...   # offline mock contracts without Docker
go test -count=1 ./internal/auth/ ./internal/gateway/ ./internal/gateway/qualify/
jenkins-mcp oauth probe-rs --profile corp --offline
jenkins-mcp gateway qualify --offline
jenkins-mcp doctor --profile corp --offline   # rs_auth residual; Mode B → warn
jenkins-mcp security self-check --json        # rs_qualification residual
```

Lab README: [`../../testdata/oauth-lab/README.md`](../../testdata/oauth-lab/README.md).  
GWY-003: [`../gateway/qualification.md`](../gateway/qualification.md).  
Roadmap: [`../roadmap/server-team-hosted.md`](../roadmap/server-team-hosted.md).

**Residuals that remain open after offline + mock lab:**

- [ ] Real Jenkins LTS + `jwt-auth-filter` (or approved proxy) version pin in §2  
- [ ] Security-approved JCasC and written production go/no-go  
- [ ] Live invalid-bearer fallthrough on all `RequiredMCPRoutes` (wrong aud/exp/iss re-prove)  
- [ ] Live Entra issuer/JWKS/audience (not lab mock keys) — **not claimed implemented  
- [ ] Production AgentCore / OAUTH-010 pin (separate from this RS doc)  
- [ ] Gateway Mode B production pin after live RS go (offline vault ≠ live)

Offline `implemented` and mock-lab green **never** close the live RS production pin.
Do **not** mark OAUTH-009 acceptance criteria complete without live evidence.
