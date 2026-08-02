# Live pin blockers — operator production pin runbook

**Status:** **Operator-owned production pin** residual runbook. Product **free-lab /
offline Tier A** is **Done\*** and is **not** blocked on corporate Entra, AgentCore,
or customer Jenkins labs (see [free-lab-qualification.md](free-lab-qualification.md)).  
**Audience:** site security / platform operators (when they need production GO);
agents must not treat this file as open product engineering DoD.  
**Related:** [free-lab-qualification.md](free-lab-qualification.md) ·
[README.md](README.md) · [qualification.md](qualification.md) ·
[deployment.md](deployment.md) · [jwt-auth-filter qualification](../auth/jwt-auth-filter-qualification.md) ·
[oauth-capability-matrix](../auth/oauth-capability-matrix.md) ·
[server-team-hosted roadmap](../roadmap/server-team-hosted.md) ·
[pilot checklist](../pilot/checklist.md) · [release gates](../release/gates.md)

---

## 0. Honesty banner (read first)

| Claim | Reality |
|-------|---------|
| Offline `gateway qualify --offline` green | **Product contracts** — not site Entra / production RS / multi-pod HA |
| Free labs (`live-jenkins-*`, `live-oauth-*`, `live-saml-*`) green | **Product free-lab qualification** — not corporate production pin |
| `make residual-smoke` green | Residual **ids still present** + honesty — **not** site production GO |
| Mode B JWT vault Ready | Offline/lab Obtain → Bearer — **not** site jwt-auth-filter pin |
| Mode C Live opt-in + mock AS | Wire-shaped HTTP — **not** AgentCore / production Entra |
| Kustomize `sessionAffinity` + `replicas: 1` | Packaging honesty — **not** multi-replica runtime |
| Doctor `mode_*_live_*_qualified=false` | **Correct** until **that site** attaches production evidence — do not “fix” from free labs |

**Product:** free-lab + offline paths may be **Done\*** without Entra.  
**Operator:** do **not** mark site production GO or flip `mode_*_live_*_qualified`
from mocks / free labs alone.

### Terminology canaries (always)

| Correct | Forbidden |
|---------|-----------|
| Jenkins is a **resource server (RS)** for bearer JWTs | Jenkins is a native **3LO authorization server** |
| AgentCore / gateway AS endpoints → **Entra (or approved AS)** | AgentCore AS URL / authorize / token → **stock Jenkins** |
| `jwt-auth-filter` (or approved proxy) = **bearer RS filter** | Filter “provides complete OAuth 3LO” by itself |
| Mode A personal API token vault | Shared Jenkins **service account** for interactive users |
| Audience = **exact Jenkins API resource** | Graph-only / generic gateway audience sent to Jenkins |

See [ADR 0003](../adr/0003-jenkins-not-oauth-authorization-server.md),
[jas-no-go.md](../auth/jas-no-go.md), architecture §6.6 / §6.8.

---

## 1. What blocks **site production** GO (operator summary)

These rows block a **site** from claiming production multi-user gateway GO on
**their** controllers/IdP. They do **not** block product free-lab Tier A Done\*
([free-lab-qualification.md](free-lab-qualification.md)).

Local Cursor **stdio** + personal API token remains the default pilot surface
(ADR 0002).

| Blocker cluster | Task IDs | Blocks **site** claim | Product free-lab / offline | Operator live still required for **their** prod |
|-----------------|----------|----------------------|----------------------------|--------------------------------------------------|
| **Jenkins RS pin** | **OAUTH-009**, HOST-010, GWY-003 Mode B | Mode B against **their** Jenkins | Fallthrough classifier, claim matrix, Mode B vault, oauth-lab mock RS, residual ids | **Their** LTS + plugin/proxy version, JCasC, route re-prove |
| **Entra + AgentCore obtain** | **OAUTH-010**, GWY-001/003 Mode C | Mode C against **their** Entra/AgentCore | Mock AS, ConsentRequired, ModeMatrix, live-oauth mock-token | App reg, Conditional Access, real 3LO/OBO, durable vault |
| **Multi-pod HA** | **HOST-008 cancelled** | ~~`replicas` > 1~~ **not a product path** | Single-replica + multi-fleet | Scale with **[multi-fleet](../fleet/multi-fleet-rollout.md)** (N independent members), not multi-pod HA |
| **Mode matrix ops** | HOST-011, REL-002 | Claiming “all modes live” in prod | Fail-closed offline + free labs | Per-mode **site** evidence + mode-selection record |

**Tier A product default:** single replica; free labs + offline. **Site** enables
modes only after **their** pin evidence. **Multi-pod HA is out of scope** (HOST-008 cancelled); enterprise scale is multi-fleet.

---

## 2. OAUTH-009 — live jwt-auth-filter pin checklist

**Detail SoT:** [jwt-auth-filter-qualification.md](../auth/jwt-auth-filter-qualification.md)
(§2 version fields, §3 routes, §4 live lab tests, §8 residuals).  
**Gateway Mode B:** [README.md](README.md) Mode B + [qualification.md](qualification.md)
`oauth009_offline_bearer_matrix`.

### 2.1 Version / pin fields (fill before go)

| Field | Value | Evidence |
|-------|-------|----------|
| Jenkins LTS | *TBD* | `X-Jenkins` / `/api/json` |
| `jwt-auth-filter` version | *TBD* | `/pluginManager/api/json` shortName `jwt-auth-filter` |
| Approved reverse-proxy RS (if used instead) | *TBD name + version* | edge config hash / change ticket |
| IdP issuer (`iss`) | *TBD* | Entra tenant discovery URL |
| Exact Jenkins audience (`aud`) | *TBD* | App registration / exposed API |
| JWKS URI | *TBD* | discovery `jwks_uri` |
| Path include patterns | *TBD* | JCasC / plugin export — must cover §2.3 |
| Path exclude patterns | *TBD* | must not punch holes in MCP routes |
| Claim → principal mapping | *TBD* | e.g. `preferred_username` / `sub` |
| Group claim / overage policy | *TBD* | fail-closed if incomplete; Graph expansion residual |
| RFC 9728 protected-resource metadata path | *TBD* | if published |
| Lab date / security approver | *TBD* | written go/no-go |

Until every non-optional field is filled and signed off, treat Mode B / `oidc_bearer`
against that controller as **unqualified**.

### 2.2 JCasC / RS config checklist

- [ ] External IdP issues **access tokens** with **exact** Jenkins API audience (never Graph-only).
- [ ] RS validates signature via JWKS; **alg allow-list** excludes `none` / HS*.
- [ ] Exact **issuer** allow-list; multi-issuer only when every issuer is approved.
- [ ] Protected paths include progressive log, artifact, and Pipeline REST (wfapi) — not only `/**/api/**`.
- [ ] Invalid Bearer → **401/403** with **no** session cookie / Basic / anonymous success.
- [ ] JWKS outage → fail closed; document cache TTL and key-rotation overlap window.
- [ ] Principal/group mapping reviewed; incomplete Entra group overage does not invent membership.
- [ ] Emergency disable / rollback (filter off → temporary personal API-token pilot only).
- [ ] Audit identity = **individual** principal (no shared bot for interactive users).
- [ ] Concurrent MCP clients spot-check (no catastrophic JWKS fetch-per-request without cache).

Illustrative JCasC sketch only: [jwt-auth-filter-qualification.md §2](../auth/jwt-auth-filter-qualification.md).

### 2.3 Routes that must be re-proved live

Constants: `auth.RequiredMCPRoutes`. Offline inventory completeness is Done\*;
**live** must re-prove fallthrough + claim fail-closed on the controller.

| ID | Pattern | Outside `/**/api/**`? |
|----|---------|----------------------|
| `whoami` | `/whoAmI/api/json` | no |
| `root_api` | `/api/json` | no |
| `job_api` | `/**/job/*/api/json` | no |
| `build_api` | `/**/job/*/<n>/api/json` | no |
| `progressive_text` | `/**/logText/progressiveText` | **yes** |
| `artifact_download` | `/**/artifact/**` | **yes** |
| `wfapi_describe` | `/**/wfapi/describe` | **yes** |
| `wfapi_node_log` | `/**/execution/node/*/wfapi/log` | **yes** |
| `queue_api` | `/queue/api/json` | no |
| `queue_item` | `/queue/item/*/api/json` | no |
| `computer_api` | `/computer/api/json` | no |
| `crumb_issuer` | `/crumbIssuer/api/json` | no |
| `plugin_manager` | `/pluginManager/api/json` | no |

Minimum live bar: **all** `OutsideAPIGlob=true` rows + `whoami` + at least one
job/build API path. Prefer full inventory before production go.

### 2.4 Live evidence to attach (never paste tokens)

| Evidence | How |
|----------|-----|
| Invalid Bearer / wrong aud / exp / iss → 401/403 on required routes | Lab curl matrix + `jenkins-mcp oauth probe-rs --profile <id>` |
| Valid Bearer → expected individual principal | `status` / `doctor` whoAmI (secret-free) |
| No Basic/session fallthrough | Classifier + real status codes; body class notes without secrets |
| JWKS outage / rotation under load | Lab network block + concurrent clients |
| Plugin + LTS pins | §2.1 table filled |
| Security go/no-go | Signed note; residual exceptions listed |

```bash
# Offline contracts (not a live pin):
jenkins-mcp oauth probe-rs --profile <id> --offline
jenkins-mcp gateway qualify --offline
go test ./internal/auth ./internal/gateway ./internal/gateway/qualify -count=1 -run 'OAUTH009|Fallthrough|OfflineFallthrough|ModeB'

# Live assist (network + qualified controller; still attach version pins):
jenkins-mcp oauth probe-rs --profile <id>
jenkins-mcp doctor --profile <id>
jenkins-mcp security self-check --json --profile <id>
```

### 2.5 Explicitly **not** a production pin

| Surface | Why residual |
|---------|--------------|
| `OfflineFallthroughFixtures` / simulated RS | No real plugin |
| Mode B `JWTVault` / HOST-010 offline Obtain | Lab tokens only |
| `make live-oauth-*` mock-rs | Disposable mock — not `jwt-auth-filter` |
| `-tags=live_oauth` mock health | Not Entra / not production plugin |
| Doctor `mode_b_live_rs_qualified=false` | Honesty field; offline Ready does not flip it |

---

## 3. OAUTH-010 — live Entra app registration + AgentCore residual checklist

**Detail SoT:** [oauth-capability-matrix.md §4](../auth/oauth-capability-matrix.md),
[qualification.md](qualification.md) (`oauth010_mode_c_offline_matrix`),
[auth-architecture.md §2.3](../auth-architecture.md), architecture §6.6.

### 3.1 Entra app registration (resource + client)

Fill during live lab; keep secrets out of git, tickets, and support bundles.

| Item | Required | Evidence |
|------|----------|----------|
| Dedicated **Jenkins API** app / exposed API | Yes | App id / application id URI |
| Exact **audience** string used by MCP + RS | Yes | Matches `JENKINS_MCP_AGENTCORE_AUDIENCE` / profile `jenkinsAudience` |
| Access token version / accepted audiences documented | Yes | Entra “Expose an API” + token claims sample (redacted) |
| Gateway / AgentCore **public client** id | Yes | `JENKINS_MCP_AGENTCORE_CLIENT_ID` (public) |
| Client secret / cert (if confidential) | Vault only | **Never** profile JSON, compose, or CLI argv |
| Redirect URIs for 3LO | For auth_code | Site-owned; match AgentCore provider |
| Admin consent / delegated permissions | Yes | Least privilege; no Graph-as-Jenkins-audience |
| Conditional Access / MFA posture | Site policy | Document residual if lab skips CA |
| Token lifetime / refresh policy | Yes | Align with vault TTL + revocation window |
| Group claims / overage behavior | If groups used | Incomplete overage must fail closed; Graph expansion residual |

### 3.2 AgentCore / gateway provider residual

| Gate | Offline Done\* | Live residual |
|------|----------------|---------------|
| AS base = Entra (Jenkins-as-AS reject) | Config validation + qualify | Production env audit |
| `authorization_code` consent metadata only | ConsentRequired URL+session; process-local metadata store | Browser 3LO UX; multi-replica consent correlation |
| `token_exchange` / OBO → Jenkins-audience Bearer | Mock AS + HTTPTokenFetcher | Real Entra OBO / RFC 8693 profile pin |
| Live opt-in (`JENKINS_MCP_GATEWAY_LIVE=1`) | Wire + fail-closed without token endpoint | Real discovery + refresh isolation SLOs |
| Per-user vault binding | Process memory cache / mock | **Durable AgentCore Identity vault** |
| Wrong audience fail-closed | Unit + qualify | Live canary tokens (redacted evidence) |
| Progressive consent tool path | `authorization_url` + `session_id` only | Operator runbook for reauth storms |
| Force re-auth / revocation foundation | **Done\* lite:** `InvalidateSubjectLocal` + `gateway subject-invalidate` (process-local principal **or** same-host `FilePrincipalCache` via `JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH` + optional same-host `FileTokenCache`); provider `Invalidate` drops principal companion; `principal_cleared` / `token_cache_cleared` honest on durable Delete fail | **Live IdP/AgentCore revocation window** still residual (OAUTH-010); multi-pod fan-out residual (HOST-008); CLI does not clear remote serve memory-only caches without shared file paths |
| Graph group expansion | Fail-closed incomplete overage | Optional funded residual — not invented membership |
| AgentCore sidecar / binary pin | None in-repo | Org AgentCore release + GWY-003/004 |

### 3.3 Live Mode C evidence to attach

- [ ] Entra app reg table (§3.1) complete; security review recorded  
- [ ] AgentCore (or approved gateway) provider points **only** at Entra AS endpoints  
- [ ] Auth-code path: consent URL reachable; tokens never in MCP/errors/logs  
- [ ] OBO/exchange path: short-lived Jenkins-audience access token only  
- [ ] Subject/tenant/workload binding matches inbound claims → Jenkins principal  
- [ ] Cross-user vault/cache isolation under concurrent Obtain  
- [ ] Revocation / refresh failure → subsequent tools fail closed  
- [ ] No shared Jenkins SA on interactive path  
- [ ] Doctor residual `mode_c_live_agentcore_qualified` only flipped after evidence (today always offline false)

**OAUTH-010 revocation honesty:** offline **Done\* lite** only for process-local
force re-auth (`InvalidateSubjectLocal` / `gateway subject-invalidate` clears
principal + optional file token cache). Live Entra/AgentCore revocation, refresh
reuse detection, and multi-pod invalidate fan-out remain **open** — do not mark
revocation DoD Done from this CLI alone.

```bash
# Offline / mock only — not live Entra Done:
jenkins-mcp gateway qualify --offline
jenkins-mcp gateway consent-residual
jenkins-mcp gateway subject-invalidate --subject-key 'tenant|sub|profile'  # force re-auth residual lite
go test ./internal/gateway ./internal/gateway/qualify -count=1 -run 'OAUTH010|ModeC|HTTPTokenFetcher|InvalidateSubject'
make live-oauth-test   # mock-token peer; opt-in; not production Entra
```

### 3.4 Forbidden Mode C claims

- “Live Entra Done” from oauth-lab or TLS test shim  
- AgentCore endpoints co-hosted with Jenkins  
- ID token used as Jenkins API credential  
- Shared service account substituted when Obtain fails  

---

## 4. HOST-008 — multi-pod HA (**cancelled / non-goal**)

**Status:** **Out of scope** (2026-08-01). Multi-pod gateway HA is **not** a product task.  
**Scale model:** **[multi-fleet](../fleet/multi-fleet-rollout.md)** — many independent single-replica members (stdio or one gateway each) + shared signed policy.  
**Detail SoT:** [deployment.md §9](deployment.md) (single-replica honesty).  
**Default:** **`replicas: 1`**, `haMultiReplica=false` forever under this product decision.

### 4.1 Historical same-host lite (not a multi-pod path)

| Item | Status | Honesty |
|------|--------|---------|
| Docs + kustomize/compose `replicas: 1` | Done\* | Default single replica |
| File vault process mutex + `flock` on `path.lock` | Done\* lite | **Same host / shared FS** only |
| Service `sessionAffinity: ClientIP` | Done\* scaffold | Packaging only; does **not** enable multi-pod |
| Doctor / admin `haMultiReplica=false` | Done\* | Always false; multi-pod runtime **cancelled** |
| Optional file Obtain / rate / principal / JWKS paths | Done\* lite | Same-host multi-process only |

### 4.2 What operators should do instead of `replicas > 1`

| Need | Approach |
|------|----------|
| More users / sites | Another multi-fleet **member** (profile + policy bundle) |
| Higher availability | Second independent single-replica process/host (not shared-memory HA) |
| Shared deny policy | Signed overlay gitops ([multi-fleet-rollout.md](../fleet/multi-fleet-rollout.md)) |
| Shared multi-pod vault/rate | **Not product** — do not raise interactive gateway replicas |

**Do not** treat `JENKINS_MCP_GATEWAY_MULTI_USER=1` as multi-replica HA.  
**Do not** claim multi-replica Done from sticky YAML alone.  
**Do not** implement multi-pod Redis/shared vault as HOST-008 follow-up without an explicit product decision reverse of this cancel.

---

## 5. What offline residual-smoke proves vs does not

### 5.1 Commands

```bash
# Opt-in residual honesty (not default make test / make ci):
make residual-smoke
# alias:
make gateway-residual-smoke
# optional doctor gateway_residual_status embed when a profile exists
# (doctor requires --profile; PROFILE empty → doctor step skipped):
make residual-smoke PROFILE=corp

# Underlying pieces:
jenkins-mcp gateway qualify --offline
jenkins-mcp release-evidence --offline
jenkins-mcp gateway residual-status   # required Wave 8 honesty (ha_multi_replica=false, oauth009_offline, residual_ids)
jenkins-mcp security self-check --json  # offline (no profile): item gateway_residual_status_honesty ok|warn
jenkins-mcp gateway consent-residual  # optional progressive consent residual snapshot
jenkins-mcp doctor --profile <id> --offline --json  # optional: gateway_residual_status nest (same map)
# script: scripts/gateway-residual-smoke.sh → dist/residual-smoke/<ts>/
#   (gateway-qualify.json, release-evidence.json, gateway-residual-status.json,
#    security-self-check.json, doctor-offline.json when PROFILE set, …)
# qualify residual lite canaries (Wave 13): gateway-qualify.json must include
#   case gateway_residual_status_offline_honesty (passed), residuals[] residual-status
#   honesty note (case name or residual-status + honesty), passed >= 20, residual_count >= 8
# residual-status honesty canaries (residual lite; offline ≠ live GO):
#   shared_subject_rate_file=false by default;
#     with JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH set → true (path never dumped);
#   shared_principal_cache_file=false by default;
#     with JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH set → true (path never dumped);
#   shared_jwks_file=false by default;
#     with JENKINS_MCP_HTTP_JWKS_CACHE_PATH set → true (path never dumped; public JWKS only);
#   shared_token_cache_file=false by default;
#     with JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH set → true (path never dumped; never opens token file);
#   shared_api_token_vault_file=false by default;
#   with JENKINS_MCP_GATEWAY_VAULT_PATH set → true (path never dumped; never opens vault;
#     VaultPathConfiguredFromEnviron requires explicit env — default XDG / XDG_DATA_HOME does not count);
#   shared_jwt_vault_file=false by default;
#   with JENKINS_MCP_GATEWAY_JWT_VAULT_PATH set → true (path never dumped; never opens vault;
#     JWTVaultPathConfiguredFromEnviron requires explicit env — default XDG / XDG_DATA_HOME does not count);
#   XDG-only residual-smoke canary: XDG_DATA_HOME set + vault files planted, vault path env unset
#     → shared_*_vault_file stay false and planted seeds never leak;
#   progressive_consent.file_backed / same_host_reload_before_persist=false by default;
#   with JENKINS_MCP_CONSENT_STORE_PATH set → both true (path never dumped; residual never opens
#     consent file; stores_tokens=false; multi_replica_shared=false — not multi-pod HA);
#   subject_limiter_max_subjects omit/absent by default (unlimited);
#     with JENKINS_MCP_GATEWAY_SUBJECT_LIMITER_MAX_SUBJECTS=N → subject_limiter_max_subjects==N
#     (HOST-006 residual lite; path never involved; process-local only);
#   principal_cache_entries file Len when seeded (secret-free only);
#     principal_cache_process_note: this-process / file Len only
#     (CLI/admin ≠ remote serve MemoryTokenCache/PrincipalCache unless shared file caches);
#   security self-check residual lite: item gateway_residual_status_honesty present;
#     status ok|warn (never fail for empty-env honesty); secret-free canary; soft-skip if subcommand missing
```

### 5.2 Residual ids that **must remain present** offline

| Residual id | Meaning |
|-------------|---------|
| `multi_user_offline` | Multi-user foundation offline only — not production multi-user GO |
| `oauth009_offline` | Bearer / RS offline matrix Done\*; live jwt-auth-filter pin open |
| `host008_single_replica` | Single-replica honesty; multi-pod HA **cancelled** (multi-fleet) |
| `gateway_modes_live` | Modes A/B/C live pin / mode-selection record still open |

`make residual-smoke` **fails** if these ids drop from offline release-evidence.
That is an **honesty canary**, not a readiness badge.

### 5.3 Proves (offline)

| Proves | Does **not** prove |
|--------|--------------------|
| Qualify suite contracts (wrong aud, Jenkins-as-AS reject, Mode A/B/C shapes, fallthrough classifiers) | Live Entra Conditional Access |
| Qualify residual lite: case `gateway_residual_status_offline_honesty` present+passed in `gateway-qualify.json`; residual-status honesty note in `residuals[]`; suite floors `passed` ≥ 20 and `residual_count` ≥ 8 | Live residual-status multi-pod / Entra / AgentCore Done |
| Residual ids still advertised in release-evidence | Live `jwt-auth-filter` version pin |
| Security self-check residual lite: item `gateway_residual_status_honesty` present in `security-self-check.json`; status **ok** or **warn** (never fail for empty-env honesty); secret-free canary | Live multi-user / Entra / AgentCore GO (self-check is offline posture only) |
| Secret-free JSON surfaces (no tokens in qualify/evidence/self-check) | Production AgentCore Identity vault |
| Doctor residual fields stay honest when profile/env set | Multi-pod shared vault safety |
| Mode B/C “live qualified” flags remain **false** offline | Production multi-user GO |
| residual-status honesty canaries (offline ≠ live GO): all `shared_*_file` default false / true when path env set (`shared_subject_rate_file`, `shared_principal_cache_file`, `shared_jwks_file`, `shared_token_cache_file`, `shared_api_token_vault_file` / `shared_jwt_vault_file` via `VaultPathConfiguredFromEnviron` / `JWTVaultPathConfiguredFromEnviron` — **explicit** env only; default XDG / `XDG_DATA_HOME` alone does **not** count — residual-smoke XDG canary; path never dumped; token/vault residual never opens files); `progressive_consent.file_backed` / `same_host_reload_before_persist` default false / true when `JENKINS_MCP_CONSENT_STORE_PATH` set (path never dumped; residual never opens consent file; `stores_tokens=false`; `multi_replica_shared=false`); `subject_limiter_max_subjects` omit default / `==N` when env set (process-local); file Len `principal_cache_entries` when seeded; `principal_cache_process_note` this-process / file Len only | Live multi-pod shared rate/principal/JWKS/token/vault/consent/concurrency or remote serve cache inventory |
| Mock oauth-lab wire (separate opt-in) | Production TLS edge / real plugin |

### 5.4 Operator rule

> Green residual-smoke + green offline qualify ⇒ **documentation and contracts
> did not silently claim live GO**.  
> Green residual-smoke **≠** permission to enable production Mode B/C multi-user
> or `replicas` > 1.

---

## 6. Doctor / self-check residual pointer (docs-only)

Prefer these **existing** secret-free fields. Do not invent code paths that mark
live pin complete without lab evidence.

| Surface | Fields / behavior | Honesty |
|---------|-------------------|---------|
| `jenkins-mcp doctor --offline` / online | `rs_auth`: `live_lab_still_required=true`, `classifier_matrix_done_star`, Mode B → **warn** | Offline matrix ≠ live pin |
| Doctor `gateway_residual_status` (JSON / text) | Same map as `gateway residual-status` via `BuildGatewayResidualStatus` under stable key `gateway_residual_status` | **Informational embed** — operators need not run a second CLI; does not drive overall fail; live `mode_*_qualified` stay false; never tokens; residual-smoke with `PROFILE=` asserts via `--json` |
| Support bundle `gateway-residual-status.json` | Same secret-free map as residual-status / doctor (always top-level zip member) | **Always present** even when doctor fails or prebuilt doctor omits nest; `ha_multi_replica` false; never tokens/subjects; see [observability.md](../observability.md) |
| Mode B enabled | `mode_b_live_rs_qualified=false`, `residual_id=oauth009_offline`, `oauth009_offline=true` | JWT vault Ready does **not** clear |
| Mode C enabled | `mode_c_live_agentcore_qualified=false`, progressive_consent residual notes | Live opt-in wire ≠ AgentCore pin |
| `gateway_status` | `ha_multi_replica=false`, `oauth009_offline_only`, `mode_*_live_*_qualified=false`, `session_affinity_recommended`, `gateway_ready` | Env/parse + Ready honesty |
| `security self-check` | item `rs_qualification` (OAUTH-009 residual summary) | Warn on `oidc_bearer` or Mode B |
| `security self-check` | item `gateway_residual_status_honesty` (GWY-003 residual lite) | Pure offline `BuildGatewayResidualStatus` honesty (same spirit as qualify `gateway_residual_status_offline_honesty`): `residual_ids` present, `ha_multi_replica=false`, live pins false, `shared_*_file` default false, secret-free; **ok** when honesty holds; **warn** if multi_user env set without claiming live multi-user GO; **exercised by residual-smoke** (`security self-check --json`, no profile); not live GO |
| Admin `GET /admin/v1/health` / `gateway/vault` | `haMultiReplica=false`, `sessionAffinityRecommended`, mode ids only | Never tokens |
| `gateway residual-status` | Unified residual snapshot (modes A/B/C, multi-user/HA/multi-pod, consent, rate, principal_cache count + process note, JWKS/token/vault path file bools, optional limiter max subjects) | Env/static honesty; Mode B id `oauth009_offline`; `shared_subject_rate_file` / `shared_principal_cache_file` / `shared_jwks_file` / `shared_token_cache_file` / `shared_api_token_vault_file` / `shared_jwt_vault_file` path residual (path never dumped; token/vault residual never opens files; vault bools via `VaultPathConfiguredFromEnviron` / `JWTVaultPathConfiguredFromEnviron` — **explicit** `JENKINS_MCP_GATEWAY_VAULT_PATH` / `JWT_VAULT_PATH` only, not default XDG); `progressive_consent.file_backed` / `same_host_reload_before_persist` when `CONSENT_STORE_PATH` set (`stores_tokens=false`, `multi_replica_shared=false`); `subject_limiter_max_subjects` when env set (omit unlimited; process-local); `principal_cache_entries` **this process / file Len only** (CLI/admin ≠ serve); never tokens/subjects; **exercised by residual-smoke** |
| Admin `GET /admin/v1/gateway/residual-status` | Same secret-free map as CLI (HOST-007 SPA Overview + Doctor residual cards surface `mode_*_live_*_qualified` / `gateway_ready` / `ha_multi_replica` as no/false; `progressive_consent.file_backed` / `same_host_reload_before_persist` when `CONSENT_STORE_PATH` set; `multi_replica_shared=false`; `stores_tokens=false`) | Viewer read; 404 hides card on older BFF; offline residual — not production GO; never tokens/paths |
| `gateway consent-residual` | Progressive consent residual snapshot | Browser 3LO not automated; residual-smoke optional |
| `gateway consent-purge` / `consent-expire` | Purge TTL-expired consent metadata (or `--session-id` / `--all --confirm=CLEAR_ALL`) | Metadata only; secret-free counts; clear_all requires exact confirm token; same-host file reload-before-persist **Done\* lite** (no serve Put resurrection); persist fail closed (non-zero on disk write fail); not multi-replica HA |
| `gateway subject-invalidate` | Force re-auth residual lite: process-local principal **or** FilePrincipalCache + optional FileTokenCache | Not live Entra revocation; multi-pod residual; share file paths for same-host CLI↔serve |
| Admin `POST /admin/v1/gateway/subject-invalidate` | Same residual lite as CLI (HOST-007 SPA Overview form; `gateway_ops`) | Not live Entra; multi-pod residual; share file paths for same-host admin↔serve |
| Admin `POST /admin/v1/gateway/consent-purge` | Same residual lite as CLI consent-purge (HOST-007 SPA Mode C form; `gateway_ops`; clear_all + `confirm: "CLEAR_ALL"`) | Metadata only; never tokens; session_id not echoed; multi-pod residual; share `JENKINS_MCP_CONSENT_STORE_PATH` for same-host admin↔serve |
| `gateway qualify --offline` | Residual notes in JSON summary | Live residuals always listed |

```bash
jenkins-mcp doctor --profile <id> --offline
jenkins-mcp doctor --profile <id> --offline --json   # includes gateway_residual_status
jenkins-mcp security self-check --json --profile <id>
jenkins-mcp oauth probe-rs --profile <id> --offline
jenkins-mcp gateway qualify --offline
jenkins-mcp gateway residual-status
jenkins-mcp gateway consent-residual
jenkins-mcp gateway consent-purge              # default: TTL expire
jenkins-mcp gateway consent-purge --session-id SESS
jenkins-mcp gateway consent-purge --all --confirm=CLEAR_ALL   # explicit clear-all (confirm required)
```

**Code residual (not done in this docs pass):** flipping any
`mode_*_live_*_qualified` to true requires a deliberate evidence-gated
implementation task — never a docs-only toggle.

---

## 7. Production GO decision tree (short)

```text
1. Local stdio pilot only?
   yes → personal API token + RO; gateway live pins not required
   no  → continue

2. Gateway Mode A only (personal API token vault)?
   yes → vault isolation + HOST-003 wire; single-replica only (HOST-008 multi-pod cancelled)
   no  → continue

3. Mode B (Bearer JWT to Jenkins)?
   yes → complete §2 OAUTH-009 live pin + HOST-010 wire evidence
        incomplete → NO GO (api_token / Mode A only)

4. Mode C (AgentCore 3LO/OBO)?
   yes → complete §3 OAUTH-010 Entra + AgentCore pin + GWY-003 live qualify
        incomplete → NO GO for Mode C

5. Need scale / more sites?
   yes → multi-fleet members (shared signed policy); keep each gateway replicas: 1
        do **not** raise multi-pod HA (HOST-008 cancelled)

6. REL / pilot: modes piloted recorded; residual-smoke still lists residual ids
   missing honesty → fix docs/automation before claiming GO
```

---

## 8. Cross-links and ownership

| Doc / surface | Role |
|---------------|------|
| [jwt-auth-filter-qualification.md](../auth/jwt-auth-filter-qualification.md) | OAUTH-009 offline + live lab detail |
| [oauth-capability-matrix.md](../auth/oauth-capability-matrix.md) | Mode C offline matrix; plugin roles |
| [qualification.md](qualification.md) | GWY-003 offline suite + live pin checklists |
| [deployment.md](deployment.md) §9 | Single-replica honesty (HOST-008 multi-pod **cancelled**) |
| [multi-fleet-rollout.md](../fleet/multi-fleet-rollout.md) | Enterprise scale model (replaces multi-pod HA) |
| [README.md](README.md) | Gateway foundation + mode wiring |
| [server-team-hosted.md](../roadmap/server-team-hosted.md) | Program path; HOST/OAUTH task order |
| [pilot/checklist.md](../pilot/checklist.md) §0 | Modes piloted + residual ids |
| [release/gates.md](../release/gates.md) | REL residual honesty smoke |
| [KNOWN_DEFECTS](../docs/security/product-residuals.md) KD-009 | Live RS lab residual tracking |
| `deploy/gateway/` | Compose/kustomize scaffold (no live AgentCore image) |
| `testdata/oauth-lab/` | Mock OIDC/RS/token peers (opt-in) |

| Task | Primary residual owner themes |
|------|-------------------------------|
| OAUTH-009 | Security + Jenkins platform (plugin/JCasC) |
| OAUTH-010 | Security + IdP + AgentCore platform |
| HOST-008 | **Cancelled** — multi-fleet scale; not multi-pod HA |
| GWY-003 live | Engineering + security (per-mode pin evidence) |
| REL-001/002 | Pilot + release evidence packaging |

---

## 9. Merge / acceptance notes (this document)

| Delivered | Not delivered |
|-----------|---------------|
| Single residual runbook for live pin blockers | Live Entra / jwt-auth-filter / AgentCore evidence |
| Checklists for OAUTH-009, OAUTH-010, HOST-008 | Code flips of live-qualified flags |
| residual-smoke proves-vs-does-not table | Multi-pod runtime |
| Doctor residual field pointer (docs-only) | Production GO sign-off |

**Do not claim** production gateway GO from this file alone.
