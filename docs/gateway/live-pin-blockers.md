# Live pin blockers — production GO residual runbook

**Status:** Residual **runbook only** — offline Done\* foundations exist; **live
production GO is not claimed**.  
**Audience:** security, platform operators, release owners, implementation agents  
**Related:** [README.md](README.md) · [qualification.md](qualification.md) ·
[deployment.md](deployment.md) · [jwt-auth-filter qualification](../auth/jwt-auth-filter-qualification.md) ·
[oauth-capability-matrix](../auth/oauth-capability-matrix.md) ·
[server-team-hosted roadmap](../roadmap/server-team-hosted.md) ·
[pilot checklist](../pilot/checklist.md) · [release gates](../release/gates.md)

---

## 0. Honesty banner (read first)

| Claim | Reality |
|-------|---------|
| Offline `gateway qualify --offline` green | **Contracts only** — not live Entra, not production RS, not multi-pod HA |
| `make residual-smoke` green | Residual **ids still present** in offline evidence — **not** a live GO |
| Mode B JWT vault Ready | Offline Obtain → Bearer for lab tokens — **not** jwt-auth-filter pin |
| Mode C Live opt-in + mock AS | Wire-shaped HTTP — **not** AgentCore Identity vault / production Entra |
| Kustomize `sessionAffinity` + `replicas: 1` | Packaging honesty — **not** multi-replica runtime |
| Doctor `mode_*_live_*_qualified=false` | **Correct** until live evidence lands — do not “fix” offline |

**Do not** mark OAUTH-009, OAUTH-010, GWY-003, or HOST-008 multi-pod **Done**
from docs, mocks, or offline smoke alone.

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

## 1. What blocks production GO (summary)

Production-shaped **team/server-hosted** gateway (Tier A multi-user, modes B/C,
or multi-pod) remains blocked until the matching residual rows below are closed
with **attached evidence**. Local Cursor **stdio** + personal API token (Mode A
local path) is a separate pilot surface (ADR 0002) and is **not** unblocked by
closing gateway live pins.

| Blocker cluster | Task IDs | Blocks | Offline Done\* today | Live still required |
|-----------------|----------|--------|----------------------|---------------------|
| **Jenkins RS pin** | **OAUTH-009**, HOST-010, GWY-003 Mode B | Mode B production; any Bearer-to-Jenkins path claiming RS safety | Fallthrough classifier, claim matrix, Mode B vault, doctor residual ids | LTS + plugin version, JCasC, full route re-prove, JWKS under load |
| **Entra + AgentCore obtain** | **OAUTH-010**, GWY-001/003 Mode C | Mode C production Obtain / 3LO / OBO | Mock AS, ConsentRequired metadata, ModeMatrix residual | App reg, Conditional Access, real 3LO/OBO, durable vault |
| **Multi-pod HA** | **HOST-008** Tier B | `replicas` > 1 interactive gateway | Single-replica docs; same-host flock lite; sticky Service scaffold | Shared multi-pod vault, shared Obtain cache, rate, audit |
| **Mode matrix ops** | HOST-011, REL-002 residual ids | Claiming “all modes live” from offline | Fail-closed mode switch offline | Per-mode live pin evidence + signed mode-selection record |

**Tier A default:** single replica, modes qualified **per site** (not all modes
required). **Tier B** multi-replica is explicitly non-goal until HOST-008
checklist 1b–8 close.

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

## 4. HOST-008 — multi-pod checklist residual

**Detail SoT:** [deployment.md §9](deployment.md).  
**Tier A default:** **`replicas: 1`**. Sticky Service affinity is **scaffold only**.

### 4.1 What is Done\* lite / scaffold (not multi-pod GO)

| Item | Status | Honesty |
|------|--------|---------|
| Docs + kustomize/compose `replicas: 1` | Done\* | Default single replica |
| File vault process mutex + `flock` on `path.lock` | Done\* lite | **Same host / shared FS** only |
| Service `sessionAffinity: ClientIP` | Done\* scaffold | Packaging; does not enable HA runtime |
| Doctor / admin `haMultiReplica=false` | Done\* | Always false until multi-replica runtime |

### 4.2 Multi-pod raise checklist (all required)

Raise Deployment `replicas` > 1 **only** when every row is met with org-owned design:

| # | Requirement | Status in this repo |
|---|-------------|---------------------|
| 1a | Shared vault path + flock (same host / shared FS) | **Done\* lite** — not multi-pod alone |
| 1b | **Durable shared token vault** (external / AgentCore Identity / multi-pod RWX) | **Residual** |
| 2 | Session affinity **or** shared session store | Scaffold affinity only; durable store residual |
| 3 | No reliance on **memory** Obtain cache alone | **Done\* lite** same-host `FileTokenCache` (`JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH`, flock + 0600); multi-pod external Obtain cache still **residual** |
| 4 | Shared or carefully partitioned cache / archive policy | Residual (STO / HOST-004) |
| 5 | Audit aggregation (central sink) | Residual |
| 6 | Sticky or shared consent / Obtain correlation | Residual (Mode C progressive consent) |
| 7 | JWKS / identity multi-instance measured | **Done\* lite** same-host file (`JENKINS_MCP_HTTP_JWKS_CACHE_PATH`, flock + public keys 0600; `shared_jwks_file: true`); multi-pod external JWKS + live Entra under load still **residual** |
| 8 | Shared subject rate / concurrency limiters | **Done\* lite** same-host `FileSubjectRateLimiter` (`JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH`, flock + secret-free JSON 0600; `shared_subject_rate_file: true`); process-local default; multi-pod external shared rate still **residual**; concurrency slots still process-local |

**Do not** treat `JENKINS_MCP_GATEWAY_MULTI_USER=1` as multi-replica HA.  
**Do not** claim multi-replica Done from sticky YAML alone.

### 4.3 Failure modes if scaled early

| Risk | Symptom |
|------|---------|
| Memory cache only | Double-mint / re-consent thrash across pods |
| emptyDir vault | Split vaults; wrong-subject miss |
| No sticky sessions | Confirm / page tokens 401 on pod B |
| Process-local rate | Uneven enforcement / budget bypass |
| Per-pod audit files | Incomplete fleet forensics |

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
jenkins-mcp gateway consent-residual  # optional progressive consent residual snapshot
jenkins-mcp doctor --profile <id> --offline --json  # optional: gateway_residual_status nest (same map)
# script: scripts/gateway-residual-smoke.sh → dist/residual-smoke/<ts>/
#   (gateway-qualify.json, release-evidence.json, gateway-residual-status.json,
#    doctor-offline.json when PROFILE set, …)
# residual-status canaries (residual lite): shared_subject_rate_file=false by default;
#   with JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH set → true (path never dumped);
#   shared_principal_cache_file=false by default;
#   with JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH set → true (path never dumped);
#   shared_jwks_file=false by default;
#   with JENKINS_MCP_HTTP_JWKS_CACHE_PATH set → true (path never dumped; public JWKS only);
#   optional file Len: principal_cache_entries count when file has entries (secret-free only);
#   principal_cache_process_note: principal_cache_entries is this-process / file Len only
#   (CLI/admin ≠ remote serve MemoryTokenCache/PrincipalCache unless shared file caches)
```

### 5.2 Residual ids that **must remain present** offline

| Residual id | Meaning |
|-------------|---------|
| `multi_user_offline` | Multi-user foundation offline only — not production multi-user GO |
| `oauth009_offline` | Bearer / RS offline matrix Done\*; live jwt-auth-filter pin open |
| `host008_single_replica` | Tier A single-replica; multi-pod HA residual |
| `gateway_modes_live` | Modes A/B/C live pin / mode-selection record still open |

`make residual-smoke` **fails** if these ids drop from offline release-evidence.
That is an **honesty canary**, not a readiness badge.

### 5.3 Proves (offline)

| Proves | Does **not** prove |
|--------|--------------------|
| Qualify suite contracts (wrong aud, Jenkins-as-AS reject, Mode A/B/C shapes, fallthrough classifiers) | Live Entra Conditional Access |
| Residual ids still advertised in release-evidence | Live `jwt-auth-filter` version pin |
| Secret-free JSON surfaces (no tokens in qualify/evidence) | Production AgentCore Identity vault |
| Doctor residual fields stay honest when profile/env set | Multi-pod shared vault safety |
| Mode B/C “live qualified” flags remain **false** offline | Production multi-user GO |
| residual-status: `shared_subject_rate_file` default false / true when path set (path never dumped); `shared_principal_cache_file` default false / true when path set (path never dumped); `shared_jwks_file` default false / true when `JENKINS_MCP_HTTP_JWKS_CACHE_PATH` set (path never dumped); file Len `principal_cache_entries` when seeded; `principal_cache_process_note` this-process / file Len only | Live multi-pod shared rate/principal/JWKS or remote serve cache inventory |
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
| Mode B enabled | `mode_b_live_rs_qualified=false`, `residual_id=oauth009_offline`, `oauth009_offline=true` | JWT vault Ready does **not** clear |
| Mode C enabled | `mode_c_live_agentcore_qualified=false`, progressive_consent residual notes | Live opt-in wire ≠ AgentCore pin |
| `gateway_status` | `ha_multi_replica=false`, `oauth009_offline_only`, `mode_*_live_*_qualified=false`, `session_affinity_recommended`, `gateway_ready` | Env/parse + Ready honesty |
| `security self-check` | item `rs_qualification` (OAUTH-009 residual summary) | Warn on `oidc_bearer` or Mode B |
| Admin `GET /admin/v1/health` / `gateway/vault` | `haMultiReplica=false`, `sessionAffinityRecommended`, mode ids only | Never tokens |
| `gateway residual-status` | Unified residual snapshot (modes A/B/C, multi-user/HA/multi-pod, consent, rate, principal_cache count + process note, JWKS file bool) | Env/static honesty; Mode B id `oauth009_offline`; `shared_subject_rate_file` / `shared_principal_cache_file` / `shared_jwks_file` path residual (path never dumped); `principal_cache_entries` **this process / file Len only** (CLI/admin ≠ serve); never tokens/subjects; **exercised by residual-smoke** |
| Admin `GET /admin/v1/gateway/residual-status` | Same secret-free map as CLI (HOST-007 SPA Overview card) | Viewer read; 404 hides card on older BFF; never tokens |
| `gateway consent-residual` | Progressive consent residual snapshot | Browser 3LO not automated; residual-smoke optional |
| `gateway consent-purge` / `consent-expire` | Purge TTL-expired consent metadata (or `--session-id` / `--all`) | Metadata only; secret-free counts; same-host file reload-before-persist **Done\* lite** (no serve Put resurrection); not multi-replica HA |
| `gateway subject-invalidate` | Force re-auth residual lite: process-local principal **or** FilePrincipalCache + optional FileTokenCache | Not live Entra revocation; multi-pod residual; share file paths for same-host CLI↔serve |
| Admin `POST /admin/v1/gateway/subject-invalidate` | Same residual lite as CLI (HOST-007 SPA Overview form; `gateway_ops`) | Not live Entra; multi-pod residual; share file paths for same-host admin↔serve |
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
jenkins-mcp gateway consent-purge --all        # explicit clear-all
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
   yes → vault isolation + HOST-003 wire; still no multi-pod without HOST-008
   no  → continue

3. Mode B (Bearer JWT to Jenkins)?
   yes → complete §2 OAUTH-009 live pin + HOST-010 wire evidence
        incomplete → NO GO (api_token / Mode A only)

4. Mode C (AgentCore 3LO/OBO)?
   yes → complete §3 OAUTH-010 Entra + AgentCore pin + GWY-003 live qualify
        incomplete → NO GO for Mode C

5. replicas > 1?
   yes → complete §4 HOST-008 rows 1b–8
        incomplete → keep replicas: 1

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
| [deployment.md](deployment.md) §9 | HOST-008 HA residual runbook |
| [README.md](README.md) | Gateway foundation + mode wiring |
| [server-team-hosted.md](../roadmap/server-team-hosted.md) | Program path; HOST/OAUTH task order |
| [pilot/checklist.md](../pilot/checklist.md) §0 | Modes piloted + residual ids |
| [release/gates.md](../release/gates.md) | REL residual honesty smoke |
| [KNOWN_DEFECTS](../KNOWN_DEFECTS.md) KD-009 | Live RS lab residual tracking |
| `deploy/gateway/` | Compose/kustomize scaffold (no live AgentCore image) |
| `testdata/oauth-lab/` | Mock OIDC/RS/token peers (opt-in) |

| Task | Primary residual owner themes |
|------|-------------------------------|
| OAUTH-009 | Security + Jenkins platform (plugin/JCasC) |
| OAUTH-010 | Security + IdP + AgentCore platform |
| HOST-008 | Platform / SRE (vault + affinity + audit) |
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
