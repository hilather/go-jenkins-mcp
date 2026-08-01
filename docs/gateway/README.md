# Managed gateway / AgentCore foundation (GWY-001/002)

**Status:** Foundation + offline mock obtain + **HOST-003 Ready wire** + **GWY-001 Live opt-in foundation** (`HTTPTokenFetcher`) + **HOST multi-user Obtain foundation** (`AuthProviderCtx` + `JENKINS_MCP_GATEWAY_MULTI_USER`).  
**Default:** `Live=false`, `Fetcher=nil` → fail-closed `not_configured` (no network). Single-subject pin remains default when multi-user env is off.  
**Live opt-in:** `JENKINS_MCP_GATEWAY_LIVE=1` + token endpoint → `EnableLiveHTTPFetcher` (Mode C only).  
**Multi-user opt-in:** `JENKINS_MCP_GATEWAY_MULTI_USER=1` → per-request Caller → Obtain (see §3b).  
**Real Entra / AgentCore Identity vault pin residual** (GWY-003 / OAUTH-010) — do **not** mark GWY-001 fully Done.  
**GWY-004:** deployment **scaffold** (compose/kustomize/docs + `.env.example` lab flags: MULTI_USER, JWKS max stale, path prefix, REQUIRE_SIGNED_POLICY, subject concurrency) only — no live AgentCore image; live pins residual.  
**Related:** [deployment.md](deployment.md), [qualification.md](qualification.md), **[live-pin-blockers.md](live-pin-blockers.md)** (OAUTH-009/010 + HOST-008 production GO residual runbook), [auth-architecture.md](../auth-architecture.md) §2.3, [ADR 0003](../adr/0003-jenkins-not-oauth-authorization-server.md), [policy-rbac.md](../policy-rbac.md), architecture §§1–2 / §6.6, **[server/team-hosted roadmap](../roadmap/server-team-hosted.md)** (Tier A path, HOST-*, 30/60/90).

---

## 1. What this is

Optional **managed-gateway** path for near-source MCP: validate an AgentCore-style
credential provider config, bind inbound Entra/workload claims into MCP
`policy.Subject`, and keep the same **deny-only RBAC** and **global read-only**
invariants as local stdio mode.

| Package | Role |
|---------|------|
| `internal/gateway` | Credential provider interface, AgentCore config validation, token cache, consent metadata, claim → subject binding |
| `internal/policy.Subject` | Optional `Tenant`, `WorkloadID`, `Groups` for gateway subjects |
| `jenkins-mcp serve --gateway` | Require provider config + bind identity; still default RO |

---

## 2. Non-negotiable: Jenkins is not the authorization server

**Threat model / default no-go:** [jas-no-go.md](../auth/jas-no-go.md) (JAS-001), [ADR 0013](../adr/0013-jas-default-no-go-enforcement.md).

| Correct | Forbidden |
|---------|-----------|
| AgentCore **discovery / authorization / token** endpoints → **Entra** (or approved AS) | Pointing those endpoints at **stock Jenkins** |
| Requested **audience** = dedicated **Jenkins API resource** | Graph / generic gateway tokens sent to Jenkins |
| Jenkins validates **Jenkins-audience** JWT as **resource server** (e.g. jwt-auth-filter) | Treating Jenkins UI OIDC / `oic-auth` as MCP 3LO |
| Full Jenkins authorization-server plugin | **Default no-go** (ADR 0011) unless funded decision |

`gateway.ValidateProviderConfig` **rejects** configs where the authorization
server base URL or auth/token endpoints share origin with the Jenkins base URL.

Regression: `go test ./internal/gateway -run JenkinsAsAS`

---

## 3. Credential modes and offline obtain path

| Mode | Intent | Default (`Live=false`) | Offline mock (`Live=true` + `Fetcher`) |
|------|--------|------------------------|----------------------------------------|
| `authorization_code` | User-delegated 3LO + consent URL propagation | `not_configured` | Cache → `TokenFetcher`; may return `ConsentRequired` |
| `token_exchange` / `obo` | OBO / RFC 8693 exchange → Jenkins-audience token | `not_configured` | Same; wrong-audience fails closed |

### Pluggable `TokenFetcher` (GWY-001 offline mock)

```text
Obtain:
  Live=false              → capability_missing / not_configured (cache ignored)
  Live=true, Fetcher=nil  → capability_missing (not silent success)
  Live=true, Fetcher set  → validate → cache hit? → Fetcher → cache → Credential
  Fetcher error           → authentication / capability_missing / ConsentRequired
                            (never shared Jenkins SA)
```

| Type | Role |
|------|------|
| `TokenFetcher` | Interface: `FetchJenkinsCredential(ctx, caller, cfg) (Credential, error)` |
| `FuncTokenFetcher` | Function adapter for unit tests |
| `HTTPTokenFetcher` | Optional production-shaped HTTPS token POST (https-only, no redirects, body cap, never log tokens). **Not** attached by `NewAgentCoreProvider` |
| `EnableLiveHTTPFetcher` | GWY-001 factory: attach `HTTPTokenFetcher` + `Live=true` when token endpoint is resolvable; fail closed without it |
| Mock AS (`httptest` TLS in tests) | Returns JSON `access_token` + `expires_in` + optional `audience` / `jenkins_principal`; consent via 401 + auth URL/session |

`NewAgentCoreProvider` always starts **Live=false**, **Fetcher=nil**. Default serve
wiring keeps that fail-closed path unless the operator sets Live opt-in env
(below). **No real Entra** is called unless Live is enabled **and** a reachable
token endpoint is configured (still contract-shaped HTTP; AgentCore pin residual).

### Live opt-in (GWY-001 foundation — not full AgentCore pin)

| Env | Meaning |
|-----|---------|
| `JENKINS_MCP_GATEWAY_LIVE=1` | Mode C only: call `EnableLiveHTTPFetcher` after provider setup |
| `JENKINS_MCP_AGENTCORE_TOKEN_ENDPOINT` | **Required** when Live=1 (absolute **https** URL or path under AS base) |

```text
Mode C serve provider:
  default                         → Live=false, Fetcher=nil, Ready=false; MemoryTokenCache
  TOKEN_CACHE_PATH set            → FileTokenCache (same-host flock lite; fail closed if invalid)
  LIVE=1 without token endpoint   → serve start error (capability_missing / not_configured)
  LIVE=1 + token endpoint         → HTTPTokenFetcher, Live=true, Ready=true
  LIVE=1 on Mode A / Mode B       → start error (no silent cross-mode)
```

`EnableLiveHTTPFetcher(p, cfg)` / `EnableLiveHTTPFetcherWithClient` (tests inject
TLS mock clients) do **not** perform network I/O at wire time; Obtain uses the
fetcher later. Real Entra discovery, durable vault, and 3LO browser UX remain
**GWY-003 / OAUTH-010 residuals**.

Consent metadata (`ConsentInfo`) may carry **authorization URL + session id** only —
never access tokens, refresh tokens, client secrets, or auth codes.
`ConsentRequired` is preserved through Obtain → AuthProvider (HOST-003) and through
the **tool error path** (`mapToolErr`): MCP model-visible message includes
`authorization_url=` + `session_id=` only (progressive consent UX residual).
`Error()` / logs stay host + truncated session (no full authorize query dump).

### Progressive consent residual (Mode C / OAUTH-010 / GWY-001)

| Path | Status |
|------|--------|
| `ConsentRequired` → auth URL + session id only (Obtain / AuthProvider / `mapToolErr`) | **Done\*** |
| Operator residual surfaces (`doctor` `gateway_status`, `gateway qualify` residual row, `gateway residual-status`, admin `GET /admin/v1/gateway/residual-status`, `gateway consent-residual`, `gateway consent-purge`, `gateway subject-invalidate`) | **Done\*** (env/static honesty; subject-invalidate is force re-auth residual lite) |
| Process-local consent metadata store (TTL; optional file under XDG data) | **Done\*** — auth URL + session id + timestamps only; never tokens |
| Same-host multi-process file honesty (reload-under-flock before mutate/write) | **Done\* lite** — CLI `consent-purge` not resurrected by live serve `Put` of stale memory; reads resync for freshness |
| Consent metadata purge/expire CLI (`gateway consent-purge` / `consent-expire`) | **Done\*** — TTL purge / `--session-id` / `--all`; secret-free summary; never tokens; same-host file lite; **persist fail closed** (CLI non-zero / admin 500 when file write fails — never silent success) |
| Consent metadata purge/expire CLI (`gateway consent-purge` / `consent-expire`) | **Done\*** — TTL purge / `--session-id` / `--all --confirm=CLEAR_ALL`; secret-free summary; never tokens; same-host file lite |
| Browser 3LO interactive UX automation | **Residual** — not automated; operator/agent opens `authorization_url` out-of-band |
| AgentCore durable consent / token vault | **Residual** (not this process-local metadata store) |
| Multi-replica / multi-pod consent correlation | **Residual** (HOST-008) — same-host file flock only; not multi-pod shared store |

**Process-local consent metadata store** (`internal/gateway/consent_store.go` + `consent_store_file.go`):

- When Obtain returns `ConsentRequired`, metadata is remembered in a process-local
  TTL store (default 30m), keyed by session id and optional SubjectKey.
- Optional file-backed crash recovery:
  `$XDG_DATA_HOME/jenkins-mcp/gateway/consent_sessions.json` (override
  `JENKINS_MCP_CONSENT_STORE_PATH`). Mode 0600; schema is metadata only
  (no `access_token` / `refresh_token` / `client_secret` fields — load rejects them).
- **Same-host multi-process Done\* lite:** every mutation (`Put` / `Delete` /
  `PurgeExpired` / `Clear`) with `FilePath` set takes flock → **reload disk** →
  apply mutation → write. Reads (`Get` / `List` / …) resync under flock so CLI
  purge is visible without waiting for a Put. Prevents the prior last-writer-wins
  resurrection of purged sessions when serve rewrote full memory to the file.
  StatusMap exposes `same_host_reload_before_persist: true` when file-backed.
- **Persist fail closed (OAUTH-010 residual lite):** mutators return `error` when
  file-backed reload/write fails (memory-only still nil). CLI `consent-purge` and
  admin `POST …/consent-purge` surface that error (non-zero exit / HTTP 500 with
  secret-free message) — never report success while disk write failed. Not multi-pod.
- API: `Get` / `GetBySubjectKey` / `List` / `Delete` / `Clear` / `PurgeExpired`
  (mutators return error on durable persist fail);
  `StatusMap` / `String` are secret-free (host + truncated session; never full
  authorize query dump in status maps).
- Operator purge CLI: `jenkins-mcp gateway consent-purge` (alias `consent-expire`)
  defaults to TTL expire; `--session-id` deletes one entry; `--all` clears all
  and **requires** exact `--confirm=CLEAR_ALL` (HOST-007 residual lite, parity
  with admin BFF `confirm: "CLEAR_ALL"` / cache EVICT). Summary: `deleted_count`,
  `remaining_count`, path basename residual only — never tokens or full
  authorize URLs.
- **Not** multi-replica / multi-pod shared store; sticky sessions / shared
  AgentCore vault remain residual (HOST-008).

```bash
jenkins-mcp gateway residual-status    # unified secret-free residual snapshot (modes A/B/C, multi-user/HA/multi-pod, consent, rate, principal_cache count + process note)
# same map on admin BFF (HOST-007 SPA Overview): GET /admin/v1/gateway/residual-status
jenkins-mcp gateway consent-residual   # progressive consent residual + last consent_sessions if file present
jenkins-mcp gateway consent-purge      # purge TTL-expired metadata (or --session-id / --all --confirm=CLEAR_ALL); secret-free counts
jenkins-mcp gateway subject-invalidate --subject-key tenant|sub|profile   # force re-auth residual lite (GWY-002/HOST-003)
jenkins-mcp gateway qualify --offline  # includes progressive_consent_residual case + residual note
jenkins-mcp doctor --profile <id> --offline [--json]  # gateway_status + gateway_residual_status embed (same map as residual-status; never live GO)
make residual-smoke                    # exercises residual-status honesty canaries (opt-in offline; PROFILE= also asserts doctor embed)
```

### Force re-auth residual lite (GWY-002 / HOST-003 subject invalidate)

Operator-facing **subject invalidate** clears process-local multi-user caches for one
subject so the next Obtain / Binding path re-fetches. This is **offline foundation**
for revocation / force re-auth — **not** live Entra or AgentCore revocation, **not**
multi-pod fan-out.

| Path | Status |
|------|--------|
| `gateway.InvalidateSubjectLocal(caller, principalCache, tokenCache?)` | **Done\*** — secret-free; drops `PrincipalStore` + optional `TokenCache` (subject-namespace purge when `DeleteBySubjectKey` available). **Honesty:** `principal_cleared` only when `PrincipalStore.Delete` succeeds; `FilePrincipalCache` IO/corrupt/save failure → `principal_cleared=false` + residual note (parity with `FileTokenCache.DeleteBySubjectKey` `-1`) |
| `CredentialProvider.Invalidate` companion principal drop (AgentCore / Mode A / Mode B) | **Done\*** — token cache (Mode C) + `PrincipalCache`; durable vault entries **not** deleted (use `gateway vault delete`) |
| CLI `jenkins-mcp gateway subject-invalidate` (alias `invalidate-subject`) | **Done\*** — process-local principal clear **or** same-host `FilePrincipalCache` via `JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH` + optional `FileTokenCache` via `JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH`; never claims `principal_cleared` when file Delete fails |
| Admin BFF `POST /admin/v1/gateway/subject-invalidate` + Overview SPA form | **Done\*** residual lite (HOST-007) — same cache semantics as CLI; requires `gateway_ops` (operator/policy_admin); secret-free StatusMap; multi-pod residual |
| Admin BFF `POST /admin/v1/gateway/consent-purge` + Overview Mode C SPA form | **Done\*** residual lite (HOST-007) — same purge semantics as CLI; clear_all requires `confirm: "CLEAR_ALL"` (SPA type-to-confirm); `gateway_ops`; secret-free counts; never tokens / session_id echo; multi-pod residual |
| Live IdP / AgentCore token revocation | **Residual** (OAUTH-010 / GWY-003) |
| Multi-pod / multi-replica invalidate fan-out | **Residual** (HOST-008) |
| Clear of a remote serve process memory-only caches without shared file paths | **Residual** — share `FilePrincipalCache` / `FileTokenCache` paths for same-host CLI/admin↔serve purge |

```bash
# Compose subject key or pass --subject-key:
jenkins-mcp gateway subject-invalidate --subject-key 'tenant|alice-sub|corp'
jenkins-mcp gateway subject-invalidate --tenant tenant --subject-id alice-sub --profile corp
# Optional same-host FilePrincipalCache + FileTokenCache purge (shared with serve when paths match):
export JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH=/var/lib/jenkins-mcp/gateway/principal_cache.json
export JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH=/var/lib/jenkins-mcp/gateway/token_cache.json
jenkins-mcp gateway subject-invalidate --subject-key 'tenant|alice-sub|corp'
```

**CLI JSON (secret-free):** `subject_key` (operator echo of typed key), `subject_key_hash`
(`audit.HashOpaque`), `principal_cleared` / `cleared.principal` / `cleared.token_cache`,
`token_cache_note`, `residual_note`. Never tokens, vault material, or `Authorization`
headers. **Durability honesty:** `principal_cleared=false` when `FilePrincipalCache.Delete`
fails (IO/corrupt/save); `token_cache_cleared=false` when subject-namespace purge returns
`-1` — CLI must not imply caches cleared while durable rows may remain.

**Library:** after `provider.Invalidate(ctx, caller)`, both token material (Mode C) and
`PrincipalCache` entry for `SubjectKey(caller)` are dropped so multi-user policy
JenkinsUserID / mutation Binding re-resolve on the next tool call.

**`gateway residual-status`** (and admin **`GET /admin/v1/gateway/residual-status`**)
combine mode-matrix residual, `multi_user_enabled`,
`ha_multi_replica=false`, `session_affinity_recommended`, multi-pod residual fields,
progressive consent residual, `rateEnabled` / `ratePerMinute` / `rateBurst`,
`shared_subject_rate_file`, optional `subject_rate_max_subjects` when
`JENKINS_MCP_GATEWAY_SUBJECT_RATE_MAX_SUBJECTS` is set, optional
`subject_limiter_max_subjects` when
`JENKINS_MCP_GATEWAY_SUBJECT_LIMITER_MAX_SUBJECTS` is set, and `principal_cache_entries`
(count only) plus `principal_cache_process_note` (this-process only: CLI/admin ≠
remote serve) and optional `principal_cache_max_entries` /
`principal_cache_ttl_seconds` when hygiene env is set.
`shared_subject_rate_file`, `shared_principal_cache_file` (true when
`JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH` set — never the path value),
`shared_jwks_file` (true when `JENKINS_MCP_HTTP_JWKS_CACHE_PATH` set),
`shared_token_cache_file` (true when `JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH` set —
same-host FileTokenCache lite; path never returned; residual never opens the
token file), `shared_api_token_vault_file` (true when
`JENKINS_MCP_GATEWAY_VAULT_PATH` **explicitly set** — Mode A path residual lite;
default XDG does not count; path never returned; residual never opens vault),
`shared_jwt_vault_file` (true when `JENKINS_MCP_GATEWAY_JWT_VAULT_PATH`
**explicitly set** — Mode B path residual lite; default XDG does not count; path
never returned; residual never opens vault), and `principal_cache_entries`
(count only) plus optional `principal_cache_max_entries` /
`principal_cache_ttl_seconds` when hygiene env is set.
Always advertises Mode B residual id `oauth009_offline` and points at
[live-pin-blockers.md](live-pin-blockers.md). Shared assembly:
`diagnostics.BuildGatewayResidualStatus`. Never tokens or subjects (no principal
inventory dump). Env/static only — not live Ready / production GO.

**Honesty:** metadata propagation alone does **not** close full GWY-001/003 DoD.
When Obtain would return `ConsentRequired`, surfaces never include tokens,
refresh material, client secrets, or `Authorization` headers — only
`authorization_url` + `session_id` on the progressive tool path. Browser 3LO is
**not** automated. Multi-replica consent correlation is residual.

Token cache: in-memory, keyed by `(tenant, user, workload, profile)` (HOST-004),
TTL-bounded. `String()` / errors / `Status` **never** include token bytes (canary tests).

When the token JSON includes `audience` / `resource`, it must **exactly** match
configured Jenkins API audience (wrong-audience residual fail-closed).

---

## 3b. HOST-003 — Serve wiring: Obtain → Jenkins client

When `--gateway` and provider **Ready**, Jenkins HTTP credentials come **only**
from `CredentialProvider.Obtain` for the **bound caller** (captured at attach
time). There is **no** keyring / static / shared-SA fallthrough after Ready.

| Step | Behavior |
|------|----------|
| Provider Ready (default) | `attachGatewayObtainAuthProvider` installs process-bound Obtain AuthProvider |
| Provider Ready + MULTI_USER | `attachGatewayObtainAuthProviderDynamic` installs context-scoped AuthProviderCtx |
| Static residual | `clearGatewayLocalSessionCredentials` clears client User/Token after attach |
| Session-start identity | `verifyGatewayObtainWhoAmI` runs whoAmI with Obtain credentials (default caller); mismatch / anonymous / Obtain fail → serve fails closed |
| Obtain failure | AuthProvider/AuthProviderCtx returns error; request not sent; never another subject’s credential |
| ConsentRequired (Mode C) | Surfaces auth URL + session id only (`AsConsentRequired` → AuthProvider → `mapToolErr` progressive fields) |
| Provider !Ready | Residual local session (Mode C default Live=false) |

Mode A Ready → Basic personal vault token. Mode B Ready → Bearer from JWT vault
(HOST-010 offline). Mode C Ready (Live opt-in) → Bearer access token.

**Bootstrap residual:** serve still loads a local profile/keyring session for
process startup (AUTH-004) before Obtain wire. When Ready, Obtain whoAmI must
match the bound Jenkins principal (env label and/or bootstrap whoAmI).

**HTTP subject pin (single-user foundation, default):** with `--gateway --http`
and multi-user **off**, serve requires lab and/or JWKS as a trusted subject
source and sets `HTTPConfig.ExpectedExternalSubject` to the process-bound
gateway `ExternalSubject`. Lab/JWT callers that present a **different** subject
get 401 — so multi-subject HTTP cannot share one process-bound Obtain caller.

**Per-request multi-user Obtain (opt-in foundation):** set
`JENKINS_MCP_GATEWAY_MULTI_USER=1` (truthy: `1`/`true`/`yes`/`on`). When
`--gateway` and provider **Ready**:

| Step | Behavior |
|------|----------|
| Auth | `attachGatewayObtainAuthProviderDynamic` installs `AuthProviderCtx` |
| Context Caller | HTTP `AfterIdentity` maps trusted `RequestIdentity` → `gateway.Caller` (ExternalSubject→Subject; Tenant/Workload from identity; ProfileID from process) |
| Context policy.Subject | Same `AfterIdentity` builds `policy.Subject` via `PolicySubjectFromHTTPInbound` (JenkinsPrincipal→JenkinsUserID; ProfileID from process; **Groups** from JWT `groups`/`roles` or lab `X-Jenkins-MCP-Lab-Groups` only — never process defaults; bounded MaxInboundGroups/name length; **Verified** only when lab/JWT verified **and** Jenkins principal present) and stores with `ContextWithCallerAndPolicySubject` |
| Obtain | `CallerFromContext` when Valid → Obtain for that caller; else process defaultCaller |
| Policy RBAC | `tools.RegisterOptions.SubjectFromContext` = `policySubjectFromGatewayCtx` (cmd adapter; tools does not import gateway). JenkinsUserID preference: (1) **PrincipalCache** after Obtain, (2) HTTP/lab `PolicySubject.JenkinsUserID`, (3) empty fail-closed. `addTool` / `listToolsAllows` use `effectiveSubject` |
| Mutation Binding | `MutationBindingFromContext` = `mutationBindingFromGatewayCtx`: Valid `PolicySubject` → PrincipalID=`JenkinsUserID` (HTTP/lab JenkinsPrincipal); else Caller + **PrincipalCache** (SubjectKey→Obtain/Mode A vault username) when set, else process principal |
| Principal cache | Default process-local `gateway.PrincipalCache` (`SubjectKey` → non-secret Jenkins principal). Optional same-host **`FilePrincipalCache`** via `JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH` (flock + 0600; CLI subject-invalidate shares with serve). Multi-user `AuthProviderCtx` **Set**s after successful Obtain (Credential.JenkinsPrincipal or Basic username). **Never** tokens. Used by **policy SubjectFromContext** (JenkinsUserID rewrite after Obtain) and mutation Binding. Optional **MaxEntries** (LRU) + **TTL** hygiene (empty env = unlimited / no expiry). Multi-pod shared principal map residual |
| Subject pin | `ExpectedExternalSubject` is **not** set (distinct lab/JWT subjects allowed) |
| Fail closed | empty subject / Obtain miss → error; never other subject's token; never shared SA; tool args never rebind identity |
| Static fields | AuthProviderCtx does **not** write User/Token on the Client (race residual); AuthProviderCtx cannot store Obtain principal **on request context** — mid-call rewrite is via process-local **PrincipalCache** (SubjectFromContext + Binding), not ctx value mutation |

| Env | Role |
|-----|------|
| `JENKINS_MCP_GATEWAY_MULTI_USER` | Opt-in multi-user Obtain + policy.Subject rebind path (default off = single-subject pin) |
| `JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_MAX` | Optional PrincipalCache max entries (non-negative int; empty/`0` = unlimited). When full, LRU (oldest `lastAccess`) is evicted on Set. Wired at gateway serve start via `ConfigureProcessPrincipalCacheFromEnviron` |
| `JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_TTL` | Optional PrincipalCache entry TTL (Go duration, e.g. `1h`, `30m`; empty = no expiry). Expired keys miss on Get and are deleted. Fixed TTL from Set (not sliding) |
| `JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH` | Optional same-host multi-process principal map file (`FilePrincipalCache`, flock + secret-free JSON 0600; SubjectKey → Jenkins principal only). Empty → process-local memory. HOST-008 lite only — **not** multi-pod HA. Invalid path fails start. residual-status `shared_principal_cache_file: true` (path never returned). Never tokens |

**Residuals (honest):**

- **Policy RBAC Subject rebind:** **Done\*** foundation — per-request
  `policy.Subject` from trusted HTTP identity on context
  (`ContextWithPolicySubject` / `SubjectFromContext` / `effectiveSubject`).
  Process `RegisterOptions.Subject` remains the multi-user-off / missing-ctx
  default. Tool args never supply identity (`RejectIdentityToolArgs`).
  **Done\*** Obtain→RBAC JenkinsUserID via process-local `PrincipalCache`:
  `policySubjectFromGatewayCtx` prefers cache (Mode A vault username) after
  successful Obtain, else HTTP/lab claim, else empty fail-closed; Verified when
  cache principal non-empty/non-anonymous; Alice/Bob deny_tools tests; groups
  never elevate. AuthProviderCtx still does not mutate request-context Values
  (cache is the rewrite path).
- **Mutation Binding PrincipalID:** **Done\*** when HTTP/lab carries
  JenkinsPrincipal (Valid PolicySubject). **Done\*** Obtain→Binding principal
  via process-local `PrincipalCache` (Mode A vault username / Credential.JenkinsPrincipal
  recorded on successful multi-user Obtain) even without lab claim — Alice/Bob
  isolation tests; cache.String secret-free.
- **IdP groups foundation (OAUTH-006 / GWY-002 residual lite): Done\*** —
  JWT access-token `groups`/`roles` → `PolicySubjectFromHTTPInbound` /
  `BindSubject` with `MaxInboundGroups=64`, name length 256, default
  `FailOnGroupOverage=true`. Lab header `X-Jenkins-MCP-Lab-Groups`
  (comma-separated) only when lab identity is on. Groups never elevate
  `deny_tools` / `force_read_only`.
- **Entra group overage fail-closed foundation (OAUTH-006): Done\*** —
  JWT payloads with `_claim_names` / `_claim_sources` group overage markers
  **or** a groups-as-reference object **without** a concrete `groups` string
  array fail closed at `ValidateAccessToken` /
  `ResolveHTTPInbound` / `ExtractGroups` / `GroupsFromValidatedToken`
  (multi-user RequireVerified gateway bind never invents empty membership).
  Hybrid tokens that still embed a full `groups` array keep the current path
  (markers ignored for membership; residual note `group_overage_hybrid`).
  Lab header path unchanged.
- **Microsoft Graph membership expansion** remains residual (OAUTH-010 /
  GWY-003): no Graph call; incomplete overage membership is never invented.
- **Live Entra / JWKS rotation / Mode C 3LO browser UX** remain GWY-003 /
  OAUTH-010 residuals.
- **MCP SDK context flow / tools/call multi-user (Done\* offline, session-scoped):**
  AuthProviderCtx / SubjectFromContext only see Caller/Subject when tool handlers
  receive a context that carries them. **Protect-layer contract**
  (`multi_user_http_test.go` + `NewHTTPProtectHandler`): `RequireSubject` + lab
  identity + `AfterIdentity` injects `gateway.Caller` + `policy.Subject` into
  `r.Context()`; mock next hop sees Alice then Bob on independent sessions;
  mid-session subject swap 401s with secret-free bodies.
  **tools/call JSON-RPC e2e (Done\* offline):**
  `TestMultiUserHTTP_ToolsCall_JSONRPC_AliceBobAuthProviderCtx` drives a real MCP
  Streamable HTTP client against `NewHTTPHandler` with lab identity headers,
  two sessions (Alice/Bob), and `CallTool` that exercises Mode A vault
  `AuthProviderCtx` Obtain + `WhoAmI` — Alice/Bob token isolation and secret
  canaries pass. **Session model:** go-sdk v1.1.0 `server.Connect(req.Context())`
  on the session-creating request (initialize) preserves context Values for
  subsequent tool handlers (`jsonrpc2` `notDone`); multi-user is therefore
  **session-scoped** (identity at Connect), not per-`tools/call` rebind from a
  later POST’s `r.Context()`. Mid-session fingerprint still fail-closes subject
  swaps at the protect layer. **Residual:** live Entra/JWKS HA; per-request
  (intra-session) Caller rebind if a future SDK exposes per-POST handler ctx;
  production multi-user GO remains gateway live pins.

## 3c. Multi-tenant isolation foundations (HOST-004 / HOST-006)

**Scope:** single-process MVP. Multi-replica / shared durable cache is **HOST-008 residual**.

### HOST-004 — cache and continuation isolation

| Resource | Isolation key | Behavior |
|----------|---------------|----------|
| Token cache (`MemoryTokenCache` default; optional `FileTokenCache`) | `CacheKey{Tenant,User,Workload,Profile}` via `Caller.CacheKey()` | Cross-user / cross-tenant Get is a miss; file lite via `JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH` (HOST-008 same-host flock; multi-pod external residual) |
| Principal cache (`PrincipalCache` default; optional `FilePrincipalCache`) | `SubjectKey` = `tenant\|subject\|profile` | Non-secret Jenkins principal only; Binding + policy RBAC fallback; never tokens. Optional `JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_MAX` / `_TTL` (LRU + TTL hygiene; empty = unlimited / no expiry). Optional same-host file via `JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH` (HOST-008 flock lite; multi-pod residual) |
| Vault (`APITokenVault` / JWT vault) | `SubjectKey` = `tenant\|subject\|profile` | Cross-subject Get → not found |
| List `page_token` | Filter fingerprint **bound** with subject via `jenkins.BindSubjectToPageFilter` / `*WithSubject` helpers | Alice's token rejected for Bob (`invalid_argument`) |
| Mutation `confirmation_token` | `mutation.Binding` = profile + principal + ExternalSubject + tenant | Alice preview rejected for Bob confirm (`binding_mismatch`) |

Stable namespace: `gateway.SubjectKey(Caller)` / `Caller.SubjectKey()` /
`SubjectKeyHash` for filesystem-safe names. **Never** derive keys from tool args.

Empty `subjectKey` leaves page tokens unbound (stdio single-user pilot). Gateway
mode should always pass a non-empty subject key.

**Serve wire (Done*):** when `--gateway` is on, `cmd/jenkins-mcp` sets
`tools.RegisterOptions.SubjectKey` from `gateway.SubjectKey(CallerFromBoundSubject)`.
List tools (`jenkins_list_jobs`, `jenkins_get_jobs`, `jenkins_list_builds`) resolve
and mint page tokens with `*WithSubject` helpers. Empty `SubjectKey` (stdio)
skips binding. **Multi-user (`JENKINS_MCP_GATEWAY_MULTI_USER`):**
`SubjectKeyFromContext` from `gateway.CallerFromContext`;
`MutationBindingFromContext` via `mutationBindingFromGatewayCtx` prefers
`PolicySubjectFromContext` when **Valid** (PrincipalID = `JenkinsUserID` from
HTTP `JenkinsPrincipal` / lab `X-Jenkins-MCP-Lab-Jenkins-Principal`) else
Caller + `PrincipalCache.Get(SubjectKey)` (Obtain/Mode A vault username) when
non-empty, else process principal. **Done\*** per-request Jenkins principal on
mutation Binding via HTTP claim/lab **or** PrincipalCache after Obtain (Mode A
without lab claim covered). **Done\*** policy RBAC JenkinsUserID via
`policySubjectFromGatewayCtx` + PrincipalCache after Obtain (prefer cache, else
HTTP claim). **Residual:** durable L1/L2 archive namespace (STO / HOST-008).

### HOST-006 — per-subject concurrent + rate budgets

| Type | Role |
|------|------|
| `SubjectLimiter` | Per-`subjectKey` concurrent slots under a process ceiling |
| `Hold` / `WithSubjectSlot` | Acquire → work → Release (prefer over bare Acquire) |
| `SubjectRateLimiter` | Per-`subjectKey` token-bucket rate under process rate ceiling |
| `Allow` | Consume one dispatch token (fail closed `CodeQuota`) |
| `StatusMap` | Non-secret doctor summary (`ha_multi_replica: false` — HOST-008 residual) |
| Mutation confirm Binding | Profile + Principal + ExternalSubject + Tenant; cooldown keys include full binding |

**Concurrency defaults:** **8** concurrent per subject, **64** process-wide
(abs ceilings **64** / **256**). Excess → `CodeQuota`.

**Rate defaults (foundation Done*):** **30** tools/min per subject sustained,
burst **10**; process default **300**/min sustained, burst **60** (abs
**600** / **120** subject; **6000** / **600** process). Excess → `CodeQuota`.
Alice at subject cap does not starve Bob (per-subject buckets; process token
refunded on subject deny).

**Serve wire (Done*):** `tools.RegisterOptions.SubjectLimiter` /
`SubjectRateLimiter` are tools interfaces (implemented by
`*gateway.SubjectLimiter` / `*gateway.SubjectRateLimiter`; tools does not
import gateway). `addTool` calls `Allow` then `Hold` when limiter(s) and
non-empty `SubjectKey` are set. Mutation Manager uses
`MutationBindingFromContext` (multi-user) so confirm tokens and cooldowns cannot
cross subjects; audit ProfileID/PrincipalID prefer the effective binding.
**Done\*** PrincipalID from per-request `policy.Subject` (HTTP JenkinsPrincipal
claim / lab header) when Valid — Alice/Bob PrincipalID mismatch tests; else
**PrincipalCache** (Obtain principal) when present, else process principal +
Caller ExternalSubject isolation. Optional env:

| Env | Role |
|-----|------|
| `JENKINS_MCP_SUBJECT_MAX_CONCURRENT` | Per-subject slots (empty → 8) |
| `JENKINS_MCP_SUBJECT_PROCESS_MAX_CONCURRENT` | Process-wide slots (empty → 64) |
| `JENKINS_MCP_GATEWAY_SUBJECT_LIMITER_MAX_SUBJECTS` | Optional max tracked subjects for `SubjectLimiter` map hygiene (HOST-006 residual lite). Empty → unlimited (0). On Acquire of a **new** subject when full: evict idle (0 in-use) oldest `lastAccess`; if all subjects still hold slots → **fail closed** (`CodeQuota`) — never steals live holders. Invalid fails start. Process-local only — **not** multi-pod |
| `JENKINS_MCP_SUBJECT_RATE_PER_MINUTE` | Per-subject sustained tools/min (empty → 30; **0 = disabled** residual) |
| `JENKINS_MCP_SUBJECT_RATE_BURST` | Per-subject token-bucket capacity (empty → 10) |
| `JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH` | Optional same-host multi-process rate state file (`FileSubjectRateLimiter`, flock + secret-free JSON 0600). Empty → process-local `SubjectRateLimiter`. HOST-008 lite only — **not** multi-pod shared rate. Invalid path fails start |
| `JENKINS_MCP_GATEWAY_SUBJECT_RATE_MAX_SUBJECTS` | Optional max tracked subjects before LRU/oldest `lastAccess` eviction (HOST-008 residual lite). Empty → unlimited (0). Invalid fails start. Process-local / file-local only — **not** multi-pod |

Rate limiter is wired under `--gateway` when `rate_per_minute > 0` after resolve
(default enabled). Explicit `0` leaves `SubjectRateLimiter` nil (unlimited rate;
concurrency still applies). When `JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH` is set,
serve constructs `FileSubjectRateLimiter` instead (same Allow / LowerRate wire;
`StatusMap` / residual-status `shared_subject_rate_file: true`; still
`ha_multi_replica: false`). Optional `JENKINS_MCP_GATEWAY_SUBJECT_RATE_MAX_SUBJECTS`
applies `SetMaxSubjects` on either limiter; when set, `StatusMap` /
residual-status include `subject_rate_max_subjects` (omit when unlimited).
Optional `JENKINS_MCP_GATEWAY_SUBJECT_LIMITER_MAX_SUBJECTS` applies
`SubjectLimiter.SetMaxSubjects`; when set, `StatusMap` / residual-status include
`subject_limiter_max_subjects` (omit when unlimited).

**Policy-driven rate reduction (HOST-006 Done\* foundation):** serve constructs
`SubjectRateLimiter` from env bootstrap, then optional overlay fields may only
**lower** via `SubjectRateLimiter.LowerRate` (absolute floors 1; never raise):

| Overlay field | Role |
|---------------|------|
| `max_tools_per_minute` | Upper bound on per-subject sustained tools/min (lower only) |
| `max_tools_burst` | Upper bound on per-subject burst (lower only) |

**Done\*** Binding PrincipalID + policy SubjectFromContext JenkinsUserID from
PrincipalCache after Obtain (prefer cache over HTTP claim). **Admin residual
knobs Done\* (read-only):** `rateEnabled` / `ratePerMinute` / `rateBurst` on
health + vault. **Done\* SPA Policy editor:** plain pilot overlay
`max_tools_per_minute` / `max_tools_burst` (policy_admin / `policy_write`; lower
only; empty omit). **Residual:** multi-pod shared rate/slots (HOST-008); same-host file rate is
**Done\* lite** via `JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH`. Raise env bootstrap
still needs serve restart.

---

## 4. Identity binding (GWY-002)

Trusted inbound claims (gateway / Entra) map to `policy.Subject` via
`gateway.BindSubject` / `BindSubjectFromEnviron`. **Live Entra claim extraction
is residual** (GWY-003 / OAUTH-010); foundation binding uses verified process
env labels + whoAmI principal.

### Claim → subject mapping

| Inbound claim / source | `policy.Subject` field | Notes |
|------------------------|------------------------|--------|
| Entra/OIDC `sub` | `ExternalSubject` | Required |
| Tenant (`tid`) | `Tenant` | Required (`DefaultBindOptions.RequireTenant`) |
| Workload id | `WorkloadID` | Required (`RequireWorkload`); process/gateway label when not in JWT |
| Groups (bounded) | `Groups` | Optional; see overage table |
| Exchanged / whoAmI / `preferred_username` Jenkins principal | `JenkinsUserID` | Required for RBAC `Valid()` |
| Profile id | `ProfileID` | Required (process profile, not client-supplied) |
| Gateway trust path | `Verified` | True only when claims verified **and** Jenkins principal present |

**Helpers:** `InboundClaimsFromJWTClaims` (verified access-token claims →
`InboundClaims` with `Verified=true`; rejects `token_use=id_token`);
`InboundClaimsFromRequestIdentity` (fail-closed HTTP inbound);
`InboundClaimsFromHTTP` / `BindSubjectFromHTTP` for lab/JWT HTTP paths.

### Binding rules matrix

| Condition | Result |
|-----------|--------|
| Missing `Subject` / `ProfileID` | Fail closed (`authentication`) |
| Missing `Tenant` (default opts) | Fail closed |
| Missing `WorkloadID` (default opts) | Fail closed |
| `Verified=false` (default opts) | Fail closed |
| `JenkinsPrincipal` empty + `RequireJenkinsPrincipal` | Fail closed |
| `JenkinsPrincipal` empty, not required | Bind OK but `Valid()==false`, `Verified==false` (not RBAC-ready) |
| `JenkinsPrincipal == "anonymous"` | Fail closed |
| Env `JENKINS_MCP_GATEWAY_JENKINS_PRINCIPAL` ≠ verified whoAmI | Fail closed (mismatch) |
| Env principal empty | Defaults to verified whoAmI |
| Env principal == whoAmI | Bind OK; `Valid()==true` when other fields present |
| `ExpectedJenkinsPrincipal` set and ≠ claim principal | Fail closed |
| Unique groups > `MaxGroups` (default 64) + `FailOnGroupOverage` | Fail closed (default production) |
| Unique groups > `MaxGroups` + truncate mode | Truncate; `GroupMeta.Truncated` + residual note; **cannot broaden** |
| Single group name > 256 bytes | Fail closed (never truncated short form) |
| Tool args supply `subject` / `jenkins_user` / `tenant` / `as_user` / … | `RejectIdentityToolArgs` → `policy_denial` |
| Mid-session claim fingerprint change | `Binding.Revalidate` fail closed |
| Mid-session HTTP subject swap (same `Mcp-Session-Id`) | `mcpserver` session fingerprint table → 401 (HOST-001; no tokens/subjects in body) |
| Mid-session group claim change (same subject) | `IdentityFingerprint` includes sorted Groups → 401 offline (lab header + lab JWT); order-only change still OK |
| PathPrefix + mid-session swap | Strip does not weaken bind; Alice→Bob under `/mcp` still 401; health root + `{prefix}` exempt |
| Binding TTL exceeded | Re-bind from claims; still fail closed on bind errors |

**API shape:** `BindSubject(claims InboundClaims, opts)` — there is **no** tool-args
parameter. Callers must never construct claims from MCP tool arguments.
`BindSubjectFromEnviron(profileID, verifiedJenkinsUser, getenv)` is the serve-path
wrapper (injectable `getenv` for offline tests).

**Group overage (OAUTH-006 parity):** `MaxInboundGroups=64`,
`MaxInboundGroupNameBytes=256`. Default `FailOnGroupOverage=true` (gateway is
stricter than local OIDC truncate-by-default). Truncate residual string:
`group_overage_truncated: stored_groups capped at N; excess ignored (cannot broaden access)`.

**Entra distributed-claim overage (OAUTH-006 foundation Done\*):** when the
access token has `_claim_names.groups` / groups-as-ref **and no full `groups`
array**, validation fails closed (`authentication` —
`entra group overage without full groups claim; membership not invented`).
No Microsoft Graph expansion (residual OAUTH-010). Hybrid with concrete
`groups` array: accepted.

**Policy**

Gateway subjects **cannot** grant tools denied by MCP `deny_tools` or defeat
`force_read_only` / global RO. Effective access remains:

```text
Jenkins allow ∧ global RO ∧ MCP deny-only ∧ budgets
```

Short TTL: `DefaultBindingTTL` (2m); revalidate per call or within window.

---

## 5. Serve / configuration

Enable gateway mode with any of:

- `jenkins-mcp serve --profile <id> --gateway`
- Profile field `gatewayMode: true`
- `JENKINS_MCP_GATEWAY_MODE=1`

**Required provider env (non-secret):**

| Env | Meaning |
|-----|---------|
| `JENKINS_MCP_AGENTCORE_AS_URL` | Authorization server base (Entra), **not** Jenkins |
| `JENKINS_MCP_AGENTCORE_AUDIENCE` | Exact Jenkins API audience |
| `JENKINS_MCP_AGENTCORE_CLIENT_ID` | Public client id (secret → keyring later) |
| `JENKINS_MCP_AGENTCORE_MODE` | `authorization_code` or `token_exchange` |
| `JENKINS_MCP_AGENTCORE_AUTH_ENDPOINT` | Optional authorize URL |
| `JENKINS_MCP_AGENTCORE_TOKEN_ENDPOINT` | Optional token URL; **required** when `JENKINS_MCP_GATEWAY_LIVE=1` |
| `JENKINS_MCP_GATEWAY_LIVE` | Mode C only: `1`/`true` enables `HTTPTokenFetcher` Live wire (default off) |
| `JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH` | Optional Mode C Obtain cache file (`FileTokenCache`, flock + 0600). Empty → `MemoryTokenCache`. HOST-008 same-host lite only — **not** multi-pod Redis/HA. Invalid path fails start. residual-status `shared_token_cache_file: true` (path never returned; residual never opens the file) |
| `JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH` | Optional principal map file (`FilePrincipalCache`, flock + secret-free JSON 0600; SubjectKey → Jenkins principal only — **never tokens**). Empty → process-local memory. HOST-008 same-host lite only — **not** multi-pod HA. Invalid path fails start |
| `JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH` | Optional gateway subject rate state file (`FileSubjectRateLimiter`, flock + secret-free JSON 0600). Empty → process-local `SubjectRateLimiter`. HOST-008 same-host lite only — **not** multi-pod shared rate. Invalid path fails start |

**Identity env (non-secret labels for foundation binding):**

| Env | Constant | Meaning |
|-----|----------|---------|
| `JENKINS_MCP_GATEWAY_MODE` | `EnvGatewayModeVar` | `1` / `true` enables gateway mode |
| `JENKINS_MCP_GATEWAY_MULTI_USER` | `EnvGatewayMultiUser` | `1` / `true` enables per-request multi-user Obtain (default off = single-subject pin) |
| `JENKINS_MCP_GATEWAY_SUBJECT` | `EnvGatewaySubject` | Entra/OIDC sub (**required** in gateway mode) |
| `JENKINS_MCP_GATEWAY_TENANT` | `EnvGatewayTenant` | Tenant id (**required**) |
| `JENKINS_MCP_GATEWAY_WORKLOAD` | `EnvGatewayWorkload` | Workload id (**required**) |
| `JENKINS_MCP_GATEWAY_JENKINS_PRINCIPAL` | `EnvGatewayJenkinsPrincipal` | Optional; defaults to verified whoAmI; **must match** whoAmI when set |

Missing AS URL/audience → serve fails closed (`capability_missing` / not_configured).  
Invalid Jenkins-as-AS → `invalid_argument`.  
Missing identity env fields → bind fails closed at serve start.

---

## 5b. HOST-001 JWKS refresh foundation (+ optional same-host file lite)

Streamable HTTP JWT subject validation uses a **refreshable JWKS source**
(`internal/auth.RefreshingJWKS` via `cmd/jenkins-mcp` `newHTTPJWKSSource`):

| Behavior | Detail |
|----------|--------|
| Initial fetch | Fail-closed at serve start unless optional same-host file snapshot is fresh enough |
| Refresh TTL | Default **5m**; env `JENKINS_MCP_HTTP_JWKS_REFRESH_TTL` (Go duration; min **30s**, max **1h**; fail closed out of bounds) |
| Max stale age | Default **0 = unlimited** stale-if-error; env `JENKINS_MCP_HTTP_JWKS_MAX_STALE` (Go duration; min **1m**, max **24h** when set; empty/`0`/`0s` = unlimited; invalid → fail closed at serve start). After a failed refresh, if snapshot age (memory **or** file) exceeds max, `Get` fails closed. |
| Optional file cache | Env `JENKINS_MCP_HTTP_JWKS_CACHE_PATH` — same-host multi-process **public JWKS** snapshot (flock + 0600 atomic rename; keys only). Empty → memory-only. residual-status `shared_jwks_file: true` (path **never** returned). HOST-001 / HOST-008 **Done\* lite** only. |
| On demand + background | `Get(ctx)` refreshes when TTL elapsed (singleflight); optional ticker also started for serve |
| Refresh failure | Prefer fresh enough **file** snapshot when configured; else **stale-if-error** (keep last good memory) unless max stale exceeded; non-secret log line only (no path, no key material) |
| Validation | IdentityResolver calls `jwksSource.Get` **each** request so rotated `kid`s work after refresh |
| Secret-free | JWKS URL must not embed credentials; never log tokens / key material / cache path (including max-stale fail-closed logs) |

**Residual (do not claim multi-pod / multi-region HA):** multi-pod external JWKS
cache (Redis/etc.) remains residual; same-host file lite is **not** multi-replica
Done. Live Entra JWKS under load / multi-replica session store (HOST-008).

---

## 6. Residuals (explicit non-goals of this foundation)

| Residual | Track |
|----------|--------|
| **Live Entra / AgentCore network acquisition pin** | GWY-003 / OAUTH-010 — Live opt-in + `HTTPTokenFetcher` prove wire contracts only; not production AgentCore |
| AgentCore Identity/Token Vault (durable) | GWY-001 completion (process memory cache is not a vault) |
| Full GWY-001 DoD (3LO browser UX, refresh/revocation isolation SLOs) | GWY-001 / GWY-003 — **Live opt-in foundation only** (not fully Done) |
| Packaging near-source gateway image (signed prod) | GWY-004 residual — scaffold hardened in `deploy/gateway/` + [deployment.md](deployment.md) (HOST-005 limits/probes; image signing residual) |
| Live AgentCore sidecar pin | GWY-003 / GWY-004 residual |
| Mode B jwt_rs_bearer Live obtain | HOST-010 residual |
| Mid-session subject rebind | HOST-003 / GWY-002 residual |
| Custom Jenkins authorization-server plugin | ADR 0011 / OAUTH-011 **default no-go** |
| Shared Jenkins service account for interactive users | **Never** |
| Real client secret storage | keyring / vault (not profile JSON) |
| Streamable HTTP multi-user subject + mid-session fingerprint | **Partial Done*** offline (HOST-001): `RequireSubject`, lab/JWT, session fingerprint, JWKS TTL refresh + MaxStaleAge, multi-user Obtain + **policy.Subject rebind foundation** + **protect→inner Alice/Bob** (`multi_user_http_test.go`) + **tools/call JSON-RPC Alice/Bob AuthProviderCtx e2e** (`multi_user_tools_call_test.go`, session-scoped Connect ctx) + **mid-session rebind residual expand** (`http_host001_rebind_expand_test.go`: PathPrefix strip + group claim change fail-closed + order-stable groups OK + health exempt; multi-user PathPrefix Alice/Bob swap; lab JWT Alice/Bob + group change in `TestHTTPHandler_LabJWT_MidSessionAliceBobSwapAndGroups`); residual: multi-instance JWKS HA, **live Entra / jwt-auth-filter (not offline expand Done)**, live Entra groups claim completeness, durable multi-replica session store, per-POST (intra-session) handler-ctx rebind if SDK adds it |
| Reverse-proxy non-local matrix | HOST-002 **Partial Done***: docs + `PathPrefix` strip + dual health + offline origin pin + expanded Host/Origin matrix residual lite (`TestHOST002_StreamableHTTPOriginHostMatrix`: missing Origin, wrong/exact Origin, Host allow-list, X-Forwarded-Host/Origin ignore, TrustedProxy true no-op, PathPrefix does not weaken Origin) + `TrustedProxy` default false; **live edge residual** (no live edge claim); no CORS wildcards |
| Health/readiness envelope | HOST-005 **partial** — `/healthz` + `/readyz` + compose/k8s limits; Obtain Ready on `/readyz` when `--gateway` |
| Multi-replica HA | HOST-008 Tier B residual (single-replica Tier A; sticky Service Done* scaffold; multi-pod vault residual) — checklist: [live-pin-blockers.md](live-pin-blockers.md) §4 |
| **Live production pin blockers** | [live-pin-blockers.md](live-pin-blockers.md) — OAUTH-009 RS, OAUTH-010 Entra/AgentCore, HOST-008 multi-pod; residual-smoke honesty |
| **Program path to team-hosted** | [roadmap/server-team-hosted.md](../roadmap/server-team-hosted.md) |

**HOST-003 wiring (Ready path):** closed for Mode A and Mode C Live-opt-in foundation
(Obtain AuthProvider, clear static, whoAmI via Obtain, ConsentRequired metadata,
no other-subject fallthrough). When Obtain is **not** Ready, local API token /
keyring / OIDC remains the residual Jenkins HTTP path so serve can still start.
Default Mode C `CredentialProvider.Obtain` stays fail-closed (`Live=false`) so no
shared SA is substituted for gateway credentials.

---

## 7. Tests

```bash
export PATH="$HOME/.local/go/bin:$PATH"
go test ./internal/gateway/ ./internal/gateway/qualify/ ./internal/mcpserver/ ./internal/auth/ ./internal/policy/ ./cmd/jenkins-mcp/ ./internal/depgraph/ -count=1
```

Coverage includes: Live=false not_configured; Live+nil Fetcher; cache hit
(Fetcher once); wrong audience; ConsentRequired; token canary never in
errors/Status/String; cancelled context; HTTPS-only HTTPTokenFetcher + mock AS;
**OAUTH-010** offline Mode C prototype matrix (`TestOAUTH010_*` + qualify
`oauth010_mode_c_offline_matrix` — not live Entra Done); offline qualify vault
hit/miss, IdP outage chaos, JWKS kid-lite (see [qualification.md](qualification.md));
HOST-001 `RequireSubject` + shared-secret not identity; mid-session
`Mcp-Session-Id` subject swap 401 (PathPrefix + multi-user + lab JWT Alice/Bob
+ group claim change fail-closed; order-stable groups OK; health exempt;
secret-free 401 bodies — `TestHOST001_*` / `TestHTTPHandler_LabJWT_MidSession*`);
multi-user tools/call JSON-RPC Alice/Bob
AuthProviderCtx isolation (`TestMultiUserHTTP_ToolsCall_JSONRPC_*`, session-scoped);
**not live Entra Done**;
HOST-004 two-user token-cache + page_token subject isolation; HOST-006
SubjectLimiter + SubjectRateLimiter fair-share. Opt-in Mode C mock peer:
`make live-oauth-*` + `go test -tags=live_oauth ./internal/gateway/qualify/`
(HOST-015; TLS residual; not Entra Done).

---

## 8. Merge notes (for PR)

- New package `internal/gateway` (FND-004 allow-list updated).
- `policy.Subject` gains optional gateway fields; API-token path unchanged.
- Profile `gatewayMode` optional bool; serve `--gateway` flag.
- Docs: this file; backlog GWY-001/002 foundation progress (not full DoD).

## Server-side auth modes (Tier A)

See [../roadmap/server-team-hosted.md](../roadmap/server-team-hosted.md). Modes **A** (HOST-009 API token vault), **B** (OAUTH-009 + HOST-010 JWT RS), **C** (OAUTH-010 + GWY-001 3LO/OBO) are all first-class; HOST-011 is the fail-closed mode matrix.

## Mode A — per-user personal API token vault (HOST-009)

```text
Obtain (APITokenVaultProvider):
  Live=false              → capability_missing / not_configured
  Live=true, Vault=nil    → not_configured
  Live=true, missing key  → not_found (never ambient keyring / other subject)
  Live=true, hit          → Credential{Mode: api_token_vault, AccessToken: token,
                                       JenkinsPrincipal: username}
  HTTPAuthFromCredential  → scheme=basic, username, token
```

| Type | Role |
|------|------|
| `APITokenVault` | `Get` / `Put` / `Delete` by `subjectKey` (never logs values) |
| `MemoryAPITokenVault` | Process memory for tests |
| `FileAPITokenVault` | Lab file under configurable path, mode **0600**; multi-process flock on `path.lock` (HOST-008 **Done* lite**; not multi-pod HA) |
| `APITokenVaultProvider` | Mode A `CredentialProvider` |
| `SubjectKey(caller)` | Stable `tenant\|subject\|profile` — **never** tool args |
| `HTTPAuthFromCredential` | HOST-003 helper: Basic (A) vs Bearer (B/C) |

**subjectKey:** `gateway.SubjectKey(Caller)` = `tenant|subject|profile` (trimmed).
Production gateways should always set all three fields so keys never collide.
CLI/operators may pass an explicit key string that matches that format.
`SubjectKeyHash` is available for filesystem-safe names when needed.

**Provision / rotate / revoke (operator CLI):**

```bash
# Token value lives only in the environment — never on argv (process list / history).
export JENKINS_MCP_GATEWAY_VAULT_TOKEN='…personal jenkins api token…'
# Or: export MY_TOKEN='…' and pass --token-env MY_TOKEN

jenkins-mcp gateway vault put \
  --subject 'tenant|entra-sub|corp' \
  --user alice \
  --vault-path /path/to/apitoken_vault.json   # optional; else $JENKINS_MCP_GATEWAY_VAULT_PATH / XDG

# Equivalent: compose subject key from parts (tenant|subject|profile)
jenkins-mcp gateway vault set \
  --tenant tenant --subject-id entra-sub --profile corp \
  --user alice --token-env MY_TOKEN

# Inventory: subject keys only (no usernames/tokens)
jenkins-mcp gateway vault list [--vault-path PATH]

# Non-secret presence check
jenkins-mcp gateway vault status --subject 'tenant|entra-sub|corp'
jenkins-mcp gateway vault exists --tenant tenant --subject-id entra-sub --profile corp

# Revoke
jenkins-mcp gateway vault delete --subject 'tenant|entra-sub|corp'
jenkins-mcp gateway vault revoke --subject 'tenant|entra-sub|corp'

# Legacy aliases (still work): vault-put / vault-delete
```

| Env | Meaning |
|-----|---------|
| `JENKINS_MCP_GATEWAY_CREDENTIAL_MODE=api_token_vault` | Select Mode A for serve provider setup |
| `JENKINS_MCP_GATEWAY_VAULT_PATH` | File vault path (default: `$XDG_DATA_HOME/jenkins-mcp/gateway/apitoken_vault.json`). residual-status `shared_api_token_vault_file: true` only when this env is **explicitly set** (default XDG does not count; path never returned; residual never opens vault) |
| `JENKINS_MCP_GATEWAY_VAULT_TOKEN` | Personal API token for `vault put` when `--token-env` is omitted |

| Subcommand | Effect |
|------------|--------|
| `vault put` / `set` | Provision or rotate personal token for subject key |
| `vault delete` / `revoke` | Remove subject key |
| `vault list` | Print **subject keys only** (never usernames/tokens) |
| `vault status` / `exists` | `exists=true\|false` only (no username/token) |

**Admin console residual:** Mode A vault **write** is **CLI-only** (HOST-007 / SPA
residual). Admin exposes secret-free vault **status** (entry count + subject-key
hashes only). Never put vault tokens in admin JSON or the browser. Same-host
shared file path is multi-process safe via flock (**HOST-008 Done* lite**);
multi-pod / sticky-session HA remains residual.

## Mode B — Jenkins-audience JWT bearer (HOST-010 offline)

```text
Obtain (JWTRSBearerProvider):
  Live=false              → capability_missing / not_configured
  Live=true, Vault=nil    → not_configured
  Live=true, missing key  → not_found (never ambient keyring / Mode A / other subject)
  Live=true, hit          → Credential{Mode: jwt_rs_bearer, AccessToken: token}
  HTTPAuthFromCredential  → scheme=bearer (never Basic; never username)
```

| Type | Role |
|------|------|
| `JWTVault` | `Get` / `Put` / `Delete` by `subjectKey` (never logs values) |
| `MemoryJWTVault` | Process memory for tests |
| `FileJWTVault` | Lab file under configurable path, mode **0600**; multi-process flock on `path.lock` (HOST-008 **Done* lite**) |
| `JWTRSBearerProvider` | Mode B `CredentialProvider` |
| `SubjectKey(caller)` | Same `tenant\|subject\|profile` key as Mode A — **never** tool args |
| `HTTPAuthFromCredential` | Bearer for Mode B (and Mode C) |

**Access tokens only:** vault entries and Obtain material must be **Jenkins-audience
access tokens**. **ID tokens must never** be used as Jenkins API credentials
(`rejectIDTokenAsAPICredential` on Put; claim bind rejects `token_use=id_token`).

| Env | Meaning |
|-----|---------|
| `JENKINS_MCP_GATEWAY_CREDENTIAL_MODE=jwt_rs_bearer` | Select Mode B for serve provider setup |
| `JENKINS_MCP_GATEWAY_JWT_VAULT_PATH` | File vault path (default: `$XDG_DATA_HOME/jenkins-mcp/gateway/jwt_vault.json`). residual-status `shared_jwt_vault_file: true` only when this env is **explicitly set** (default XDG does not count; path never returned; residual never opens vault) |

**Residual (explicit):** Live **jwt-auth-filter** / real Entra issuance pin is
**OAUTH-009** — offline vault does **not** close production RS qualification.
See [../auth/jwt-auth-filter-qualification.md](../auth/jwt-auth-filter-qualification.md).
`ModeMatrix.Residual` notes this when Mode B is enabled. Doctor/self-check must
remain honest when RS is not live-qualified.

**GWY-002 claim helpers:**

| Helper | Role |
|--------|------|
| `InboundClaimsFromJWTClaims(auth.AccessTokenClaims, profileID, workloadID)` | Verified JWT claims → `InboundClaims` (`Verified=true`); requires `sub` + profile; copies `Groups` |
| `InboundClaimsFromRequestIdentity(HTTPInbound, profileID)` | Fail-closed HTTP inbound → claims (subject + verified + profile + groups) |
| `PolicySubjectFromHTTPInbound` / `…WithMeta` | Multi-user rebind: Jenkins principal + bounded inbound groups (never process groups) |
| `RejectIdentityToolArgs` | Tool args still cannot set identity |

### AgentCore modes (Mode C / GWY-001)

| Mode | Intent | Default (`Live=false`) | Offline mock (`Live=true` + `Fetcher`) |
|------|--------|------------------------|----------------------------------------|
| `authorization_code` | User-delegated 3LO + consent URL propagation | `not_configured` | Cache → `TokenFetcher`; may return `ConsentRequired` |
| `token_exchange` / `obo` | OBO / RFC 8693 exchange → Jenkins-audience token | `not_configured` | Same; wrong-audience fails closed |

### Pluggable `TokenFetcher` (GWY-001 offline mock)

```text
Obtain:
  Live=false              → capability_missing / not_configured (cache ignored)
  Live=true, Fetcher=nil  → capability_missing (not silent success)
  Live=true, Fetcher set  → validate → cache hit? → Fetcher → cache → Credential
  Fetcher error           → authentication / capability_missing / ConsentRequired
                            (never shared Jenkins SA)
```

| Type | Role |
|------|------|
| `TokenFetcher` | Interface: `FetchJenkinsCredential(ctx, caller, cfg) (Credential, error)` |
| `FuncTokenFetcher` | Function adapter for unit tests |
| `HTTPTokenFetcher` | Optional production-shaped HTTPS token POST (https-only, no redirects, body cap, never log tokens). **Not** attached by `NewAgentCoreProvider` |
| Mock AS (`httptest` TLS in tests) | Returns JSON `access_token` + `expires_in` + optional `audience` / `jenkins_principal`; consent via 401 + auth URL/session |

`NewAgentCoreProvider` always starts **Live=false**, **Fetcher=nil**. Serve may
opt in via `JENKINS_MCP_GATEWAY_LIVE` + token endpoint (`EnableLiveHTTPFetcher`).
**No real Entra** unless that opt-in is configured (AgentCore pin still residual).

Consent metadata (`ConsentInfo`) may carry **authorization URL + session id** only —
never access tokens, refresh tokens, client secrets, or auth codes.
Tool path: `mapToolErr` surfaces progressive `authorization_url` + `session_id`
(**Done\*** metadata path; browser 3LO not automated — GWY-003 / OAUTH-010 residual).
Process-local consent metadata store (optional XDG file) remembers metadata only
when Obtain returns `ConsentRequired` — same-host reload-before-persist flock lite
(**Done\***); not multi-replica / multi-pod shared store (HOST-008 residual).
See §3 progressive consent residual table; CLI: `jenkins-mcp gateway consent-residual`,
`jenkins-mcp gateway consent-purge` (TTL expire / `--session-id` / `--all --confirm=CLEAR_ALL`).

Token cache: in-memory, keyed by `(user, workload, profile)`, TTL-bounded.
`String()` / errors / `Status` **never** include token bytes (canary tests).

When the token JSON includes `audience` / `resource`, it must **exactly** match
configured Jenkins API audience (wrong-audience residual fail-closed).

See §3 Live opt-in and §3b HOST-003 for serve wiring details.

---
