# Managed gateway / AgentCore foundation (GWY-001/002)

**Status:** Foundation + offline mock obtain + **HOST-003 Ready wire** + **GWY-001 Live opt-in foundation** (`HTTPTokenFetcher`) + **HOST multi-user Obtain foundation** (`AuthProviderCtx` + `JENKINS_MCP_GATEWAY_MULTI_USER`).  
**Default:** `Live=false`, `Fetcher=nil` → fail-closed `not_configured` (no network). Single-subject pin remains default when multi-user env is off.  
**Live opt-in:** `JENKINS_MCP_GATEWAY_LIVE=1` + token endpoint → `EnableLiveHTTPFetcher` (Mode C only).  
**Multi-user opt-in:** `JENKINS_MCP_GATEWAY_MULTI_USER=1` → per-request Caller → Obtain (see §3b).  
**Real Entra / AgentCore Identity vault pin residual** (GWY-003 / OAUTH-010) — do **not** mark GWY-001 fully Done.  
**GWY-004:** deployment **scaffold** (compose/kustomize/docs + `.env.example` lab flags: MULTI_USER, JWKS max stale, path prefix, REQUIRE_SIGNED_POLICY, subject concurrency) only — no live AgentCore image; live pins residual.  
**Related:** [deployment.md](deployment.md), [qualification.md](qualification.md), [auth-architecture.md](../auth-architecture.md) §2.3, [ADR 0003](../adr/0003-jenkins-not-oauth-authorization-server.md), [policy-rbac.md](../policy-rbac.md), architecture §§1–2 / §6.6, **[server/team-hosted roadmap](../roadmap/server-team-hosted.md)** (Tier A path, HOST-*, 30/60/90).

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
  default                         → Live=false, Fetcher=nil, Ready=false
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

**Progressive consent residual (Mode C):** full browser 3LO UX, durable consent
session store, and multi-replica consent correlation remain **GWY-003 /
OAUTH-010 / HOST-008** — not closed by metadata propagation alone.

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
| Policy RBAC | `tools.RegisterOptions.SubjectFromContext` = `gateway.PolicySubjectFromContext`; `addTool` / `listToolsAllows` use `effectiveSubject` (ctx subject when present, else process Subject) |
| Mutation Binding | `MutationBindingFromContext` = `mutationBindingFromGatewayCtx`: Valid `PolicySubject` → PrincipalID=`JenkinsUserID` (HTTP/lab JenkinsPrincipal); else Caller + process principal. Mode A vault multi-user: send lab/JWT JenkinsPrincipal matching vault username |
| Subject pin | `ExpectedExternalSubject` is **not** set (distinct lab/JWT subjects allowed) |
| Fail closed | empty subject / Obtain miss → error; never other subject's token; never shared SA; tool args never rebind identity |
| Static fields | AuthProviderCtx does **not** write User/Token on the Client (race residual); AuthProviderCtx cannot store Obtain principal on ctx (HTTP claim is multi-user PrincipalID source) |

| Env | Role |
|-----|------|
| `JENKINS_MCP_GATEWAY_MULTI_USER` | Opt-in multi-user Obtain + policy.Subject rebind path (default off = single-subject pin) |

**Residuals (honest):**

- **Policy RBAC Subject rebind:** **Done\*** foundation — per-request
  `policy.Subject` from trusted HTTP identity on context
  (`ContextWithPolicySubject` / `SubjectFromContext` / `effectiveSubject`).
  Process `RegisterOptions.Subject` remains the multi-user-off / missing-ctx
  default. Tool args never supply identity (`RejectIdentityToolArgs`).
- **Mutation Binding PrincipalID:** **Done\*** when HTTP/lab carries
  JenkinsPrincipal (Valid PolicySubject). Mode A vault multi-user tests must
  send `X-Jenkins-MCP-Lab-Jenkins-Principal` (or JWT preferred_username) matching
  vault username. **Residual:** Obtain/`AuthProviderCtx` success does not
  re-inject whoAmI principal onto request context mid-call.
- **IdP groups foundation (OAUTH-006 / GWY-002 residual lite): Done\*** —
  JWT access-token `groups`/`roles` → `PolicySubjectFromHTTPInbound` /
  `BindSubject` with `MaxInboundGroups=64`, name length 256, default
  `FailOnGroupOverage=true`. Lab header `X-Jenkins-MCP-Lab-Groups`
  (comma-separated) only when lab identity is on. Groups never elevate
  `deny_tools` / `force_read_only`.
- **Live Entra group overage / Microsoft Graph membership expansion** remains
  residual (OAUTH-010 / GWY-003): no Graph call; overage references do not invent membership.
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
| Token cache (`MemoryTokenCache`) | `CacheKey{Tenant,User,Workload,Profile}` via `Caller.CacheKey()` | Cross-user / cross-tenant Get is a miss |
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
Caller + process principal. **Done\*** per-request Jenkins principal on mutation
Binding when the trusted HTTP claim/lab path carries JenkinsPrincipal (Mode A
vault multi-user: send lab/JWT principal matching vault username). **Residual:**
durable L1/L2 archive namespace (STO / HOST-008); Obtain/`AuthProviderCtx` does
not re-inject whoAmI principal onto ctx mid-call (HTTP claim remains the
multi-user PrincipalID source).

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
process principal + Caller ExternalSubject isolation. Optional env:

| Env | Role |
|-----|------|
| `JENKINS_MCP_SUBJECT_MAX_CONCURRENT` | Per-subject slots (empty → 8) |
| `JENKINS_MCP_SUBJECT_PROCESS_MAX_CONCURRENT` | Process-wide slots (empty → 64) |
| `JENKINS_MCP_SUBJECT_RATE_PER_MINUTE` | Per-subject sustained tools/min (empty → 30; **0 = disabled** residual) |
| `JENKINS_MCP_SUBJECT_RATE_BURST` | Per-subject token-bucket capacity (empty → 10) |

Rate limiter is wired under `--gateway` when `rate_per_minute > 0` after resolve
(default enabled). Explicit `0` leaves `SubjectRateLimiter` nil (unlimited rate;
concurrency still applies).

**Residual:** multi-replica shared rate/slots (HOST-008); policy-driven rate
reduction beyond env; Obtain principal not re-injected onto request ctx mid-call
(Binding PrincipalID uses HTTP claim / lab JenkinsPrincipal when Valid).

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
| Mid-session HTTP subject swap (same `Mcp-Session-Id`) | `mcpserver` session fingerprint table → 401 (HOST-001; no tokens in body) |
| Binding TTL exceeded | Re-bind from claims; still fail closed on bind errors |

**API shape:** `BindSubject(claims InboundClaims, opts)` — there is **no** tool-args
parameter. Callers must never construct claims from MCP tool arguments.
`BindSubjectFromEnviron(profileID, verifiedJenkinsUser, getenv)` is the serve-path
wrapper (injectable `getenv` for offline tests).

**Group overage (OAUTH-006 parity):** `MaxInboundGroups=64`,
`MaxInboundGroupNameBytes=256`. Default `FailOnGroupOverage=true` (gateway is
stricter than local OIDC truncate-by-default). Truncate residual string:
`group_overage_truncated: stored_groups capped at N; excess ignored (cannot broaden access)`.

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

## 5b. HOST-001 JWKS refresh foundation (process-local)

Streamable HTTP JWT subject validation uses a **refreshable JWKS source**
(`internal/auth.RefreshingJWKS` via `cmd/jenkins-mcp` `newHTTPJWKSSource`):

| Behavior | Detail |
|----------|--------|
| Initial fetch | Fail-closed at serve start |
| Refresh TTL | Default **5m**; env `JENKINS_MCP_HTTP_JWKS_REFRESH_TTL` (Go duration; min **30s**, max **1h**; fail closed out of bounds) |
| Max stale age | Default **0 = unlimited** stale-if-error; env `JENKINS_MCP_HTTP_JWKS_MAX_STALE` (Go duration; min **1m**, max **24h** when set; empty/`0`/`0s` = unlimited; invalid → fail closed at serve start). After a failed refresh, if last good snapshot age exceeds max, `Get` fails closed (process-local clock). |
| On demand + background | `Get(ctx)` refreshes when TTL elapsed (singleflight); optional ticker also started for serve |
| Refresh failure | **Stale-if-error** (keep last good) unless max stale exceeded; non-secret log line only |
| Validation | IdentityResolver calls `jwksSource.Get` **each** request so rotated `kid`s work after refresh |
| Secret-free | JWKS URL must not embed credentials; never log tokens / key material (including max-stale fail-closed logs) |

**Residual (do not claim multi-region HA):** multi-instance shared JWKS cache
(`MaxStaleAge` / `JENKINS_MCP_HTTP_JWKS_MAX_STALE` is **process-local** only — each
replica tracks its own last-good age); live Entra JWKS under load / multi-replica
session store (HOST-008).

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
| Streamable HTTP multi-user subject + mid-session fingerprint | **Partial Done*** offline (HOST-001): `RequireSubject`, lab/JWT, session fingerprint, JWKS TTL refresh + MaxStaleAge, multi-user Obtain + **policy.Subject rebind foundation** + **protect→inner Alice/Bob** (`multi_user_http_test.go`) + **tools/call JSON-RPC Alice/Bob AuthProviderCtx e2e** (`multi_user_tools_call_test.go`, session-scoped Connect ctx); residual: multi-instance JWKS HA, live Entra groups claim completeness, per-POST (intra-session) handler-ctx rebind if SDK adds it |
| Reverse-proxy non-local matrix | HOST-002 **Partial Done***: docs + `PathPrefix` strip + dual health + offline origin pin fixtures + `TrustedProxy` default false; live edge residual; no CORS wildcards |
| Health/readiness envelope | HOST-005 **partial** — `/healthz` + `/readyz` + compose/k8s limits; Obtain Ready on `/readyz` when `--gateway` |
| Multi-replica HA | HOST-008 Tier B residual (single-replica Tier A default) |
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
`Mcp-Session-Id` subject swap 401; multi-user tools/call JSON-RPC Alice/Bob
AuthProviderCtx isolation (`TestMultiUserHTTP_ToolsCall_JSONRPC_*`, session-scoped);
HOST-004 two-user token-cache + page_token subject isolation; HOST-006
SubjectLimiter + SubjectRateLimiter fair-share. Opt-in Mode C mock peer:
`make live-oauth-*` (HOST-015).

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
| `FileAPITokenVault` | Lab file under configurable path, mode **0600** |
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
| `JENKINS_MCP_GATEWAY_VAULT_PATH` | File vault path (default: `$XDG_DATA_HOME/jenkins-mcp/gateway/apitoken_vault.json`) |
| `JENKINS_MCP_GATEWAY_VAULT_TOKEN` | Personal API token for `vault put` when `--token-env` is omitted |

| Subcommand | Effect |
|------------|--------|
| `vault put` / `set` | Provision or rotate personal token for subject key |
| `vault delete` / `revoke` | Remove subject key |
| `vault list` | Print **subject keys only** (never usernames/tokens) |
| `vault status` / `exists` | `exists=true\|false` only (no username/token) |

**Admin console residual:** Mode A vault **write** is **CLI-only** (HOST-007 / SPA
residual). Admin exposes secret-free vault **status** (entry count + subject-key
hashes only). Never put vault tokens in admin JSON or the browser. Live multi-host
shared vault is residual (HOST-008).

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
| `FileJWTVault` | Lab file under configurable path, mode **0600** |
| `JWTRSBearerProvider` | Mode B `CredentialProvider` |
| `SubjectKey(caller)` | Same `tenant\|subject\|profile` key as Mode A — **never** tool args |
| `HTTPAuthFromCredential` | Bearer for Mode B (and Mode C) |

**Access tokens only:** vault entries and Obtain material must be **Jenkins-audience
access tokens**. **ID tokens must never** be used as Jenkins API credentials
(`rejectIDTokenAsAPICredential` on Put; claim bind rejects `token_use=id_token`).

| Env | Meaning |
|-----|---------|
| `JENKINS_MCP_GATEWAY_CREDENTIAL_MODE=jwt_rs_bearer` | Select Mode B for serve provider setup |
| `JENKINS_MCP_GATEWAY_JWT_VAULT_PATH` | File vault path (default: `$XDG_DATA_HOME/jenkins-mcp/gateway/jwt_vault.json`) |

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
(Mode C residual; full 3LO browser UX remains GWY-003 / OAUTH-010).

Token cache: in-memory, keyed by `(user, workload, profile)`, TTL-bounded.
`String()` / errors / `Status` **never** include token bytes (canary tests).

When the token JSON includes `audience` / `resource`, it must **exactly** match
configured Jenkins API audience (wrong-audience residual fail-closed).

See §3 Live opt-in and §3b HOST-003 for serve wiring details.

---
