# Managed gateway / AgentCore foundation (GWY-001/002)

**Status:** Foundation + **offline mock obtain path** (pluggable `TokenFetcher`).  
**Default:** `Live=false`, `Fetcher=nil` → fail-closed `not_configured` (no network).  
**Offline qualify** (GWY-003 lite) available; **live Entra / AgentCore pin residual**.  
**GWY-004:** deployment **scaffold** (compose/kustomize/docs) only — no live AgentCore image.  
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
| Mock AS (`httptest` TLS in tests) | Returns JSON `access_token` + `expires_in` + optional `audience` / `jenkins_principal`; consent via 401 + auth URL/session |

`NewAgentCoreProvider` always starts **Live=false**, **Fetcher=nil**. Tests (or future operators) inject a fetcher and set `Live=true` explicitly. **No real Entra** is called from default serve wiring.

Consent metadata (`ConsentInfo`) may carry **authorization URL + session id** only —
never access tokens, refresh tokens, client secrets, or auth codes.

Token cache: in-memory, keyed by `(tenant, user, workload, profile)` (HOST-004),
TTL-bounded. `String()` / errors / `Status` **never** include token bytes (canary tests).

When the token JSON includes `audience` / `resource`, it must **exactly** match
configured Jenkins API audience (wrong-audience residual fail-closed).

---

## 3b. Multi-tenant isolation foundations (HOST-004 / HOST-006)

**Scope:** single-process MVP. Multi-replica / shared durable cache is **HOST-008 residual**.

### HOST-004 — cache and continuation isolation

| Resource | Isolation key | Behavior |
|----------|---------------|----------|
| Token cache (`MemoryTokenCache`) | `CacheKey{Tenant,User,Workload,Profile}` via `Caller.CacheKey()` | Cross-user / cross-tenant Get is a miss |
| Vault (`APITokenVault`) | `SubjectKey` = `tenant\|subject\|profile` | Cross-subject Get → not found |
| List `page_token` | Filter fingerprint **bound** with subject via `jenkins.BindSubjectToPageFilter` / `*WithSubject` helpers | Alice's token rejected for Bob (`invalid_argument`) |

Stable namespace: `gateway.SubjectKey(Caller)` / `Caller.SubjectKey()` /
`SubjectKeyHash` for filesystem-safe names. **Never** derive keys from tool args.

```go
// Multi-tenant list pagination (call sites in gateway mode):
fp := jenkins.FilterFingerprint(folder, name)
tok := jenkins.EncodePageTokenWithSubject(offset, limit, fp, gateway.SubjectKey(caller))
off, lim, err := jenkins.ResolveListPaginationWithSubject(pageToken, …, fp, gateway.SubjectKey(caller))
```

Empty `subjectKey` leaves page tokens unbound (stdio single-user pilot). Gateway
mode should always pass a non-empty subject key.

**Residual (HOST-004 serve wire):** list tools under `internal/jenkins` /
`internal/tools` still use unbound `ResolveListPagination` by default. Package
APIs + tests are ready; wiring subject from `RegisterOptions.Subject` /
gateway binding into every list tool is a follow-up (same PR optional; not
required for foundation). Support-bundle/doctor remain secret-free (no tokens
in keys or Status).

### HOST-006 — per-subject concurrent budgets

| Type | Role |
|------|------|
| `SubjectLimiter` | Per-`subjectKey` concurrent slots under a process ceiling |
| `Hold` / `WithSubjectSlot` | Acquire → work → Release (prefer over bare Acquire) |
| `StatusMap` | Non-secret doctor summary (`ha_multi_replica: false`) |

Defaults: **8** concurrent per subject, **64** process-wide (clamped to abs
ceilings **64** / **256**). Excess → `CodeQuota` (fail closed). Empty subjectKey
→ `invalid_argument`. Policy may only **reduce** caps (construction clamps to
absolute ceilings; never silent elevation past abs).

```go
lim := gateway.NewSubjectLimiter(8, 64)
release, err := lim.Hold(gateway.SubjectKey(caller))
if err != nil { /* CodeQuota */ }
defer release()
// … tool work …
```

**Fair-share policy (documented + tested):** each subject gets up to
`maxPerSubject` until `processMax` binds. Subject A filling its cap does not
consume subject B's slots while process headroom remains.

**Residual (HOST-006 serve wire):** limiter API is exported for AuthGate-adjacent
middleware; full `tools.Register` / `addTool` integration is optional. Concurrent
limiting is **not** a pure `AuthGate` (`Check` without `Release`) — use `Hold`.
Mutation confirm tokens already bind profile+principal (cannot replay across
subjects). HOST-008 multi-process HA out of scope.

```bash
go test ./internal/gateway/ ./internal/jenkins/ -count=1 -run 'HOST004|SubjectLimiter|PageToken_Subject|TwoUser'
```

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
| `JENKINS_MCP_AGENTCORE_TOKEN_ENDPOINT` | Optional token URL |

**Identity env (non-secret labels for foundation binding):**

| Env | Constant | Meaning |
|-----|----------|---------|
| `JENKINS_MCP_GATEWAY_MODE` | `EnvGatewayModeVar` | `1` / `true` enables gateway mode |
| `JENKINS_MCP_GATEWAY_SUBJECT` | `EnvGatewaySubject` | Entra/OIDC sub (**required** in gateway mode) |
| `JENKINS_MCP_GATEWAY_TENANT` | `EnvGatewayTenant` | Tenant id (**required**) |
| `JENKINS_MCP_GATEWAY_WORKLOAD` | `EnvGatewayWorkload` | Workload id (**required**) |
| `JENKINS_MCP_GATEWAY_JENKINS_PRINCIPAL` | `EnvGatewayJenkinsPrincipal` | Optional; defaults to verified whoAmI; **must match** whoAmI when set |

Missing AS URL/audience → serve fails closed (`capability_missing` / not_configured).  
Invalid Jenkins-as-AS → `invalid_argument`.  
Missing identity env fields → bind fails closed at serve start.

---

## 6. Residuals (explicit non-goals of this foundation)

| Residual | Track |
|----------|--------|
| **Live Entra / AgentCore network acquisition pin** | GWY-003 / OAUTH-010 — offline mock + `HTTPTokenFetcher` only prove contracts |
| AgentCore Identity/Token Vault (durable) | GWY-001 completion (process memory cache is not a vault) |
| Serve wiring that injects `HTTPTokenFetcher` + Live | Operator config residual; default remains fail-closed (HOST-003) |
| Packaging near-source gateway image (signed prod) | GWY-004 residual — scaffold in `deploy/gateway/` + [deployment.md](deployment.md) |
| Live AgentCore sidecar pin | GWY-003 / GWY-004 residual |
| Custom Jenkins authorization-server plugin | ADR 0011 / OAUTH-011 **default no-go** |
| Shared Jenkins service account for interactive users | **Never** |
| Real client secret storage | keyring / vault (not profile JSON) |
| Streamable HTTP gateway transport hardening | GWY-004 residual (HOST-001 / HOST-002) |
| **Program path to team-hosted** | [roadmap/server-team-hosted.md](../roadmap/server-team-hosted.md) |

Until live AgentCore is pinned, local **API token + keyring** remains the Jenkins
HTTP credential path when serve still starts. Default `CredentialProvider.Obtain`
stays fail-closed (`Live=false`) so no shared SA is substituted for gateway credentials.

---

## 7. Tests

```bash
export PATH="$HOME/.local/go/bin:$PATH"
go test ./internal/gateway/ ./internal/gateway/qualify/ ./internal/auth/ ./internal/policy/ ./cmd/jenkins-mcp/ ./internal/depgraph/ -count=1
```

Coverage includes: Live=false not_configured; Live+nil Fetcher; cache hit
(Fetcher once); wrong audience; ConsentRequired; token canary never in
errors/Status/String; cancelled context; HTTPS-only HTTPTokenFetcher + mock AS;
offline qualify vault hit/miss, IdP outage chaos, JWKS kid-lite (see
[qualification.md](qualification.md)); HOST-004 two-user token-cache +
page_token subject isolation; HOST-006 SubjectLimiter per-subject vs process
ceilings and fair-share.

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

**Provision / rotate / revoke (CLI):**

```bash
# Token value lives only in the environment — never on argv.
export MY_TOKEN='…personal jenkins api token…'
jenkins-mcp gateway vault-put \
  --subject 'tenant|entra-sub|corp' \
  --user alice \
  --token-env MY_TOKEN \
  --vault-path /path/to/apitoken_vault.json   # optional

jenkins-mcp gateway vault-delete --subject 'tenant|entra-sub|corp'
```

| Env | Meaning |
|-----|---------|
| `JENKINS_MCP_GATEWAY_CREDENTIAL_MODE=api_token_vault` | Select Mode A for serve provider setup |
| `JENKINS_MCP_GATEWAY_VAULT_PATH` | File vault path (default: `$XDG_DATA_HOME/jenkins-mcp/gateway/apitoken_vault.json`) |

**Admin console residual:** Mode A vault provision/list is **CLI-only** in this
foundation (HOST-007 / admin SPA residual). Never put vault tokens in admin JSON.

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
| `InboundClaimsFromJWTClaims(auth.AccessTokenClaims, profileID, workloadID)` | Verified JWT claims → `InboundClaims` (`Verified=true`); requires `sub` + profile |
| `InboundClaimsFromRequestIdentity(HTTPInbound, profileID)` | Fail-closed HTTP inbound → claims (subject + verified + profile) |
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

`NewAgentCoreProvider` always starts **Live=false**, **Fetcher=nil**. Tests (or future operators) inject a fetcher and set `Live=true` explicitly. **No real Entra** is called from default serve wiring.

Consent metadata (`ConsentInfo`) may carry **authorization URL + session id** only —
never access tokens, refresh tokens, client secrets, or auth codes.

Token cache: in-memory, keyed by `(user, workload, profile)`, TTL-bounded.
`String()` / errors / `Status` **never** include token bytes (canary tests).

When the token JSON includes `audience` / `resource`, it must **exactly** match
configured Jenkins API audience (wrong-audience residual fail-closed).

---
