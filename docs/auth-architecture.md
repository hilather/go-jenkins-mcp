# Authentication architecture lock (AUTH-000)

**Status:** Binding terminology and path order (Phase 0)  
**ADRs:** [0003](adr/0003-jenkins-not-oauth-authorization-server.md) (no native Jenkins AS), [0009](adr/0009-personal-api-token-secret-service.md) (API token first), [0011](adr/0011-custom-jenkins-authz-plugin-gated.md) (full AS plugin gated)  
**Threat model:** [security/threat-model.md](security/threat-model.md)  
**Architecture:** `docs/architecture/README.md` (historical: `docs/archive/jenkins-mcp-enterprise-architecture.md`) §§1–2, §6  

This note is the security-facing summary so code and docs **never** claim that
stock Jenkins is a native three-legged OAuth (3LO) authorization server.

---

## 1. Non-negotiable terminology

| Correct | Forbidden (never claim) |
|---------|-------------------------|
| Jenkins is a **resource server** (or protected API) for scripted clients | Never claim stock Jenkins is a native 3LO provider or OAuth provider |
| **External IdP** (e.g. Entra) is the **authorization server** for PKCE/3LO | Never claim stock Jenkins issues OAuth access tokens for third-party apps |
| `jwt-auth-filter` validates **bearer JWTs** (resource-server filter) | Never claim the filter alone provides complete native 3LO |
| AgentCore **3LO/OBO against Entra** for a **Jenkins-audience** token | Never point AgentCore AS endpoints at stock Jenkins |
| Full Jenkins AS plugin = **conditional / default no-go** (ADR 0011) | Never list “native Jenkins 3LO” as a baseline supported auth mode |

**Regression guard:** `go test ./internal/auth -run Terminology` fails on
affirmative “Jenkins is … 3LO/OAuth provider/AS” claims in tracked `.md`/`.go`
(see `terminology_doc_test.go`).

---

## 2. Supported identity paths (order)

### 2.1 Personal API token (first production)

- Scripted client model: HTTPS Basic `username:api_token`.  
- Token from **Linux Secret Service** on Tier 1 (ADR 0009); never primary docs for argv/env.  
- Per-person only; shared/generic SAs prohibited for interactive users.  
- Identity verified against an approved Jenkins identity endpoint; anonymous/wrong principal fails closed.

```text
Cursor --stdio--> jenkins-mcp --Basic(user:api_token)--> Jenkins
                      ^
                      keyring (Secret Service)
```

### 2.2 External IdP PKCE → Jenkins-audience token → resource server

- Authorization Code + PKCE against **Entra or approved IdP**.  
- MCP (local) owns browser/loopback PKCE; Cursor remote OAuth is not a substitute for Jenkins UI SSO.  
- Access token must be for the **exact Jenkins API audience**; Graph/generic gateway tokens rejected.  
- Jenkins validates via **`jwt-auth-filter`** (or approved fork/proxy) as **resource server only**.  
- Implement under OAUTH-* (not in AUTH-000).

```text
Cursor -> MCP -> Entra (AS: authorize + token)
                    |
                    +-> Jenkins-audience JWT
                              |
                              v
                    Jenkins jwt-auth-filter (RS)
```

### 2.3 AgentCore / gateway: 3LO and OBO point at Entra, not Jenkins

Qualification order (architecture §6.6, ADR 0011):

1. User-delegated authorization-code 3LO against **Entra** (resource = Jenkins API).  
2. OBO / RFC 8693 / RFC 7523 exchange → short-lived Jenkins-audience token.  
3. Exact-audience JWT passthrough only when inbound token already has Jenkins audience and security approves.  
4. Narrow broker/filter if Entra cannot mint the resource token.  
5. **Full Jenkins authorization-server plugin** — last resort, funded security decision only.

AgentCore discovery/authorization/token endpoints are **Entra (or approved AS)**,
never stock Jenkins, unless epic (5) is approved and shipped.

---

## 3. Explicit non-solutions (plugin categories)

| Plugin / mechanism | Actual role | MCP stance |
|--------------------|-------------|------------|
| **`oic-auth`** | Browser security realm (UI login) | Not MCP API 3LO; scripted clients still use tokens/bearer |
| **`oidc-provider`** | Workload identity **from builds outward** | Opposite direction; exclude from user→Jenkins auth |
| **`github-oauth`** | GitHub-specific UI realm | Not a general enterprise 3LO design |
| **`oauth-credentials`** | Credentials framework for plugins | Not a delegated authorization server |
| **`jwt-auth-filter`** | Bearer JWT **resource server** | In-scope for qualification; not an AS; harden fallthrough + routes |

---

## 4. `jwt-auth-filter` is resource server only

- Validates externally issued JWTs (JWKS, audience, paths, RFC 9728 metadata).  
- Does **not** create authorization codes, consent, or third-party token issuance.  
- Production requires: complete MCP route coverage (not only `/**/api/**`), fail-closed on invalid bearer (no Basic/session/anon fallthrough for OAuth-required profiles), claim mapping, JWKS rotation/outage behavior.  
- Tracked under OAUTH / jwt qualification tasks — not AUTH-000 implementation.

---

## 5. Shared-account prohibition

Every interactive profile is a **personal** identity. Executable and non-secret
config may be shared; credentials, refresh material, cache namespaces, and audit
identity must not substitute a generic service account.

---

## 6. What AUTH-000 does **not** implement

| Deferred | Task family |
|----------|-------------|
| Keyring login/logout UX | AUTH-001+ |
| Profile schema + reject Jenkins URL as AS endpoint | CFG-001 |
| Local PKCE browser login | OAUTH-002 residual (writes via `OIDCProvider.StoreTokens`) |
| Token refresh store + single-flight refresh | OAUTH-004 (`TokenBundle` / keyring `method=oidc_tokens`) |
| OAuth logout / status `has_refresh` / recovery | OAUTH-007 |
| jwt-auth-filter lab qualification | OAUTH-009 ([jwt-auth-filter-qualification.md](auth/jwt-auth-filter-qualification.md); offline classifier implemented Wave 33; live pin residual) |
| Capability matrix (paths/plugins) | [auth/oauth-capability-matrix.md](auth/oauth-capability-matrix.md) (OAUTH-008) |
| AgentCore providers | GWY-* / OAUTH-010+ |
| Full Jenkins AS plugin | Decision gate + separate epic (ADR 0011) |
| Live Entra pin | Lab/security residual (not epoch) |

### Wave 14 serve continuity (landed)

| Piece | Location |
|-------|----------|
| Mid-serve refresh | `jenkins.Client.AuthProvider` + `auth.LiveSessionSource` (single-flight `Authenticate`) |
| Tool-path gate | `tools.RegisterOptions.AuthGate` (`*auth.SessionGuard` / MultiGate / IdentityReverifyGate) |
| ListTools discovery gate (Wave 29) | Same `AuthGate`: `InstallListToolsPolicyFilter` empties `tools/list` when `Check()` fails (no tool-name leak after session death) |
| Serve JWT re-validate | `auth.ValidateServeAccessToken` (discovery JWKS; opaque skips) |
| Groups → subject | `GroupsFromValidatedToken` → `policy.Subject.WithGateway` (deny-only still applies) |

### OAUTH-003 offline claim validation (landed\*)

Full offline matrix (issuer, audience, alg allow-list, exp/nbf skew, azp/tid,
ID-token rejection, Graph/known-bad audiences, size bound) is enforced by
`auth.ValidateAccessToken`. Login (`LoginOIDC`) and serve both use it for
JWT-shaped access tokens; **opaque** tokens skip JWT parse and bind via whoAmI.

| Doc | Detail |
|-----|--------|
| Claim matrix + residuals | [auth/oauth-003-claim-validation.md](auth/oauth-003-claim-validation.md) |
| Groups caps (OAUTH-006 light) | `MaxStoredGroups=64`, `MaxGroupNameBytes=256` |
| Entra group overage (OAUTH-006 foundation implemented) | `_claim_names`/`_claim_sources` or groups-as-ref without full `groups` array → fail closed (`CheckIncompleteGroupOverage`); hybrid concrete groups OK; no Graph expansion (OAUTH-010 residual) |
| Still residual | Live jwt-auth-filter lab / bearer RS pin — **OAUTH-005 / OAUTH-009** (offline classifier `implemented` Wave 33; production pin still residual); Graph group expansion — **OAUTH-010** |

### Wave 15 cross-process session invalidation (landed)

CLI `logout` / re-`login` must not leave a long-lived `serve` process using
in-memory OIDC material until refresh fails or the process restarts.

| Piece | Behavior |
|-------|----------|
| **Epoch file** | Non-secret `$profileDataDir/session.epoch` (mode **0600**, atomic temp+rename). Content: monotonic seq + RFC3339Nano + random nonce — **never tokens**. |
| **Bump on login** | After durable token store (`OIDCProvider.StoreTokens` / `LoginOIDC` with `Epoch`) |
| **Bump on logout** | After local keyring clear (`OIDCProvider.LogoutDetailed` when `Epoch` set) |
| **Serve watch** | `auth.SessionEpochWatcher` bound at serve start; checked on `LiveSessionSource.Credentials` **and** `LiveSessionSource.Check` (tool AuthGate). On change → `SessionGuard.Disable` + clear process-local `TokenBundle`; next auth reloads keyring (empty → auth error). |
| **Helpers** | `auth.SessionEpochStore`, `auth.SessionEpochWatcher` |

Residual without epoch (still valid fallback): refresh fail / process exit still
mark or drop the in-process guard.

### Wave 23 AUTH-004 mid-serve whoAmI re-verify (landed)

Serve no longer binds identity only at process start. Tool dispatch re-checks
the Jenkins principal on a short TTL so credential swap / anonymous fallback /
revoked tokens fail closed mid-session.

| Piece | Behavior |
|-------|----------|
| **IdentityReverifyGate** | `auth.IdentityReverifyGate` implements `Check()` (tools.AuthGate). Cache hit within configured TTL → OK; else `VerifyIdentityCachedHTTP` with current Session + Profile + HTTP client. |
| **Bound principal** | Serve-time `principal.ID` is fixed at construction; any whoAmI id change → sticky authentication failure (re-authenticate). |
| **Fail closed** | whoAmI transport/401, anonymous, missing id, principal drift — never elevate; errors never include tokens. |
| **api_token** | AuthGate = reverify alone (principal binding on TTL expiry). |
| **OIDC** | AuthGate = `auth.MultiGates(LiveSessionSource, IdentityReverifyGate)` — epoch/guard first, then whoAmI. Session loader uses live credentials after refresh. |
| **MultiGate** | Ordered short-circuit; empty/nil fails closed. |
| **Clock** | `IdentityCache.WithNow` / gate `Now` for tests; production uses wall clock. |
| **Audit (Wave 28)** | Optional `IdentityReverifyConfig.Audit` + `ProfileID`. On fail-closed re-verify emit `type=auth_fail`, `action=identity_reverify`, `decision=fail`. Reason codes: `identity_principal_drift`, `identity_reverify_fail` (401-class), `identity_unbound`. At most **one event per reason class** per gate lifetime (sticky transition or first auth-class fail — no spam on sticky re-Check). `principalId` is only the serve-time **bound** id; unexpected whoAmI ids and tokens never appear. Emit is best-effort (never changes Check outcome). Nil sink: same fail-closed auth, no panic. |
| **ListTools (Wave 29)** | When AuthGate is set, `tools/list` runs `Check()` once; fail → empty Tools (discovery tracks session death). Nil AuthGate (tests) skips. Policy/RO filters still apply when Check OK. ListTools does not log Check errors (no secret leak / audit flood). |

### Wave 24 AUTH-004 configurable re-verify TTL (landed)

Operators can shorten (or lengthen within bounds) the whoAmI re-verify window so
a revoked `api_token` fails closed sooner than the default 5m cache.

| Surface | Behavior |
|---------|----------|
| **Env** | `JENKINS_MCP_IDENTITY_REVERIFY_TTL` — Go duration (`30s`, `1m`, `5m`) |
| **CLI** | `jenkins-mcp serve --identity-reverify-ttl=30s` **overrides** env when set |
| **Default** | Empty or zero (`0`, `0s`) → `DefaultIdentityCacheTTL` (**5m**) |
| **Bounds** | Min **10s**, max **30m**. Invalid / out-of-range → **fail closed at serve start** (`ParseIdentityReverifyTTL`) |
| **Wire** | Parsed TTL → `NewIdentityCache(ttl)` shared with `IdentityReverifyGate` for the serve lifetime |
| **Log** | Serve logs effective TTL (no secrets) |

**Residual (by design):** re-verify is **not** continuous every-call whoAmI. Tool
dispatch uses a cache hit within TTL; network whoAmI runs only on miss / expiry.
A revoked token may still succeed until the configured TTL elapses. Cross-process
api_token invalidation remains keyring clear + process restart (epoch is
OIDC-oriented).

**Wave 28 closed:** mid-serve re-verify fail-closed paths now emit privacy-
preserving audit events (see Wave 23 table **Audit** row).

**Wave 29 closed:** ListTools fail-closed on AuthGate so discovery no longer
advertises tools after session revoke / reverify sticky fail (CallTool already
denied). See Wave 23 table **ListTools** row and [policy-rbac.md](policy-rbac.md).

---

## 7. Consistency checklist for authors

1. Prefer “external IdP + Jenkins resource server” over “Jenkins OAuth.”  
2. If mentioning 3LO, name the **authorization server** (Entra/IdP), not Jenkins core.  
3. Label conditional plugin work as **default no-go** unless a recorded decision overrides ADR 0011.  
4. Keep CLI help, READMEs, and code comments aligned with ADR 0003.  
5. Run `go test ./internal/auth -run Terminology` before claiming doc-only auth changes done.
