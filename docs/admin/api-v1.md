# Admin BFF API v1 (UI-002–UI-009)

**ADR:** [0014](../adr/0014-admin-console-reactive-spa.md)  
**Base path:** `/admin/v1`  
**Content-Type:** `application/json; charset=utf-8`

**Agent hint:** This contract is the SoT for the operator console. When product
features change operator day-2 behavior, **update this document and the BFF/SPA
together** (or mark residual). See root [`AGENTS.md`](../../AGENTS.md) → “keep
the admin console current”.

## Authentication (shared secret)

Optional shared secret (recommended). When configured, every `/admin/v1/*` request must present:

```http
Authorization: Bearer <token>
```

or

```http
X-Jenkins-MCP-Admin-Token: <token>
```

Constant-time compare. Token never logged and **never** returned in JSON bodies.

| Mode | Behavior |
|------|----------|
| Token configured | Missing/wrong → **401** `{ "code": "authentication", "message": "unauthorized" }` |
| Token empty on loopback | Pilot residual: API open to local processes; process **role still applies**; prefer `--require-token` |
| Non-local bind | Token **required** at start (`--admin-allow-non-local`) |

**CSRF residual:** v1 uses Bearer / header token (not cookies), so browser CSRF is **N/A** for the shared-secret gate. Future httpOnly cookie sessions (if any) **must** add CSRF tokens; full OIDC is out of v1.

## Authorization (console RBAC — UI-003)

Process-wide role via `jenkins-mcp admin serve --admin-role=…` (default **`viewer`**).  
Console roles are **separate** from MCP deny-only subjects (ADR 0004). They never elevate Jenkins rights and **never** defeat enterprise `force_read_only`.

| Role | Name | Permissions | Writes |
|------|------|-------------|--------|
| `viewer` | Read-only operator | `read` (GET routes) | none |
| `operator` | Day-2 ops | `read` + `cache_destructive` + `gateway_ops` | cache/doctor destructive (UI-007); subject-invalidate + consent-purge (HOST-007) |
| `policy_admin` | Policy apply | `read` + `policy_write` + `gateway_ops` | policy validate/apply (UI-004); subject-invalidate + consent-purge (HOST-007) |

- Invalid `--admin-role` → **fail start**.
- **UI-004** ships `POST /admin/v1/policy/validate` and `POST /admin/v1/policy/apply` (require `policy_write`).
- `policy_admin` may hold `policy_write` but **`CanWidenForceReadOnly` is always false** for every role — admin cannot disable or weaken enterprise force RO.
- Missing permission on a write → **403** `{ "code": "permission_denied", "message": "permission denied" }`.

## Common error body

```json
{
  "code": "invalid_argument",
  "message": "human-safe message (redacted)"
}
```

Stable codes include: `invalid_argument`, `authentication`, `permission_denied` / `authorization`, `not_found`, `internal`, …

## GET /admin/v1/me

Current process authentication state and console role. **Never includes the token value.**

```json
{
  "authenticated": true,
  "role": "viewer",
  "permissions": ["read"],
  "tokenConfigured": true,
  "residual": "optional note when no token on loopback"
}
```

| Field | Meaning |
|-------|---------|
| `authenticated` | `true` when token configured **and** matched, **or** when no token is required (loopback residual). Middleware returns 401 before this handler when token is required and missing/wrong. |
| `role` | `viewer` \| `operator` \| `policy_admin` |
| `permissions` | e.g. `["read"]`, `["read","cache_destructive","gateway_ops"]`, `["read","policy_write","gateway_ops"]` |
| `tokenConfigured` | Whether the server was started with a non-empty shared secret |
| `residual` | Present when loopback pilot mode has no token (role still applies) |

## GET /admin/v1/health

```json
{
  "status": "ok",
  "version": "v0.1.0",
  "commit": "abc1234",
  "uiBuild": "",
  "enabledModes": ["api_token_vault"],
  "credentialMode": "api_token_vault",
  "multiUserEnabled": false,
  "gatewayReady": false,
  "haMultiReplica": false,
  "sessionAffinityRecommended": false,
  "multiPodVaultResidual": true,
  "kubernetesEnvDetected": false,
  "rateEnabled": true,
  "ratePerMinute": 30,
  "rateBurst": 10,
  "sharedSubjectRateFile": false,
  "sharedPrincipalCacheFile": false,
  "sharedJwksFile": false,
  "sharedTokenCacheFile": false,
  "progressiveConsentMetadataDoneStar": true,
  "progressiveConsentBrowser3loAutomated": false,
  "residual": "subject rate default process-local (HOST-006); optional same-host FileSubjectRateLimiter when JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH set (HOST-008 lite); multi-pod shared rate residual; multiPodVaultResidual=true; never tokens"
}
```

When Mode C (`agentcore_3lo_obo`) is enabled in the HOST-011 mode matrix, health
also includes a secret-free progressive-consent residual note (example primary
Mode C):

```json
{
  "credentialMode": "agentcore_3lo_obo",
  "enabledModes": ["agentcore_3lo_obo"],
  "progressiveConsentMetadataDoneStar": true,
  "progressiveConsentBrowser3loAutomated": false,
  "progressiveConsentResidual": "Mode C progressive consent UX residual (OAUTH-010 / GWY-001): browser 3LO not automated; ConsentRequired metadata path (authorization_url + session_id only) Done*; process-local consent metadata store Done* (optional file; never tokens; same-host reload-before-persist flock lite; not multi-replica shared store); multi-pod consent correlation residual (HOST-008)"
}
```

| Field | Meaning |
|-------|---------|
| `status` | Always `ok` when the BFF process is up (liveness). |
| `version` / `commit` / `uiBuild` | Secret-free binary / SPA build metadata |
| `enabledModes` | **HOST-007 / HOST-011:** optional list of gateway credential mode **ids** from env (`JENKINS_MCP_GATEWAY_ENABLED_MODES` or primary-only default). **Never** tokens, vault bytes, or subjects. Omitted or empty when mode config is invalid (see `/gateway/vault` residual). **Not** a multi-user “production ready” pin — listing a mode id means it is **enabled in config**, not that live multi-user GO / `JENKINS_MCP_GATEWAY_MULTI_USER` residual is closed. |
| `credentialMode` | **HOST-008 residual:** primary `JENKINS_MCP_GATEWAY_CREDENTIAL_MODE` id (empty when invalid). Mode id only — never tokens. |
| `multiUserEnabled` | **HOST-008 residual:** `true` when `JENKINS_MCP_GATEWAY_MULTI_USER` is truthy. Foundation residual only — **not** production multi-user GO. |
| `gatewayReady` | Always **`false` on admin BFF** (separate process from MCP serve). Live Obtain Ready is `GET /readyz` on the gateway serve process. |
| `haMultiReplica` | Always **`false`** (HOST-008 Tier A single-replica default; multi-replica runtime not implemented). |
| `sessionAffinityRecommended` | **HOST-008 residual:** `true` when multi-user env is set. Recommends kustomize Service sticky scaffold (`sessionAffinity: ClientIP`) if replicas are ever scaled — **not** multi-replica Done. Scaffold packaging only. |
| `multiPodVaultResidual` | Always **`true`** (HOST-008 multi-pod durable vault residual honesty). Parity with doctor `gateway_status.multi_pod_vault_residual`. **Not** multi-replica Done. See [gateway/deployment.md §9](../gateway/deployment.md). **SPA Overview** displays this bool on Health and Gateway vault cards. |
| `kubernetesEnvDetected` | **`true`** when `KUBERNETES_SERVICE_HOST` is set (in-cluster residual). Residual string then includes multi-pod checklist summary (sticky, shared vault, rate, Obtain cache). Never tokens. **SPA Overview** shows a multi-pod residual checklist card when true (secret-free; not multi-replica Done). |
| `rateEnabled` | **HOST-006 / HOST-008 residual:** `true` when subject rate env would enable limiting (empty `JENKINS_MCP_SUBJECT_RATE_PER_MINUTE` → default on; explicit `0` → false). Default process-local; optional same-host file when path set. **Not** multi-pod shared rate. Never tokens. |
| `ratePerMinute` | **HOST-006 residual knob:** resolved bootstrap tools/min via `gateway.SubjectRateConfigFromEnviron` (package default **30**; **0** when disabled). Never tokens. |
| `rateBurst` | **HOST-006 residual knob:** resolved bootstrap burst (package default **10**; **0** when rate off). Never tokens. |
| `sharedSubjectRateFile` | **HOST-008 Done\* lite residual:** `true` when `JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH` is non-empty (same-host `FileSubjectRateLimiter`). **Not** multi-pod HA. Path value never returned. Never tokens. |
| `sharedPrincipalCacheFile` | **HOST-007 / HOST-008 Done\* lite residual:** `true` when `JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH` is non-empty (same-host `FilePrincipalCache`). **Not** multi-pod HA. Path value never returned. Never tokens. |
| `sharedJwksFile` | **HOST-001 / HOST-007 / HOST-008 Done\* lite residual:** `true` when `JENKINS_MCP_HTTP_JWKS_CACHE_PATH` is non-empty (same-host public JWKS snapshot). **Not** multi-pod external JWKS HA. Path value never returned. Public keys only — never tokens. |
| `sharedTokenCacheFile` | **HOST-007 / HOST-008 Done\* lite residual:** `true` when `JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH` is non-empty (same-host `FileTokenCache`). **Not** multi-pod Redis/HA. Path value never returned. Residual never opens the cache file — never tokens. CamelCase parity with residual-status `shared_token_cache_file`. |
| `progressiveConsentMetadataDoneStar` | **OAUTH-010 / GWY-001 residual:** always **`true`**. ConsentRequired metadata path Done*. Static residual only — never embeds authorize URLs or secrets. |
| `progressiveConsentBrowser3loAutomated` | **OAUTH-010 residual:** always **`false`** until browser 3LO is automated (GWY-003). |
| `progressiveConsentResidual` | **OAUTH-010 residual note** when Mode C enabled. Omitted otherwise. Never tokens or authorize URL secrets. |
| `residual` | Secret-free honesty note (never tokens). Process-local rate + HOST-008 multi-pod residual; multi-user/k8s notes as applicable. |

## GET /admin/v1/gateway/vault

Secret-free HOST-011 mode matrix + Mode A vault **inventory** (HOST-009 residual).
Requires console `read`. **Never** returns API tokens, raw vault file contents,
Authorization headers, or raw subject keys.

```json
{
  "mode": "api_token_vault",
  "enabledModes": ["api_token_vault"],
  "multiUserEnabled": false,
  "haMultiReplica": false,
  "sessionAffinityRecommended": false,
  "multiPodVaultResidual": true,
  "kubernetesEnvDetected": false,
  "rateEnabled": true,
  "ratePerMinute": 30,
  "rateBurst": 10,
  "sharedSubjectRateFile": false,
  "sharedPrincipalCacheFile": false,
  "sharedJwksFile": false,
  "sharedTokenCacheFile": false,
  "vaultConfigured": true,
  "entryCount": 1,
  "subjects": ["a1b2c3…"],
  "residual": "vault write is CLI-only: jenkins-mcp gateway vault put|delete (never put tokens in the browser); subject rate default process-local (HOST-006); optional same-host FileSubjectRateLimiter when path set (HOST-008 lite); multi-pod shared rate residual; multiPodVaultResidual=true"
}
```

| Field | Meaning |
|-------|---------|
| `mode` | Primary credential mode id |
| `enabledModes` | Allow-list of mode ids (secret-free) |
| `multiUserEnabled` | `JENKINS_MCP_GATEWAY_MULTI_USER` truthy parse (foundation residual; not production GO) |
| `haMultiReplica` | Always `false` (HOST-008 Tier A; multi-replica not implemented) |
| `sessionAffinityRecommended` | `true` when multi-user env set (HOST-008 sticky Service scaffold honesty; not multi-replica Done) |
| `multiPodVaultResidual` | Always `true` (HOST-008 multi-pod vault residual; parity with doctor `multi_pod_vault_residual`) |
| `kubernetesEnvDetected` | `true` when `KUBERNETES_SERVICE_HOST` set; residual notes multi-pod checklist (not HA Done) |
| `rateEnabled` | HOST-006 env residual (rate would be enabled; default process-local; not multi-pod shared rate) |
| `ratePerMinute` | Resolved bootstrap tools/min (default or `JENKINS_MCP_SUBJECT_RATE_PER_MINUTE`); **0** when disabled. Never tokens. |
| `rateBurst` | Resolved bootstrap burst (default or `JENKINS_MCP_SUBJECT_RATE_BURST`); **0** when rate disabled. Never tokens. |
| `sharedSubjectRateFile` | **HOST-008 Done\* lite:** `true` when `JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH` set (same-host file rate). **Not** multi-pod HA. Path never returned. Never tokens. |
| `sharedPrincipalCacheFile` | **HOST-007 / HOST-008 Done\* lite:** `true` when `JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH` set (same-host FilePrincipalCache). **Not** multi-pod HA. Path never returned. Never tokens. |
| `sharedJwksFile` | **HOST-001 / HOST-007 / HOST-008 Done\* lite:** `true` when `JENKINS_MCP_HTTP_JWKS_CACHE_PATH` set (same-host public JWKS snapshot). **Not** multi-pod external JWKS HA. Path never returned. Public keys only — never tokens. |
| `sharedTokenCacheFile` | **HOST-007 / HOST-008 Done\* lite:** `true` when `JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH` set (same-host FileTokenCache). **Not** multi-pod Redis/HA. Path never returned. Residual never opens the cache file — never tokens. CamelCase parity with residual-status `shared_token_cache_file`. |
| `vaultConfigured` | Whether the Mode A vault file exists |
| `entryCount` | Number of subject entries |
| `subjects` | **SubjectKeyHash** values only (never raw keys or tokens) |
| `residual` | Operator notes (CLI-only write; Mode B/C residuals; HOST-006 process-local rate residual; multi-user / k8s honesty when env set) |

Writes remain CLI-only. SPA Overview may display this status; provision/rotate/revoke
is not available from the browser.

**Multi-user residual (secret-free):** Admin JSON never returns Jenkins tokens,
vault bytes, Authorization headers, or raw subject keys. `multiUserEnabled` reports
env parse only — it does **not** certify multi-user MCP production readiness.
When the env is set, `residual` includes an honesty note (no tokens) and
`sessionAffinityRecommended` is `true` (kustomize sticky scaffold honesty only).
Operators rely on gateway/REL evidence for live multi-user claims. Multi-replica
remains HOST-008 Tier B (`haMultiReplica: false`).

## GET /admin/v1/gateway/residual-status

**HOST-007.** Unified secret-free gateway residual snapshot — **same field assembly**
as CLI `jenkins-mcp gateway residual-status`
(`diagnostics.BuildGatewayResidualStatus`). Requires console `read` (viewer ok).
Env/static honesty only: no Obtain, vault open, or browser. **Never** tokens,
vault bytes, Authorization headers, raw subjects, or production GO claims.

Field names match the CLI JSON contract (snake_case residual honesty fields;
rate knobs keep admin health names `rateEnabled` / `ratePerMinute` / `rateBurst`).

```json
{
  "mode_matrix": {
    "primary": "jwt_rs_bearer",
    "enabled": ["jwt_rs_bearer"],
    "residual": "…"
  },
  "mode_matrix_residual": "…",
  "mode_a_enabled": false,
  "mode_b_enabled": true,
  "mode_c_enabled": false,
  "mode_a_live_obtain_qualified": false,
  "mode_b_live_rs_qualified": false,
  "mode_c_live_agentcore_qualified": false,
  "residual_id": "oauth009_offline",
  "oauth009_offline": true,
  "oauth009_offline_only": true,
  "residual_ids": [
    "multi_user_offline",
    "oauth009_offline",
    "oauth010_offline",
    "progressive_consent_offline",
    "host008_single_replica",
    "gateway_modes_live"
  ],
  "multi_user_enabled": false,
  "gateway_ready": false,
  "ha_multi_replica": false,
  "session_affinity_recommended": false,
  "multi_pod_vault_residual": true,
  "kubernetes_env_detected": false,
  "vault_path_emptydir_heuristic": false,
  "replicas_env_residual": false,
  "progressive_consent": {
    "metadata_path_done_star": true,
    "browser_3lo_automated": false
  },
  "rateEnabled": true,
  "ratePerMinute": 30,
  "rateBurst": 10,
  "shared_subject_rate_file": false,
  "subject_slots_process_local": true,
  "principal_cache_entries": 0,
  "principal_cache_process_note": "principal_cache_entries is count for this process only (CLI/admin ≠ serve MemoryTokenCache/PrincipalCache unless shared file caches)",
  "shared_principal_cache_file": false,
  "shared_jwks_file": false,
  "shared_token_cache_file": false,
  "shared_api_token_vault_file": false,
  "shared_jwt_vault_file": false,
  "residual_note": "unified gateway residual snapshot … see docs/gateway/live-pin-blockers.md",
  "doc": "docs/gateway/live-pin-blockers.md"
}
```

When PrincipalCache hygiene env is set (positive max/ttl only), also includes:

```json
{
  "principal_cache_max_entries": 256,
  "principal_cache_ttl_seconds": 7200
}
```

When Mode C is enabled, also includes `progressive_consent_residual` and
`progressive_consent_surfaces`. When multi-pod signals are present, includes
`multi_pod_residual_checklist` (secret-free; never embeds k8s host values).

| Field | Meaning |
|-------|---------|
| `mode_*_enabled` | HOST-011 mode ids enabled in config (not live pin GO) |
| `mode_*_live_*_qualified` | Always `false` until live pins land; SPA Overview + Doctor residual cards show **no/false** with honesty *offline residual — not production GO* |
| `residual_id` / `oauth009_offline` | Mode B residual pointer (always advertised) |
| `residual_ids` | Structured residual ids for operator grepping |
| `multi_user_enabled` | `JENKINS_MCP_GATEWAY_MULTI_USER` truthy parse (foundation residual) |
| `gateway_ready` | Always `false` on admin BFF (Ready is serve `/readyz`) |
| `ha_multi_replica` | Always `false` (HOST-008 Tier A) |
| `session_affinity_recommended` | `true` when multi-user env set (scaffold honesty) |
| `multi_pod_vault_residual` | Always `true` (HOST-008 multi-pod vault residual) |
| `kubernetes_env_detected` | `true` when `KUBERNETES_SERVICE_HOST` set (value never embedded) |
| `vault_path_emptydir_heuristic` | Heuristic residual when vault path looks emptyDir-like (value never embeds host path secrets) |
| `replicas_env_residual` | Residual when replica-count env suggests multi-pod intent (not HA Done) |
| `multi_pod_residual_checklist` | Optional secret-free multi-pod honesty checklist string |
| `progressive_consent` | OAUTH-010 / GWY-001 StatusMap (static; never tokens) |
| `rateEnabled` / `ratePerMinute` / `rateBurst` | HOST-006 process-local rate knobs |
| `shared_subject_rate_file` | `true` only when `JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH` set (HOST-008 same-host lite); path never returned |
| `principal_cache_entries` | Principal cache **count** for **this process only** (CLI or admin BFF — not remote MCP serve unless shared file caches) |
| `principal_cache_process_note` | Secret-free honesty sentence for process-local count scope |
| `shared_subject_rate_file` | `true` when `JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH` set (path never returned) |
| `principal_cache_entries` | Principal cache **count** only (memory or file; never inventory) |
| `shared_principal_cache_file` | `true` when `JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH` set (HOST-008 same-host `FilePrincipalCache` lite; path never returned; never tokens) |
| `shared_jwks_file` | **HOST-001 / HOST-008 Done\* lite:** `true` when `JENKINS_MCP_HTTP_JWKS_CACHE_PATH` set (same-host public JWKS snapshot). **Not** multi-pod external JWKS HA. Path value **never** returned. Public keys only — never tokens. |
| `shared_token_cache_file` | **HOST-008 Done\* lite:** `true` when `JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH` set (same-host `FileTokenCache`). **Not** multi-pod Redis/HA. Path value **never** returned. Residual never opens the cache file — never tokens. |
| `shared_api_token_vault_file` | **HOST-008 Done\* lite:** `true` when `JENKINS_MCP_GATEWAY_VAULT_PATH` is **explicitly set** (Mode A same-host `FileAPITokenVault` path residual). Default XDG vault path does **not** count. Path value **never** returned. Residual never opens the vault — never tokens. **Not** multi-pod shared vault HA. |
| `shared_jwt_vault_file` | **HOST-008 Done\* lite:** `true` when `JENKINS_MCP_GATEWAY_JWT_VAULT_PATH` is **explicitly set** (Mode B same-host `FileJWTVault` path residual). Default XDG JWT vault path does **not** count. Path value **never** returned. Residual never opens the vault — never tokens. **Not** multi-pod shared vault HA. |
| `progressive_consent_residual` / `progressive_consent_surfaces` | Mode C only; secret-free residual note + surface ids |
| `rateEnabled` / `ratePerMinute` / `rateBurst` | HOST-006 process-local rate knobs (admin health field names) |
| `shared_subject_rate_file` | **HOST-008 Done\* lite:** `true` when `JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH` is non-empty (same-host `FileSubjectRateLimiter`). **Not** multi-pod HA. Path value **never** returned. Never tokens. |
| `subject_rate_max_subjects` | Optional rate-map MaxSubjects when env > 0 (omit = unlimited). Process/file-local only — not multi-pod. |
| `subject_limiter_max_subjects` | Optional SubjectLimiter MaxSubjects when `JENKINS_MCP_GATEWAY_SUBJECT_LIMITER_MAX_SUBJECTS` > 0 (omit = unlimited). Process-local only — not multi-pod. |
| `subject_slots_process_local` | **Always `true`:** SubjectLimiter concurrency slots are process-local (HOST-008 residual; **not** multi-pod shared concurrency). Secret-free honesty. |
| `principal_cache_entries` | Process-local principal cache **count** only (never subjects). On admin BFF this is **the admin process**, not necessarily MCP serve. |
| `principal_cache_max_entries` | Optional hygiene max when env > 0 (omit = unlimited). Never subjects. |
| `principal_cache_ttl_seconds` | Optional hygiene TTL seconds when env > 0 (omit = no TTL). Never subjects. |
| `residual_note` / `doc` | Honesty sentence + pointer to [live-pin-blockers.md](../gateway/live-pin-blockers.md) |

**SPA:** Overview card “Gateway residual status” loads this route; **404 hides the
card** on older BFF builds. SPA shows `shared_subject_rate_file`,
`shared_principal_cache_file`, `shared_jwks_file` (bool when
`JENKINS_MCP_HTTP_JWKS_CACHE_PATH` set; same-host FileJWKS lite only — path never
shown; not multi-pod external JWKS HA), `shared_token_cache_file` (bool when
`JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH` set; same-host FileTokenCache lite only —
path never shown; secrets never shown; not multi-pod Redis/HA),
`shared_api_token_vault_file` / `shared_jwt_vault_file` (bool when Mode A/B vault
path env explicitly set; default XDG path does not count; path never shown; vault
never opened for residual; not multi-pod vault HA), principal_cache count,
optional max/ttl, optional `subject_limiter_max_subjects` when env set, and always
`subject_slots_process_local` with honesty (same-host rate/principal/JWKS/token/vault
path lite; admin BFF process for cache count; concurrency process-local — not multi-pod).
Operators may also run CLI `gateway residual-status`.

## POST /admin/v1/gateway/subject-invalidate

**HOST-007 force re-auth residual lite.** Mirrors CLI
`jenkins-mcp gateway subject-invalidate` (alias `invalidate-subject`).

Requires console permission **`gateway_ops`** (`operator` or `policy_admin`).
Viewer → **403** `permission_denied`.

Clears multi-user caches for one subject so the next Obtain re-fetches:

| Cache | Behavior |
|-------|----------|
| Principal | `FilePrincipalCache` when `JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH` is set (same-host flock lite shared with MCP serve); otherwise `ProcessPrincipalCache` in **this admin process only** |
| Token | `FileTokenCache` subject-namespace purge when `JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH` is set; otherwise residual note only (serve `MemoryTokenCache` not reachable from admin BFF) |

**Never** accepts or returns tokens, vault bytes, Authorization material, or
cache path values. **Not** live Entra/AgentCore revocation. **Not** multi-pod
fan-out (HOST-008 residual).

### Request body

Provide **`subject_key`** *or* compose parts (`subject_id` required when key omitted):

```json
{
  "subject_key": "tenant|alice-sub|corp"
}
```

```json
{
  "tenant": "tenant",
  "subject_id": "alice-sub",
  "profile": "corp",
  "workload": ""
}
```

| Field | Required | Meaning |
|-------|----------|---------|
| `subject_key` | preferred | `tenant\|subject\|profile` (exactly three pipe fields) |
| `tenant` | optional | Used when composing |
| `subject_id` | when no key | Subject (user) id |
| `profile` | optional | Profile id when composing |
| `workload` | optional | Exact `CacheKey` fallback only (usually unused with FileTokenCache purge) |

Unknown body fields (e.g. `token`, `access_token`) are **ignored** — never treated
as credentials and never echoed.

### Response (secret-free; CLI `StatusMap` + admin notes)

```json
{
  "subject_key": "tenant|alice-sub|corp",
  "subject_key_hash": "…",
  "principal_cleared": true,
  "token_cache_cleared": false,
  "token_cache_entries_deleted": -1,
  "token_cache_note": "token_cache not provided (…)",
  "residual_note": "force re-auth residual lite … multi-pod …",
  "cleared": {
    "principal": true,
    "token_cache": false
  },
  "doc": "docs/gateway/README.md § force re-auth residual lite",
  "token_cache_path_configured": false,
  "principal_cache_path_configured": false,
  "token_cache_admin_note": "JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH unset — serve MemoryTokenCache not reachable from admin BFF",
  "principal_process_note": "PrincipalCache clear is process-local to this admin serve process; set JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH to share with MCP serve (HOST-008 lite)"
}
```

| HTTP | When |
|------|------|
| **200** | Invalidate attempted (principal/token flags describe outcome) |
| **400** | Missing/malformed subject key or unusable cache path |
| **401** | Admin shared secret required and missing/wrong |
| **403** | Role lacks `gateway_ops` (viewer) |
| **405** | Method not POST |

**SPA:** Overview “Subject invalidate (force re-auth)” form when `/me` includes
`gateway_ops`; viewers see a residual note only. Never put tokens in the form.

**Same-host multi-process:** set the same principal/token cache path env on
admin BFF and MCP serve so invalidate reaches serve’s caches. Multi-pod external
shared map remains residual (HOST-008).

## POST /admin/v1/gateway/consent-purge

**HOST-007 Mode C progressive consent metadata purge residual lite.** Mirrors CLI
`jenkins-mcp gateway consent-purge` (alias `consent-expire`).

Requires console permission **`gateway_ops`** (`operator` or `policy_admin`).
Viewer → **403** `permission_denied`.

Purges **metadata only** (authorization URL + session id + timestamps) from the
consent session store opened via `OpenConsentSessionStoreForPurge`:

| Source | Behavior |
|--------|----------|
| Body `path` | Optional absolute override; **must be a direct file under the configured consent store directory** (dir of env/XDG path). Wins over env when allowed. Outside that dir → **400** (path jail — no arbitrary file overwrite). Full path never returned. |
| Env | `JENKINS_MCP_CONSENT_STORE_PATH` |
| Default | XDG data `…/jenkins-mcp/gateway/consent_sessions.json` |

| Action | When | Effect |
|--------|------|--------|
| `purge_expired` | **default** (empty body or `action: "purge_expired"`) | Delete TTL-expired sessions; return counts |
| `delete_session` | `action: "delete_session"` **or** `session_id` set | Delete one session by id (metadata only) |
| `clear_all` | `clear_all: true` **or** `action: "clear_all"` **plus** `confirm: "CLEAR_ALL"` (exact) | Clear all entries; `deleted_count` = pre-clear `EntryCount` |

**Destructive confirm (HOST-007 residual lite):** `clear_all` requires body
field `confirm` exactly equal to `"CLEAR_ALL"` (parity with cache
`confirm: "EVICT"` and CLI `gateway consent-purge --all --confirm=CLEAR_ALL`).
Missing, empty, or wrong token → **400** `invalid_argument` and **no** store
mutation. `purge_expired` and `delete_session` do **not** require `confirm`.

**Never** accepts or returns tokens, vault bytes, Authorization material, full
store path values, or `session_id` echo. **Not** multi-pod HA (HOST-008 residual).
**Not** browser 3LO automation. Same-host file reload-before-persist Done\* lite
(admin/CLI purge not resurrected by serve Put of stale memory). Memory-only serve
process is **not** cleared unless it shares the same file path.

### Request body

```json
{}
```

```json
{
  "action": "purge_expired"
}
```

```json
{
  "action": "delete_session",
  "session_id": "sess-abc"
}
```

```json
{
  "clear_all": true,
  "confirm": "CLEAR_ALL"
}
```

```json
{
  "action": "clear_all",
  "confirm": "CLEAR_ALL",
  "path": "/optional/override/consent_sessions.json"
}
```

| Field | Required | Meaning |
|-------|----------|---------|
| `action` | optional | `purge_expired` (default) \| `delete_session` \| `clear_all` |
| `session_id` | for delete | Consent session correlation id (metadata only; **not** echoed) |
| `clear_all` | for clear | Explicit flag required for clear-all (mirrors CLI `--all`) |
| `confirm` | for clear_all | Must be exact `"CLEAR_ALL"` (parity with cache `"EVICT"`). Missing/wrong → **400**. Ignored for other actions. |
| `path` | optional | Absolute consent metadata file path under the configured store directory only (admin path jail). Relative / traversal / outside-dir → 400. Never echoed. |

`clear_all` and `session_id` are **mutually exclusive** (400). Unknown body
fields (e.g. `token`, `access_token`) are **ignored** — never treated as
credentials and never echoed.

### Response (secret-free; CLI summary + admin notes)

```json
{
  "action": "purge_expired",
  "deleted_count": 1,
  "remaining_count": 2,
  "metadata_only": true,
  "stores_tokens": false,
  "process_local": true,
  "multi_replica_shared": false,
  "browser_3lo_automated": false,
  "durable_agentcore_vault_residual": true,
  "file_backed": true,
  "file_basename": "consent_sessions.json",
  "consent_store_path_configured": true,
  "residual_note": "consent metadata purge only (OAUTH-010 residual); never tokens; same-host file reload-before-persist Done* lite …",
  "doc": "docs/gateway/README.md § progressive consent residual",
  "admin_note": "mirrors CLI gateway consent-purge; set JENKINS_MCP_CONSENT_STORE_PATH … multi-pod residual"
}
```

| HTTP | When |
|------|------|
| **200** | Purge persisted successfully (counts describe outcome) |
| **400** | Mutual exclusion, missing session_id, unknown action, path jail / unusable path |
| **200** | Purge attempted (counts describe outcome) |
| **400** | Mutual exclusion, missing session_id, unknown action, clear_all missing/wrong `confirm`, path jail / unusable path |
| **401** | Admin shared secret required and missing/wrong |
| **500** | File-backed consent store reload/persist failed (fail closed; secret-free `code`+`message`; never tokens or full path) — OAUTH-010 residual lite; not multi-pod |
| **403** | Role lacks `gateway_ops` (viewer) |
| **405** | Method not POST |

**SPA:** Overview “Progressive consent residual (Mode C)” card embeds a small
consent-purge form when `/me` includes `gateway_ops` (shown when Mode C is on
health **or** always for gateway_ops residual). For **clear_all**, the form
requires typing `CLEAR_ALL` before submit (server re-checks). Viewers see
CLI-only residual. Never put tokens in the form; response never echoes
`session_id`.

**Same-host multi-process:** set the same `JENKINS_MCP_CONSENT_STORE_PATH` on
admin BFF and MCP serve so purge reaches serve’s file-backed store. Multi-pod
external shared store remains residual (HOST-008).

## GET /admin/v1/version

Subset of `jenkins-mcp version --json` (version, commit, buildTime, goVersion, os, arch). No secrets.

## GET /admin/v1/profiles/{id}/policy/effective

Same shape as `policy show-effective --json` for profile `id` (secret-free effective RO + deny lists + signature state).

Query: none required. Optional `?readOnly=1` / `?allowMutations=1` for simulation flags (must not defeat enterprise force).

## GET /admin/v1/policy/overlay (UI-004)

Returns the current **plain pilot** overlay document when the resolved policy path is a plain `overlay.json` (no private keys, no PEM, signature field stripped).

```json
{
  "available": true,
  "path_base": "overlay.json",
  "signature_state": "unverified_pilot",
  "overlay": {
    "version": 1,
    "force_read_only": true,
    "fleet_telemetry_force_off": false,
    "mode": "pilot",
    "deny_tools": ["jenkins_get_build_logs"],
    "max_result_bytes": 65536,
    "max_tools_per_minute": 15,
    "max_tools_burst": 5
  },
  "notes": ["plain pilot overlay (unsigned); production should use signed bundles"]
}
```

| Case | Response |
|------|----------|
| Missing file | `available: false`, `signature_state: absent`, residual note |
| Signed bundle at resolved path | `available: false`, residual: browser cannot edit/sign bundles |
| Plain overlay | `available: true` + secret-free `overlay` object |

Requires `read` (all roles). Token gate applies when configured.

## POST /admin/v1/policy/validate (UI-004)

Requires **`policy_write`** (`policy_admin`). Dry-run only — does not write.

**Request body** (either wrapper or bare overlay):

```json
{
  "profileId": "corp",
  "overlay": {
    "version": 1,
    "force_read_only": true,
    "mode": "pilot",
    "deny_tools": ["jenkins_get_build_logs"],
    "deny_job_prefixes": [],
    "max_result_bytes": 32768,
    "max_tools_per_minute": 10,
    "max_tools_burst": 4
  }
}
```

- `overlay.signature` from the browser is **ignored/cleared** (never accepted as trust material).
- Body size cap: 256 KiB.
- `max_tools_per_minute` / `max_tools_burst` are optional positive ints (HOST-006). Omitted = no overlay rate knobs. Zero/negative fail closed via `Overlay.Validate()`.

**Response:**

```json
{
  "valid": false,
  "errors": [
    { "field": "force_read_only", "message": "cannot set force_read_only=false when enterprise/current force is enforced …" }
  ],
  "effectivePreview": { /* same shape as show-effective subset when valid */ },
  "notes": []
}
```

**Monotonic restrict (v1):**

| Rule | Behavior |
|------|----------|
| `force_read_only` | If current effective/overlay force is **true**, draft must keep `force_read_only: true`. **`CanWidenForceReadOnly` is always false.** |
| `fleet_telemetry_force_off` | If current overlay pin is **true**, draft must keep `fleet_telemetry_force_off: true` (MGR-002; admin cannot re-enable fleet telemetry against enterprise pin). |
| Deny lists | When a current overlay exists, each proposed deny list must be a **set superset** of the current list (entries may only grow). |
| `mode` | Cannot weaken `strict` → `pilot`. |
| `max_result_bytes` | When current has a cap, draft cannot clear it or raise it. |
| `max_tools_per_minute` / `max_tools_burst` | When current has a cap, draft cannot clear it or raise it (HOST-006 lower-only write path; live serve also clamps via `SubjectRateLimiter.LowerRate`). |
| Schema | `Overlay.Validate()` field-level errors (positive-only for rate/budget fields). |

Always HTTP **200** with `valid: true|false` when authz succeeds (invalid draft is not 4xx for validate). Authz failures: **401** / **403**.

## POST /admin/v1/policy/apply (UI-004)

Requires **`policy_write`**. Re-validates with the same rules as validate (**no partial apply**).

**On success:** writes plain pilot overlay to default path (`…/policy/overlay.json` or `JENKINS_MCP_POLICY_FILE` when it is not a signed bundle) with mode **0600**. Returns applied effective summary.

```json
{
  "applied": true,
  "path_base": "overlay.json",
  "effective": { /* show-effective shape subset */ },
  "notes": ["plain pilot overlay written (mode 0600); signing remains host-side CLI only"]
}
```

**Fail closed (no write):**

| Condition | HTTP | Notes |
|-----------|------|--------|
| Lacks `policy_write` | 403 | `permission_denied` |
| Token required missing/wrong | 401 | `authentication` |
| Validation / monotonic fail | 400 | `applied: false` + field `errors` |
| `JENKINS_MCP_POLICY_REQUIRED=1` | 403 | refuse write refused; use CLI `policy sign` on host |
| Trusted public keys configured | 403 | signed bundles required; keys never leave the host |
| Resolved path is signed bundle | 403 | browser cannot clobber/sign bundles |

**Audit:** best-effort secret-free events (`policy_apply` / `policy_validate` deny) on the profile audit path when `profileId` / `--profile` is set. Fields: type, decision, reasonCode only — never tokens or key material.

**Residuals:**

- Signed-bundle apply / multi-sig from the browser is **out of scope** (CLI `jenkins-mcp policy sign` on host).
- Multi-source merge beyond “current plain/signed overlay baseline + draft” is simplified; at minimum force RO and deny-list superset are enforced.
- Hot-reload of a running `serve` process is separate (existing policy reload path); admin apply writes the file only.
- **Subject rate (HOST-006):** SPA can edit `max_tools_per_minute` / `max_tools_burst` on plain pilot overlays (`policy_admin` / `policy_write` only). Overlay **lowers only** vs serve env bootstrap (`JENKINS_MCP_SUBJECT_RATE_*`); raising bootstrap needs serve restart. Rate is **process-local**; multi-replica shared rate residual (HOST-008). Live raise above current limiter is never applied (`LowerRate`).

## GET /admin/v1/metrics

```json
{
  "available": true,
  "counters": {
    "tool_calls": 0,
    "mcp_subject_rate_quota": 0,
    "mcp_subject_slot_quota": 0
  },
  "gauges": {},
  "residual": "process-local snapshot; empty if no serve registry"
}
```

When global registry unset: `available: false`, empty maps, residual note.

**Subject quota (HOST-006 / OBS residual lite):** when the linked serve registry
is present, `mcp_subject_rate_quota` / `mcp_subject_slot_quota` may appear as
process-local counters (CodeQuota from subject rate `Allow` / slot `Hold`).
**Never** subject keys, principal ids, or tokens as series labels. Multi-pod
aggregation residual. SPA Metrics page prefers those keys in sparkline selection
when non-zero present.

## GET /admin/v1/profiles/{id}/audit

Query:

| Param | Default | Max | Notes |
|-------|---------|-----|--------|
| `limit` | 50 | 200 | page size |
| `type` | | | filter event type (exact match) |
| `before` | | | RFC3339 exclusive upper bound |
| `external_subject` | | 128 runes | optional **exact** match (case-sensitive) on event `externalSubject` after Normalize; empty / whitespace skips; oversize clipped. IdP subject label only — **never a token** |

```json
{
  "profileId": "corp",
  "events": [ /* audit.Event objects */ ],
  "truncated": false
}
```

Events are `internal/audit.Event` JSON (secret-free). Optional multi-user correlation
fields when present: `externalSubject` (IdP label, redacted/clipped), `subjectKeyHash`
(`HashOpaque(tenant|subject|profile)` only — never raw subject keys or vault material).
SPA list columns surface those fields (truncated/muted); type filter includes
`tool_deny` / `tool_error` / `tool_success` / `mutation_*`.

**Same-host rotated merge (Done\* lite):** the BFF merges the active profile audit
JSONL with numbered rotates produced by the File sink (`audit.jsonl.1` …
`audit.jsonl.N`, default keep 3) and optional timestamp-like siblings next to the
active path. Newest matching events first; `limit` / `type` / `before` /
`external_subject` apply across the merge set; corrupt lines are skipped. Memory
stays bounded to `limit`.

**`external_subject` (Done\* lite):** exact match on the normalized
`externalSubject` field so multi-user correlation works across page loads without
loading the full JSONL into the browser. Prefer exact identity match (fail-closed)
over substring. SPA sends the filter as `external_subject` and keeps a client-side
exact residual for older BFFs. **Multi-pod** audit aggregation (central sink /
fleet timeline) is not provided — this is per-host profile path merge only (HOST-008).

Missing audit file (and no rotated siblings) → empty `events` (not 500). Path
traversal on `{id}` rejected.

## GET /admin/v1/profiles/{id}/doctor

Query: `offline=1` (default true for v1). Returns bounded JSON summary (status fields only). Fail closed on invalid profile.

Response is `diagnostics.Report` JSON: `profileId`, `overall`, `checks[]`, plus **`gateway_residual_status`** — the same secret-free map as CLI `gateway residual-status` / `GET /admin/v1/gateway/residual-status` (`diagnostics.BuildGatewayResidualStatus`). Informational only (does not drive overall fail); live `mode_*_qualified` stay false; pointer to [live-pin-blockers.md](../gateway/live-pin-blockers.md). Never tokens/subjects.

**SPA (HOST-007 residual lite):** Doctor page renders a **Gateway residual status** card after Overall when `gateway_residual_status` is present (shared_*_file, principal_cache_entries count, residual_id honesty; hides when omitted on older BFF). Same honesty helpers as Overview residual card; not live GO.

**Online doctor (`offline=0`)** requires a configured admin shared secret. Without a token, the BFF returns `403 permission_denied` so loopback residual cannot exercise keyring → Jenkins network identity.

## Static SPA

`GET /` and `/assets/*` served from (UI-008 priority): `--assets-dir` → packaged `/usr/share/jenkins-mcp/admin-ui` → dev `web/admin/dist` → embedded `uiembed` FS. API under `/admin/v1` only. Static assets are **not** gated by the admin token (loopback residual); API always is when a token is configured.

All responses (SPA + JSON) include strict CSP and related security headers (see [`README.md`](README.md) § Security headers).
## UI-007 — Profiles, cache, support-bundle

All profile path params use the same **`ValidateProfileID`** rules (no path traversal, no absolute paths, safe charset). Responses are **secret-free**: no API tokens, keyring payloads, passwords, or client secrets. Credential presence is a boolean only (`hasCredential`).

### Role matrix (UI-007)

| Endpoint | Method | Permission |
|----------|--------|------------|
| `/admin/v1/profiles` | GET | `read` |
| `/admin/v1/profiles/{id}` | GET | `read` |
| `/admin/v1/profiles/{id}/cache` | GET | `read` |
| `/admin/v1/profiles/{id}/security-selfcheck` | GET | `read` |
| `/admin/v1/profiles/{id}/cache/evict-plan` | POST | `read` (non-destructive) |
| `/admin/v1/profiles/{id}/cache/evict` | POST | `cache_destructive` + body `confirm: "EVICT"` |
| `/admin/v1/profiles/{id}/support-bundle` | POST | `cache_destructive` (operator) |

### GET /admin/v1/profiles

Lists profiles from the XDG profile store (secret-free summaries).

```json
{
  "profiles": [
    {
      "id": "corp",
      "displayName": "Corp Jenkins",
      "jenkinsURL": "https://jenkins.example.corp/",
      "jenkinsHost": "jenkins.example.corp",
      "authMethod": "api_token",
      "username": "alice",
      "readOnly": false,
      "hasCredential": true,
      "cacheEncryption": false
    }
  ]
}
```

### GET /admin/v1/profiles/{id}

Same summary shape as one list element. Missing profile → **404**. Path traversal → **400**.

### GET /admin/v1/profiles/{id}/cache

Secret-free quota/usage summary for the profile data dir.

| Field | Meaning |
|-------|---------|
| `available` | `false` when meta/store is missing or unreadable (**HTTP 200**, not 500) |
| `residual` | Human-safe reason when unavailable |
| `needsEviction` | From `QuotaManager.NeedsEviction` when available |
| `usage` | `store.UsageStats` (physical bytes, quota, generations, packs, …) |
| `pins` | Count of durable pins (not full pin list — residual for SPA) |

### GET /admin/v1/profiles/{id}/security-selfcheck

Offline `diagnostics.RunSecuritySelfCheck` JSON (items + residuals). No network; secret canaries must never appear in the body.

### POST /admin/v1/profiles/{id}/cache/evict-plan

Non-destructive plan (mirrors `jenkins-mcp cache eviction-plan`). Body optional:

```json
{ "targetBytes": 0 }
```

Response includes `dryRun: true`, `candidates[]` (`kind`, `id`, `bytes`, optional `age`/`reason`), usage, `pinsSkipped`. Never deletes.

### POST /admin/v1/profiles/{id}/cache/evict

**Operator only.** Destructive apply (mirrors `cache evict --confirm`). Body:

```json
{ "confirm": "EVICT", "targetBytes": 0 }
```

| Case | Status |
|------|--------|
| Viewer / policy_admin | **403** `permission_denied` |
| Missing or wrong `confirm` (must be exact `"EVICT"`) | **400** `invalid_argument` |
| Operator + `EVICT` | **200** plan/result; `applied` true when run completed |

Server-side double-confirm is the `confirm` string. SPA adds a modal that requires typing `EVICT` twice. Audit event type `admin_cache_evict` is emitted best-effort on apply.

### POST /admin/v1/profiles/{id}/support-bundle

**Operator only** (`cache_destructive`). Body:

```json
{ "preview": true, "offline": true }
```

| Field | Default | Notes |
|-------|---------|-------|
| `preview` | `false` | When true, returns category plan + `outputPath` only (no zip write) |
| `offline` | `true` | Online (`false`) requires admin shared secret (same as doctor) |

Create returns **path + size** (`path`, `bytes`) — not zip file bytes in JSON. Audit event `admin_support_bundle` on non-preview create.

### Residuals (UI-007)

- Full **pin list** UI / API (use CLI `cache pins --json`).
- Full **cache repair** / verify from the console (CLI `cache repair` / `cache verify`).
- Policy write editor (UI-004).
- SPA does not download support-bundle bytes over HTTP (local path for loopback operator).

## Testing (UI-009)

Admin console adversarial / contract coverage is **Go-first** (no Playwright/Cypress dependency in default CI).

### Primary gate — `go test ./internal/admin`

| Test | Covers |
|------|--------|
| `TestUI009_AuthGate_WrongAndMissingToken` | 401 missing/wrong token; secret canary never in body |
| `TestUI009_ViewerCannotApplyPolicy` | viewer/operator **403** on validate/apply; policy_admin validate dry-run OK |
| `TestUI009_AuditXSSCanaries_JSONEscaped` | XSS payloads in audit `tool`/`reasonCode`/type returned as **JSON text** (`application/json`, HTML-escaped wire) |
| `TestUI009_PolicyApply_XSSAndPathTraversalRejected` | adversarial draft fields; planted admin token never echoed on errors |
| `TestUI009_CSPHeaders_RootAndHealth` | CSP + nosniff on `/` and `/admin/v1/health` (UI-008) |
| `TestUI009_OnlineDoctorWithoutToken_403` | online doctor without shared secret → **403** |
| `TestUI009_SPADeepLink_ServesIndexShell` | BrowserRouter deep links serve SPA shell |
| `TestUI009_CacheEvict_Viewer403_OperatorMissingConfirm400` | viewer evict **403**; operator wrong confirm **400** |
| `TestUI009_SecretCanaryAbsentAcrossRoutes` | planted secret absent across health/me/metrics/profiles/audit/doctor/cache |

XSS assertion model: BFF always writes JSON via `encoding/json` with `SetEscapeHTML(true)` (`Content-Type: application/json`). Wire body must not contain raw `<script>` markup; decoded fields are **text only** for SPA rendering. CSP `script-src 'self'` further blocks inline script execution if HTML were ever mis-served.

### Opt-in E2E smoke (not default CI)

```bash
make admin-e2e
# or: scripts/admin-e2e-smoke.sh
```

Starts a real `jenkins-mcp admin serve` on an ephemeral loopback port against a temp XDG tree + minimal SPA (or `web/admin/dist` when present), curls health/me/metrics/policy/audit, checks **401** without token, SPA shell + deep link, CSP, viewer apply **403**, and secret-canary absence. Writes `dist/admin-e2e/status.json`.

**Not** part of `make test` / `make ci` unless operators opt in (same pattern as `stdio-smoke` / `live-jenkins-test`).

### Residual

- Full **browser** Playwright/Cypress suite (DOM XSS “does not execute”, HAR scrub automation, multi-page SPA flows) is **not** shipped — defer until product requires browser CI.
- CSRF remains **N/A** for v1 Bearer/header auth; cookie sessions would need CSRF tests.
