# Admin / operator guide — go-jenkins-mcp

**Audience:** platform admins packaging and piloting jenkins-mcp on Tier-1 Linux.  
**Platforms:** Rocky Linux (supported majors), Ubuntu LTS. **Windows out of scope.**  
**Wave 20 (DOC-001):** operator path synced for policy, gateway, live lab, telemetry, HTTP.

Deep packaging detail: [`../packaging.md`](../packaging.md).  
Pilot evidence: [`../pilot/README.md`](../pilot/README.md).  
Security: [`../security/operator-guide.md`](../security/operator-guide.md).  
Policy bundles: [`../security/policy-bundles.md`](../security/policy-bundles.md).  
Fleet telemetry privacy: [`../security/fleet-telemetry.md`](../security/fleet-telemetry.md).  
Gateway deploy: [`../gateway/deployment.md`](../gateway/deployment.md).  
Release gates: [`../release/gates.md`](../release/gates.md).  
User Cursor path: [`../user/README.md`](../user/README.md).

### Admin console (UI-000–UI-009)

A **reactive SPA** lives under `web/admin/` (React + TypeScript + Vite; ADR [0014](../adr/0014-admin-console-reactive-spa.md)). The **local admin BFF** is started only via explicit CLI or Docker — **admin HTTP is off by default** until `jenkins-mcp admin serve` (or the local Docker stack). Contract: [`api-v1.md`](api-v1.md).

**Agent / implementer note:** Treat the console as a living operator surface. Feature work that affects policy, metrics, audit, doctor/cache, profiles, or other day-2 ops **must** update BFF + SPA + this API contract in the same change (or record an explicit residual). **Also** expose the same capability via MCP **`admin_*` tools** (or **MCP-OPS-*** residual) so agents manage without admin HTTP — [mcp-ops-parity.md](mcp-ops-parity.md). Standing rules: root [`AGENTS.md`](../../AGENTS.md) → “keep the admin console current” + “admin MCP ops parity”.

#### Enable path A — Docker (no host package install)

**Preferred when you want the admin UI/BFF without installing a Tier-1 package or building Go on the host.** First-class stack: [`../../deploy/local/README.md`](../../deploy/local/README.md).

```bash
# From repo root (Docker Compose v2). Cursor MCP stdio remains host-native.
cp deploy/local/.env.example deploy/local/.env
echo "JENKINS_MCP_ADMIN_TOKEN=$(openssl rand -hex 24)" >> deploy/local/.env
make local-docker-up
# Admin UI: http://127.0.0.1:8787  — Bearer token from deploy/local/.env
# Optional lab Jenkins: LOCAL_COMPOSE_PROFILES=with-jenkins make local-docker-up
make local-docker-down   # when finished (wipes volumes)
```

Profiles: `LOCAL_COMPOSE_PROFILES=http` and/or `with-jenkins`. Smoke: `make local-docker-smoke` (opt-in; not in default CI).

#### Enable path B — host binary (pilot / package install)

```bash
# 1) Prefer a shared secret on multi-user hosts (never commit; never put value on argv).
export JENKINS_MCP_ADMIN_TOKEN='…'

# 2) Start loopback BFF (default 127.0.0.1:8787). SPA assets resolve automatically
#    when packaged under /usr/share/jenkins-mcp/admin-ui (UI-008) or via --assets-dir.
jenkins-mcp admin serve \
  --addr 127.0.0.1:8787 \
  --profile corp \
  --admin-token-env JENKINS_MCP_ADMIN_TOKEN \
  --admin-role viewer \
  --require-token
# Optional override: --assets-dir /path/to/web/admin/dist
```

| Flag | Meaning |
|------|---------|
| `--addr` | Listen address (default `127.0.0.1:8787`, loopback only) |
| `--admin-token-env` / `--admin-token-file` | Shared secret source (env **name** or file **path** only; mode 0600 for file) |
| `--require-token` | Fail start if no secret configured |
| `--admin-role` | `viewer` (default) \| `operator` \| `policy_admin` (UI-003) |
| `--assets-dir` | Optional SPA static root (overrides package/dev/embed defaults) |
| `--admin-allow-non-local` | Residual non-loopback bind; **requires** token (HOST-007; not multi-tenant production) |

#### SPA asset resolution (UI-008)

Priority when `--assets-dir` is empty:

1. **Packaged** `/usr/share/jenkins-mcp/admin-ui` (if `index.html` exists) — fresh install without npm  
2. **Dev residual** `web/admin/dist` (cwd-relative, after `make admin-ui`)  
3. **Embedded** `internal/admin/uiembed` (committed placeholder, or full SPA after `make admin-ui-embed` + rebuild)  

`GET /admin/v1/health` and `GET /admin/v1/version` expose secret-free `uiBuild` when a stamp is available (`UI_BUILD` file or embed id).

Package with SPA assets:

```bash
make admin-ui && make package
# BUILD_INFO: admin_ui=present|missing
```

Package **does not fail** when `web/admin/dist` is missing (`admin_ui=missing` residual in `BUILD_INFO`).

#### Security headers and timeouts (UI-008)

All admin responses include:

| Header | Value (summary) |
|--------|-----------------|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `no-referrer` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` |

`style-src 'unsafe-inline'` is intentional for Vite/React residual inline styles; **scripts remain `'self'` only** (no CDN). Subresource Integrity for third-party CDNs is **not** used — assets are same-origin only.

HTTP server timeouts (local admin, not multi-tenant gateway): `ReadHeaderTimeout` 10s, `ReadTimeout` 30s, `WriteTimeout` 60s, `IdleTimeout` 120s.

**Reverse-proxy residual:** prefer **same-origin** (SPA + `/admin/v1` on one host). If TLS terminates upstream, do **not** strip or weaken CSP carelessly; re-apply or pass through origin headers.

**Console RBAC** (separate from MCP deny-only subjects): `viewer` = read GETs; `operator` = day-2 destructive + gateway ops; `policy_admin` = policy write + gateway ops. **No role can widen enterprise `force_read_only`.** API contract: [`api-v1.md`](api-v1.md) (includes `GET /admin/v1/me`). SPA notes: [`../../web/admin/README.md`](../../web/admin/README.md).

### Design notes — admin users (v1, intentional)

The admin console is an **operator control plane for one process/host**, not an
application with a local user directory.

| Today (shipped) | Not in product |
|-----------------|----------------|
| **One shared secret** authenticates the console (`--admin-token-env` / `--admin-token-file`; Bearer / header) | Local username/password signup or multi-operator password DB |
| **One process-wide role** (`--admin-role=viewer\|operator\|policy_admin`) for the whole BFF | Per-person admin accounts with different roles on the same process |
| `GET /admin/v1/me` returns role + permissions + `tokenConfigured` — **never** the token | Cookie sessions / multi-session logout table (residual with SSO) |
| Role is **console-only** — never elevates Jenkins or MCP deny-only rights | Treating the admin token as a multi-user MCP identity |

**How operators “manage admin users” today:** issue/rotate the shared secret
out-of-band (secret manager, file mode 0600); set the process role at serve
start; restart or redeploy to change role. Multiple humans share that
token+role for a given host — that is the pilot model (HOST-007 honesty:
single process role).

**SAML admin SSO (POL-007 implemented offline):**

| Piece | Detail |
|-------|--------|
| Config | `JENKINS_MCP_SAML_CONFIG` → JSON SP file (`testdata/saml-lab/config.example.json`) |
| Trust | `idp_certificate_pem_path` (IdP **public** cert PEM) |
| Session | Optional `JENKINS_MCP_SAML_SESSION_KEY`; cookie `jenkins_mcp_admin_saml` (process-local; not multi-pod HA) |
| Routes | `GET /admin/v1/saml/status`, `GET …/login` (live redirect residual), `POST …/acs` (`SAMLResponse`) |
| Role map | `group_roles` in config; unmapped groups **deny**; shared-secret pilot remains when `require=false` |
| Residual | Live Entra/Okta/ADFS pin; browser IdP redirect automation |

**Future residual:**

| Path | Intent |
|------|--------|
| **UI-011 SPA Access** | Optional local binding editor; fleet SoT remains config (**MGR-001**) |
| **Live IdP pin** | Production metadata + browser ACS against real IdP |

Admin SSO must not invent group membership: groups come from the assertion
(or OIDC claims); missing/overage claims fail closed. SP/session secrets stay
in secret stores / env — **not** committed config. See ADR 0015.

| Surface | SPA status (honest) |
|---------|---------------------|
| Overview / policy effective / doctor read | Scaffold (UI-001) + BFF (UI-002) + role badge / token control (UI-003) + serve/CSP packaging (UI-008). **MCP-OPS:** same reads available as `admin_*` tools when serve uses `--enable-admin-mcp` (default off) — [mcp-ops-parity.md](mcp-ops-parity.md) |
| **Fleet-cache** (FLC-063) | **BFF+MCP implemented: `GET /admin/v1/fleet-cache/status` / `doctor`, `POST …/purge` (`confirm: "PURGE"`, operator); MCP `admin_fleet_cache_status` / `_doctor` / `_purge`. Process-local; mode default **off**. **SPA page residual** (no dedicated SPA section yet). See [api-v1.md](api-v1.md) § Fleet-cache. |
| **Metrics** (UI-005) | Auto-refresh (15s) with pause on hidden tab + manual pause; **Apache ECharts** snapshot bars + session history (≤60 pts); tables under charts; secret-free JSON export. **Residual:** process-local only; no fleet aggregation |
| **Audit** (UI-006) | type dropdown (catalog from settings API + static fallback), limit/before, BFF **`external_subject`** exact match (case-sensitive) on multi-user `externalSubject`, **externalSubject** / **subjectKeyHash** table columns (muted/truncated), SPA client exact filter residual for older BFF, detail drawer, load-older, export includes multi-user fields. **Event type settings:** enable/disable all known AUD-001 types (`GET`/`PUT …/audit/settings`, `gateway_ops` on write; `type_filter.json`; File sink reloads on mtime). **Residual:** no live SSE tail; page-capped client export only; multi-pod aggregation residual |
| Policy write editor | Not yet (UI-004) |
| Destructive ops | Not yet (UI-007) |

**Residuals:** loopback without token is pilot-only (any local process can call the API with the configured role); token-in-`localStorage` SPA UX is pilot-only; v1 Bearer/header auth (CSRF N/A); cookie sessions / OIDC not implemented; policy apply not exposed yet (UI-004); no CDN/SRI; multi-arch SPA packaging is the same static tree for all arches.

### HOST-007 — Gateway operator admin residual (non-SaaS)

The admin console is an **operator** surface for a single process / host — **not**
a multi-tenant end-user control plane or SaaS console.

| Topic | Guidance |
|-------|----------|
| Non-loopback bind | Only with **token required** (`--admin-allow-non-local` + `--require-token` / token env). Prefer reverse-proxy **mTLS or OIDC** residual design before exposing beyond loopback. |
| Vault / Jenkins tokens | **Never** in browser JSON or SPA. Mode A vault inventory is hash-only subjects via `GET /admin/v1/gateway/vault`; writes remain CLI (`gateway vault-put` / `vault-delete`). |
| Enabled auth modes | Secret-free mode **ids** on `GET /admin/v1/health` (`enabledModes`) and `GET /admin/v1/gateway/vault` (`mode` + `enabledModes`). No secrets, no vault material. |
| Unified residual-status | **HOST-007:** `GET /admin/v1/gateway/residual-status` returns the same secret-free map as CLI `gateway residual-status` (`diagnostics.BuildGatewayResidualStatus`). Modes, multi_user, HA, multi-pod, consent, rate knobs, `shared_subject_rate_file` / `shared_principal_cache_file` / `shared_jwks_file` / `shared_token_cache_file` / `shared_api_token_vault_file` / `shared_jwt_vault_file` (same-host lite bools only; paths never returned; token/vault residual never opens files; vault bools env-explicit only), `principal_cache_entries` (count; this admin process), optional `principal_cache_max_entries` / `principal_cache_ttl_seconds`, `oauth009_offline`. SPA Overview residual card shows live pin bools (`mode_*_live_*_qualified`, `gateway_ready`, `ha_multi_replica`) as **no/false** with honesty **offline residual — not production GO**; hides on 404 (older BFF). **Progressive consent nest:** SPA Overview residual + Mode C card + Doctor residual surface `progressive_consent.file_backed` / `same_host_reload_before_persist` (when `JENKINS_MCP_CONSENT_STORE_PATH` set), `multi_replica_shared=false`, `stores_tokens=false` (path never shown; not multi-pod HA). Health/vault also surface camelCase parity bools `sharedSubjectRateFile` / `sharedPrincipalCacheFile` / `sharedJwksFile` / `sharedTokenCacheFile` (paths never returned; not multi-pod HA; token residual never opens cache file). **Health progressive consent store camelCase parity:** `progressiveConsentFileBacked` / `progressiveConsentSameHostReload` (true when `CONSENT_STORE_PATH` set; same helper residual-status uses; path never returned; residual never opens consent file) + always-false `progressiveConsentStoresTokens` / `progressiveConsentMultiReplicaShared` (SPA Mode C card honesty: same-host lite; not multi-pod HA). Pointer: [live-pin-blockers.md](../gateway/live-pin-blockers.md). Never tokens/subjects / production GO. |
| Doctor `gateway_residual_status` SPA | **HOST-007 residual lite:** doctor BFF already embeds the same secret-free map under `gateway_residual_status` (informational; does not drive overall). SPA **Doctor** page shows a residual card **after Overall** when the field is present (hides on older BFF that omits it). Surfaces explicit `mode_*_live_*_qualified=no/false`, `gateway_ready=no/false`, `ha_multi_replica=no/false` with honesty **offline residual — not production GO** (same fields residual-status always emits). Reuses Overview helpers (`pickResidualLivePinFields` + `pickResidualRateCacheFields` / shared_*_file / principal count). Live pin pointer: [live-pin-blockers.md](../gateway/live-pin-blockers.md). Never tokens/subjects / live GO. |
| Subject invalidate (force re-auth residual lite) | **HOST-007:** `POST /admin/v1/gateway/subject-invalidate` mirrors CLI `gateway subject-invalidate`. Requires `gateway_ops` (`operator` / `policy_admin`). Body: `subject_key` or `tenant`+`subject_id`+`profile`. Clears process or same-host FilePrincipalCache / FileTokenCache when env paths set. Secret-free StatusMap response. **Not** live Entra revocation; **not** multi-pod fan-out. SPA Overview form when role has `gateway_ops`. See [api-v1.md](api-v1.md). |
| Consent purge (Mode C progressive consent residual lite) | **HOST-007:** `POST /admin/v1/gateway/consent-purge` mirrors CLI `gateway consent-purge` / `consent-expire`. Requires `gateway_ops`. Body: optional `action` `purge_expired` (default) \| `delete_session`+`session_id` \| `clear_all` + exact `confirm: "CLEAR_ALL"` (parity with cache `EVICT`; CLI `--all --confirm=CLEAR_ALL`). Uses `OpenConsentSessionStoreForPurge` / `JENKINS_MCP_CONSENT_STORE_PATH`. Optional body `path` is **jailed** to a direct file under the configured consent store directory (absolute only; outside-dir / relative / nested → 400 — no arbitrary overwrite). Secret-free counts (`deleted_count`, `remaining_count`); never tokens; `session_id` / full path not echoed. Persist fail closed (500 secret-free when file write fails). Same-host file reload-before-persist lite; **not** multi-pod HA; browser 3LO not automated. SPA Overview Mode C residual card form (type `CLEAR_ALL` for clear_all). See [api-v1.md](api-v1.md). |
| Mode C progressive consent | **OAUTH-010 residual (static):** health always exposes `progressiveConsentMetadataDoneStar: true` and `progressiveConsentBrowser3loAutomated: false` via `gateway.NewProgressiveConsentResidual`. When Mode C is enabled, `progressiveConsentResidual` carries the secret-free residual note. **HOST-007 store residual:** health also always surfaces camelCase `progressiveConsentFileBacked` / `progressiveConsentSameHostReload` (env path configured via `ConsentStorePathConfiguredFromEnviron`) and always-false `progressiveConsentStoresTokens` / `progressiveConsentMultiReplicaShared` — same honesty as residual-status nest; path never shown; not multi-pod HA. **Never** `authorization_url` with query secrets, tokens, or client secrets. SPA Overview shows this card when Mode C / residual is present. |
| Multi-operator sessions | **Residual: single process role** (`--admin-role`) for the whole BFF. No multi-user admin session table / CSRF cookies in v1. |
| localStorage token UX | **Pilot / quarantine for production.** SPA may store admin Bearer in `localStorage` for loopback labs only — **not** a production multi-host authn story. Prefer httpOnly cookie + CSRF or reverse-proxy mTLS/OIDC residual (ADR 0014). |
| Multi-user MCP gateway pin | **Foundation residual:** `JENKINS_MCP_GATEWAY_MULTI_USER=1` enables per-request Obtain + SubjectKey from HTTP Caller (not a production GO flip). Policy.Subject still process-bound; live Entra residual. Shared admin token ≠ per-user MCP subject. Admin never surfaces tokens/subjects raw. Health/vault expose secret-free `multiUserEnabled` + residual note when env is set. |
| Gateway Ready / HA | Admin health always reports `gatewayReady: false` and `haMultiReplica: false` (admin BFF ≠ MCP serve `/readyz`; HOST-008 single-replica Tier A). Always `multiPodVaultResidual: true` (multi-pod vault residual honesty — not multi-replica Done). When multi-user env is set, `sessionAffinityRecommended: true` (kustomize sticky scaffold honesty only). When `KUBERNETES_SERVICE_HOST` is set, `kubernetesEnvDetected: true` and `residual` includes multi-pod checklist (sticky, shared vault, rate, Obtain cache). **SPA Overview** surfaces `multiPodVaultResidual` / `kubernetesEnvDetected` on Health and Gateway vault cards, and shows the multi-pod residual checklist card when `kubernetesEnvDetected` is true (secret-free; never multi-replica Done from k8s env alone). Live Ready is on the gateway serve process only. Doctor parity: `gateway_status.multi_pod_vault_residual` — see [gateway/deployment.md §9](../gateway/deployment.md). |
| CSP under reverse-proxy | Prefer **same-origin** (SPA + `/admin/v1`). Do not strip CSP; re-apply if TLS terminates upstream. |
| HA admin | Multi-pod admin plane **out of scope** (HOST-008 cancelled; multi-fleet). See [gateway/deployment.md §9](../gateway/deployment.md). |

See also [`api-v1.md`](api-v1.md) health + gateway/vault + gateway/residual-status; [`../gateway/deployment.md`](../gateway/deployment.md); [`../gateway/live-pin-blockers.md`](../gateway/live-pin-blockers.md).
---

## 1. Packaging (RPM / DEB / tar)

| Artifact | Producer | Notes |
|----------|----------|-------|
| `jenkins-mcp_<version>_linux_amd64.tar.gz` | `make package` | Always; portable layout `usr/bin/jenkins-mcp` |
| `jenkins-mcp_<version>_amd64.deb` | when `dpkg-deb` present | Ubuntu / Debian |
| `jenkins-mcp-<version>-1.*.rpm` | when `rpmbuild` present | Rocky / RHEL-family |
| `dist/SHA256SUMS`, `dist/BUILD_INFO` | package script | Secret-free release metadata |
| `make sbom` | modules + `go version -m` | Scanner input |

```bash
export PATH="$HOME/.local/go/bin:$PATH"
make test
make package
ls -la dist/
cat dist/BUILD_INFO
jenkins-mcp version --json
```

### Install examples

```bash
# Portable tarball
tar -xzf jenkins-mcp_*_linux_amd64.tar.gz
sudo install -m 0755 usr/bin/jenkins-mcp /usr/local/bin/jenkins-mcp

# Ubuntu
sudo dpkg -i jenkins-mcp_*_amd64.deb

# Rocky
sudo dnf install ./jenkins-mcp-*.rpm
```

Ordinary operation does **not** require root after the binary is on `PATH`. Config, cache, and credentials are **per-user**.

Optional deps: Secret Service for tokens; `fuse3` only for future optional L2 mount inspection (core path works without FUSE).

---

## 2. XDG paths and cache dirs

**How caching works and how to size it per deploy type** (Cursor stdio, multi-fleet, local Docker, gateway, multi-user HTTP): **[caching.md](../caching.md)**. Deep CLI: [arc/eviction.md](../arc/eviction.md), [arc/cache-pins.md](../arc/cache-pins.md), [security/cache-encryption.md](../security/cache-encryption.md).

| Kind | Default |
|------|---------|
| Config / profiles | `$XDG_CONFIG_HOME/jenkins-mcp` → `~/.config/jenkins-mcp` |
| Data (L1 frames, SQLite meta, L2 packs) | `$XDG_DATA_HOME/jenkins-mcp` → `~/.local/share/jenkins-mcp` |
| Cache (support bundles, etc.) | `$XDG_CACHE_HOME/jenkins-mcp` → `~/.cache/jenkins-mcp` |
| Policy overlay (pilot) | `…/jenkins-mcp/policy/overlay.json` |
| Policy signed bundle | `…/jenkins-mcp/policy/overlay.bundle.json` |
| Policy trusted keys | `…/jenkins-mcp/policy/trusted_keys/` |
| Policy last-good cache | `$XDG_CACHE_HOME/jenkins-mcp/policy/last_good.json` |

Per-profile data root holds:

- L1 independent Zstandard **payload frames** (not single-frame random-access claims)
- SQLite `metadata.sqlite`
- L2 multi-frame seekable `archives/*.tar.zst` (+ index) when compaction runs

**Secrets never live under these trees** — API tokens are in Linux Secret Service.

Default total physical quota: **10 GiB** (`store.DefaultTotalQuotaBytes`); operator-tunable via `--cache-total-quota-bytes` / `JENKINS_MCP_CACHE_TOTAL_QUOTA_BYTES` (and low-disk twin). Admin BFF/MCP use the same env resolve as serve. See [caching.md](../caching.md) and packaging cache notes (ARC-007/008).

---

## 3. Enterprise policy overlay (deny-only)

Optional JSON under the policy path can **only restrict** privileges further (force RO, deny tools, deny job prefixes, deny node/view names; result budget ≤ serve-bootstrap ceiling). It never elevates Jenkins rights. Invalid overlay ⇒ fail closed. Full model: [`../policy-rbac.md`](../policy-rbac.md).

### Plain pilot overlay example (`overlay.json`)

```json
{
  "version": 1,
  "force_read_only": true,
  "mode": "pilot",
  "deny_tools": ["jenkins_get_build_logs", "jenkins_start_job"],
  "deny_job_prefixes": ["secret-folder", "infra/prod"],
  "deny_node_names": ["prod-agent-*"],
  "deny_view_names": ["secret-view"],
  "deny_artifact_paths": ["secrets/**", "*.pem"],
  "deny_branch_names": ["release/*", "main"],
  "max_result_bytes": 65536,
  "max_tools_per_minute": 15,
  "max_tools_burst": 5
}
```

| Field | Operator meaning |
|-------|------------------|
| `force_read_only` | Cannot be defeated by `--allow-mutations` or weaker flags |
| `deny_tools` | Exact MCP tool names blocked for every subject |
| `deny_job_prefixes` | Call-time deny for `job_name` / seed `name` (exact, children, `/**`, `*`, mid-path `**/`, limited `{a,b}` braces, character classes `[…]`; not bare string prefix). Also omits matching rows from `jenkins_list_jobs` (`policy_filtered` / `policy_omitted_count`; Wave 39 collect+filter+repaginate; Wave 40 policy-bound page tokens) |
| `deny_node_names` | Call-time deny for `node_name` (e.g. `jenkins_get_node`; Wave 35/36). Also omits matching rows from list-all `jenkins_get_nodes` (`policy_filtered` / `policy_omitted_count`) |
| `deny_view_names` | Call-time deny for `view_name` / seed `view` (e.g. `jenkins_list_jobs`; Wave 35) |
| `deny_artifact_paths` | Call-time deny for relative artifact `path` / `artifact_path` (e.g. `jenkins_get_artifact_text`; Wave 36). Same pattern language as jobs |
| `deny_branch_names` | Call-time deny for `branch_name` / seed `branch` (Wave 37). Also omits matching `kind=branch` / `matrix_child` rows from `jenkins_list_jobs` (`policy_filtered` / `policy_omitted_count`; Wave 39 collect+filter+repaginate; Wave 40 policy-bound page tokens). Same pattern language as jobs |
| `max_result_bytes` | Bounds hard MCP result budget; mid-serve raise/lower ≤ serve-bootstrap ceiling (Wave 31) |
| `max_tools_per_minute` | Per-subject tools/min cap under `--gateway` (HOST-006); **lower only** vs env bootstrap; omitted = no change. Admin SPA Policy editor (policy_admin / `policy_write`) can set on plain pilot overlays. |
| `max_tools_burst` | Per-subject burst cap (HOST-006 LowerRate; lower only). Admin SPA Policy editor (same as rate/min). Process-local; multi-pod shared rate out of scope (HOST-008 cancelled). |

**Signed fleets (MGR-001):** prefer `overlay.bundle.json` + Ed25519 public keys under `policy/trusted_keys/` (or `JENKINS_MCP_POLICY_TRUSTED_KEYS`). Invalid, expired, untrusted, or rolled-back bundles fail closed. Operator guide: [`../security/policy-bundles.md`](../security/policy-bundles.md).

### policy verify / show-effective / sign

```bash
# Verify a signed bundle (or plain pilot overlay when no keys)
jenkins-mcp policy verify \
  --file /etc/jenkins-mcp/policy/overlay.bundle.json \
  --keys /etc/jenkins-mcp/policy/trusted_keys \
  --json
# Optional anti-rollback: --check-downgrade

# Secret-free effective policy for a profile
jenkins-mcp policy show-effective --profile corp --json
# Prints force_read_only, fleet_telemetry_force_off, deny_tools, deny_job_prefixes, deny_node_names, deny_view_names, deny_artifact_paths, deny_branch_names, max_result_bytes, max_tools_per_minute, max_tools_burst, signature_state

# DEV ONLY — requires JENKINS_MCP_POLICY_SIGN_DEV=1; never commit private keys
export JENKINS_MCP_POLICY_SIGN_DEV=1
jenkins-mcp policy sign \
  --file overlay.json \
  --key /secure/path/policy-ed25519.pem \
  --key-id corp-policy-2026 \
  --bundle-seq 42 \
  --out overlay.bundle.json
```

`policy sign` is a **developer aid**, not a fleet CA. Production signing should use HSM/KMS or offline tooling.

Cursor / fleet env examples must show `--read-only` / `JENKINS_MCP_READ_ONLY=true`. Do **not** document a generic switch that bypasses stronger RO. Do **not** put `JENKINS_MCP_AUTH` in pilot configs.

---

## 3b. Enterprise redact patterns (SEC-002)

Optional extra detectors (built-ins always apply). **Config source is file + env**, not policy overlay:

| Variable | Meaning |
|----------|---------|
| `JENKINS_MCP_REDACT_PATTERNS_FILE` | Path to JSON array `[{"name":"corp_id","expr":"..."}]` |

- **Unset / empty** → no enterprise patterns (default).
- **Valid file** → compile at `serve` start; install process-wide.
- **Invalid / missing / oversized** → **fail closed** (serve does not start).

```bash
# Validate without serving
jenkins-mcp redact validate-patterns --file /etc/jenkins-mcp/redact-patterns.json
jenkins-mcp redact validate-patterns --file ./patterns.json --json

# Serve with enterprise patterns
export JENKINS_MCP_REDACT_PATTERNS_FILE=/etc/jenkins-mcp/redact-patterns.json
jenkins-mcp serve --profile corp --read-only
```

Reports expose **category counts only**. Residual: never log match samples or secrets; redaction is layered best-effort (see [`../security/operator-guide.md`](../security/operator-guide.md) §5).

---

## 4. Doctor, security self-check, support bundle, pilot evidence

```bash
jenkins-mcp doctor --profile corp --offline
jenkins-mcp doctor --profile corp --bundle-preview
jenkins-mcp support-bundle --profile corp --preview
jenkins-mcp support-bundle --profile corp            # writes privacy-scrubbed zip under XDG cache
jenkins-mcp security self-check --json
jenkins-mcp security self-check --json --profile corp
jenkins-mcp pilot-check --profile corp --offline
jenkins-mcp release-evidence --offline --profile corp --output dist/release-evidence.json
jenkins-mcp oauth probe-rs --profile corp --offline   # RS residual matrix (OAUTH-009)
```

| Command | Use |
|---------|-----|
| `doctor` | Local integrity + optional whoAmI; includes `rs_auth` residual and Wave 32 **`mutations`** check (registration vs executable; pass `--allow-mutations` / `--read-only` to mirror serve). MCP `jenkins_doctor` uses the live RO gate. JSON/BFF embed `gateway_residual_status` (same residual-status map; informational). SPA Doctor residual card when present (HOST-007 lite) |
| `support-bundle` / `doctor --bundle` | Privacy-scrubbed zip (OPS-001 / Wave 23): doctor, cache, metrics, offline security self-check, release-evidence lite (version/runtime), RS qualification summary, error signature hashes — **no** tokens/keyring/full logs |
| `security self-check` | Secret-free posture items (RO default, policy, keyring, RS residual, …); also embedded in support-bundle |
| `pilot-check` | Combines doctor + cache status + sample verify → JSON (REL-001) |
| `release-evidence --offline` | **Lite** local summary; full gates: [`../release/gates.md`](../release/gates.md) |

Support-bundle default path: `$XDG_CACHE_HOME/jenkins-mcp/support-bundles/<profileId>/support-bundle-*.zip` (mode **0600**). Always prefer `--preview` / `--bundle-preview` first. Categories and exclusions are printed before any write. See [privacy-data-retention.md](../security/privacy-data-retention.md) §6 and [observability.md](../observability.md).

Offline pack automation:

```bash
make pilot-evidence PROFILE=corp SKIP_GO_TEST=1
# → dist/pilot-evidence/<ts>/MANIFEST.json
```

See [pilot/README.md](../pilot/README.md). Packs are **secret-free** by construction.

---

## 5. Live Jenkins lab (opt-in only)

**Default `make test` / CI unit jobs never start Docker.** Live coverage is manual or workflow_dispatch.

```bash
export PATH="$HOME/.local/go/bin:$PATH"

# One-shot: compose up → wait healthy → mint token → live tests → compose down -v
make live-jenkins-test

# Or: make live-jenkins-up / live-jenkins-down
# Wrapper: ./scripts/jenkins-live-smoke.sh
```

Ephemeral lab credentials live only in the disposable container volume — do not log tokens, do not commit them, and do not treat the lab password as a production secret. Full matrix: [`../tst/README.md`](../tst/README.md).

**Residual:** multi-LTS + proxy grid and live Entra/jwt-auth-filter lab are not default gates.

---

## 6. Gateway mode (env vars — no secrets)

Optional managed-gateway / AgentCore foundation (GWY-001/002). **Default serve is local stdio, not gateway.** Live Entra obtain remains residual.

```bash
jenkins-mcp serve --profile corp --gateway --read-only
# or JENKINS_MCP_GATEWAY_MODE=1
jenkins-mcp gateway qualify --offline
```

### Non-secret environment (safe in compose / unit files)

| Variable | Meaning |
|----------|---------|
| `JENKINS_MCP_GATEWAY_MODE` | `1` / `true` enables gateway mode |
| `JENKINS_MCP_AGENTCORE_AS_URL` | Authorization server base (**Entra**), **never** Jenkins |
| `JENKINS_MCP_AGENTCORE_AUDIENCE` | Exact Jenkins API resource audience |
| `JENKINS_MCP_AGENTCORE_CLIENT_ID` | Public OAuth client id |
| `JENKINS_MCP_AGENTCORE_MODE` | `authorization_code` or `token_exchange` |
| `JENKINS_MCP_AGENTCORE_AUTH_ENDPOINT` | Optional authorize URL |
| `JENKINS_MCP_AGENTCORE_TOKEN_ENDPOINT` | Optional token URL |
| `JENKINS_MCP_GATEWAY_SUBJECT` | Entra/OIDC `sub` (required when binding) |
| `JENKINS_MCP_GATEWAY_TENANT` | Tenant id |
| `JENKINS_MCP_GATEWAY_WORKLOAD` | Workload id |
| `JENKINS_MCP_GATEWAY_JENKINS_PRINCIPAL` | Optional; must match whoAmI when set |
| `JENKINS_MCP_READ_ONLY` | Force read-only |

**Never place in env or compose files:** API tokens, client secrets, refresh tokens, private keys, cookies, `JENKINS_MCP_AUTH`, or retired `-auth`. Full tables: [`../gateway/deployment.md`](../gateway/deployment.md).

---

## 7. HTTP mode (loopback + allowed-origin)

Prefer **stdio** for Cursor (ADR 0002). Streamable HTTP is optional and **not** the pilot default.

| Control | Behavior |
|---------|----------|
| Default bind | **Loopback only** (`127.0.0.1`, `localhost`, `::1`). `0.0.0.0` / LAN binds are **rejected** |
| Escape hatch | `--http-allow-non-local` — residual tests / advanced; **requires** one or more `--http-allowed-origin` (fail closed). **Not** production packaging guidance |
| Body cap | 4 MiB request body |
| Host / Origin | Non-GET: loopback `Host` by default; `Origin` must be loopback **or** exact-match `--http-allowed-origin` |
| Optional shared secret | `--http-token-env=VAR` or `--http-token-file=PATH` (mode 0600). Clients: `Authorization: Bearer` or `X-Jenkins-MCP-Token`. **Never** put token on argv. See [`../packaging.md`](../packaging.md) |
| Residual | **No per-user auth** (KD-008). Shared secret is a single optional gate — not multi-tenant production-ready. Prefer stdio |

```bash
# Local debug only
jenkins-mcp serve --profile corp --http 127.0.0.1:8765 --read-only
# Optional: --http-token-env=MCP_HTTP_TOKEN  (token value in env, not argv)
```

Package installs and pilot Cursor configs should use **stdio only**.

---

## 8. Fleet telemetry (opt-in, privacy)

Telemetry is **disabled by default**. When enabled, export is schema-bounded and must not centralize Jenkins content. Privacy review: [`../security/fleet-telemetry.md`](../security/fleet-telemetry.md).

| Control | Default | Notes |
|---------|---------|--------|
| `JENKINS_MCP_TELEMETRY` | off | Truthy enables local snapshot + queue |
| `JENKINS_MCP_TELEMETRY_URL` | empty | Optional HTTPS POST; empty ⇒ local queue only |

```bash
jenkins-mcp telemetry status --json
jenkins-mcp telemetry show --json
```

Exports: version, OS/arch, auth method enum, allowlisted counters, stable error codes, hashed profile id — **never** logs, prompts, tokens, artifacts, or raw parameters. Network failures never fail MCP serve.

---

## 9. Maintenance flags (serve + CLI)

### Serve-time identity re-verify TTL (AUTH-004 Wave 24)

Mid-serve tool dispatch re-checks Jenkins `whoAmI` on a short cache TTL (not
every call). Operators can tighten the window so a revoked API token fails
closed sooner.

| Flag / env | Effect |
|------------|--------|
| `--identity-reverify-ttl=30s` | Serve flag; **overrides** env when set |
| `JENKINS_MCP_IDENTITY_REVERIFY_TTL` | Same duration (e.g. `30s`, `1m`, `5m`) |
| Unset or zero (`0` / `0s`) | Default **5m** |
| Bounds | Min **10s**, max **30m**; invalid → **fail closed at serve start** |

```bash
# Shorter residual window after token revoke (still not every-call whoAmI)
export JENKINS_MCP_IDENTITY_REVERIFY_TTL=30s
jenkins-mcp serve --profile corp --read-only
# or
jenkins-mcp serve --profile corp --read-only --identity-reverify-ttl=30s
```

**Residual (by design):** not continuous every-call whoAmI — only on TTL expiry
or cache miss. See [`../auth-architecture.md`](../auth-architecture.md).

### Serve-time cache maintenance

Full matrix (quota, pins, gateway caches, Docker share models): **[caching.md](../caching.md)**.

When `jenkins-mcp serve --profile <id>` opens the store:

- Recovers eviction journal
- Evicts when over quota
- Optionally packs sealed unpinned L1 into L2 (keeps L1 until release residual)
- Default interval **5m**

| Flag / env | Effect |
|------------|--------|
| `--no-cache-maintenance` | Disable loop |
| `JENKINS_MCP_NO_CACHE_MAINTENANCE=1` | Same |
| `--cache-maintenance-interval 5m` | Tick interval |
| `JENKINS_MCP_CACHE_MAINTENANCE_INTERVAL` | Same |

### Offline cache CLI

```bash
jenkins-mcp cache status --profile corp
jenkins-mcp cache verify --profile corp --sample 3   # or --full
jenkins-mcp cache repair --profile corp --index-only # rebuild sidecars; never rewrite pack bodies
```

### Cache pins (ARC-007)

Durable pins protect **eviction** for L1 generations and L2 packs. Fail closed if the profile or data directory is missing (commands do not create a cache root).

```bash
# Pin / unpin by meta generation id (SQLite log_generations.id)
jenkins-mcp cache pin generation --profile corp --generation 42
jenkins-mcp cache unpin generation --profile corp --generation 42

# Pin / unpin L2 pack id
jenkins-mcp cache pin pack --profile corp --pack pack-abc
jenkins-mcp cache unpin pack --profile corp --pack pack-abc

# List pins (secret-free: kind, target_id, pinned_at only)
jenkins-mcp cache pins --profile corp
jenkins-mcp cache pins --profile corp --json
```

**Residual:** pins do **not** protect against manual wipe of the profile data tree (`rm -rf` of the XDG data dir / `profile remove` cleanup). They only influence quota eviction and L1→L2 release gates. See [`../arc/cache-pins.md`](../arc/cache-pins.md).

### Cache eviction plan and apply (ARC-007)

Operators can inspect what serve-time maintenance would reclaim **without deleting anything**, or apply reclaim offline with an explicit confirm flag. Fail closed if the profile or data directory is missing. **Serve-time maintenance remains the primary reclaim path**; the CLI apply path is an operator escape hatch.

```bash
# Dry-run plan (PlanEviction only; never Evict)
jenkins-mcp cache eviction-plan --profile corp
jenkins-mcp cache eviction-plan --profile corp --json
jenkins-mcp cache eviction-plan --profile corp --json --target-bytes 1048576

# Default dry-run (same as plan — never deletes without --confirm/--yes)
jenkins-mcp cache evict --profile corp --json --target-bytes 1048576

# Apply (destructive): requires --confirm or --yes; recovers journal, re-plans, then Evict
jenkins-mcp cache evict --profile corp --confirm --json --target-bytes 1048576
jenkins-mcp cache eviction-apply --profile corp --yes --json

# Usage / quota snapshot only
jenkins-mcp cache quota --profile corp
jenkins-mcp cache quota --profile corp --json
```

Output is secret-free: usage stats, `needs_eviction`, candidate list (`kind`, `id`, `bytes`, optional `age`/`reason`), `pins_skipped`, and on apply `evicted` / `reclaimed_bytes` / `applied`. Never prints credentials or absolute secret-bearing paths.

See [`../arc/eviction.md`](../arc/eviction.md).

### Optional cache encryption (ARC-009)

Opt-in AES-256-GCM for L1 frames. Keys live only in the OS keyring (Secret Service on Tier-1 Linux); profile JSON holds non-secret flags only.

```bash
jenkins-mcp cache key init --profile corp
jenkins-mcp cache key status --profile corp   # never prints key material
jenkins-mcp cache key rotate --profile corp   # N+1 write; N as prev; drop N-2 (last 2 only)
```

Full contract, fail-closed behavior, and residuals (no full re-encrypt): [`../security/cache-encryption.md`](../security/cache-encryption.md).

---

## 10. SELinux / AppArmor (smoke)

- **Rocky (SELinux):** binary under `/usr/bin` or `/usr/local/bin` typically unconfined / `bin_t`. No custom policy module ships in PKG-001. If Secret Service D-Bus is blocked, fix session policy or run offline doctor.
- **Ubuntu (AppArmor):** no dedicated profile ships; user binary expected unconfined. Site profiles must allow XDG home paths + session D-Bus for keyring.

These are pilot smoke notes — not a confinement product.

---

## 11. Updates (UPD-001)

Prefer **enterprise software distribution** (RPM/DEB repos, signed packages).

```bash
# Signed metadata check (production: install update public keys first)
export JENKINS_MCP_UPDATE_MANIFEST_URL=https://releases.example.corp/jenkins-mcp/stable.json
# keys: $XDG_CONFIG_HOME/jenkins-mcp/update/trusted_keys/ or JENKINS_MCP_UPDATE_TRUSTED_KEYS
jenkins-mcp update-check --channel stable --json

# Offline verify
jenkins-mcp update verify-manifest --file /tmp/stable.json --keys /etc/jenkins-mcp/update/trusted_keys

# Optional: download + sha256 only (never installs)
jenkins-mcp update download --channel stable --outdir /var/tmp/jenkins-mcp-updates
```

If the manifest URL is **unset** (default), update-check skips the network and prints the residual.  
Unsigned manifests are allowed only when **no** keys are configured **and** `JENKINS_MCP_UPDATE_ALLOW_UNSIGNED=1` (`unverified_pilot`).  
**Residual:** no auto-install / binary rollback — operators reinstall via package manager. Full contract: [`../release/update.md`](../release/update.md) and [`../packaging.md`](../packaging.md).

---

## 12. Storage residual (for support conversations)

- L1: progressive Jenkins log bytes → **independent checksummed Zstd frames** (no unbounded `ReadAll`).
- L2: **seekable multi-frame** `.tar.zst` only — never call a single-frame `.tar.zst` “random access.”
- Optional `ratarmount-rs` qualification is diagnostic; native Go readers are the primary path.
- Affinity packs / seek tables / recovery: see architecture + `docs/arc/`.

---

## 13. Uninstall

Packages remove the binary only. Per-user cleanup is explicit:

```bash
jenkins-mcp logout --profile corp   # keyring
rm -rf ~/.config/jenkins-mcp ~/.local/share/jenkins-mcp ~/.cache/jenkins-mcp
```


## Result hard-max bootstrap (Wave 37)

Serve-time absolute MCP result ceiling (bytes):

| Source | Precedence |
|--------|------------|
| Default | 1 MiB (`DefaultHardMaxBytes`) |
| Env `JENKINS_MCP_HARD_MAX_BYTES` | Fallback when flag unset; invalid fails closed |
| Flag `--hard-max-bytes N` | Wins over env |
| Overlay `max_result_bytes` | **Only lowers** within the bootstrap ceiling |

Raising the absolute ceiling requires re-serve with a higher flag/env. Mid-serve overlay reload cannot raise above process bootstrap ceiling.

## list_jobs collect safety page cap (Wave 41)

When live `deny_job_prefixes` / `deny_branch_names` force full-list collect+filter on
`jenkins_list_jobs`, the collector pages ListJobs internally up to a safety page
cap (each page ≤ 200 jobs). Large fleets may hit the cap → `truncated=true` and a
non-secret incomplete `message` (unchanged text).

| Source | Precedence |
|--------|------------|
| Default | **50** pages (`DefaultListJobsCollectMaxPages`; ~10k jobs at max page size) |
| Env `JENKINS_MCP_LIST_JOBS_COLLECT_MAX_PAGES` | Fallback when flag unset; empty/0 = default; invalid fails closed |
| Flag `--list-jobs-collect-max-pages N` | Wins over env |
| Absolute fail-closed max | **200** pages (`AbsoluteMaxListJobsCollectMaxPages`); oversize flag/env rejected at serve start |

Empty deny patterns still use a single ListJobs (no multi-fetch cost). Raising the
cap requires re-serve with a higher flag/env (≤ 200).

## nodes / views collect safety page caps (Wave 42)

When live `deny_node_names` forces collect+filter on `jenkins_get_nodes`, or live
`deny_view_names` forces collect+filter on `jenkins_list_views`, collectors page
internally up to a safety page cap (each page ≤ 200 rows). Cap hit →
`truncated=true` and a non-secret incomplete `message`.

| Source | Nodes | Views |
|--------|-------|-------|
| Default | **50** pages (`DefaultNodesCollectMaxPages`) | **50** pages (`DefaultViewsCollectMaxPages`) |
| Env | `JENKINS_MCP_NODES_COLLECT_MAX_PAGES` | `JENKINS_MCP_VIEWS_COLLECT_MAX_PAGES` |
| Flag | `--nodes-collect-max-pages N` (wins over env) | `--views-collect-max-pages N` (wins over env) |
| Absolute fail-closed max | **200** (`AbsoluteMaxNodesCollectMaxPages`) | **200** (`AbsoluteMaxViewsCollectMaxPages`) |

Empty deny patterns still use a single GetNodes / ListViews (no multi-fetch cost).
Raising either cap requires re-serve with a higher flag/env (≤ 200). Shared
resolve helper: `ResolveCollectMaxPages` (same precedence and fail-closed rules
as list_jobs).


### HTTP deny anonymous loopback (Wave 41)

Opt-in: `JENKINS_MCP_HTTP_DENY_ANONYMOUS=1` is an alias for require-token (fail closed without shared secret). Default remains open residual on loopback (KD-008; prefer stdio).


## Artifacts hard cap (Wave 42)

| Source | Meaning |
|--------|---------|
| Default | 500 |
| Env `JENKINS_MCP_ARTIFACTS_HARD_CAP` | Fallback when flag unset |
| Flag `--artifacts-hard-cap N` | Wins over env |
| Absolute max | 2000 fail-closed |

Used when live `deny_artifact_paths` force a hard-cap fetch; also upper-bounds `max_artifacts`.


## Artifacts list JSON body bound (Wave 43)

| Source | Meaning |
|--------|---------|
| Default | 2097152 (2 MiB) |
| Env `JENKINS_MCP_ARTIFACTS_LIST_BODY_BYTES` | Fallback when flag unset |
| Flag `--artifacts-list-body-bytes N` | Wins over env |
| Absolute max | 8388608 (8 MiB) fail-closed |

Bounds the raw Jenkins `api/json` artifacts-tree body for `jenkins_list_artifacts`.
Invalid values and values above absolute max fail closed at serve start (no silent
clamp). Empty/0 at the winning layer means default. Serve logs the non-secret
resolved value as `artifacts_list_body_bytes=…`. Raise when very long paths near
the AbsoluteMax count hard cap (2000) would otherwise truncate the body before
the count cap is reached.

### Jenkins MaxJSONBodyBytes (Wave 46 Track A / NET-003)

| Control | Value |
|---------|-------|
| Default | 33554432 (32 MiB) |
| Env `JENKINS_MCP_MAX_JSON_BODY_BYTES` | Fallback when flag unset |
| Flag `--max-json-body-bytes N` | Wins over env |
| Absolute max | 134217728 (128 MiB) fail-closed |

Transport-level decoded body cap for non-log Jenkins API responses
(`ResilienceConfig.MaxJSONBodyBytes`). Invalid values and values above absolute
max fail closed at serve start (no silent clamp). Empty/0 at the winning layer
means default. Serve logs the non-secret resolved value as
`max_json_body_bytes=…`. Progressive log paths keep LOG-001 caps only (this
bound does not wrap them). Residual: live multi-controller chaos / network
matrix still residual.

### Jenkins MaxRetries (Wave 47 Track A / NET-003)

| Control | Value |
|---------|-------|
| Default | 2 (extra GET/HEAD attempts after the first) |
| Env `JENKINS_MCP_MAX_RETRIES` | Fallback when flag unset |
| Flag `--max-retries N` | Wins over env |
| Explicit `0` | Disables GET/HEAD auto-retry (total attempts = 1) |
| Absolute max | 10 fail-closed |

Transport-level extra retries for idempotent GET/HEAD only
(`ResilienceConfig.MaxRetries`). Invalid values, negatives, and values above
absolute max fail closed at serve start (no silent clamp). Empty/whitespace at
the winning layer means default **2**. Unlike MaxJSONBodyBytes, explicit **0**
means zero retries (not “use default”). Serve logs the non-secret resolved
value as `max_retries=…` (combined with `max_json_body_bytes=…` and
`circuit_failure_threshold=…`). POST/PUT/PATCH/DELETE never auto-retry
regardless of this setting. Residual: live multi-controller chaos / network
matrix still residual.

### Jenkins CircuitFailureThreshold (Wave 48 Track A / NET-003)

| Control | Value |
|---------|-------|
| Default | 5 (consecutive 5xx/transport failures before open) |
| Env `JENKINS_MCP_CIRCUIT_FAILURE_THRESHOLD` | Fallback when flag unset |
| Flag `--circuit-failure-threshold N` | Wins over env |
| Explicit `0` | Means default **5** (cannot disable circuit by 0) |
| Absolute max | 50 fail-closed |

Transport-level circuit breaker trip threshold
(`ResilienceConfig.CircuitFailureThreshold`). Invalid values, negatives, and
values above absolute max fail closed at serve start (no silent clamp).
Empty/whitespace/0 at the winning layer means default **5**. Unlike MaxRetries,
explicit **0** does not disable the breaker — fail-closed safety maps 0 to
default. Serve logs the non-secret resolved value as
`circuit_failure_threshold=…` (combined with `max_json_body_bytes=…` /
`max_retries=…` / `circuit_open_duration=…`). Circuit still opens only on
consecutive 5xx/transport failures; POST never auto-retries. Residual: live
multi-controller chaos / network matrix still residual.

### Jenkins CircuitOpenDuration (Wave 49 Track A / NET-003)

| Control | Value |
|---------|-------|
| Default | 15s (open period before half-open probe) |
| Env `JENKINS_MCP_CIRCUIT_OPEN_DURATION` | Fallback when flag unset |
| Flag `--circuit-open-duration DURATION` | Wins over env (Go duration, e.g. `15s`, `1m`) |
| Explicit `0` / `0s` | Means default **15s** (cannot disable open period by 0) |
| Min | 1s fail-closed |
| Absolute max | 5m fail-closed |

Transport-level circuit breaker open window
(`ResilienceConfig.CircuitOpenDuration`). Invalid values, negatives, values
below min, and values above absolute max fail closed at serve start (no silent
clamp). Empty/whitespace/0/`0s` at the winning layer means default **15s**.
Serve logs the non-secret resolved value as `circuit_open_duration=…`
(combined with `max_json_body_bytes=…` / `max_retries=…` /
`circuit_failure_threshold=…` / `max_concurrent=…`). Circuit still opens only on
consecutive 5xx/transport failures; POST never auto-retries. Residual: live
multi-controller chaos / network matrix still residual.

### Jenkins MaxConcurrent (Wave 50 Track A / NET-003)

| Control | Value |
|---------|-------|
| Default | 0 (unlimited per-client concurrency) |
| Env `JENKINS_MCP_MAX_CONCURRENT` | Fallback when flag unset |
| Flag `--max-concurrent N` | Wins over env |
| Explicit `0` | Unlimited concurrency (same as default; not remapped) |
| Absolute max | 256 fail-closed |

Transport-level per-client concurrency semaphore
(`ResilienceConfig.MaxConcurrent`). Invalid values, negatives, and values above
absolute max fail closed at serve start (no silent clamp). Empty/whitespace at
all layers means default **0** (unlimited). Unlike MaxRetries (where **0**
disables GET/HEAD auto-retry) and MaxJSONBodyBytes (where **0** means default
body size), MaxConcurrent **0** means unlimited concurrency. Serve logs the
non-secret resolved value as `max_concurrent=…` (combined with
`max_json_body_bytes=…` / `max_retries=…` / `circuit_failure_threshold=…` /
`circuit_open_duration=…` / `initial_backoff=…` / `max_backoff=…`). POST never
auto-retries. Residual: live multi-controller chaos / network matrix still residual.

### Jenkins InitialBackoff (Wave 51 Track A / NET-003)

| Control | Value |
|---------|-------|
| Default | 100ms (base delay before first GET/HEAD retry) |
| Env `JENKINS_MCP_INITIAL_BACKOFF` | Fallback when flag unset |
| Flag `--initial-backoff DURATION` | Wins over env (Go duration) |
| Explicit `0` / `0s` | Default (cannot disable base delay by 0) |
| Min | 10ms fail-closed |
| Absolute max | 2s fail-closed |
| Ordering | Must be ≤ resolved MaxBackoff |

GET/HEAD retry initial backoff (`ResilienceConfig.InitialBackoff`). Invalid
values, negatives, below-min, and oversize flag/env fail closed at serve start
(no silent clamp). Empty/whitespace/`0`/`0s` at all layers means default
**100ms**. After both backoffs resolve, max must be ≥ initial (fail closed;
library normalize raises max when inverted). Serve logs non-secret
`initial_backoff=…`. POST never auto-retries. Residual: live multi-controller
chaos / network matrix still residual.

### Jenkins MaxBackoff (Wave 51 Track A / NET-003)

| Control | Value |
|---------|-------|
| Default | 5s (cap on exponential backoff and Retry-After) |
| Env `JENKINS_MCP_MAX_BACKOFF` | Fallback when flag unset |
| Flag `--max-backoff DURATION` | Wins over env (Go duration) |
| Explicit `0` / `0s` | Default (cannot disable cap by 0) |
| Min | 100ms fail-closed |
| Absolute max | 1m fail-closed |
| Ordering | Must be ≥ resolved InitialBackoff |

GET/HEAD retry max backoff (`ResilienceConfig.MaxBackoff`). Invalid values,
negatives, below-min, and oversize flag/env fail closed at serve start (no
silent clamp). Empty/whitespace/`0`/`0s` at all layers means default **5s**.
After both backoffs resolve, max must be ≥ initial (fail closed). Serve logs
non-secret `max_backoff=…` (combined with `initial_backoff=…` and other
resilience log fields). POST never auto-retries. Residual: live multi-controller
chaos / network matrix still residual.

## Operator caps snapshot (Wave 43–46)

Offline security self-check / support-bundle item `operator_caps_snapshot` reports secret-free integers for live process caps (collect max pages, artifacts hard/body caps) and package constants (HTTP body 4/16 MiB, identity reverify TTL, Jenkins MaxJSON body default/absolute **32/128 MiB**, default max retries, circuit failure threshold, default circuit open duration seconds, MaxConcurrent default **0** unlimited, default initial/max backoff ms). Artifact list body detail keys: `artifacts_list_body_bytes`, `default_artifacts_list_body_bytes`, `absolute_max_artifacts_list_body_bytes` (default **2 MiB**, absolute **8 MiB**). Live getters reflect package defaults until serve `Set*` runs; MaxJSON resolve is serve-time (`--max-json-body-bytes` / `JENKINS_MCP_MAX_JSON_BODY_BYTES`); MaxRetries resolve is serve-time (`--max-retries` / `JENKINS_MCP_MAX_RETRIES`); CircuitFailureThreshold resolve is serve-time (`--circuit-failure-threshold` / `JENKINS_MCP_CIRCUIT_FAILURE_THRESHOLD`); CircuitOpenDuration resolve is serve-time (`--circuit-open-duration` / `JENKINS_MCP_CIRCUIT_OPEN_DURATION`); MaxConcurrent resolve is serve-time (`--max-concurrent` / `JENKINS_MCP_MAX_CONCURRENT`, absolute **256** fail-closed); InitialBackoff resolve is serve-time (`--initial-backoff` / `JENKINS_MCP_INITIAL_BACKOFF`, min **10ms**, absolute **2s** fail-closed); MaxBackoff resolve is serve-time (`--max-backoff` / `JENKINS_MCP_MAX_BACKOFF`, min **100ms**, absolute **1m** fail-closed; must be ≥ InitialBackoff).

Wave 45 also reports package constants only (no live serve HTTP/auth state offline):

| Detail key | Meaning |
|------------|---------|
| `default_http_max_body_bytes` | Streamable HTTP default body cap (**4 MiB**) |
| `absolute_max_http_max_body_bytes` | Streamable HTTP absolute fail-closed ceiling (**16 MiB**) |
| `min_identity_reverify_ttl_seconds` | Min mid-serve whoAmI re-verify TTL (**10**) |
| `max_identity_reverify_ttl_seconds` | Max mid-serve whoAmI re-verify TTL (**1800** = 30m) |
| `default_identity_reverify_ttl_seconds` | Default re-verify TTL when unset (**300** = 5m) |

### Mutation ConfirmCooldown (Wave 52 Track A / MUT-001)

| Control | Value |
|---------|-------|
| Default | 5s (per profile + action + targetHash after successful confirm) |
| Env `JENKINS_MCP_MUTATION_CONFIRM_COOLDOWN` | Fallback when flag unset |
| Flag `--mutation-confirm-cooldown DURATION` | Wins over env (Go duration, e.g. `5s`, `30s`, `1m`) |
| Explicit `0` / `0s` | Means default **5s** (cannot disable cooldown by 0) |
| Min | 1s fail-closed |
| Absolute max | 5m fail-closed |

Process-local confirm cooldown for the mutation preview/confirm gate
(`mutation.Manager`). Invalid values, negatives, below-min, and oversize
flag/env fail closed at serve start (no silent clamp). Empty/whitespace/`0`/`0s`
at all layers means default **5s**. Serve `SetConfirmCooldown` installs the live
process value used when library `Config.ConfirmCooldown` is 0 (Managers created
at tool registration). Serve logs non-secret `mutation_confirm_cooldown=…`
(combined with resilience log fields). After TokenTTL also resolves, serve
fail-closes when cooldown ≥ token TTL (`EnsureConfirmCooldownLessThanTokenTTL`).
Residual honesty: library `Config.ConfirmCooldown` negative still turns cooldown
off for tests; the operator resolve path cannot set 0/disable. Mutations remain
opt-in (`--allow-mutations`); pilot default is still read-only.

### Mutation MaxPreviewsPerMinute (Wave 52 Track C / MUT-001)

| Control | Value |
|---------|-------|
| Default | 30 (sliding 1-minute Preview window) |
| Env `JENKINS_MCP_MUTATION_MAX_PREVIEWS_PER_MINUTE` | Fallback when flag unset |
| Flag `--mutation-max-previews-per-minute N` | Wins over env |
| Explicit `0` | Means default **30** (cannot disable / unlimited via 0) |
| Absolute max | 300 fail-closed |

Process-local Preview rate for `mutation.Manager` after serve resolve +
`SetMaxPreviewsPerMinute`. Invalid values, negatives, and values above absolute
max fail closed at serve start (no silent clamp). Empty/whitespace at the
winning layer means default **30**. Serve logs non-secret
`mutation_max_previews_per_minute=…`. Library `Config` negative remains
unlimited for tests only (operator path never yields unlimited). Residual:
multi-tenant gateway mutations not covered.

### Mutation TokenTTL (Wave 53 Track A / MUT-001)

| Control | Value |
|---------|-------|
| Default | 2m (confirmation token window after Preview) |
| Env `JENKINS_MCP_MUTATION_TOKEN_TTL` | Fallback when flag unset |
| Flag `--mutation-token-ttl DURATION` | Wins over env (Go duration, e.g. `30s`, `2m`, `5m`) |
| Explicit `0` / `0s` | Means default **2m** (cannot disable TTL by 0) |
| Min | 10s fail-closed |
| Absolute max | 15m fail-closed (Wave 48 sanity bound) |

Process-local confirmation token TTL for the mutation preview/confirm gate
(`mutation.Manager`). Invalid values, negatives, below-min, and oversize
flag/env fail closed at serve start (no silent clamp). Empty/whitespace/`0`/`0s`
at all layers means default **2m**. Serve `SetTokenTTL` installs the live
process value used when library `Config.TTL` ≤ 0 (Managers created at tool
registration). Serve logs non-secret `mutation_token_ttl=…` (combined with
resilience/mutation log fields). After both ConfirmCooldown and TokenTTL
resolve, serve fail-closes when cooldown ≥ TTL
(`EnsureConfirmCooldownLessThanTokenTTL`) so cooldown cannot exhaust (or equal)
the confirmation window; package defaults keep DefaultConfirmCooldown (5s) <
DefaultTokenTTL (2m). No unlimited/disabled TTL path (library `Config.TTL` ≤0
still yields a positive TTL). Mutations remain opt-in (`--allow-mutations`);
pilot default is still read-only.

### UI-009 testing

- Default gate: `go test ./internal/admin -run UI009` (included in `make test`).
- Opt-in smoke: `make admin-e2e` → `dist/admin-e2e/status.json` (not in default CI).
- Residual: full-browser Playwright/Cypress not required for v1.
