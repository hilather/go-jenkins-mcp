# Packaging — Tier-1 Linux (Rocky / Ubuntu)

| Field | Value |
|-------|--------|
| **Task** | PKG-001 |
| **Platforms** | Rocky Linux (supported majors), Ubuntu (supported LTS) |
| **Out of scope** | **macOS** and **Windows** packages (ADR 0008) |

## Artifacts

| Artifact | When produced | Notes |
|----------|---------------|--------|
| `jenkins-mcp_<version>_linux_amd64.tar.gz` | Always (`make package`) | Portable layout: `usr/bin/jenkins-mcp` + docs |
| `jenkins-mcp_<version>_amd64.deb` | When `dpkg-deb` is installed | Ubuntu / Debian installers |
| `jenkins-mcp-<version>-1.*.rpm` | When `rpmbuild` is installed | Rocky / RHEL-family |
| `dist/SHA256SUMS` | Always when tarball written | Content hashes for release evidence |
| `dist/BUILD_INFO` | Always | `version`, `commit`, `go`, `built` (no secrets) |
| `dist/modules.json` | `make sbom` | Go module graph (SBOM-ish) |
| `dist/jenkins-mcp.gomod.txt` | `make sbom` (after build) | `go version -m` on the binary |

**Primary CI path:** Ubuntu runner produces tarball (+ DEB when `dpkg-deb` present). Rocky container job produces tarball; RPM when `rpm-build` is available, otherwise a documented skip (portable tarball remains valid).

## Build

```bash
export PATH="$HOME/.local/go/bin:$PATH"
make build          # bin/jenkins-mcp with -ldflags version/commit/buildTime
make package        # build + scripts/package-linux.sh → dist/
make sbom           # modules.json (+ gomod text when binary exists)
make package-amd64  # cross-compile linux/amd64 then package (host may differ)
```

### Local Docker support stack (first-class, opt-in)

**First-class** disposable **admin / support** path under [`deploy/local/`](../deploy/local/)
(not the default Cursor stdio path — ADR 0002). Preferred when operators want the
admin BFF/SPA without a host package install. SoT: [`deploy/local/README.md`](../deploy/local/README.md).

```bash
make local-docker-up      # admin BFF on 127.0.0.1:8787 (creates deploy/local/.env if missing)
make local-docker-doctor  # offline doctor one-shot
make local-docker-smoke   # opt-in config + up + health + down
make local-docker-down    # remove containers + volumes
```

Profiles: `LOCAL_COMPOSE_PROFILES=http,with-jenkins` (comma-separated).  
`deploy/local/.env` is **gitignored** — lab tokens only.  
Gateway (near-Jenkins) scaffold remains under [`deploy/gateway/`](../deploy/gateway/).

### Admin console SPA assets (UI-008)

Optional operator console static files ship when `web/admin/dist` exists at package time:

```bash
make admin-ui && make package
# stages usr/share/jenkins-mcp/admin-ui into tarball / DEB / RPM
# BUILD_INFO: admin_ui=present admin_ui_path=/usr/share/jenkins-mcp/admin-ui
```

| Item | Behavior |
|------|----------|
| Missing `web/admin/dist` | Package **succeeds**; `BUILD_INFO` records `admin_ui=missing` (residual) |
| Present | Copies production Vite tree (never `node_modules`) to `/usr/share/jenkins-mcp/admin-ui` |
| Runtime | `jenkins-mcp admin serve` resolves assets: `--assets-dir` → packaged path → `web/admin/dist` (dev) → `go:embed` placeholder/full |
| Bake into binary | `make admin-ui-embed` then `make build` (optional; binary still builds without Node using committed placeholder) |
| Default-off | Admin HTTP stays off until explicit `admin serve` (see [`admin/README.md`](admin/README.md)) |

Version metadata comes from git when available:

```text
VERSION  = git describe --tags --always --dirty
COMMIT   = git rev-parse --short HEAD
BUILDTIME = UTC ISO-8601
```

Embedded in the binary via ldflags (`main.version`, `main.commit`, `main.buildTime`) and written into package `BUILD_INFO` (plus secret-free `admin_ui*` fields when packaging runs).

**DEB/RPM Version sanitization:** Debian Policy requires the package `Version` field to **start with a digit**. When `VERSION` is a bare git SHA (common on shallow CI checkouts that lack tags), `scripts/package-linux.sh` maps it to a manager-safe form such as `0.0.0+git.<sha>` for `.deb` / `.rpm` and `package_version=` in `BUILD_INFO`. Tarball **filenames** still use the raw `VERSION` string for CI artifact identity.

### Version CLI (UPD-001)

```bash
jenkins-mcp version
jenkins-mcp version --json
# {
#   "version": "…",
#   "commit": "…",
#   "buildTime": "…",
#   "goVersion": "go1.…",
#   "os": "linux",
#   "arch": "amd64"
# }
```

### Update check and signed manifests (UPD-001)

Prefer **enterprise software distribution** (signed RPM/DEB/repos). The binary does **not** auto-install updates. Full signed-metadata verify + optional checksum-only download, LKG, and download preflight are implemented; **install/rollback remains operator-owned**.

| Item | Behavior |
|------|----------|
| Env URL | `JENKINS_MCP_UPDATE_MANIFEST_URL` — HTTPS JSON manifest URL |
| Env keys | `JENKINS_MCP_UPDATE_TRUSTED_KEYS` or `$XDG_CONFIG_HOME/jenkins-mcp/update/trusted_keys/` |
| Env pilot | `JENKINS_MCP_UPDATE_ALLOW_UNSIGNED=1` — unsigned only when **no** keys configured (`unverified_pilot`) |
| Env downgrade | `JENKINS_MCP_UPDATE_ALLOW_DOWNGRADE=1` — opt-in; **default rejects download of older versions** (equal/newer only) |
| Env LKG path | `JENKINS_MCP_UPDATE_LKG_PATH` — override LKG JSON path |
| Default URL | **empty** ⇒ `update-check` skips network and prints residual |
| CLI | `jenkins-mcp update-check [--channel stable] [--json]` — current vs latest vs LKG |
| CLI | `jenkins-mcp update verify-manifest --file PATH [--keys PATH] [--json]` |
| CLI | `jenkins-mcp update download --channel stable [--outdir DIR]` — signed check + preflight; checksum only; records LKG; never executes/installs |
| CLI | `jenkins-mcp update show-lkg [--json]` — offline LKG inspect |
| On match | Reports `newer_available`, `latest_version`, `lkg_*`, `changelog_url`, `signature_state` |
| LKG | `$XDG_DATA_HOME/jenkins-mcp/update/last_known_good.json` — secret-free (version, channel, sha256, basename, key ids); no URLs/private keys |
| Residual | No auto-install; no binary rollback/swap in-process; LKG is metadata only; emergency disable via policy/adapter force-off (not updater) — see [release/update.md](release/update.md) |

**Primary schema (schema_version 2, signed):** see [`release/update.md`](release/update.md).

**Lite schema (schema_version 1, unsigned pilot only):**

```json
{
  "schema_version": 1,
  "channel": "stable",
  "latest": {
    "version": "1.2.3",
    "commit": "abc1234",
    "changelog_url": "https://releases.example.corp/jenkins-mcp/changelog/1.2.3",
    "published_at": "2026-08-01T00:00:00Z"
  },
  "notes": "optional non-secret publisher note"
}
```

Operators who see a newer version should reinstall via package manager and re-run `doctor` / `pilot-check`. Optional `update download` only stages a checksum-verified artifact.

### Release evidence lite (REL-002)

```bash
jenkins-mcp release-evidence --offline
jenkins-mcp release-evidence --offline --profile corp --output dist/release-evidence.json
```

Emits secret-free JSON schema **`jenkins-mcp.release-evidence.v2`**: version/commit, MCP SDK pin (go.mod or build info), security self-check summary, policy deny-only self-test, update LKG present/absent, gateway offline qualify, optional doctor/cache when `--profile` set, and structured `residual[]` (live Entra, Cursor host CI, install operator, production sign-off). Does **not** run `make test` and is **not** production sign-off. Full checklist: [`release/gates.md`](release/gates.md).
## Install (operators)

### Portable tarball (any Tier-1 Linux)

```bash
tar -C /usr/local -xzf jenkins-mcp_<version>_linux_amd64.tar.gz
# binary: /usr/local/usr/bin/jenkins-mcp
# or extract and copy:
tar -xzf jenkins-mcp_<version>_linux_amd64.tar.gz
sudo install -m 0755 usr/bin/jenkins-mcp /usr/local/bin/jenkins-mcp
```

Ordinary operation does **not** require root after the binary is on `PATH`. Cache, config, and credentials are per-user.

### Ubuntu (DEB)

```bash
sudo dpkg -i jenkins-mcp_<version>_amd64.deb
# binary: /usr/bin/jenkins-mcp
```

### Rocky Linux (RPM)

```bash
sudo dnf install ./jenkins-mcp-<version>-1.*.rpm
# or: sudo rpm -Uvh jenkins-mcp-….rpm
```

If CI did not produce an RPM (`skip rpm: rpmbuild not installed`), use the portable tarball on Rocky — same binary and XDG layout.

### Optional dependencies

| Package | Purpose |
|---------|---------|
| Secret Service (`libsecret` / `gnome-keyring` / `keepassxc`) | Personal API token storage (AUTH-003) |
| `fuse3` / `fuse` | **Optional** future L2 mount inspection only; core MCP + native Go L1/L2 reader work **without** FUSE |

### Cache / quota operator notes (ARC-007/008)

**Unified operator guide (all deployment types):** [caching.md](caching.md) — two cache planes, XDG layout, quota/maintenance, gateway file caches, Cursor/Docker/multi-fleet/gateway matrix, residuals.

- Per-profile data root holds L1 `frames/`, SQLite `metadata.sqlite`, L2 `archives/*.tar.zst` (+ `.idx.json`).
- Default total physical quota: **10 GiB** (`store.DefaultTotalQuotaBytes`); low-disk threshold default **1 GiB**. Operator tunables (flag wins over env; empty/`0` = default; fail-closed bounds):
  - `--cache-total-quota-bytes` / `JENKINS_MCP_CACHE_TOTAL_QUOTA_BYTES` — min **64 MiB**, max **1 TiB**
  - `--cache-low-disk-bytes` / `JENKINS_MCP_CACHE_LOW_DISK_BYTES` — min **16 MiB**, max **1 TiB**
  - Shared resolve: serve maintenance, offline `cache quota` / `eviction-plan` / `evict`, admin BFF/MCP (`store.ResolveQuotaConfig`)
- Serve loop (with `--profile`): recovers eviction journal, evicts when over quota, optionally packs sealed unpinned L1 into L2 (keeps L1 until release residual). Interval default **5m**.
- Disable maintenance: `--no-cache-maintenance` or `JENKINS_MCP_NO_CACHE_MAINTENANCE=1`. Interval: `--cache-maintenance-interval` / `JENKINS_MCP_CACHE_MAINTENANCE_INTERVAL`.
- Result hard-max bootstrap ceiling (Wave 37/38): `--hard-max-bytes N` or `JENKINS_MCP_HARD_MAX_BYTES` (flag wins; empty/0 = default 1 MiB). Process absolute fail-closed cap **64 MiB** (`AbsoluteMaxHardMaxBytes`); oversize flag/env rejected at serve start. Overlay `max_result_bytes` may only lower within the bootstrap ceiling; raise serve-bootstrap ceiling (≤ 64 MiB) by re-serving with a higher flag/env. Invalid values fail closed at serve start.
- Soft structured-result target (Wave 47/51 Track C / ADR 0010; clamp log Wave 53 Track C): `--target-bytes N` or `JENKINS_MCP_TARGET_BYTES` (flag wins; empty/0 = default **64 KiB**). Process absolute fail-closed cap **64 MiB** (`AbsoluteMaxTargetBytes` = `AbsoluteMaxHardMaxBytes`); oversize flag/env rejected at serve start. Soft target is clamped to the live hard max at enforce (`Normalize` / `effectiveBudget`); if resolve yields target > bootstrap hard max (e.g. raised `--target-bytes` without raising `--hard-max-bytes`), serve clamps after `Normalize` and logs non-secret `target_bytes_clamped=true|false` plus `target_bytes_resolved=N` on the result-budget line (`target_bytes=` is post-clamp). Pair raises of hard max and soft target when both should exceed defaults.
- Structured serve log level (OBS-001 / pilot offline analysis): `--log-level LEVEL` or `JENKINS_MCP_LOG_LEVEL` (flag wins; empty = **info**; values `debug|info|warn|error`; invalid fail closed). At `debug`, tool dispatch emits secret-free JSON lines on stderr (`tool_dispatch_start` / `tool_dispatch_ok` / `tool_dispatch_deny` / `tool_dispatch_error`). Capture with `2> pilot-serve.stderr`. Residual: bootstrap still uses redacted `log.Printf` (not JSON).
- Jenkins API JSON/decoded body cap (Wave 46 Track A / NET-003): `--max-json-body-bytes N` or `JENKINS_MCP_MAX_JSON_BODY_BYTES` (flag wins; empty/0 = default **32 MiB**). Process absolute fail-closed cap **128 MiB** (`AbsoluteMaxJSONBodyBytes`); oversize flag/env rejected at serve start (not clamped silently). Applies to non-log Jenkins API responses only; progressive log paths keep LOG-001 caps. Residual: live multi-controller chaos / network matrix still residual.
- Jenkins GET/HEAD max extra retries (Wave 47 Track A / NET-003): `--max-retries N` or `JENKINS_MCP_MAX_RETRIES` (flag wins; empty = default **2** extra attempts after the first). Explicit **0** disables auto-retry for GET/HEAD (unlike body-bytes where 0 means default). Process absolute fail-closed cap **10** (`AbsoluteMaxRetries`); oversize/invalid/negative flag/env rejected at serve start (not clamped silently). POST/PUT/PATCH/DELETE never auto-retry. Residual: live multi-controller chaos / network matrix still residual.
- Jenkins circuit failure threshold (Wave 48 Track A / NET-003): `--circuit-failure-threshold N` or `JENKINS_MCP_CIRCUIT_FAILURE_THRESHOLD` (flag wins; empty/0 = default **5** consecutive 5xx/transport failures before open). Explicit **0** means default (cannot disable the circuit by 0 — fail-closed safety). Process absolute fail-closed cap **50** (`AbsoluteMaxCircuitFailureThreshold`); oversize/invalid/negative flag/env rejected at serve start (not clamped silently). Residual: live multi-controller chaos / network matrix still residual.
- Jenkins circuit open duration (Wave 49 Track A / NET-003): `--circuit-open-duration DURATION` or `JENKINS_MCP_CIRCUIT_OPEN_DURATION` (flag wins; empty/0/`0s` = default **15s** open before half-open probe). Go duration strings (`15s`, `1m`, …). Explicit **0**/**0s** means default (cannot disable the open period to 0 — fail-closed safety). Min **1s** (`MinCircuitOpenDuration`); absolute max **5m** (`AbsoluteMaxCircuitOpenDuration`); below-min/oversize/invalid/negative flag/env rejected at serve start (not clamped silently). Serve logs non-secret `circuit_open_duration=…`. Residual: live multi-controller chaos / network matrix still residual.
- Jenkins max concurrent (Wave 50 Track A / NET-003): `--max-concurrent N` or `JENKINS_MCP_MAX_CONCURRENT` (flag wins; empty = default **0** = unlimited). Explicit **0** means unlimited concurrency (not remapped to a positive limit). Contrast `--max-retries 0` which disables GET/HEAD auto-retry. Process absolute fail-closed cap **256** (`AbsoluteMaxConcurrent`); oversize/invalid/negative flag/env rejected at serve start (not clamped silently). Serve logs non-secret `max_concurrent=…` (0 = unlimited). POST never auto-retries. Residual: live multi-controller chaos / network matrix still residual.
- Jenkins GET/HEAD initial backoff (Wave 51 Track A / NET-003): `--initial-backoff DURATION` or `JENKINS_MCP_INITIAL_BACKOFF` (flag wins; empty/0/`0s` = default **100ms** base delay before first retry). Go duration strings (`100ms`, `250ms`, `1s`, …). Explicit **0**/**0s** means default (cannot disable the base delay to 0 — fail-closed safety). Min **10ms** (`MinInitialBackoff`); absolute max **2s** (`AbsoluteMaxInitialBackoff`); below-min/oversize/invalid/negative flag/env rejected at serve start (not clamped silently). After both backoffs resolve, max must be ≥ initial (fail closed). Serve logs non-secret `initial_backoff=…`. POST never auto-retries. Residual: live multi-controller chaos / network matrix still residual.
- Jenkins GET/HEAD max backoff (Wave 51 Track A / NET-003): `--max-backoff DURATION` or `JENKINS_MCP_MAX_BACKOFF` (flag wins; empty/0/`0s` = default **5s** cap on exponential backoff and Retry-After). Go duration strings (`5s`, `30s`, `1m`, …). Explicit **0**/**0s** means default (cannot disable the cap to 0 — fail-closed safety). Min **100ms** (`MinMaxBackoff`); absolute max **1m** (`AbsoluteMaxMaxBackoff`); below-min/oversize/invalid/negative flag/env rejected at serve start (not clamped silently). After both backoffs resolve, max must be ≥ initial (fail closed). Serve logs non-secret `max_backoff=…`. POST never auto-retries. Residual: live multi-controller chaos / network matrix still residual.
- Mutation confirm cooldown (Wave 52 Track A / MUT-001): `--mutation-confirm-cooldown DURATION` or `JENKINS_MCP_MUTATION_CONFIRM_COOLDOWN` (flag wins; empty/0/`0s` = default **5s** per (profile, action, targetHash) after successful confirm). Go duration strings (`5s`, `30s`, `1m`, …). Explicit **0**/**0s** means default (cannot disable the cooldown to 0 — fail-closed safety). Min **1s** (`MinConfirmCooldown`); absolute max **5m** (`AbsoluteMaxConfirmCooldown`); below-min/oversize/invalid/negative flag/env rejected at serve start (not clamped silently). Serve `SetConfirmCooldown` installs the process live value used when `mutation.Config.ConfirmCooldown` is 0. Serve logs non-secret `mutation_confirm_cooldown=…`. After TokenTTL also resolves, serve fail-closes when cooldown ≥ token TTL (`EnsureConfirmCooldownLessThanTokenTTL`). Residual: library `Config.ConfirmCooldown` negative still disables cooldown for tests; operator resolve path cannot set 0. Mutations remain opt-in (`--allow-mutations`); global RO default unchanged. Confirm tokens bind profile+principal+ExternalSubject+tenant (`mutation.Binding`); multi-user serve sets `MutationBindingFromContext` via `mutationBindingFromGatewayCtx` (prefer Valid PolicySubject PrincipalID from HTTP/lab JenkinsPrincipal; else Caller + process principal) so tokens cannot replay across subjects on a shared Manager.
- Mutation Preview rate (Wave 52 Track C / MUT-001): `--mutation-max-previews-per-minute N` or `JENKINS_MCP_MUTATION_MAX_PREVIEWS_PER_MINUTE` (flag wins; empty/0 = default **30** / sliding minute). Explicit **0** means default (cannot use 0 for unlimited on the operator path). Process absolute fail-closed cap **300** (`AbsoluteMaxPreviewsPerMinute`); oversize/invalid/negative flag/env rejected at serve start (not clamped silently). Serve logs non-secret `mutation_max_previews_per_minute=…`. Library `Config.MaxPreviewsPerMinute` negative remains unlimited for tests only. Residual: process-local Manager still not multi-replica. Per-request Jenkins principal on Binding is **Done\*** when multi-user HTTP claim/lab carries JenkinsPrincipal (`PolicySubjectFromContext`) **or** after Obtain via process-local `PrincipalCache` (Mode A vault username). Policy RBAC JenkinsUserID is **Done\*** via `policySubjectFromGatewayCtx` preferring PrincipalCache after Obtain (else HTTP claim).
- Mutation confirmation token TTL (Wave 53 Track A / MUT-001): `--mutation-token-ttl DURATION` or `JENKINS_MCP_MUTATION_TOKEN_TTL` (flag wins; empty/0/`0s` = default **2m** confirmation window). Go duration strings (`30s`, `2m`, `5m`, …). Explicit **0**/**0s** means default (cannot disable the TTL to 0 — fail-closed safety). Min **10s** (`MinTokenTTL`); absolute max **15m** (`AbsoluteMaxTokenTTL`, Wave 48 sanity bound); below-min/oversize/invalid/negative flag/env rejected at serve start (not clamped silently). Serve `SetTokenTTL` installs the process live value used when `mutation.Config.TTL` ≤ 0. Serve logs non-secret `mutation_token_ttl=…`. After both ConfirmCooldown and TokenTTL resolve, serve fail-closes when cooldown ≥ TTL (`EnsureConfirmCooldownLessThanTokenTTL`) so cooldown cannot exhaust (or equal) the confirmation window; package defaults remain DefaultConfirmCooldown 5s < DefaultTokenTTL 2m. Mutations remain opt-in (`--allow-mutations`); global RO default unchanged.
- list_jobs policy-collect safety page cap (Wave 41): `--list-jobs-collect-max-pages N` or `JENKINS_MCP_LIST_JOBS_COLLECT_MAX_PAGES` (flag wins; empty/0 = default **50**). Process absolute fail-closed cap **200** (`AbsoluteMaxListJobsCollectMaxPages`); oversize flag/env rejected at serve start. Applies only when live deny patterns force full-list collect+filter; cap hit → `truncated` + non-secret incomplete message (not silent under-count).
- nodes / views policy-collect safety page caps (Wave 42): `--nodes-collect-max-pages N` / `JENKINS_MCP_NODES_COLLECT_MAX_PAGES` and `--views-collect-max-pages N` / `JENKINS_MCP_VIEWS_COLLECT_MAX_PAGES` (flag wins; empty/0 = default **50**). Absolute fail-closed cap **200** each (`AbsoluteMaxNodesCollectMaxPages` / `AbsoluteMaxViewsCollectMaxPages`); oversize rejected at serve start. Applies only when live `deny_node_names` / `deny_view_names` force full-list collect+filter; cap hit → `truncated` + non-secret incomplete message.
- Pins and retention protect investigations from **eviction** (not manual delete-all of the profile data tree). Offline pin CLI (ARC-007):
  - `cache pin generation|pack --profile <id> --generation|--pack <id>`
  - `cache unpin generation|pack …`
  - `cache pins --profile <id> [--json]` (secret-free)
  - Fail closed when profile or data directory is missing.
- Offline eviction (ARC-007): `cache eviction-plan --profile <id> [--json] [--target-bytes N] [--cache-total-quota-bytes N] [--cache-low-disk-bytes N]` calls `PlanEviction` only (never `Evict`). `cache evict` / `cache eviction-apply` default to the same dry-run; destructive apply requires `--confirm` or `--yes` (recover journal → re-plan → `Evict`). `cache quota --profile <id> [--json] [--cache-total-quota-bytes N]` prints usage stats (quota bytes from resolve). Serve-time maintenance remains the primary reclaim path; CLI apply is an operator escape hatch.
- `cache verify` / `cache repair` are offline integrity maintenance (no secrets in reports).

## Paths (XDG)

| Kind | Default |
|------|---------|
| Config / profiles | `$XDG_CONFIG_HOME/jenkins-mcp` (fallback `~/.config/jenkins-mcp`) |
| Data (L1 frames, meta) | `$XDG_DATA_HOME/jenkins-mcp` (fallback `~/.local/share/jenkins-mcp`) |
| Session epoch (non-secret) | `$XDG_DATA_HOME/jenkins-mcp/profiles/<id>/session.epoch` (logout/login invalidation) |
| Cache | `$XDG_CACHE_HOME/jenkins-mcp` (fallback `~/.cache/jenkins-mcp`) |
| Policy overlay | `$XDG_CONFIG_HOME/jenkins-mcp/policy/overlay.json` |
| Policy signed bundle | `$XDG_CONFIG_HOME/jenkins-mcp/policy/overlay.bundle.json` |
| Policy trusted keys | `$XDG_CONFIG_HOME/jenkins-mcp/policy/trusted_keys/` |
| Policy last-good | `$XDG_CACHE_HOME/jenkins-mcp/policy/last_good.json` |
| Update trusted keys | `$XDG_CONFIG_HOME/jenkins-mcp/update/trusted_keys/` |
| Update last-known-good | `$XDG_DATA_HOME/jenkins-mcp/update/last_known_good.json` |

Secrets **never** live under these trees. Tokens are stored in the OS secret store (Linux Secret Service).

## Cursor — secret-free stdio config

Credentials must not appear in Cursor `command`/`args`, shell history, or committed config.

```json
{
  "mcpServers": {
    "jenkins": {
      "command": "/usr/bin/jenkins-mcp",
      "args": ["serve", "--profile", "corp"]
    }
  }
}
```

Alternative with tarball install path:

```json
{
  "mcpServers": {
    "jenkins": {
      "command": "/usr/local/bin/jenkins-mcp",
      "args": ["--profile", "corp"]
    }
  }
}
```

Setup once (interactive / out of band):

```bash
jenkins-mcp login --profile corp
# stores token in Secret Service; profile JSON holds only non-secret fields
jenkins-mcp doctor --profile corp --offline
```

**Do not** use `-auth user:token` or `JENKINS_MCP_AUTH` — removed (fail closed). Use profile + login only.

## HTTP mode (optional — not pilot default)

Prefer **stdio** for Cursor (ADR 0002). Streamable HTTP is behind explicit `serve --http ADDR` for local debugging and future gateway paths.

| Control | Behavior |
|---------|----------|
| Default bind | **Loopback only** (`127.0.0.1`, `localhost`, `::1`). `0.0.0.0` / LAN binds are **rejected**. |
| Escape hatch | `--http-allow-non-local` — residual for tests / advanced operators; **requires** one or more `--http-allowed-origin`, one or more `--http-allowed-host`, **and** a shared secret (fail closed). **Not** production packaging guidance |
| Body cap | Default **4 MiB** request body (`internal/mcpserver.DefaultMaxBodyBytes`). Raise with `--http-max-body-bytes N` or `JENKINS_MCP_HTTP_MAX_BODY_BYTES` (flag wins; empty/0 = default). Absolute fail-closed cap **16 MiB** (`AbsoluteMaxBodyBytes`); oversize flag/env rejected at serve start. Residual: non-loopback hardening beyond `AllowedHosts` remains separate. |
| Host / Origin | Loopback bind: `Host` must be loopback; when `Origin` is present on non-GET it must be loopback **or** exact-match `--http-allowed-origin`. Non-local bind: `Host` hostname must match `--http-allowed-host` (case-insensitive, optional `:port` stripped); Origins must match the allow-list (arbitrary browser Origins rejected) |
| Allowed Host | `--http-allowed-host=HOSTNAME` (repeatable; hostname or IP, optional `:port`). **Required** with `--http-allow-non-local` (DNS rebinding defense). Unused on loopback-only binds |
| Shared secret (KD-008 lite) | `--http-token-env=VAR` (env var **name** only) or `--http-token-file=PATH` (mode **0600**, read once). Clients send `Authorization: Bearer <token>` **or** `X-Jenkins-MCP-Token: <token>` (constant-time exact match). **Never** put the token value on argv. On loopback, when unset the auth gate is off (compat residual). |
| Require token (fail closed) | `--http-require-token` or `JENKINS_MCP_HTTP_REQUIRE_TOKEN=1` (also `true`/`yes`/`on`): serve start **fails** if no token was loaded. **Always required** with `--http-allow-non-local`. Logs only `http_token_required` / `http_token_configured` bools — never the secret. |
| Residual risk | **Not per-user auth** and **not** multi-tenant OAuth. Shared secret is a single gate; same-machine holders of the token can still call the port. Prefer **stdio** for pilot (ADR 0002). Do not document HTTP as multi-tenant production-ready (KD-008 residual). |

Example (local debug only):

```bash
jenkins-mcp serve --profile corp --http 127.0.0.1:8765 --read-only
# Optional shared secret (token value lives in env/file — never on argv):
# export MCP_HTTP_TOKEN='…'   # set out-of-band
# jenkins-mcp serve --profile corp --http 127.0.0.1:8765 --http-token-env=MCP_HTTP_TOKEN --read-only
# Fail closed if secret missing (recommended when any local process must not hit the port):
# jenkins-mcp serve --profile corp --http 127.0.0.1:8765 --http-require-token --http-token-env=MCP_HTTP_TOKEN --read-only
# # or: JENKINS_MCP_HTTP_REQUIRE_TOKEN=1
# jenkins-mcp serve --profile corp --http 127.0.0.1:8765 --http-token-file=$XDG_CONFIG_HOME/jenkins-mcp/http.token --read-only
```

Package installs and pilot Cursor configs should continue to use **stdio only**.

## Uninstall

| Install method | Binary | Per-user data / credentials |
|----------------|--------|------------------------------|
| DEB | `sudo dpkg -r jenkins-mcp` | **Not** removed automatically — delete `~/.config/jenkins-mcp`, `~/.local/share/jenkins-mcp`, `~/.cache/jenkins-mcp` and Secret Service item if desired |
| RPM | `sudo dnf remove jenkins-mcp` | Same user-controlled cleanup |
| Tarball | Remove the installed binary | Same user-controlled cleanup |

Uninstall of cache and credentials is **explicit and user-controlled** on each Tier-1 OS.

## SELinux / AppArmor (smoke notes)

- **Rocky (SELinux):** default targeted policy; local stdio binary under `/usr/bin` or `/usr/local/bin` typically runs unconfined or as `bin_t`. No custom policy module is shipped in PKG-001. If confinement blocks Secret Service D-Bus, allow the user session or run doctor offline diagnostics.
- **Ubuntu (AppArmor):** no dedicated profile is shipped; default unconfined user binary is expected. If a site profile is applied, allow home XDG paths + D-Bus session for Secret Service.

These are smoke-level notes for pilot hosts — not a full confinement product.

## Code signing (placeholder for signed releases)

This repository’s `make package` path **does not** require real signing keys and **does not** embed private keys.

| Surface | Pilot / CI | Signed release (future pipeline) |
|---------|------------|-----------------------------------|
| Tarball | `SHA256SUMS` only | Cosign / GPG detach-sign over tarball + sums |
| DEB | unsigned `.deb` | `dpkg-sig` or launchpad/PPA signing key |
| RPM | unsigned `.rpm` | `rpmsign --addsign` with org RPM key |

Operators verifying pilot builds should check `SHA256SUMS` against the downloaded artifacts. Organizations publishing signed packages own key generation, storage (HSM/CI secret store), and rotation — document the org-specific key id next to release notes when signing is enabled.

## macOS

**Out of scope.** No darwin packages, notarization, or Keychain product support (ADR 0008).

## Windows

**Out of scope.** No `.exe`, MSI, MSIX, or WinFsp packaging.

## SBOM

```bash
make sbom
# dist/modules.json  — go list -m -json all
# dist/jenkins-mcp.gomod.txt — go version -m bin/jenkins-mcp (when binary present)
```

Use these as lightweight SBOM inputs for scanners; SPDX export can be layered later without changing `make package`.

## Verify locally

```bash
export PATH="$HOME/.local/go/bin:$PATH"
make test
make package
ls -la dist/
cat dist/BUILD_INFO
# optional: make sbom
```

## Pilot readiness

See [docs/pilot/README.md](pilot/README.md) and `jenkins-mcp pilot-check` for limited RO pilot steps on Rocky/Ubuntu.

```bash
make pilot-evidence PROFILE= SKIP_GO_TEST=1
# → dist/pilot-evidence/<timestamp>/MANIFEST.json (secret-free offline pack)
```

## Optional managed gateway package (GWY-004 / HOST-005 scaffold)

Near-source `jenkins-mcp serve --gateway` packaging is **scaffold + operator
envelope** — same MCP binary, no bundled live AgentCore sidecar, no signed
production image from this repo.

| Artifact | Path | Notes |
|----------|------|--------|
| Deployment guide | [gateway/deployment.md](gateway/deployment.md) | HOST-002 reverse-proxy matrix, HOST-005 readiness; multi-pod HA cancelled (multi-fleet) |
| Compose example | [deploy/gateway/docker-compose.yml](../deploy/gateway/docker-compose.yml) | Non-root, read-only root, CPU/mem limits, secret-free env |
| Env example | [deploy/gateway/.env.example](../deploy/gateway/.env.example) | **Non-secret vars only** |
| Dockerfile | [deploy/gateway/Dockerfile](../deploy/gateway/Dockerfile) | Distroless nonroot; build from repo root |
| Kustomize stub | [deploy/gateway/kustomize/](../deploy/gateway/kustomize/) | replicas:1; probes `/healthz` `/readyz`; limits |

```bash
# Validate compose (when docker available); do not require secrets
docker compose -f deploy/gateway/docker-compose.yml config
```

**Residuals (explicit):** live AgentCore sidecar/binary pin; image signing
(cosign/registry provenance); Streamable HTTP mTLS hardening; multi-replica HA
(HOST-008 multi-pod **cancelled** — multi-fleet scale). See [gateway/deployment.md](gateway/deployment.md).

## User / admin / security docs

| Doc | Audience |
|-----|----------|
| [user/README.md](user/README.md) | Cursor stdio setup, login, RO default, common tools |
| [admin/README.md](admin/README.md) | Packages, SELinux/AppArmor, cache, maintenance, pilot-check |
| [caching.md](caching.md) | Log store + gateway caches; config by deployment type |
| [security/operator-guide.md](security/operator-guide.md) | Tokens, keyring, support bundles, threat-model pointer |
| [tool-contracts.md](tool-contracts.md) | MCP tool inventory and budgets |
| [agent-usage.md](agent-usage.md) | Agent triage workflow |
| [release/gates.md](release/gates.md) | Production release gates |
| [gateway/deployment.md](gateway/deployment.md) | Optional managed gateway deploy scaffold (GWY-004) |

## Optional cache encryption (ARC-009)

See [docs/security/cache-encryption.md](security/cache-encryption.md) and the encryption section of [caching.md](caching.md). Keys stay in Secret Service; never in profile JSON.

### MCP protocol pin and offline matrix (FND-006)

| Offline protocol matrix (unit CI) | `go test ./internal/tools/ ./internal/mcpserver/ -count=1 -run 'ProtocolMatrix\|MCPProtocolMatrix'` — Initialize, ListTools RO, CallTool success/invalid/unknown/cancel, loopback HTTP Initialize/ListTools |
| Offline stdio **binary** host-lifecycle smoke (opt-in / optional CI) | `make stdio-smoke` → `scripts/mcp-stdio-smoke.sh` + `scripts/mcpstdiosmoke` — real `jenkins-mcp` over stdio (`mcp.CommandTransport`), httptest Jenkins, **host-lifecycle matrix**: Initialize, ListTools RO, CallTool success (`jenkins_get_jobs`), invalid args, unknown tool, cancel mid-flight (hanging fixture + client cancel), ListTools again, clean shutdown + secret canary scrub. Uses profile + `JENKINS_MCP_KEYRING_FILE` headless file keyring (no Secret Service required). Wave 25 baseline + Wave 33 expansion. Optional CI job `stdio-smoke` keeps `continue-on-error` (not merge-gate). |

| Residual id | Status | Notes |
|-------------|--------|--------|
| Offline host-lifecycle matrix (unit + binary smoke) | **Done*** | Unit protocol matrix + `make stdio-smoke` host-lifecycle expansion |
| Cursor product binary / real Cursor host stdio CI | **Residual (not closed)** | Still no automated job that spawns Cursor (or equivalent product host) against this binary |

**Residual (not closed):** **Cursor product binary / host stdio CI** — real Cursor (or equivalent MCP host) process spawning this binary over stdio via product `mcpServers` config. Offline host-lifecycle matrix is **Done***; unit tests and binary smoke deliberately do **not** require a Cursor binary or Docker. Pilot operators still validate product stdio manually via [user guide](user/README.md).

## Package smoke (Wave 22)

Build

```bash
export PATH="$HOME/.local/go/bin:$PATH"
make build          # bin/jenkins-mcp with -ldflags version/commit/buildTime
make package        # build + scripts/package-linux.sh → dist/
make package-smoke  # PKG-001 offline smoke: tarball + SHA256SUMS + BUILD_INFO canaries (SKIP_DEB/RPM)
make sbom           # modules.json (+ gomod text when binary exists)
make package-amd64  # cross-compile linux/amd64 then package (host may differ)
```

Version metadata comes from git when available:

```text
VERSION  = git describe --tags --always --dirty
COMMIT   = git rev-parse --short HEAD
BUILDTIME = UTC ISO-8601
```

Embedded in the binary via ldflags (`main.version`, `main.commit`, `main.buildTime`) and written into package `BUILD_INFO`.

**DEB/RPM Version sanitization:** when `VERSION` is a bare git SHA (no tags in checkout), package managers get `0.0.0+git.<sha>` so Debian `Version` starts with a digit. Tarball filenames keep the raw `VERSION`. See `scripts/package-linux.sh`.

### Version CLI (UPD-001)

```bash
jenkins-mcp version
jenkins-mcp version --json
# {
#   "version": "…",
#   "commit": "…",
#   "buildTime": "…",
#   "goVersion": "go1.…",
#   "os": "linux",
#   "arch": "amd64"
# }
```

### Update check and signed manifests (UPD-001)

Prefer **enterprise software distribution** (signed RPM/DEB/repos). The binary do

### Update check and signed manifests (UPD-001)

Prefer **enterprise software distribution** (signed RPM/DEB/repos). The binary does **not** auto-install updates. Full signed-metadata verify + optional checksum-only download, LKG, and download preflight are implemented; **install/rollback remains operator-owned**.

| Item | Behavior |
|------|----------|
| Env URL | `JENKINS_MCP_UPDATE_MANIFEST_URL` — HTTPS JSON manifest URL |
| Env keys | `JENKINS_MCP_UPDATE_TRUSTED_KEYS` or `$XDG_CONFIG_HOME/jenkins-mcp/update/trusted_keys/` |
| Env pilot | `JENKINS_MCP_UPDATE_ALLOW_UNSIGNED=1` — unsigned only when **no** keys configured (`unverified_pilot`) |
| Env downgrade | `JENKINS_MCP_UPDATE_ALLOW_DOWNGRADE=1` — opt-in; **default rejects download of older versions** (equal/newer only) |
| Env LKG path | `JENKINS_MCP_UPDATE_LKG_PATH` — override LKG JSON path |
| Default URL | **empty** ⇒ `update-check` skips network and prints residual |
| CLI | `jenkins-mcp update-check [--channel stable] [--json]` — current vs latest vs LKG |
| CLI | `jenkins-mcp update verify-manifest --file PATH [--keys PATH] [--json]` |
| CLI | `jenkins-mcp update download --channel stable [--outdir DIR]` — signed check + preflight; checksum only; records LKG; never executes/installs |
| CLI | `jenkins-mcp update show-lkg [--json]` — offline LKG inspect |
| CLI | `jenkins-mcp update verify-lkg [--json] [--file PATH]` — re-hash staged artifact vs LKG sha256 (fail closed) |
| On match | Reports `newer_available`, `latest_version`, `lkg_*`, `changelog_url`, `signature_state` |
| LKG | `$XDG_DATA_HOME/jenkins-mcp/update/last_known_good.json` — secret-free (version, channel, sha256, basename, key ids); no URLs/private keys |
| LKG re-verify | Default artifact path: update data dir + `path_basename`; `--file` for custom download outdir; doctor check `update_lkg` (skip if absent) |
| Residual | No auto-install; no binary rollback/swap in-process; LKG is metadata only; emergency disable via policy/adapter force-off (not updater) — see [release/update.md](release/update.md) |

**Primary schema (schema_version 2, signed):** see [`release/update.md`](release/update.md).

**Lite schema (schema_version 1, unsigned pilot only):**

```json
{
  "schema_version": 1,
  "channel": "stable",
  "latest": {
    "version": "1.2.3",
    "commit": "abc1234",
    "changelog_url": "https://releases.example.corp/jenkins-mcp/changelog/1.2.3",
    "published_at": "2026-08-01T00:00:00Z"
  },
  "notes": "optional non-secret publisher note"
}
```

Operators who see a newer version should reinstall via package manager and re-run `doctor` / `pilot-check`. Optional `update download` only stages a checksum-verified artifact.

### Release evidence lite (REL-002)

```bash
jenkins-mcp release-evidence --offline
jenkins-mcp release-evidence --offline --profile corp --output dist/release-evidence.json
```

Emits secret-free JSON schema **`jenkins-mcp.release-evidence.v2`**: version/commit, MCP SDK pin (go.mod or build info), security self-check summary, policy deny-only self-test, update LKG present/absent, gateway offline qualify, optional doctor/cache when `--profile` set, and structured `residual[]` (live Entra, Cursor host CI, install operator, production sign-off). Does **not** run `make test` and is **not** production sign-off. Full checklist: [`release/gates.md`](release/gates.md).

| Deny anonymous (alias) | `JENKINS_MCP_HTTP_DENY_ANONYMOUS=1` (also `true`/`yes`/`on`): **same** as require-token — sets `RequireToken=true` and fails closed without a configured secret. Opt-in residual mitigation for operators who prefer the deny-anonymous name; default remains open for local pilot. |

# # or: JENKINS_MCP_HTTP_DENY_ANONYMOUS=1   # alias of require-token (Wave 41)


- jenkins_list_artifacts hard cap (Wave 42): `--artifacts-hard-cap N` or `JENKINS_MCP_ARTIFACTS_HARD_CAP` (flag wins; empty/0 = default **500**). Absolute fail-closed cap **2000**. Used for deny_artifact_paths hard-cap fetch and as upper bound for caller max_artifacts.
- jenkins_list_artifacts JSON body bound (Wave 43): `--artifacts-list-body-bytes N` or `JENKINS_MCP_ARTIFACTS_LIST_BODY_BYTES` (flag wins; empty/0 = default **2097152** / 2 MiB). Absolute fail-closed cap **8388608** / 8 MiB. Raise when large inventories near AbsoluteMax hard cap hit the body limit before the count hard cap (fail closed on truncated/invalid JSON).

- Cache maintenance interval (Wave 49): `--cache-maintenance-interval` / `JENKINS_MCP_CACHE_MAINTENANCE_INTERVAL` (default **5m**; absolute fail-closed **30s–1h** via `app.ResolveMaintenanceInterval`).
- Cache total quota / low-disk (ARC-007 tunables): `--cache-total-quota-bytes` / `JENKINS_MCP_CACHE_TOTAL_QUOTA_BYTES` (default **10 GiB**; min **64 MiB**; max **1 TiB**); `--cache-low-disk-bytes` / `JENKINS_MCP_CACHE_LOW_DISK_BYTES` (default **1 GiB**; min **16 MiB**; max **1 TiB**); empty/`0` = default; flag wins; `store.ResolveQuotaConfig` shared by serve + offline cache CLI + admin.
