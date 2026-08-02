# Local Docker — support / admin UI stack

**Source of truth** for the disposable **admin + support** Docker path.  
**Audience:** operators, support engineers, and agents who need day-2 surfaces
without a full host package install.  
**Platforms:** Rocky Linux / Ubuntu + Docker Compose v2. **Windows out of scope.**

| | |
|--|--|
| **Admin BFF / SPA** | `http://127.0.0.1:8787` (default service `mcp`) |
| **Optional MCP HTTP** | Profile `http` → `127.0.0.1:8081` |
| **Optional lab Jenkins** | Profile `with-jenkins` → `127.0.0.1:18080` |
| **Makefile** | `make local-docker-up` / `down` / `doctor` / `smoke` / … |
| **Helper** | `scripts/local-docker.sh` |
| **Env** | `deploy/local/.env` (from `.env.example`; **never commit**) |

---

## When to use / when not

| Use this stack | Prefer something else |
|----------------|------------------------|
| Support: doctor, version, policy show-effective in a clean env | Production **gateway** near Jenkins — `deploy/gateway/` |
| Admin console without host RPM/DEB/npm | Live Entra multi-user GO — roadmap Tier A JWT path |
| Lab: disposable Jenkins + admin together | Live API-token lab only — `testdata/jenkins-compose/` + `make live-jenkins-*` |
| **Warm log/cache for agents** via shared XDG (see below) | Default `make test` / `make ci` (must stay offline, no Docker) |
| Demo admin UI on loopback | Multi-tenant / team-hosted OAuth production |

**Default Cursor path remains host `serve --stdio` (ADR 0002).** Docker is not “stdio inside the container” unless you opt into a shared-XDG or HTTP model below.

---

## Prerequisites

- Docker Engine + Compose v2 (`docker compose version`)
- Repo checkout (image build context is the monorepo root)
- Optional on host: Go/Node only if you also run host binary / SPA dev

---

## 60-second quick start

From **repository root**:

```bash
export PATH="$HOME/.local/go/bin:$PATH"

# 1) Env (gitignored — never commit deploy/local/.env)
cp deploy/local/.env.example deploy/local/.env
echo "JENKINS_MCP_ADMIN_TOKEN=$(openssl rand -hex 24)" >> deploy/local/.env

# 2) Build + start admin BFF (loopback :8787)
make local-docker-up

# 3) Open admin UI / API
#    URL:  http://127.0.0.1:8787
#    Token: value of JENKINS_MCP_ADMIN_TOKEN in deploy/local/.env
#    SPA: paste token in the console when prompted (pilot localStorage residual)

# 4) Health (Bearer required when token is set)
set -a && source deploy/local/.env && set +a
curl -fsS -H "Authorization: Bearer $JENKINS_MCP_ADMIN_TOKEN" \
  http://127.0.0.1:8787/admin/v1/health

# 5) Support one-shots
make local-docker-doctor
make local-docker-version

# 6) Tear down (destroys named volumes)
make local-docker-down
```

`make local-docker-up` creates `.env` from the example if missing; still set a
lab admin token before treating the stack as “locked down.”

---

## Agent + cache models (configure deliberately)

**Operator SoT for all cache planes and deploy types:** [docs/caching.md](../../docs/caching.md) (plane A log store, plane B gateway caches, quota, shared-XDG caveats).

Three supported lab layouts. Pick one; do not assume admin Docker alone warms
Cursor’s default host cache.

```text
Model 1 — Host stdio only (default pilot)
  Cursor ──stdio──► host jenkins-mcp ──► Jenkins
                      └── host ~/.config|share|cache/jenkins-mcp

Model 2 — Shared XDG (recommended when Docker cache is valuable)
  Cursor ──stdio──► host jenkins-mcp ──► Jenkins
                      └── .local-mcp/xdg/{config,data,cache}/jenkins-mcp
  Docker admin/http ─────────────────────┘  (same dirs bind-mounted)

Model 3 — Streamable HTTP MCP in Docker (opt-in clients)
  MCP client ──HTTP──► mcp-http :8081 ──► Jenkins
                          └── Docker volumes or shared XDG bind mounts
  Cursor: only if the host supports MCP over HTTP URL (many setups are stdio-only)
```

### Model 1 — Host stdio only (default)

No Docker required for the agent. Cache is per-OS-user XDG on the host.
See [user guide § Cursor stdio](../../docs/user/README.md#4-cursor-stdio-configuration-read-only-default).

Docker admin (`make local-docker-up`) is a **separate** process with **named
volumes** (`local-config` / `local-data` / `local-cache`). It does **not** share
cache with host Cursor unless you enable Model 2.

### Model 2 — Shared Docker/host XDG cache (recommended for warm agent cache)

**Why:** L1 log mirrors, store generations, and doctor/cache status stay warm
whether you hit Jenkins from Cursor tools or from admin/doctor in Docker.

**One-time setup (repo root):**

```bash
# 1) Host package dirs (gitignored .local-mcp/)
mkdir -p .local-mcp/xdg/{config,data,cache}/jenkins-mcp

# 2) Compose override (gitignored if named docker-compose.override.yml)
cp deploy/local/docker-compose.shared-xdg.example.yml \
   deploy/local/docker-compose.override.yml

# 3) Lab env + admin token
cp -n deploy/local/.env.example deploy/local/.env
# set JENKINS_MCP_ADMIN_TOKEN in .env

# 4) Start admin (and optionally lab Jenkins)
# LOCAL_COMPOSE_PROFILES=with-jenkins make local-docker-up
make local-docker-up
make local-docker-init-profile   # if profile missing
# With Jenkins in compose: init with JENKINS_URL=http://jenkins:8080
```

**Host Cursor MCP entry** (same profile id; RO; **shared XDG**):

```json
{
  "mcpServers": {
    "jenkins": {
      "command": "jenkins-mcp",
      "args": [
        "serve",
        "--profile",
        "corp",
        "--read-only",
        "--stdio"
      ],
      "env": {
        "JENKINS_MCP_READ_ONLY": "true",
        "XDG_CONFIG_HOME": "/ABSOLUTE/PATH/TO/REPO/.local-mcp/xdg/config",
        "XDG_DATA_HOME": "/ABSOLUTE/PATH/TO/REPO/.local-mcp/xdg/data",
        "XDG_CACHE_HOME": "/ABSOLUTE/PATH/TO/REPO/.local-mcp/xdg/cache"
      }
    }
  }
}
```

Notes:

- Use **absolute** paths in Cursor `env` (Cursor’s cwd is not the repo).
- **Never** put API tokens in Cursor config. Use `jenkins-mcp login --profile corp`
  on the host with the same XDG env so the keyring still holds the secret, **or**
  a lab token flow documented for disposable Jenkins only.
- Profile id must match Docker (`JENKINS_MCP_PROFILE`, default `corp`).
- After host `login` / first tool use, Docker doctor sees the same cache/data
  roots: `make local-docker-doctor` / admin Cache metrics (process-local still
  residual for multi-pod).
- Tear-down: `make local-docker-down` does **not** delete host `.local-mcp/`
  bind mounts; remove manually if you want a cold cache.

**Keyring residual:** Linux Secret Service is host-side. In-container admin does
not use your desktop keyring for Jenkins API tokens. Shared XDG shares
**profiles + store/cache**, not Secret Service material.

### Model 3 — Streamable HTTP MCP inside Docker

For MCP clients that speak **HTTP** (not the default Cursor stdio entry):

```bash
# Admin + HTTP serve (+ optional Jenkins)
LOCAL_COMPOSE_PROFILES=http,with-jenkins make local-docker-up
# Prefer shared XDG override (Model 2) so admin + HTTP share cache.
```

| Item | Value |
|------|--------|
| URL | `http://127.0.0.1:8081` (see `LOCAL_HTTP_HOST_PORT`) |
| Auth | Set `JENKINS_MCP_HTTP_TOKEN` in `.env` (lab only); client sends Bearer |
| Cache | Same volumes / shared XDG as above |
| Cursor | Residual if the product only supports `command`+`args` stdio — use Model 2 |

Entrypoint: `serve-http` → `jenkins-mcp serve --http … --http-allow-non-local`
(loopback publish only).

### Agent hints (summary)

| Goal | Configure |
|------|-----------|
| Daily Cursor RO pilot | Model 1 host stdio |
| Warm cache + admin UI + Cursor tools | **Model 2** shared XDG |
| Non-Cursor HTTP MCP client | Model 3 `http` profile |
| Production multi-user JWT | Not this stack — Tier A gateway roadmap |

Coding agents: prefer `jenkins_mirror_logs` / diagnose once so L1 fills the shared
cache; do not re-download full logs when mirror/cache already has frames. Point
operators at this section when cache “disappears” after Docker-only vs host-only
splits (Model 1 vs 2 confusion).

### Admin UI URL + token

| Item | Value |
|------|--------|
| URL | `http://127.0.0.1:8787` (override host port with `LOCAL_ADMIN_HOST_PORT` in `.env`) |
| Token | `JENKINS_MCP_ADMIN_TOKEN` in `deploy/local/.env` |
| Role | `JENKINS_MCP_ADMIN_ROLE` (`viewer` default; `operator` / `policy_admin` for write labs) |
| Profile id | `JENKINS_MCP_PROFILE` (default `corp`) — must exist on the config volume for profile-bound APIs |

Bootstrap a secret-free profile on the Docker volume (once):

```bash
make local-docker-init-profile
# Lab Jenkins (same compose network):
# make local-docker-init-profile JENKINS_URL=http://jenkins:8080
```

---

## Profiles

Set via **`LOCAL_COMPOSE_PROFILES`** (preferred) or `COMPOSE_PROFILES`
(comma-separated). Passed through `scripts/local-docker.sh` as Compose
`--profile` flags.

| Profile | What starts | Host bind |
|---------|-------------|-----------|
| *(none / default)* | `mcp` — admin BFF + SPA | `127.0.0.1:8787` |
| `http` | + `mcp-http` Streamable HTTP | `127.0.0.1:8081` |
| `with-jenkins` | + disposable Jenkins LTS lab | `127.0.0.1:18080` |

```bash
# Admin + lab Jenkins
LOCAL_COMPOSE_PROFILES=with-jenkins make local-docker-up

# Admin + HTTP + Jenkins
LOCAL_COMPOSE_PROFILES=http,with-jenkins make local-docker-up

# Equivalent
COMPOSE_PROFILES=http,with-jenkins make local-docker-up
```

After Jenkins is healthy, lab API token (disposable only):

```bash
docker compose -f deploy/local/docker-compose.yml exec jenkins \
  cat /var/jenkins_home/mcp-api-token
```

From **containers**, Jenkins URL is `http://jenkins:8080`. From **host**,
`http://127.0.0.1:18080`.

**Mode A gateway vault (HOST-009 residual):** this stack does **not** auto-wire a
multi-user API-token vault. For host-side gateway Mode A labs, provision with the
operator CLI (token via env only — never argv):

```bash
export JENKINS_MCP_GATEWAY_VAULT_TOKEN='…lab personal token…'
export JENKINS_MCP_GATEWAY_VAULT_PATH="$PWD/.local-vault/apitoken_vault.json"
jenkins-mcp gateway vault put \
  --subject 'lab|alice|corp' --user alice
jenkins-mcp gateway vault list
jenkins-mcp gateway vault status --subject 'lab|alice|corp'
# revoke: jenkins-mcp gateway vault delete --subject 'lab|alice|corp'
```

See [`docs/gateway/README.md`](../../docs/gateway/README.md) Mode A. Admin console
vault **write** remains residual (secret-free status only).

---

## Makefile targets

| Target | Action |
|--------|--------|
| `make local-docker-build` | Build `jenkins-mcp-local:dev` |
| `make local-docker-up` | Build + up default `mcp` (admin); creates `.env` if missing |
| `make local-docker-down` | `down -v` (wipe volumes) |
| `make local-docker-ps` | Compose ps |
| `make local-docker-logs` | Follow `mcp` logs |
| `make local-docker-doctor` | `doctor --offline` one-shot |
| `make local-docker-init-profile` | Bootstrap secret-free profile on volume |
| `make local-docker-version` | `version --json` |
| `make local-docker-shell` | Interactive bash as nonroot |
| `make local-docker-run ARGS='…'` | Pass-through CLI (e.g. `ARGS='policy show-effective --profile corp --json'`) |
| `make local-docker-config` | Validate compose file |
| `make local-docker-smoke` | Opt-in config + up + health + down (`scripts/local-docker-smoke.sh`) |

Helper equivalent: `scripts/local-docker.sh up|down|build|…`.

---

## Entrypoint modes

Image default `CMD` is `admin`. Override via `docker compose run` / `local-docker-run`:

| Command | Behavior |
|---------|----------|
| `admin` | `jenkins-mcp admin serve` (default) |
| `serve-http` | `serve --http` + allow-non-local (container network) |
| `doctor` | `doctor --profile …` |
| `support-bundle` | support-bundle |
| `version` | version --json |
| `shell` | bash |
| any CLI | `jenkins-mcp <args…>` |

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Port already allocated / bind error | Host port in use | Change `LOCAL_ADMIN_HOST_PORT` / `LOCAL_HTTP_HOST_PORT` / `JENKINS_HOST_PORT` in `.env`, or stop the other process |
| Compose starts only partial services | Profile not enabled | Export `LOCAL_COMPOSE_PROFILES=http,with-jenkins` (no spaces issues: commas OK) before `up` |
| Health returns **401** | Admin token required (all `/admin/v1/*` when token set) | `source deploy/local/.env` and send `Authorization: Bearer $JENKINS_MCP_ADMIN_TOKEN`. Compose healthcheck already sends Bearer when `JENKINS_MCP_ADMIN_TOKEN` is in the service env. |
| SPA **404** / blank shell / placeholder only | UI assets not baked into image | API still works; rebuild after `make admin-ui-embed` or accept UI-008 residual (placeholder embed). Package path is host install, not required for BFF |
| `make local-docker-smoke` fails at build | No network / Docker build cache cold | `make local-docker-build` and inspect `docker compose … build` logs |
| Profile APIs empty / doctor offline profile missing | No profile on volume | `make local-docker-init-profile` |
| Jenkins from admin container unreachable | Wrong URL or profile off | Use `http://jenkins:8080` with `with-jenkins`; ensure same compose project |
| Permission / volume oddities | Leftover volumes | `make local-docker-down` then `up` again |

Validate compose without starting:

```bash
make local-docker-config
# or: scripts/local-docker.sh config
```

---

## Security

- **Loopback host ports only** (compose default `127.0.0.1:…`). Do not publish to LAN for labs.
- **Lab tokens only** — generate with `openssl rand -hex 24`; never production IdP secrets or shared Jenkins service accounts.
- **`.env` is gitignored** (`deploy/local/.env`). Never commit tokens or passwords.
- Admin token via env / file **name** wiring in entrypoint; never bake secrets into the image.
- Default **read-only** via `JENKINS_MCP_READ_ONLY=true`.
- Keyring / Secret Service is **not** available in-container by default — personal API-token login for live Jenkins remains host-side or lab residual.
- No shared Jenkins SA for interactive users; disposable lab password (`JENKINS_ADMIN_PASSWORD=test`) is not a production secret.

---

## Residuals

| Residual | Notes |
|----------|--------|
| Cursor stdio | Host binary still required for Model 1/2 agent path (ADR 0002); Docker alone is admin/HTTP unless shared XDG |
| Shared XDG | Optional override `docker-compose.shared-xdg.example.yml` — bind-mount lab dirs under `.local-mcp/` |
| Cursor HTTP MCP | Model 3 residual if the IDE only supports stdio `command`/`args` |
| Profile bootstrap | First-time `profile add` may need `local-docker-init-profile` / `local-docker-run` |
| SPA assets in image | May show placeholder unless admin-ui embedded at image build (UI-008); BFF JSON still works |
| Production gateway | Use `deploy/gateway/` + HOST/GWY tasks — not this stack |
| OAuth/JWT labs | Separate `testdata/oauth-lab` / HOST-012…015 |
| Multi-user / file caches | Optional knobs in `.env.example` are **same-host lite only** — not multi-pod HA; not live Entra (see below) |
| Default CI | `local-docker-*` is **opt-in**; never required by `make test` / `make ci` |

---

## Residual gateway env knobs (optional opt-in)

Default `make local-docker-up` is **admin BFF / support** only. Waves 8–11 landed optional
same-host **file cache / subject rate** env names for gateway multi-user foundation.
They are **commented** in [`.env.example`](./.env.example) so operators can opt in
without inventing names. Compose passes them into `mcp` / `mcp-http` when set
(`scripts/local-docker.sh` already uses `--env-file deploy/local/.env`).

| Env (names only) | Meaning | Residual honesty |
|------------------|---------|------------------|
| `JENKINS_MCP_GATEWAY_MULTI_USER` | Per-request multi-user Obtain foundation | **Not** production multi-user GO / multi-replica HA |
| `JENKINS_MCP_GATEWAY_CREDENTIAL_MODE` / `_ENABLED_MODES` | HOST-011 mode matrix ids | Mode ids only — never tokens |
| `JENKINS_MCP_SUBJECT_MAX_CONCURRENT` / `_PROCESS_MAX_CONCURRENT` | Concurrency slots | Process-local |
| `JENKINS_MCP_GATEWAY_SUBJECT_LIMITER_MAX_SUBJECTS` | SubjectLimiter map hygiene max | Process-local; idle LRU; fail closed if all hold slots |
| `JENKINS_MCP_SUBJECT_RATE_PER_MINUTE` / `_RATE_BURST` | Token-bucket rate | Process-local default; multi-pod residual |
| `JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH` | Same-host `FileSubjectRateLimiter` | flock lite; **not** multi-pod shared rate |
| `JENKINS_MCP_GATEWAY_SUBJECT_RATE_MAX_SUBJECTS` | Subject-map LRU max | Process-local / file-local only |
| `JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_MAX` / `_TTL` | PrincipalCache hygiene | Empty = unlimited / no expiry; multi-pod residual |
| `JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH` | Same-host `FilePrincipalCache` | Never tokens; **not** multi-pod HA |
| `JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH` | Same-host `FileTokenCache` | Path only — never put token values in `.env`; **not** multi-pod Redis |
| `JENKINS_MCP_HTTP_JWKS_URL` / `_JWT_ISSUER` / `_JWT_AUDIENCE` / `JENKINS_MCP_HTTP_JWKS_MAX_STALE` / `JENKINS_MCP_HTTP_JWKS_CACHE_PATH` | Process-local JWKS + optional public keys file | **Not** multi-pod external JWKS; **not** live Entra |

Suggested lab paths under the `local-data` volume (see `.env.example`):

`/home/nonroot/.local/share/jenkins-mcp/gateway/{subject_rate,principal_cache,token_cache,jwks_cache}.json`

**Do not claim:** multi-pod HA, live Entra / jwt-auth-filter production pin, or
production multi-user GO from enabling these flags in this stack.

| Deeper residual tracker | Link |
|-------------------------|------|
| Live production pin blockers (OAUTH-009/010, HOST-008, multi-user GO) | [`docs/gateway/live-pin-blockers.md`](../../docs/gateway/live-pin-blockers.md) |
| Gateway packaging + multi-user lab flags | [`deploy/gateway/README.md`](../gateway/README.md) · [`.env.example`](../gateway/.env.example) |
| Deployment / HA residual | [`docs/gateway/deployment.md`](../../docs/gateway/deployment.md) |
| Mock OAuth labs (not Entra) | [`testdata/oauth-lab/`](../../testdata/oauth-lab/) · HOST-012…015 |

---

## Related

- Operator admin guide: [`../../docs/admin/README.md`](../../docs/admin/README.md)  
- Packaging note: [`../../docs/packaging.md`](../../docs/packaging.md)  
- Gateway scaffold: [`../gateway/README.md`](../gateway/README.md)  
- Live pin blockers: [`../../docs/gateway/live-pin-blockers.md`](../../docs/gateway/live-pin-blockers.md)  
- Live Jenkins lab only: [`../../testdata/jenkins-compose/README.md`](../../testdata/jenkins-compose/README.md)  
- Server roadmap: [`../../docs/roadmap/server-team-hosted.md`](../../docs/roadmap/server-team-hosted.md)  
- Agent policy (Docker scaffolds): root [`AGENTS.md`](../../AGENTS.md)  


### SPA bake

The image multi-stage build runs `npm ci && npm run build` and installs assets under `/usr/share/jenkins-mcp/admin-ui`. Host npm is not required after the image exists. `SKIP_SPA=1` yields a placeholder only.
