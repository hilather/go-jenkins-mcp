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
| Support: doctor, version, policy show-effective in a clean env | **Cursor daily driver** — host **stdio** MCP (ADR 0002) |
| Admin console without host RPM/DEB/npm | Production **gateway** near Jenkins — `deploy/gateway/` |
| Lab: disposable Jenkins + admin together | Live API-token lab only — `testdata/jenkins-compose/` + `make live-jenkins-*` |
| Demo admin UI on loopback | Multi-tenant / team-hosted OAuth — `docs/roadmap/server-team-hosted.md` |
| CI-adjacent opt-in smoke (`make local-docker-smoke`) | Default `make test` / `make ci` (must stay offline, no Docker) |

**Cursor MCP stdio always stays on the host.** This stack does not replace
`jenkins-mcp serve --stdio` for agent tool discovery.

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
| Cursor stdio | Still install host binary / package for MCP agent path |
| Profile bootstrap | First-time `profile add` may need `local-docker-init-profile` / `local-docker-run` |
| SPA assets in image | May show placeholder unless admin-ui embedded at image build (UI-008); BFF JSON still works |
| Production gateway | Use `deploy/gateway/` + HOST/GWY tasks — not this stack |
| OAuth/JWT labs | Separate `testdata/oauth-lab` / HOST-012…015 |
| Default CI | `local-docker-*` is **opt-in**; never required by `make test` / `make ci` |

---

## Related

- Operator admin guide: [`../../docs/admin/README.md`](../../docs/admin/README.md)  
- Packaging note: [`../../docs/packaging.md`](../../docs/packaging.md)  
- Gateway scaffold: [`../gateway/README.md`](../gateway/README.md)  
- Live Jenkins lab only: [`../../testdata/jenkins-compose/README.md`](../../testdata/jenkins-compose/README.md)  
- Server roadmap: [`../../docs/roadmap/server-team-hosted.md`](../../docs/roadmap/server-team-hosted.md)  
- Agent policy (Docker scaffolds): root [`AGENTS.md`](../../AGENTS.md)  


### SPA bake

The image multi-stage build runs `npm ci && npm run build` and installs assets under `/usr/share/jenkins-mcp/admin-ui`. Host npm is not required after the image exists. `SKIP_SPA=1` yields a placeholder only.
