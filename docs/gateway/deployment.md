# Managed gateway deployment (GWY-004 / HOST-002 / HOST-005)

**Status:** Packaging / deployment **scaffold + operator matrix**. No live
AgentCore binary or signed production image is published by this repository.  
**Platforms:** Rocky Linux and Ubuntu (Tier-1). **Windows is out of scope.**  
**Related:** [README.md](README.md), [qualification.md](qualification.md),
[packaging.md](../packaging.md), [server-team-hosted roadmap](../roadmap/server-team-hosted.md),
architecture §§1–2 / §6.6, ADR 0003 / 0008.

---

## 1. Architecture (per-user gateway)

The optional **managed gateway** runs the **same MCP core** near Jenkins so that
large log/artifact traffic stays close to the controller while **personal
identity**, **deny-only MCP RBAC**, and **global read-only** stay identical to
local stdio mode.

```text
  Cursor / agent client
        │  Streamable HTTP or stdio (site-chosen)
        ▼
  reverse-proxy (TLS terminate; optional mTLS) ── residual path-prefix
        │
  jenkins-mcp serve --gateway --profile <id> --http …
        │  per-user subject binding (Entra / AgentCore claims)
        │  no shared Jenkins service account for interactive users
        ▼
  Jenkins controller (resource server; jwt-auth-filter or approved RS)
```

| Principle | Requirement |
|-----------|-------------|
| Personal identity | Every call bound to an authenticated individual + verified Jenkins principal |
| No shared SA | Interactive path never uses a generic robot credential |
| Isolation | Tokens, cache, continuations, archive handles namespaced by user/tenant/profile |
| Policy parity | Global RO + deny-only MCP RBAC match local mode |
| Origin safety | AgentCore AS URL is **Entra (or approved AS)**, never stock Jenkins |

### Deployment shapes (MVP)

| Shape | When | Notes |
|-------|------|-------|
| **Docker Compose** (scaffold) | Lab / single-node pilot near Jenkins | `deploy/gateway/docker-compose.yml` |
| **Kustomize stub** | Kubernetes near-source | `deploy/gateway/kustomize/` placeholders |
| Systemd unit on Rocky/Ubuntu | Operator host next to controller | Same binary as local package; `--gateway` + env |

This repo ships **compose + env example + docs**, not a production Operator or
Helm chart. Image build/signing remains organization-owned (see residuals).

**Tier A default:** **single replica** per logical gateway subject/namespace
(HOST-008). Multi-replica is Tier B residual until durable vault + affinity exist.

---

## 2. Process model

```bash
jenkins-mcp serve --profile <id> --gateway --read-only [--http 127.0.0.1:8081]
```

| Flag / mode | Behavior |
|-------------|----------|
| `--gateway` / `JENKINS_MCP_GATEWAY_MODE=1` / profile `gatewayMode` | Require AgentCore provider config; bind inbound subject |
| `--read-only` / `JENKINS_MCP_READ_ONLY=true` | Force global RO (pilot/production default) |
| `--http ADDR` | Optional HTTP listener (site transport; harden before production) |
| `--stdio` | Default local transport; less common for multi-client gateway |

**Non-root:** container and host unit should run as an unprivileged user. Cache
and config mount under that user’s XDG paths (or explicit volume mounts).

**One logical user per process (MVP recommendation):** isolate cache and
credentials by running one gateway instance (or namespace) per subject/profile
until multi-tenant quotas land fully. Do not multiplex interactive users onto a
shared Jenkins token.

---

## 3. Reverse-proxy and non-loopback matrix (HOST-002)

### Allowed deployment shapes

| Shape | TLS | Listen | Auth gates | CORS / Origin | Notes |
|-------|-----|--------|------------|---------------|-------|
| **A. Lab loopback** | Optional (none on loopback) | `127.0.0.1:8081` | Optional shared secret; gateway requires subject | Default: loopback origins only | Compose scaffold default |
| **B. TLS terminate at reverse-proxy** (preferred non-local) | **Proxy terminates TLS** | App may stay loopback behind mesh, or non-local with flags | Shared secret **and** per-request subject; proxy may mTLS residual | **Exact** `AllowedOrigins` only — **no CORS wildcard** | Production-shaped |
| **C. App TLS residual** | App holds certs | Non-local bind | Same as B | Same as B | Not scaffolded; org-owned cert path |
| **D. Bare non-local without gates** | Any | `0.0.0.0` / LAN without flags | — | — | **Forbidden** — fail closed at serve start |

### Fail-closed rules (code: `internal/mcpserver`)

| Control | Behavior |
|---------|----------|
| Default bind | Loopback only (`127.0.0.1`, `localhost`, `::1`) |
| `--http-allow-non-local` | Requires **non-empty** `AllowedOrigins`, **non-empty** `AllowedHosts`, **non-empty** shared secret, and **subject** (HOST-001) |
| Empty AllowedOrigins / AllowedHosts on non-local | **Reject at start** |
| CORS wildcard (`*`, `https://*.example`, path `/*`) | **Reject at start** — exact-match origins only |
| Host header (non-local) | Must exact-match AllowedHosts (DNS rebinding defense) |
| Origin on non-GET | Exact-match AllowedOrigins (or loopback when allow-list empty on loopback-only) |
| `--http-path-prefix` / `JENKINS_MCP_HTTP_PATH_PREFIX` | Optional MCP mount prefix (e.g. `/mcp`); invalid prefix **reject at start**; see below |

```bash
# Non-local residual (tests / advanced) — never ship bare :8081 alone
jenkins-mcp serve --profile corp --gateway --read-only \
  --http 0.0.0.0:8081 \
  --http-allow-non-local \
  --http-allowed-host mcp.example.corp \
  --http-allowed-origin https://portal.example.corp \
  --http-token-env MCP_HTTP_TOKEN \
  --http-require-subject
```

### Path-prefix reverse-proxy (HOST-002)

Streamable HTTP can be mounted under a site reverse-proxy **path prefix** so the
public MCP base URL is e.g. `https://edge.example.corp/mcp` while the process
still listens on loopback or a private port.

| Control | Behavior |
|---------|----------|
| CLI | `--http-path-prefix=/mcp` |
| Env | `JENKINS_MCP_HTTP_PATH_PREFIX` (flag wins when both set) |
| Config | `HTTPConfig.PathPrefix` |
| Validation (fail closed) | Must start with `/`; no `//`; no `.` / `..` segments; no backslash; trailing `/` normalized away; bare `/` = no prefix |
| MCP routes when prefix set | **Only** under `{prefix}` (and `{prefix}/…`); prefix stripped before SDK |
| MCP routes when prefix empty | Unchanged: root path space (as today) |
| Health | `GET /healthz` and `GET /readyz` **always** at root; also at `{prefix}/healthz` and `{prefix}/readyz` when prefix set |
| Origin / Host | Unchanged after strip (exact `AllowedOrigins` / `AllowedHosts`; no CORS wildcards) |

```bash
# App: loopback MCP under /mcp (proxy terminates TLS and forwards /mcp/*)
jenkins-mcp serve --profile corp --gateway --read-only \
  --http 127.0.0.1:8081 \
  --http-path-prefix=/mcp \
  --http-require-subject \
  --http-token-env MCP_HTTP_TOKEN

# Example nginx shape (illustrative — site-owned TLS and auth remain residual)
# location /mcp/ {
#   proxy_pass http://127.0.0.1:8081/mcp/;   # keep prefix; app strips
#   proxy_set_header Host $host;
#   proxy_set_header Origin $http_origin;  # do not invent *
#   proxy_http_version 1.1;
#   proxy_buffering off;                   # SSE / streamable
# }
# Probes may hit app root or prefixed health:
#   GET /healthz  or  GET /mcp/healthz
#   GET /readyz   or  GET /mcp/readyz
```

**Clients** must use the public base including the prefix
(e.g. Streamable endpoint `https://edge.example.corp/mcp`). Do not configure a
CORS `*` allow-list on the proxy for browser agents.

**Residual (NET-001 / HOST-002 live matrix):** a full **live path-prefix origin
pin matrix** (edge strips/rewrites `Host`/`Origin`/`X-Forwarded-*`, multi-prefix
Jenkins vs MCP edge) is **not** automated here. Document site proxy config in
pilot evidence; Origin pin pure helpers remain offline. Do not claim automatic
multi-prefix production support beyond the strip + dual health surface above.

### Health endpoints — secret-free (HOST-002 / HOST-005)

| Path | Auth | Body | Notes |
|------|------|------|-------|
| `GET /healthz` | None | `{"status":"ok"}` | Liveness only (always) |
| `GET /readyz` | None | Process-up: `{"status":"ok"}`; gateway wired: `{"status":"ok\|not_ready","gateway_ready":bool}` | **503** when `gateway_ready=false` |
| `GET {prefix}/healthz` | None | Same as `/healthz` | When `--http-path-prefix` / `PathPrefix` set |
| `GET {prefix}/readyz` | None | Same as `/readyz` | When prefix set |

- Unauthenticated by design (probes must not require tokens).  
- **Never** include tool inventory, subjects, tokens, vault material, or Jenkins
  job lists.  
- Exact path match only (no open prefix that could expose MCP tool inventory as
  “health”).  
- When `--gateway` is set, serve wires `ReadyCheck` from Obtain Ready; when
  Obtain is not Ready, **readiness fails (503)** while liveness stays ok.

Regression tests: `go test ./internal/mcpserver -run 'Health|Readyz|PathPrefix|AllowedHosts|Wildcard'`.

---

## 4. Environment variables (non-secret only)

### AgentCore provider (required for `--gateway`)

| Variable | Meaning | Secret? |
|----------|---------|---------|
| `JENKINS_MCP_AGENTCORE_AS_URL` | Authorization server base (**Entra**), **not** Jenkins | No |
| `JENKINS_MCP_AGENTCORE_AUDIENCE` | Exact Jenkins API resource audience | No |
| `JENKINS_MCP_AGENTCORE_CLIENT_ID` | Public OAuth client id | No |
| `JENKINS_MCP_AGENTCORE_MODE` | `authorization_code` or `token_exchange` | No |
| `JENKINS_MCP_AGENTCORE_AUTH_ENDPOINT` | Optional authorize URL | No |
| `JENKINS_MCP_AGENTCORE_TOKEN_ENDPOINT` | Optional token URL | No |

### Gateway identity labels (foundation binding)

| Variable | Meaning | Secret? |
|----------|---------|---------|
| `JENKINS_MCP_GATEWAY_MODE` | `1` / `true` enables gateway mode | No |
| `JENKINS_MCP_GATEWAY_SUBJECT` | Entra/OIDC `sub` | No (identifier) |
| `JENKINS_MCP_GATEWAY_TENANT` | Tenant id | No |
| `JENKINS_MCP_GATEWAY_WORKLOAD` | Workload id | No |
| `JENKINS_MCP_GATEWAY_JENKINS_PRINCIPAL` | Optional Jenkins principal label | No |

### Mode matrix (HOST-011)

| Variable | Meaning | Secret? |
|----------|---------|---------|
| `JENKINS_MCP_GATEWAY_CREDENTIAL_MODE` | Primary: `api_token_vault` \| `jwt_rs_bearer` \| `agentcore_3lo_obo` | No |
| `JENKINS_MCP_GATEWAY_ENABLED_MODES` | Optional comma allow-list of mode ids | No |

### Streamable HTTP (optional; not pilot default)

| Variable | Meaning | Secret? |
|----------|---------|---------|
| `JENKINS_MCP_HTTP_PATH_PREFIX` | MCP mount path prefix (e.g. `/mcp`); flag `--http-path-prefix` wins | No |
| `JENKINS_MCP_HTTP_MAX_BODY_BYTES` | Request body cap (bytes); flag wins; max 16 MiB absolute | No |
| `JENKINS_MCP_HTTP_REQUIRE_TOKEN` / `JENKINS_MCP_HTTP_DENY_ANONYMOUS` | Require shared secret on loopback | No (bool) |
| `JENKINS_MCP_HTTP_REQUIRE_SUBJECT` | Require per-request subject (HOST-001) | No (bool) |

### General serve / policy (shared with local)

| Variable | Meaning |
|----------|---------|
| `JENKINS_MCP_READ_ONLY` | Force read-only when `true` |
| `XDG_CONFIG_HOME` / `XDG_DATA_HOME` / `XDG_CACHE_HOME` | Per-user paths for profile + cache |

**Never place in env or compose files:** API tokens, client secrets, refresh
tokens, private keys, cookies, `JENKINS_MCP_AUTH`, or seed-style `-auth`. Client
secrets (when live AgentCore lands) belong in OS secret store / vault — not
profile JSON, not `.env` committed to git.

See also [`.env.example`](../../deploy/gateway/.env.example).

---

## 5. Platform matrix

| Platform | Gateway package / deploy | Notes |
|----------|--------------------------|-------|
| Rocky Linux | Supported (Tier-1) | SELinux smoke: unconfined user binary; no custom module shipped |
| Ubuntu LTS | Supported (Tier-1) | AppArmor: no dedicated profile shipped |
| macOS | Non-blocking | Not a gateway pilot gate |
| **Windows** | **Out of scope** | No native FUSE; no Windows gateway image (ADR 0008) |

---

## 6. Compose / kustomize scaffold (GWY-004 / HOST-005)

```bash
cd deploy/gateway
cp .env.example .env   # edit non-secret placeholders only
# Build or mount a Tier-1 linux binary; compose is illustrative.
docker compose config  # validate
# docker compose up     # only after image + secrets strategy exist
```

| Path | Purpose |
|------|---------|
| `deploy/gateway/docker-compose.yml` | Example service: non-root, read-only root, resource limits, health probes |
| `deploy/gateway/.env.example` | Non-secret env placeholders |
| `deploy/gateway/Dockerfile` | Distroless nonroot image |
| `deploy/gateway/kustomize/` | Deployment (probes + limits) + ClusterIP Service |

The compose file intentionally uses a **placeholder image name** and does not
bundle AgentCore. Operators supply the signed image from their registry.

### Pilot resource envelope (HOST-005)

| Resource | Pilot default (scaffold) | Notes |
|----------|--------------------------|-------|
| CPU limit | 1.0 | Raise for multi-client if measured |
| Memory limit | 512 MiB | Cache volumes separate; still bound process RSS |
| CPU request | 0.1 | K8s / compose reservation |
| Memory request | 128 MiB | |
| `/tmp` | 64 MiB tmpfs / emptyDir | |
| File descriptors | OS default; residual site ulimit | Not hardcoded in binary |
| Replicas | **1** (Tier A) | HOST-008 multi-replica residual |

Tune per site; do not treat these as production SLOs without load evidence.

---

## 7. Health / readiness (HOST-005)

| Check | How |
|-------|-----|
| Liveness | `GET /healthz` → `{"status":"ok"}` (process up) |
| Readiness | `GET /readyz` — when `--gateway`, includes `gateway_ready` from Obtain Ready; **503** if not Ready |
| Config valid | `gateway.ValidateProviderConfig` at serve start (fail closed) |
| Offline qualify | `jenkins-mcp gateway qualify --offline` (CI / pilot evidence) |
| Identity | `doctor` / `pilot-check` with profile when applicable |

Compose / kustomize scaffold probe both paths. Live AgentCore readiness beyond
Obtain Ready and Streamable HTTP mTLS hardening remain residuals.

**Honest residual:** when not in gateway mode (or ReadyCheck not wired),
`/readyz` is process-up only (`{"status":"ok"}` without `gateway_ready`).

---

## 8. Security invariants (deploy checklist)

- [ ] AS URL is Entra/approved AS — **never** Jenkins origin  
- [ ] Audience is exact Jenkins API resource  
- [ ] No shared Jenkins SA for interactive users  
- [ ] Read-only default on; mutations only under separate approved exception  
- [ ] Per-user/profile cache volume isolation  
- [ ] Non-root UID; no secrets in image layers, compose, or git  
- [ ] Non-local HTTP: AllowedHosts + AllowedOrigins + secret + subject (no CORS `*`)  
- [ ] Health probes secret-free; no inventory without auth  
- [ ] TLS terminate at reverse-proxy (or mesh) for non-loopback  
- [ ] Image SBOM + signature verified before production (org pipeline)

---

## 9. HA / multi-replica residual (HOST-008 — Tier B)

**Tier A default: single replica.** Do not scale Deployment `replicas` > 1 for
interactive multi-user until the checklist below is satisfied.

### Multi-replica checklist (not Tier A MVP)

| Requirement | Why |
|-------------|-----|
| Durable shared token vault (external) | Process-memory vault is not multi-pod safe |
| Session affinity **or** shared session store | Subject bind / confirm tokens must not split-brain |
| Shared or partitioned cache policy | Avoid cross-pod archive handle confusion |
| Audit aggregation | Per-pod files are not a fleet audit plane |
| Sticky or shared Obtain cache | Refresh/consent must not double-mint unsafely |

**Explicit non-goal until vault exists:** multi-replica HA SaaS control plane.
See [roadmap § HOST-008](../roadmap/server-team-hosted.md).

---

## 10. Residuals (explicit)

| Residual | Track |
|----------|--------|
| **Live AgentCore sidecar / binary pin** | GWY-003 live pin + org AgentCore release |
| **Image signing** (cosign / registry signing) | Org release pipeline; not in `make package` |
| Streamable HTTP transport hardening + mTLS | GWY-004 production / HOST-001 |
| Live path-prefix origin pin matrix | HOST-002 / NET-001 residual |
| Multi-tenant quotas + enforced namespace isolation in one process | Storage / MGR / HOST-004 |
| Private ratarmount-rs sidecar packaging | ARC / platform |
| Measurable near-source bandwidth benefit study | PERF / pilot metrics |
| Durable token vault (AgentCore Identity) | GWY-001 completion (offline mock + memory cache only today) |
| Live Entra / AgentCore obtain pin | GWY-003 / OAUTH-010 — `TokenFetcher` / mock AS prove contracts offline |
| Multi-replica HA | HOST-008 Tier B |

**Do not claim** production GWY-004 DoD complete from this scaffold alone.
HOST-002 docs + fail-closed matrix and HOST-005 probe/envelope pieces are
shippable as operator guidance; live Entra/AgentCore remain residual.

---

## 11. Related evidence

```bash
export PATH="$HOME/.local/go/bin:$PATH"
go test ./internal/gateway/ ./internal/gateway/qualify/ ./internal/mcpserver/ ./cmd/jenkins-mcp/ -count=1
jenkins-mcp gateway qualify --offline
make pilot-evidence SKIP_GO_TEST=1   # includes gateway qualify JSON when binary built
```

Docs: [qualification.md](qualification.md), [release/gates.md](../release/gates.md),
[packaging.md](../packaging.md), [auth/jwt-auth-filter-qualification.md](../auth/jwt-auth-filter-qualification.md).
