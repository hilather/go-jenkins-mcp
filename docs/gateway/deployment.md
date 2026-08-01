# Managed gateway deployment (GWY-004 MVP scaffold)

**Status:** Packaging / deployment **scaffold only**. No live AgentCore binary or
signed production image is published by this repository.  
**Platforms:** Rocky Linux and Ubuntu (Tier-1). **Windows is out of scope.**  
**Related:** [README.md](README.md), [qualification.md](qualification.md),
[packaging.md](../packaging.md), architecture §§1–2 / §6.6, ADR 0003 / 0008.

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
  jenkins-mcp serve --gateway --profile <id>
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

---

## 2. Process model

```bash
jenkins-mcp serve --profile <id> --gateway --read-only [--http :8081]
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

## 3. Environment variables (non-secret only)

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

## 4. Platform matrix

| Platform | Gateway package / deploy | Notes |
|----------|--------------------------|-------|
| Rocky Linux | Supported (Tier-1) | SELinux smoke: unconfined user binary; no custom module shipped |
| Ubuntu LTS | Supported (Tier-1) | AppArmor: no dedicated profile shipped |
| macOS | Non-blocking | Not a gateway pilot gate |
| **Windows** | **Out of scope** | No native FUSE; no Windows gateway image (ADR 0008) |

---

## 5. Compose / kustomize scaffold

```bash
cd deploy/gateway
cp .env.example .env   # edit non-secret placeholders only
# Build or mount a Tier-1 linux binary; compose is illustrative.
docker compose config  # validate
# docker compose up     # only after image + secrets strategy exist
```

| Path | Purpose |
|------|---------|
| `deploy/gateway/docker-compose.yml` | Example service: `jenkins-mcp serve --gateway` |
| `deploy/gateway/.env.example` | Non-secret env placeholders |
| `deploy/gateway/kustomize/` | Minimal base kustomization stub |

The compose file intentionally uses a **placeholder image name** and does not
bundle AgentCore. Operators supply the signed image from their registry.

---

## 6. Health / readiness (MVP)

Until dedicated HTTP probes land:

| Check | How |
|-------|-----|
| Process up | container/systemd active |
| Config valid | `gateway.ValidateProviderConfig` at serve start (fail closed) |
| Offline qualify | `jenkins-mcp gateway qualify --offline` (CI / pilot evidence) |
| Identity | `doctor` / `pilot-check` with profile when applicable |

Live AgentCore readiness and Streamable HTTP hardening are residuals.

---

## 7. Security invariants (deploy checklist)

- [ ] AS URL is Entra/approved AS — **never** Jenkins origin  
- [ ] Audience is exact Jenkins API resource  
- [ ] No shared Jenkins SA for interactive users  
- [ ] Read-only default on; mutations only under separate approved exception  
- [ ] Per-user/profile cache volume isolation  
- [ ] Non-root UID; no secrets in image layers, compose, or git  
- [ ] Image SBOM + signature verified before production (org pipeline)

---

## 8. Residuals (explicit)

| Residual | Track |
|----------|--------|
| **Live AgentCore sidecar / binary pin** | GWY-003 live pin + org AgentCore release |
| **Image signing** (cosign / registry signing) | Org release pipeline; not in `make package` |
| Streamable HTTP transport hardening + mTLS | GWY-004 production |
| Multi-tenant quotas + enforced namespace isolation in one process | Storage / MGR |
| Private ratarmount-rs sidecar packaging | ARC / platform |
| Measurable near-source bandwidth benefit study | PERF / pilot metrics |
| Durable token vault (AgentCore Identity) | GWY-001 completion (offline mock + memory cache only today) |
| Live Entra / AgentCore obtain pin | GWY-003 — `TokenFetcher` / mock AS prove contracts offline |

**Do not claim** production GWY-004 DoD complete from this scaffold alone.

---

## 9. Related evidence

```bash
export PATH="$HOME/.local/go/bin:$PATH"
go test ./internal/gateway/ ./internal/gateway/qualify/ ./cmd/jenkins-mcp/ -count=1
jenkins-mcp gateway qualify --offline
make pilot-evidence SKIP_GO_TEST=1   # includes gateway qualify JSON when binary built
```

Docs: [qualification.md](qualification.md), [release/gates.md](../release/gates.md),
[packaging.md](../packaging.md).
