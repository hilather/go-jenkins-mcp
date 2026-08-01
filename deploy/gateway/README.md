# deploy/gateway — optional managed gateway scaffold (GWY-004 / HOST-002 / HOST-005)

Illustrative packaging for `jenkins-mcp serve --gateway` near Jenkins.

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Non-root, read-only root, CPU/memory limits, health probes, secret-free env |
| `.env.example` | Non-secret env vars only (never tokens/client secrets) |
| `Dockerfile` | Distroless non-root image build of the same MCP binary |
| `kustomize/` | Deployment (probes + limits, replicas: 1) + ClusterIP Service |

**Docs:** [docs/gateway/deployment.md](../../docs/gateway/deployment.md) (reverse-proxy matrix, readiness, HA residual)

## Security shape (scaffold)

| Control | Scaffold default |
|---------|------------------|
| User | `65532:65532` (distroless nonroot) |
| Root FS | read-only; writable volumes only for XDG config/data/cache + `/tmp` |
| Privileges | `no-new-privileges`; k8s `drop: [ALL]`, `runAsNonRoot` |
| Secrets | **None** in compose/image; `.env` is gitignored operator copy of `.env.example` |
| HTTP bind | Container **loopback** `127.0.0.1:8081` (host port mapped loopback); all-interfaces + mesh residual |
| CORS | Exact AllowedOrigins only when non-local; **no wildcard** |
| Replicas | **1** (Tier A default; HOST-008 multi-replica HA non-goal until durable vault — see deployment.md §9) |

## Pilot resource limits (HOST-005)

| Resource | Limit | Request / reservation |
|----------|-------|------------------------|
| CPU | 1.0 | 0.1 |
| Memory | 512 MiB | 128 MiB |
| `/tmp` | 64 MiB | tmpfs / emptyDir |

Tune after measurement. Not a production SLO.

## Health probes

| Probe | Path | Expect |
|-------|------|--------|
| Liveness | `GET /healthz` | `200` `{"status":"ok"}` |
| Readiness | `GET /readyz` | `200` when process (and gateway Obtain when wired) ready; **`503`** when `gateway_ready=false` |

Bodies are **secret-free** (no inventory, tokens, subjects). See deployment.md §3 / §7.

## Residuals (honest)

| Residual | Track |
|----------|--------|
| Live AgentCore sidecar pin | GWY-003 / OAUTH-010 |
| Image signing / SBOM attach | Org pipeline |
| Streamable HTTP mTLS + non-local production pin | HOST-001 / HOST-002 |
| Live reverse-proxy path-prefix matrix | HOST-002 / NET-001 |
| Multi-replica HA | HOST-008 Tier B (docs residual only; replicas stay 1) |
| Real Entra / jwt-auth-filter production pin | OAUTH-009 / OAUTH-010 |

**Windows is out of scope** (ADR 0008).

```bash
# Validate compose (requires docker compose plugin)
docker compose -f deploy/gateway/docker-compose.yml config

# Offline qualify (no deploy required)
export PATH="$HOME/.local/go/bin:$PATH"
make build
./bin/jenkins-mcp gateway qualify --offline

# Unit tests for health/origin matrix
go test ./internal/mcpserver/ -count=1 -run 'Health|Readyz|AllowedHosts|Wildcard'
```
