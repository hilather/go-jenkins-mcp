# deploy/gateway — optional managed gateway scaffold (GWY-004)

Illustrative packaging for `jenkins-mcp serve --gateway` near Jenkins.

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Compose service with env placeholders, non-root, read-only root |
| `.env.example` | Non-secret env vars only |
| `Dockerfile` | Distroless non-root image build of the same MCP binary |
| `kustomize/` | Minimal Deployment + Service stub |

**Docs:** [docs/gateway/deployment.md](../../docs/gateway/deployment.md)

**Residuals:** live AgentCore sidecar pin, image signing/provenance, Streamable
HTTP hardening. Windows is out of scope.

```bash
# Validate compose (requires docker compose plugin)
docker compose -f deploy/gateway/docker-compose.yml config

# Offline qualify (no deploy required)
export PATH="$HOME/.local/go/bin:$PATH"
make build
./bin/jenkins-mcp gateway qualify --offline
```
