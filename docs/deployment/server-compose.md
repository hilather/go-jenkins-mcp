# Deploy — server Docker Compose

**Support status:** Opt-in supported (scaffold) · Free-lab validated offline

Canonical files under `deploy/gateway/`:

| File | Role |
|------|------|
| `docker-compose.yml` | Non-root, RO root FS, limits, health |
| `.env.example` | Non-secret env only |
| `Dockerfile` | Distroless non-root image |

```bash
cp deploy/gateway/.env.example deploy/gateway/.env
docker compose -f deploy/gateway/docker-compose.yml --env-file deploy/gateway/.env up -d --build
```

Health: `GET /healthz`, `GET /readyz` (secret-free bodies).

Full notes: [../gateway/deployment.md](../gateway/deployment.md) ·
[../../deploy/gateway/README.md](../../deploy/gateway/README.md)

Quick start: [getting-started/server.md](../getting-started/server.md)
