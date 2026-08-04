# Deploy — Kubernetes scaffold

**Support status:** Experimental / scaffold

Kustomize under `deploy/gateway/kustomize/`:

- Single replica default (multi-pod HA is not a product goal)
- Non-root, drop ALL capabilities
- HTTP probes for health/ready
- Optional `sessionAffinity: ClientIP` scaffold only

Apply only after reviewing and supplying secrets via your platform (never in git).

See [../gateway/deployment.md](../gateway/deployment.md).
