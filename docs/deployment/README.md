# Deployment reference

Drill-downs for operators. Prefer [getting-started/](../getting-started/) for
first-run paths; this section holds volumes, TLS, upgrades, and alternate topologies.

| Page | Status | Notes |
|------|--------|--------|
| [local-native-stdio.md](local-native-stdio.md) | Supported | Host process + remote Jenkins |
| [local-docker.md](local-docker.md) | Opt-in supported | Workstation container → remote Jenkins |
| [local-docker-admin.md](local-docker-admin.md) | Opt-in supported | Admin/support UI stack |
| [server-compose.md](server-compose.md) | Opt-in supported (scaffold) | Canonical server topology |
| [server-kubernetes.md](server-kubernetes.md) | Experimental / scaffold | Kustomize under `deploy/gateway/kustomize/` |
| [server-systemd.md](server-systemd.md) | Experimental | Host unit pattern |
| [reverse-proxy-and-tls.md](reverse-proxy-and-tls.md) | Supported (patterns) | TLS terminate, headers, origins |
| [upgrades-and-rollback.md](upgrades-and-rollback.md) | Supported | Backup, upgrade, rollback |

## Related

- Packaging: [packaging.md](../packaging.md)
- Gateway: [gateway/deployment.md](../gateway/deployment.md)
