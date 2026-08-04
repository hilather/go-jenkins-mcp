# Deploy — local Docker admin / support UI

**Support status:** Opt-in supported · Free-lab validated

Distinct from pure MCP triage: runs admin BFF + SPA on loopback for day-2
operations without a full host package install.

Canonical operator doc: [../../deploy/local/README.md](../../deploy/local/README.md).

| Surface | Default |
|---------|---------|
| Admin | `http://127.0.0.1:8787` |
| Optional MCP HTTP | profile `http` → `127.0.0.1:8081` |
| Optional lab Jenkins | profile `with-jenkins` → `127.0.0.1:18080` |

```bash
make local-docker-up
make local-docker-smoke   # opt-in
make local-docker-down
```

Cursor stdio remains host-native by default (ADR 0002).
