# Deploy — local Docker (MCP → remote Jenkins)

**Support status:** Opt-in supported

## Compose

Primary files:

- `deploy/local/docker-compose.yml`
- `deploy/local/.env.example` (copy to `.env`, never commit)
- `deploy/local/Dockerfile`
- Optional shared XDG: `deploy/local/docker-compose.shared-xdg.example.yml`

Makefile: `make local-docker-up|down|doctor|status|smoke`.

## Remote Jenkins

Configure the container profile/env to the **remote** Jenkins base URL. Do not
require `with-jenkins` for normal use; that profile is a disposable lab fixture.

## Credentials

- Prefer mounted secret / keyring-file patterns documented in
  [../../deploy/local/README.md](../../deploy/local/README.md)
- Never put tokens in Compose YAML or git

## Related

- Quick start: [getting-started/local-docker.md](../getting-started/local-docker.md)
- Admin-focused notes: [local-docker-admin.md](local-docker-admin.md)
