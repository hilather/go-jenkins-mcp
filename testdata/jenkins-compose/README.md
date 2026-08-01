# Disposable Jenkins LTS (TST-001 live harness)

Ephemeral Jenkins controller for **local / optional CI** live smoke tests of
`go-jenkins-mcp`. **Not production.** Never commit API tokens or real passwords.

## What it provides

| Seed | Purpose |
|------|---------|
| User `admin` | Password from `JENKINS_ADMIN_PASSWORD` (default **`test`**, disposable only) |
| API token | Written inside the container to `/var/jenkins_home/mcp-api-token` at boot |
| `sample-freestyle` | Shell + JUnit sample XML + small artifact; one build triggered at init |
| `sample-pipeline` | Minimal Pipeline (`agent any`); one build triggered at init |
| `mock-inv-*` (12 jobs) | Mock investigation pipelines — see [FIXTURES.md](FIXTURES.md) |
| Plugins | `workflow-aggregator`, `junit`, `ws-cleanup` (see `plugins.txt`) |

## Prerequisites

- Docker Engine + Compose v2
- Host port free (default **18080**)
- Go toolchain for tests (`export PATH="$HOME/.local/go/bin:$PATH"`)

## Quick start (Makefile)

From the **repository root**:

```bash
export PATH="$HOME/.local/go/bin:$PATH"

# Build + start (waits for healthcheck)
make live-jenkins-up

# Run live smoke (compose up if needed, fetch token, go test -tags=live_jenkins, down)
make live-jenkins-test

# Tear down and remove volume (destroys ephemeral credentials)
make live-jenkins-down
```

## Manual compose

```bash
cd "$(git rev-parse --show-toplevel)"
export JENKINS_ADMIN_PASSWORD="${JENKINS_ADMIN_PASSWORD:-test}"
export JENKINS_HOST_PORT="${JENKINS_HOST_PORT:-18080}"

docker compose -f testdata/jenkins-compose/docker-compose.yml up -d --build --wait

# Ephemeral credentials (process env only — do not log or commit)
export JENKINS_URL="http://127.0.0.1:${JENKINS_HOST_PORT}"
export JENKINS_USER="$(docker compose -f testdata/jenkins-compose/docker-compose.yml exec -T jenkins cat /var/jenkins_home/mcp-api-user)"
export JENKINS_API_TOKEN="$(docker compose -f testdata/jenkins-compose/docker-compose.yml exec -T jenkins cat /var/jenkins_home/mcp-api-token)"

go test ./internal/jenkins/live/ -count=1 -tags=live_jenkins

docker compose -f testdata/jenkins-compose/docker-compose.yml down -v
```

Or use the wrapper:

```bash
./scripts/jenkins-live-smoke.sh
```

## Mock investigation fixtures

Twelve `mock-inv-*` Pipeline jobs cover failure modes for MCP triage drills
(compile/test/unstable/nested/parallel/docker/OOM/long-log/post/artifacts).
Catalog and example prompts: [FIXTURES.md](FIXTURES.md).

## OAuth / JWT labs (planned — HOST-012…015)

This compose is the **mode A** (API token) live harness today. Server-side
**mode B** (JWT RS) and **mode C** (AgentCore/token exchange) Docker scaffolds
are backlog tasks:

| Task | Lab |
|------|-----|
| **HOST-012** | Umbrella Makefile + docs for auth labs |
| **HOST-013** | Jenkins + jwt-auth-filter **or** mock RS reverse-proxy |
| **HOST-014** | Mock OIDC IdP (PKCE/JWKS/claims) |
| **HOST-015** | Mock AgentCore / token-exchange peer |

Planning SoT: [`docs/roadmap/server-team-hosted.md`](../../docs/roadmap/server-team-hosted.md).  
Agent policy: always scaffold Docker for integration tests where possible
([`AGENTS.md`](../../AGENTS.md)). Real Entra remains residual; mocks must still
fail closed on wrong audience/issuer.

Rebuild all fixture jobs on a running lab:

```bash
chmod +x scripts/jenkins-fixture-rebuild.sh
./scripts/jenkins-fixture-rebuild.sh
```

## Environment variables

| Variable | Default | Role |
|----------|---------|------|
| `JENKINS_ADMIN_PASSWORD` | `test` | Disposable admin password for this lab only |
| `JENKINS_HOST_PORT` | `18080` | Host port mapped to container 8080 |
| `JENKINS_URL` | (required for tests) | Base URL, e.g. `http://127.0.0.1:18080` |
| `JENKINS_USER` | `admin` | API user |
| `JENKINS_API_TOKEN` / `JENKINS_TOKEN` | (from container) | Personal API token (never commit) |
| `JENKINS_LIVE_JOB` | `sample-freestyle` | Job used for get-build / log tail |
| `JENKINS_LIVE_KEEP` | unset | If `1`, smoke script skips `compose down` |

## Security notes

- Default password `test` is **only** for disposable local/CI labs.
- Token files live in the container volume; `down -v` destroys them.
- Do not paste tokens into docs, git, CI logs, or support bundles.
- Windows is out of scope (no FUSE / Tier-1 claim); Linux (and optional macOS Docker Desktop) only.

## Related

- Live tests: `internal/jenkins/live/` (`//go:build live_jenkins`)
- Script: `scripts/jenkins-live-smoke.sh`
- Docs: `docs/tst/README.md`
