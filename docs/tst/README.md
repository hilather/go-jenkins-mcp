# TST-001 — Jenkins integration tests and route matrix

**Task:** [TST-001](../jenkins-mcp-enterprise-agent-todo.md#tst-001---create-the-disposable-jenkins-integration-test-and-route-matrix)  
**Status (MVP offline):** machine-readable route matrix + httptest fixture inventory  
**Status (live harness MVP):** disposable Jenkins Compose + tagged live smoke (opt-in; not default CI)  
**Residual:** full LTS major/plugin/proxy/OIDC matrix cells (see below)

---

## Sources of truth

| Artifact | Role |
|----------|------|
| [`internal/jenkins/route_matrix.go`](../../internal/jenkins/route_matrix.go) | Go SoT for routes, classes, tools, fixture flags |
| [`docs/tst/route-matrix.json`](./route-matrix.json) | Golden export (validated by `TestRouteMatrix_GoldenJSON`) |
| [`internal/jenkins/jenkins_fixture_test.go`](../../internal/jenkins/jenkins_fixture_test.go) | Offline httptest Jenkins emulator |
| [`internal/jenkins/requestclass.go`](../../internal/jenkins/requestclass.go) | auth / read / mutate / unclassified classifier (POL-004) |
| [`testdata/jenkins-compose/`](../../testdata/jenkins-compose/) | Disposable Jenkins LTS Compose + init groovy |
| [`internal/jenkins/live/`](../../internal/jenkins/live/) | `//go:build live_jenkins` smoke tests |

When you add a `CallJenkins` path:

1. Add a `RouteEntry` (or extend prefixes) in `KnownRouteMatrix()`.
2. Add a marker to `KnownAPIPathMarkers()` if it is a new path family.
3. Regenerate golden JSON (see below).
4. Prefer an httptest fixture cell; mark `fixture_covered` honestly.
5. Classification tests must keep mutation paths fail-closed under RO.

---

## Offline verification (no Jenkins required)

```bash
export PATH="$HOME/.local/go/bin:$PATH"
go test ./internal/jenkins/ -count=1 -run 'TestRouteMatrix|TestContract|TestClassify'
# QA-002 HTTP chaos (httptest fault injection; part of make test):
go test ./internal/jenkins/ -count=1 -run ChaosHTTP
# Full default suite (must stay green without Docker / live tag):
go test ./... -count=1
# or:
make test
```

Assertions:

- Every `KnownAPIPathMarkers()` entry appears in the matrix.
- Golden `docs/tst/route-matrix.json` matches `RouteMatrixJSON()`.
- Route classes are consistent with `ClassifyJenkinsRequest`.
- Fixture inventory lists **covered**, **partial**, and **residual_live** cells.

### Regenerate golden JSON

```bash
export PATH="$HOME/.local/go/bin:$PATH"
cd "$(git rev-parse --show-toplevel)"
cat > /tmp/gen_rm.go <<'EOF'
package main
import (
  "os"
  "github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
)
func main() {
  b, err := jenkins.RouteMatrixJSON()
  if err != nil { panic(err) }
  os.WriteFile("docs/tst/route-matrix.json", append(b, '\n'), 0o644)
}
EOF
go run /tmp/gen_rm.go
```

---

## Live disposable Jenkins (opt-in)

**Default `make test` / CI unit job never starts Docker.** Live coverage is manual or workflow_dispatch.

### Exact commands

```bash
export PATH="$HOME/.local/go/bin:$PATH"
cd "$(git rev-parse --show-toplevel)"

# One-shot: compose up → wait healthy → mint token → live tests → compose down -v
make live-jenkins-test

# Or step-by-step:
make live-jenkins-up
# Export credentials from the container (do not log the token):
export JENKINS_URL="http://127.0.0.1:${JENKINS_HOST_PORT:-18080}"
export JENKINS_USER="$(docker compose -f testdata/jenkins-compose/docker-compose.yml exec -T jenkins cat /var/jenkins_home/mcp-api-user)"
export JENKINS_API_TOKEN="$(docker compose -f testdata/jenkins-compose/docker-compose.yml exec -T jenkins cat /var/jenkins_home/mcp-api-token)"
go test ./internal/jenkins/live/ -count=1 -tags=live_jenkins -timeout=5m
make live-jenkins-down
```

Wrapper (same as `make live-jenkins-test`):

```bash
./scripts/jenkins-live-smoke.sh
# Keep controller after tests:
JENKINS_LIVE_KEEP=1 ./scripts/jenkins-live-smoke.sh
```

### Environment (live tests)

| Variable | Required | Notes |
|----------|----------|--------|
| `JENKINS_URL` | yes | Skip all live tests if unset |
| `JENKINS_API_TOKEN` or `JENKINS_TOKEN` | yes when URL set | Ephemeral; from container `mcp-api-token` |
| `JENKINS_USER` | no (default `admin`) | |
| `JENKINS_ADMIN_PASSWORD` | compose only | Default **`test`** — disposable lab only |
| `JENKINS_HOST_PORT` | no (default `18080`) | Host map to container 8080 |
| `JENKINS_LIVE_JOB` | no (default `sample-freestyle`) | Job for get-build / log tail |

### Smoke coverage (live tag)

| Test | Client API |
|------|------------|
| `TestLive_WhoAmI` | `WhoAmI` |
| `TestLive_ListJobs` | `ListJobs` |
| `TestLive_GetBuild` | `ListBuilds` + `GetBuildDetailsByJob` |
| `TestLive_ProgressiveLogTail` | `GetBuildLogTail` / `GetBuildLogs` |
| `TestLive_CapabilityDiscovery` | `RefreshCapabilities` |

Seeded controller jobs: `sample-freestyle` (JUnit + artifact), `sample-pipeline`,
and twelve `mock-inv-*` investigation fixtures — see
[`testdata/jenkins-compose/FIXTURES.md`](../../testdata/jenkins-compose/FIXTURES.md).

### Security

- Never commit tokens or production passwords.
- Default compose password `test` is **lab-only**.
- `make live-jenkins-down` / smoke script uses `docker compose down -v` to destroy the volume.
- Live tests assert API tokens never appear in error strings.

---

## Fixture coverage vs residual live cells

See `fixture_inventory` in [`route-matrix.json`](./route-matrix.json).

| Cell | Offline today | Live status |
|------|---------------|-------------|
| Core REST + progressive logs + queue/computer | httptest **covered** | Smoke: whoAmI, jobs, build, progressive tail |
| Pipeline wfapi / JUnit / artifacts | httptest **covered** | Seed jobs present; full route walk residual |
| API-token Basic / Bearer headers | unit | **partial** — live Basic smoke; OIDC/JWT residual |
| Jenkins ACL 403/404 | partial fixture | Role strategy matrix residual |
| Reverse-proxy path prefix | NormalizeBaseURL unit | Live proxy residual |
| Multibranch / matrix / views | path encoding unit | **residual_live** |
| OAuth-required anti-fallback | design tests | **residual_live** (must fail CI when enforced) |
| Disposable Jenkins LTS harness | n/a | **partial** — compose + smoke MVP; multi-version matrix residual |

### Layout

```text
testdata/jenkins-compose/          # docker compose + Dockerfile + init groovy
internal/jenkins/live/             # //go:build live_jenkins
scripts/jenkins-live-smoke.sh      # up → test → down -v
```

---

## Acceptance mapping (TST-001)

| Criterion | MVP offline | Live harness MVP | Still residual |
|-----------|-------------|------------------|----------------|
| CI covers declared Jenkins/plugin/proxy matrix | Route + fixture inventory in unit tests | Opt-in `make live-jenkins-test`; workflow_dispatch job (not default gate) | Multi-LTS + proxy grid in CI |
| Ephemeral credentials + destroy | N/A offline | Compose init token + `down -v` | Broader multi-user lifecycle |
| API-token, RO, MCP-RBAC, inaccessible, identity | Unit + httptest + POL-005 | API-token whoAmI + jobs | RO/RBAC/ACL live matrix |
| Large/growing/truncated log fixtures | httptest progressive | Small seed logs | Live multi-GiB |
| Every route classified auth/read/mutation + linked tests | `route-matrix.json` + classifier tests | Smoke subset of routes | Expand per cell |
| OAuth-required route without anti-fallback fails CI | Residual (documented) | Not enforced in smoke | Enforce when OAuth lab lands |

---

## Related

- [POL-005 adversarial tests](../policy-rbac.md)
- [QA-005 security review pack](../security/security-review-checklist.md)
- [internal/jenkins README](../../internal/jenkins/README.md) (origin pin, body limits, retries)
- [Compose README](../../testdata/jenkins-compose/README.md)
