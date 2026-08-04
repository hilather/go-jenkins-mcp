# Contributing

## Policy

All contributors and coding agents must follow root **`AGENTS.md`**:

- Tests for every feature; regression tests for every fix
- Code review on every non-trivial change set
- Documentation kept current with behavior
- Free disposable labs are sufficient for product qualification
- Open work lives in **GitHub Issues**, not Markdown backlogs
- Root `README.md` stays high-level; drill-down docs live under `docs/`

## Development workflow

```bash
export PATH="$HOME/.local/go/bin:$PATH"   # if Go is installed under ~/.local/go
export JENKINS_MCP_AUTH=""                # never inject real Jenkins credentials into unit tests

make fmt
make lint                # gofmt check + go vet
make test                # unit/contract tests (no live Jenkins)
make build
make package             # optional; required CI also packages
make vuln                # govulncheck (required CI job)
make ci                  # lint + test + build (fast local gate)
make docs-check          # Markdown links, policy, integration coverage
```

Go version: see `go.mod` (**1.25.x**). Tier-1 hosts: Rocky Linux and Ubuntu only.

## Pull requests

1. Reference a **GitHub Issue** when one exists (task IDs / wave numbers are not required).
2. Include tests and documentation in the same PR for behavior changes.
3. In the PR body, list:
   - What behavior changed
   - Tests run (`make test` / scoped packages)
   - Free labs run **or** why no lab applies
   - Docs/diagrams updated
   - Security / compatibility / migration / persistent-format impact (or “none”)
   - How to verify and how to roll back
   - Remaining work filed as Issues (not Markdown TODOs in product docs)
4. Do not add phase boards, `Done*`, or backlog checkbox updates to the repo.

Operational runbooks may keep unchecked procedure steps; those are operator
checklists, not implementation-completion trackers.

### Reproduce required CI locally (canonical)

Use Go **1.25.x** (see `go.mod`). Put the official toolchain on `PATH` if needed
(`export PATH="$HOME/.local/go/bin:$PATH"`). Required merge-gate jobs map to:

```bash
export PATH="$HOME/.local/go/bin:$PATH"
export JENKINS_MCP_AUTH=""

make fmt
make lint
go test -count=1 -timeout=20m ./...
# Ubuntu matrix cell also runs:
# go test -count=1 -race -timeout=30m ./...
make build
make package
make vuln

# Fast combined gate (lint + test + build; not package/vuln):
make ci
```

Optional (non-required, `continue-on-error` on GitHub):

```bash
make package-smoke
make fuzz-smoke          # CI uses FUZZTIME=500x
make stdio-smoke
make docs-check
```

**Free disposable labs** (opt-in; not required for product qualification):
`make live-jenkins-test`, `make live-oauth-test`, `make live-jwt-rs-test`,
`make live-saml-test`, `make fleet-cache-lab-smoke`. Customer production Entra,
AgentCore, or corporate Jenkins is **optional operator validation**, not a merge
or release gate.

Rocky Linux 9 is exercised in the GitHub Actions container matrix cell
(`rockylinux:9` in `.github/workflows/ci.yml`); local Ubuntu/host runs cover the
same offline unit/contract path.

## CI matrix

Workflow: [`.github/workflows/ci.yml`](.github/workflows/ci.yml). Workflow-level
`permissions: contents: read` only — untrusted PR jobs never receive Jenkins or
OAuth secrets.

| Job name (display) | Merge gate? | Notes |
|--------------------|-------------|-------|
| `lint-test-build` | **Yes** | Ubuntu + Rocky 9; gofmt, vet, test, race (Ubuntu), build, package |
| `govulncheck` | **Yes** | `golang.org/x/vuln` scan of `./...` |
| `docs-check` | **Yes** (when present) | Links, policy greps, integration coverage |
| `package-smoke` | No | `continue-on-error` |
| `fuzz-smoke` | No | `continue-on-error` |
| `stdio-smoke` | No | Offline MCP binary host-lifecycle; not Cursor product CI |
| `live-jenkins-smoke` | No | `workflow_dispatch` only |

**Branch protection** should require `lint-test-build`, `govulncheck`, and
`docs-check` (when the job exists).

## Chaos / fault-injection

Deterministic suites (no live Jenkins; included in `make test` when fast):

```bash
export PATH="$HOME/.local/go/bin:$PATH"
go test ./internal/store/ ./internal/logmirror/ ./internal/archive/ -count=1 -run Chaos
go test ./internal/jenkins/ -count=1 -run ChaosHTTP
go test ./internal/mcpserver/ ./internal/tools/ -count=1 -run 'Cancel|cancel'
go test ./internal/tools/ ./internal/mcpserver/ -count=1 -run 'ProtocolMatrix|MCPProtocolMatrix'
make stdio-smoke   # opt-in offline binary smoke
```

## Fuzz testing

Native Go fuzz targets cover high-risk parsers (`internal/jenkins`, `archive`,
`redact`, `tools`, `contracts`, `mutation`, `update`, `policy`, `auth`).

```bash
make fuzz-smoke                # default FUZZTIME=500x
make fuzz-smoke FUZZTIME=5s
```

Fuzz targets must not panic on garbage. Inputs are size-capped.

## Documentation

- Markdown under `docs/` is canonical; see `docs/README.md` for navigation.
- Support labels: Supported / Opt-in supported / Free-lab validated / Experimental / Stub/demo / Not implemented.
- Architecture changes include Mermaid diagrams where helpful.
- Run `make docs-check` before merging docs-heavy PRs.

## License

Contributions are under the MIT license (`LICENSE`) with attribution in
`NOTICE` and `docs/HISTORY.md`.
