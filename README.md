# go-jenkins-mcp (enterprise)

Enterprise Jenkins MCP for Cursor: local per-user stdio client with optional
managed-gateway path. Built from the community seed
[`simonfxr/go-jenkins-mcp`](https://github.com/simonfxr/go-jenkins-mcp) as a
**behavioral seed**, not the long-term architecture.

## Status

**Phase 0 — baseline and architecture lock** (in progress). See
[`docs/phase0-progress.md`](docs/phase0-progress.md).

| Resource | Description |
|----------|-------------|
| [`AGENTS.md`](AGENTS.md) | Mandatory agent policy (tests, review, docs, todos) |
| [`docs/user/README.md`](docs/user/README.md) | User guide: Cursor stdio, profiles, login, RO default |
| [`docs/admin/README.md`](docs/admin/README.md) | Admin: packaging, cache, SELinux/AppArmor, pilot-check |
| [`docs/security/operator-guide.md`](docs/security/operator-guide.md) | Operator security: keyring, secrets, support bundles |
| [`docs/security/privacy-data-retention.md`](docs/security/privacy-data-retention.md) | Privacy inventory & retention (QA-006) |
| [`docs/adapters/README.md`](docs/adapters/README.md) | Optional integration adapters (INT-001) |
| [`docs/perf-budgets.json`](docs/perf-budgets.json) | Perf regression budgets (QA-003) |
| [`docs/tool-contracts.md`](docs/tool-contracts.md) | MCP tool contracts and budgets |
| [`docs/agent-usage.md`](docs/agent-usage.md) | Agent triage guidance |
| [`docs/pilot/README.md`](docs/pilot/README.md) | Limited RO pilot kit (REL-001) |
| [`docs/release/gates.md`](docs/release/gates.md) | Production release gates (REL-002) |
| [`docs/packaging.md`](docs/packaging.md) | Tier-1 packages, update-check, XDG paths |
| [`docs/README-jenkins-mcp-enterprise-planning-pack.md`](docs/README-jenkins-mcp-enterprise-planning-pack.md) | Planning pack index |
| [`docs/jenkins-mcp-enterprise-architecture.md`](docs/jenkins-mcp-enterprise-architecture.md) | Architecture |
| [`docs/jenkins-mcp-enterprise-agent-todo.md`](docs/jenkins-mcp-enterprise-agent-todo.md) | Implementation backlog |
| [`UPSTREAM.md`](UPSTREAM.md) | Frozen seed commit and hashes |
| [`KNOWN_DEFECTS.md`](KNOWN_DEFECTS.md) | Seed defects expected to change |
| [`README.upstream.md`](README.upstream.md) | Upstream seed README (tool list) |

## Layout

```text
cmd/jenkins-mcp/          # process entry (stdio default / optional -http)
internal/jenkins/         # Jenkins HTTP client (no MCP imports)
internal/tools/           # MCP tool registration (no raw HTTP)
internal/contracts/       # typed refs (FND-005)
internal/apperr/          # error taxonomy (FND-005)
internal/{auth,policy,…}/ # architecture packages (FND-004)
internal/adapter/         # optional integrations (INT-001; default off)
docs/                     # architecture + backlog
docs/adr/                 # architecture decision records
docs/perf-baseline.md     # PERF-001 progressive log baselines
docs/perf-budgets.json    # QA-003 continuous regression budgets
```

## Platforms (Tier 1)

- **Rocky Linux** (supported majors)
- **Ubuntu** (supported LTS Desktop/Server)

macOS is nice-to-have. **Windows is out of scope** (no native FUSE).

## Build and test

Requires Go (see `go.mod`). No live Jenkins credentials for unit tests.

```bash
make test
make build
./bin/jenkins-mcp version --json
./bin/jenkins-mcp update-check --json   # no network unless JENKINS_MCP_UPDATE_MANIFEST_URL is set
./bin/jenkins-mcp release-evidence --offline
```

**Setup for Cursor (no secrets in config):** see [`docs/user/README.md`](docs/user/README.md).

Credentials via `-auth user:token` or `JENKINS_MCP_AUTH` remain a **known seed
defect** (KD-003); prefer `jenkins-mcp login --profile` + Secret Service. Do not put
tokens in shell history or committed config.

## License

MIT. Upstream attribution in `LICENSE`, `NOTICE`, and `UPSTREAM.md`.
