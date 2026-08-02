# Contributing

## Agent and human policy

All contributors and coding agents must follow root **`AGENTS.md`**:

- Tests for every feature
- Regression tests for every fix
- Code review on every change set
- Documentation kept current
- Incomplete work tracked with next steps

## Implementation backlog

Work is planned against:

- `docs/jenkins-mcp-enterprise-architecture.md`
- `docs/jenkins-mcp-enterprise-agent-todo.md` (task source of truth)
- `docs/jenkins-mcp-enterprise-task-index.json` (dependencies)

Prefer **one task ID per pull request** unless a task allows pairing.

## Development workflow

```bash
make test    # unit/contract tests (no live Jenkins credentials)
make build   # local binary with version metadata
make lint    # formatting + static checks when configured
```

## Chaos / fault-injection (QA-002)

Deterministic suites (no live Jenkins; included in `make test` when fast):

```bash
export PATH="$HOME/.local/go/bin:$PATH"
# L1 frames, L2 packs, logmirror
go test ./internal/store/ ./internal/logmirror/ ./internal/archive/ -count=1 -run Chaos
# Jenkins client HTTP faults (truncated progressive, cancel, empty JSON, POST no-retry)
go test ./internal/jenkins/ -count=1 -run ChaosHTTP
# MCP tool-context cancel + HTTP serve cancel (FND-006 residual)
go test ./internal/mcpserver/ ./internal/tools/ -count=1 -run 'Cancel|cancel'
# Offline MCP protocol matrix (FND-006 Wave 20; Cursor host CI still residual)
go test ./internal/tools/ ./internal/mcpserver/ -count=1 -run 'ProtocolMatrix|MCPProtocolMatrix'
# Offline MCP stdio binary smoke (FND-006 Wave 25; opt-in; not in make test)
make stdio-smoke
```

Do not add multi-second sleeps in chaos tests unless unavoidable; prefer
`httptest` + context cancel. Mutation POSTs must never auto-retry (duplicate
trigger safety). See `docs/pilot/README.md` for residual live-chaos gaps.

## Fuzz testing (QA-001)

Native Go fuzz targets (`testing.F`, go1.18+) cover high-risk parsers:

| Package | Targets (representative) |
|---------|---------------------------|
| `internal/jenkins` | `FuzzBuildJobPath`, `FuzzNormalizeBaseURL`, `FuzzSanitizeArtifactPath`, `FuzzInventoryZip`, progressive limits |
| `internal/archive` | `FuzzOpenPack`, `FuzzParseSeekTable`, `FuzzParseIndex`, `FuzzScanFrames` |
| `internal/redact` | `FuzzStripControlSequences`, `FuzzRedactText`, `FuzzSanitizeForModel`, `FuzzRedactJSON` |
| `internal/tools` | `FuzzJobFullName`, `FuzzPrepareBuildLogsForModel`, `FuzzPolicyTargetFromArgs` |
| `internal/contracts` | `FuzzParseJobFullName`, `FuzzIsAbsoluteHTTPURL` |
| `internal/mutation` | `FuzzNormalizeParams`, `FuzzValidateAgainstDefinitions` (MUT-002) |
| `internal/update` | `FuzzParseManifest`, `FuzzLoadLKG` (UPD-001 fail-closed) |
| `internal/policy` | `FuzzLoadOverlayJSON`, `FuzzDenyJobPrefixMatch` (POL overlay / job prefixes) |
| `internal/auth` | `FuzzClassifyFallthroughProbe`, `FuzzParseProtectedResourceMetadata` (OAUTH-009 pure) |

Seed corpora are registered with `f.Add(...)` in each `Fuzz*` function. Crashers
found by the fuzzer are retained under `testdata/fuzz/<FuzzName>/` (git-friendly).

**Unit test path (no generation):** `go test` runs each `Fuzz*` once over its seeds.

**Short smoke (opt-in):**

```bash
export PATH="$HOME/.local/go/bin:$PATH"
make fuzz-smoke              # default FUZZTIME=2s per target
make fuzz-smoke FUZZTIME=5s  # slightly longer
```

**Longer local / CI nightlies:**

```bash
go test ./internal/jenkins  -run=^$ -fuzz=FuzzSanitizeArtifactPath -fuzztime=5m
go test ./internal/archive  -run=^$ -fuzz=FuzzOpenPack -fuzztime=10m
go test ./internal/redact   -run=^$ -fuzz=FuzzSanitizeForModel -fuzztime=5m
go test ./internal/mutation -run=^$ -fuzz=FuzzValidateAgainstDefinitions -fuzztime=5m
go test ./internal/update   -run=^$ -fuzz=FuzzParseManifest -fuzztime=5m
go test ./internal/policy   -run=^$ -fuzz=FuzzLoadOverlayJSON -fuzztime=5m
go test ./internal/auth     -run=^$ -fuzz=FuzzParseProtectedResourceMetadata -fuzztime=5m
```

Fuzz targets must not panic on garbage (returning an error is fine). Inputs are
size-capped inside the targets so accidental huge corpora stay bounded.

## Pull requests

1. Reference the task ID (e.g. `FND-003`) in the PR title or body.
2. Include tests and doc updates in the same PR.
3. Do not check backlog DoD boxes without demonstrated evidence.
4. If work is incomplete, list **next steps** in the PR.

## CI matrix (FND-007)

Workflow: [`.github/workflows/ci.yml`](.github/workflows/ci.yml). Workflow-level
`permissions: contents: read` only — untrusted PR jobs never receive Jenkins or
OAuth secrets.

| Job name (display) | Job id | When | Merge gate? | Notes |
|--------------------|--------|------|-------------|-------|
| `lint-test-build` | `check` | push / PR | **Yes** | Ubuntu host + Rocky 9 container; gofmt, vet, test, race (Ubuntu only), build, `make package`; optional perf step (continue-on-error) |
| `govulncheck` | `govulncheck` | push / PR | **Yes** | `golang.org/x/vuln` scan of `./...` |
| `package-smoke` | `package-smoke` | push / PR | No | Bare Ubuntu only; `make package-smoke` (PKG-001 offline); `continue-on-error` |
| `fuzz-smoke` | `fuzz-smoke` | push / PR | No | `make fuzz-smoke FUZZTIME=1s`; `continue-on-error` |
| `stdio-smoke (host-lifecycle offline)` | `stdio-smoke` | push / PR | No | Wave 26+33 FND-006 offline MCP binary host-lifecycle (`make stdio-smoke`); `continue-on-error`; **not** Cursor product binary CI |
| `live-jenkins-smoke (manual)` | `live-jenkins-smoke` | `workflow_dispatch` only | No | Disposable Jenkins LTS via Docker Compose; not on push/PR |

**Configure branch protection** so only `lint-test-build` and `govulncheck` are
required checks. Optional jobs surface signal without blocking the merge path.
Cursor product binary / host stdio lifecycle CI remains residual even when
`stdio-smoke` is green (offline host-lifecycle matrix is Done*).

Local equivalents:

```bash
export PATH="$HOME/.local/go/bin:$PATH"
make ci                  # lint + test + build (fast local gate)
make package-smoke       # optional PKG-001 offline package checks
make fuzz-smoke FUZZTIME=1s   # optional QA-001 short fuzz (CI uses 1s)
make stdio-smoke         # optional FND-006 offline binary host-lifecycle MCP smoke (CI optional job)
```

## Branch protection

The default branch should require:

- Reviewed pull requests (no direct push for ordinary contributors)
- Passing required CI checks: **`lint-test-build`** and **`govulncheck`** only
  (see [CI matrix](#ci-matrix-fnd-007) above)

Repository owners configure GitHub branch protection for `master`/`main`.

## License

Contributions are under the MIT license (`LICENSE`) with attribution in
`NOTICE` and `docs/HISTORY.md`.
