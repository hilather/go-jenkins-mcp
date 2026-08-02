# Phase 0 progress

Updated after parallel subagent merge (FND-004/005, PERF-001, FND-006/008).  
Incomplete items list **next steps**.

## Status board

| Task | Status | Notes |
|------|--------|--------|
| **FND-001** | Done | Historical import recorded in `docs/HISTORY.md` + `docs/archive/`; NOTICE/SECURITY/CONTRIBUTING present. Module path `github.com/hilather/go-jenkins-mcp`. |
| **FND-002** | Done | Makefile, package-linux.sh, version ldflags, Linux tarball/deb. |
| **FND-003** | Done | Fixture + contract tests; KNOWN_DEFECTS; seed tool inventory. |
| **FND-004** | Done | `cmd/jenkins-mcp`, full `internal/*` skeleton, `depgraph` boundaries. Wave 17: split oversized `internal/jenkins/client.go` into `client.go` / `client_types.go` / `client_jobs.go` / `client_builds.go` / `client_logs.go` / `client_mutations.go` (mechanical, no behavior change). |
| **FND-005** | Done | `internal/contracts` refs + `internal/apperr` taxonomy + redaction; tools map errors. |
| **FND-006** | Done* | SDK pin `go-sdk v1.7.0` + ADR 0006 + in-memory MCP smoke. *Wave 17: CallTool/RunHTTP cancel smoke. Wave 20: offline protocol matrix (Initialize/ListTools/CallTool success·invalid·unknown·cancel + loopback HTTP). Wave 25: offline stdio **binary** smoke (`make stdio-smoke`). Wave 26: optional CI job `stdio-smoke` (non-merge-gate). Wave 33: offline binary **host-lifecycle** expansion (invalid/unknown/cancel + post-call ListTools + canary scrub) — offline host-lifecycle matrix Done*. Cursor product binary / host stdio CI still residual (not closed). |
| **FND-007** | Done* | GitHub Actions CI: merge gate = `lint-test-build` + `govulncheck`; optional `package-smoke` (Ubuntu), `fuzz-smoke` (FUZZTIME=1s), `stdio-smoke` (Wave 26, continue-on-error), perf step; live Jenkins = workflow_dispatch only. *Residuals: Cursor host CI, SBOM attach, secret/code scanning productization, required-check owner config. |
| **FND-008** | Done | ADRs 0001–0011 under `docs/adr/`. |
| **PERF-001** | Done | Progressive log benches + `docs/perf-baseline.md` + `make bench-progressive`. KD-001 locked as baseline. |

## Package map (FND-004)

```text
cmd/jenkins-mcp/          entry (stdio default; -http optional)
internal/jenkins/         HTTP client — no MCP imports
internal/tools/           MCP registration — no raw Jenkins HTTP
internal/contracts/       typed refs (FND-005)
internal/apperr/          error codes + safe wrap (FND-005)
internal/redact/          secret scrubbing
internal/depgraph/        dependency allow-list tests
internal/{app,config,profile,auth,keyring,policy,logmirror,
          store,archive,search,diagnostics,audit,telemetry,
          capabilities,mcpserver}/   skeletons (doc.go / thin interfaces)
docs/adr/                 architecture decision records
```

## Error taxonomy (FND-005)

Codes include: `authentication`, `authorization`, `not_found`, `capability_missing`,
`throttled`, `timeout`, `cancelled`, `corrupt_cache`, `quota`, `policy_denial`,
`upstream_protocol`, plus `invalid_argument` / `internal`. Model-visible `Error()` is
redacted; `Cause`/`Unwrap` for local diagnostics.

## PERF-001 lock-in

| Request | Wire (seed) | Returned logs |
|---------|-------------|---------------|
| 8192 B | full logical log (e.g. 1 MiB / 10 MiB) | truncated to 8192 |

See `docs/perf-baseline.md`. Re-run after LOG-001; expect wire ≈ request.

## ADRs (FND-008)

Index: [`docs/adr/README.md`](adr/README.md) — package layout, stdio, no native 3LO, read-only/RBAC, zstd frames, L2 tar.zst, platforms, keyring, budgets, gated Jenkins AS plugin, MCP SDK.

## Verify

```bash
export PATH="$HOME/.local/go/bin:$PATH"
make test
make lint
make ci
make bench-progressive   # PERF-001 only; not in default CI
./bin/jenkins-mcp -version
```

## Phase 1 wave (merged) — see `docs/phase1-progress.md`

SEC-001, AUTH-000, CFG-001, AUTH-001/002, POL-001, MCP-001, LOG-001, NET-001 landed via subagents.

## Next steps

Open work only (completed lines removed per agent session-todo rule):

- [ ] Branch protection: required PR review + CI (owners)
- [ ] Cursor product binary / host stdio lifecycle CI (FND-006 residual; offline protocol matrix Wave 20; offline binary host-lifecycle smoke Wave 25+33 Done* — neither closes Cursor product host CI)
- [ ] Formal ADR security sign-off process

Phase 1 foundations (AUTH/CFG/POL/NET/LOG/STO) landed — see `docs/phase1-progress.md`.
