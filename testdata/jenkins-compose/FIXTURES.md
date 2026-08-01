# Mock investigation fixtures (TST-001 lab)

Disposable **Pipeline** jobs seeded by `init.groovy.d/03-mock-fixtures.groovy` for
local MCP triage drills. **Not production data.**

Machine-readable index: [`mock-pipelines/manifest.json`](mock-pipelines/manifest.json)

## Lab HTTP coverage (avoid MCP 404 noise)

The disposable controller installs **`pipeline-rest-api`** (see `plugins.txt`) so
Pipeline REST paths such as `/job/…/wfapi/describe` and stage logs resolve for
`mock-inv-*` jobs instead of returning HTTP 404.

| Endpoint | Fixture |
|----------|---------|
| `wfapi/describe` / stage log | Any `mock-inv-*` Pipeline build (e.g. `mock-inv-baseline-green` #1) |
| `testReport/api/json` | `mock-inv-baseline-green`, `mock-inv-test-failure`, `sample-freestyle`, `sample-pipeline`, `mock-inv-long-log`, `mock-inv-unstable` |
| Build graph | `mock-inv-build-graph-downstream` last build → upstream edge to `mock-inv-build-graph-upstream` |
| Queue | `mock-inv-queue-blocked` (stays queued) |
| Artifacts | `mock-inv-multi-artifact` #1 (`out/reports/summary.txt`, …) |
| Views | `mock-investigations` view (seeded by `04-lab-view.groovy`) |

After changing `plugins.txt` or init groovy, recreate the volume:
`make live-jenkins-down && make live-jenkins-up` (or `LOCAL_COMPOSE_PROFILES=with-jenkins make local-docker-down && …`).

## Refresh fixtures on an existing volume

Init groovy runs only on **first boot** of a volume. To pick up new fixtures after
pulling repo changes:

```bash
make live-jenkins-down
make live-jenkins-up
```

Or rebuild without destroying the volume (jobs skipped if names already exist —
prefer `down -v` when fixture definitions change).

Trigger fresh builds on a running controller:

```bash
./scripts/jenkins-fixture-rebuild.sh
```

## Fixture catalog

| Job | Expected result | Investigation focus |
|-----|-----------------|---------------------|
| `mock-inv-baseline-green` | SUCCESS | Compare baseline, stage logs, green diagnose |
| `mock-inv-regression-broken` | FAILURE | `compare_builds` vs baseline; regression window |
| `mock-inv-compile-failure` | FAILURE | Early compile failure; failed Compile stage |
| `mock-inv-test-failure` | FAILURE | JUnit failures + errors; test report tools |
| `mock-inv-unstable` | UNSTABLE | Non-fatal failure; Publish still runs |
| `mock-inv-nested-stages` | FAILURE | Nested stage failure (Contract child) |
| `mock-inv-parallel-mixed` | FAILURE | Parallel branches; npm error signature |
| `mock-inv-docker-error` | FAILURE | Docker daemon connection signature |
| `mock-inv-oom-killed` | FAILURE | OOM / exit 137 signature |
| `mock-inv-long-log` | SUCCESS | Progressive log tail (~500 lines) |
| `mock-inv-post-failure` | FAILURE | Failed Deploy + post always/failure hooks |
| `mock-inv-multi-artifact` | SUCCESS | Artifact list/inspect/text |
| `mock-inv-build-graph-downstream` | SUCCESS | Build graph leaf node |
| `mock-inv-build-graph-upstream` | SUCCESS | Triggers downstream; graph edge |
| `mock-inv-queue-blocked` | QUEUED | Queue delay / pressure (no agent label) |

Legacy seeds (unchanged): `sample-freestyle`, `sample-pipeline`.

## Example MCP prompts (read-only)

| Goal | Prompt |
|------|--------|
| Diagnose test failure | Diagnose build 1 of `mock-inv-test-failure` |
| Compare regression | Compare `mock-inv-regression-broken` #1 vs `mock-inv-baseline-green` #1 |
| Stage log | Get stage log for Contract in `mock-inv-nested-stages` build 1 |
| Survey failures | Survey recent failures for jobs prefixed `mock-inv-` |
| Log tail budget | Tail last 2KB of `mock-inv-long-log` build 1 |
| Artifacts | List artifacts for `mock-inv-multi-artifact` build 1 |

See [agent-usage.md](../../docs/agent-usage.md) for triage order.

## Adding a fixture

1. Add `mock-pipelines/<name>.jenkinsfile`
2. Register in `mock-pipelines/manifest.json`
3. Append to the `fixtures` list in `03-mock-fixtures.groovy`
4. Document a row in this file
5. Recreate the compose volume (`make live-jenkins-down && make live-jenkins-up`)
