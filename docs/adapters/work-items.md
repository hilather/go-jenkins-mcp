# Work-item / source-host correlation (INT-004 MVP)

Package: [`internal/correlate`](../../internal/correlate)  
Adapter ID: `work-items` (built-in lifecycle stub; disabled by default)  
Tool: `jenkins_get_change_correlation` (optional; enable via adapter)

## What this is

Extract **explicit** work-item and SCM host identifiers that are **already
present** on a Jenkins build:

- Build parameters (non-sensitive keys)
- SCM changeSets (commit messages, commit SHAs, repo URLs)

Present them as bounded `work_items[]` with source and evidence labels. Optional
`work-items` adapter may **echo refs only** (no ticket network).

## What this is not

| Residual | Status |
|----------|--------|
| Jira / GitHub / GitLab / Bitbucket ticket API lookup | **Not implemented |
| Broad project scrape or private discussion content | **Forbidden** |
| Automatic inclusion of unrelated issues | **Forbidden** (pattern allowlist only) |
| Using Jenkins credentials for ticket hosts | **Forbidden** |

MVP responses always include a residual that ticket-system APIs remain open.
Offline security self-check item `adapter_framework_residual` (Wave 43) sets
Details `production_work_items_saas=false` for residual honesty.

## Disabled by default

| Path | Default |
|------|---------|
| Adapter | Off unless `serve --enable-adapter=work-items` |
| Tool `jenkins_get_change_correlation` | Not registered unless `EnableChangeCorrelation` |
| Ticket lookup | Stub only when adapter started |

```bash
# Default: no correlation tool
jenkins-mcp serve --profile corp --read-only

# Enable INT-004 extraction + work-items stub
jenkins-mcp serve --profile corp --read-only --enable-adapter=work-items
```

## Extracted kinds

| Kind | Example |
|------|---------|
| `jira_key` | `PROJ-123` |
| `github_issue` / `github_pull` | `acme/demo#12` from GitHub URL |
| `gitlab_issue` / `gitlab_merge_request` | path + `#N` from GitLab URL |
| `bitbucket_pull` | workspace/repo `#N` |
| `commit_sha` | git SHA from changeSet items |
| `scm_host` | `github.com/acme/demo` from repo URL |

### Safety

- Values for **sensitive parameter names** (`password`, `token`, `secret`, …)
  are never read.
- Repo URLs have **userinfo stripped**; query strings dropped from returned URLs.
- Max **32** items by default (hard max **64**).
- Text scan per field bounded (4 KiB).

## Response shape (`jenkins_get_change_correlation`)

| Field | Notes |
|-------|--------|
| `work_items[]` | `kind`, `id`, optional `url`/`host`, `source`, `evidence_source` |
| `evidence_sources` | e.g. `jenkins_build_metadata`, `jenkins_scm` |
| `freshness` | `live` (Jenkins APIs) |
| `residuals` | Ticket API residual text |
| `adapter_stub` | Optional echoed ids when work-items adapter wired |
| `truncated` | Cap exceeded |

SCM fetch failure does **not** fail the tool: parameters are still returned and
a residual is added.

## Adapter capabilities

`work-items` declares `lifecycle` + `work_item`. It holds **no** network client
and **no** Jenkins credentials. Lookup is passthrough refs for future ticket
enrichment.

Pure extractors live in `internal/correlate` (leaf package; no Jenkins import).
Tools call Jenkins client + extractors; cmd bridges the optional adapter.

## Related

- Framework: [adapters/README.md](README.md) (INT-001)
- External logs: [ext-logs.md](ext-logs.md) (INT-003)
- SCM tool: `jenkins_get_build_changes` (SCM-001)
