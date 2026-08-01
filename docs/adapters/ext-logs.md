# External log-system adapter (INT-003 MVP)

Package: [`internal/adapter`](../../internal/adapter) (`extlogs.go`, `extlogs_http.go`)  
Adapter ID: `ext-logs` (built-in; disabled by default)  
Tool: `jenkins_query_external_logs` (optional; registered only when adapter enabled)

## What this is

Query an **approved external log system** using **Jenkins job/build identity**
plus a **bounded time window** and a **short free-text filter**. Results are
**entry refs + short redacted excerpts**, with source and freshness labels.

**Fail-closed Jenkins ACL preflight (Wave 18):** before any external backend
call, the tool performs a cheap Jenkins `GetBuildDetailsByJob` for the typed
job+build using the serve-time principal. On **401** → `authentication`; on
**403** → `authorization`; on **404** → `not_found`. The external querier is
**not** invoked when Jenkins denies or the build is missing — models cannot
probe an operator-pinned log backend for jobs they cannot read.

## What this is not

| Residual | Status |
|----------|--------|
| Real Splunk / ELK / OpenSearch / Datadog Logs client | **Not implemented** |
| Shipping **MCP security audit** (AUD-001 JSONL) to SIEM | **Not this adapter** — see [audit-trail-review.md](../security/audit-trail-review.md) **AUD-T-010…012** |
| Full console dump proxy / progressive log passthrough | **Forbidden** |
| Arbitrary backend query-language (SPL, Lucene DSL, …) passthrough | **Forbidden** |
| Adapter credentials in config or URL userinfo | **Forbidden** (keyring namespace residual) |
| Cross-use of Jenkins API tokens for external systems | **Forbidden** |
| Offline-only MCP policy Target job binding (POL-004) | **Separate** — Jenkins ACL preflight does not replace MCP RBAC job targets |

MVP responses always include a residual note that real SaaS clients remain open.
Offline security self-check item `adapter_framework_residual` (Wave 43) sets
Details `production_ext_logs_saas=false` for residual honesty.

## Disabled by default

| Path | Default |
|------|---------|
| Adapter | Off unless `serve --enable-adapter=ext-logs` |
| Tool `jenkins_query_external_logs` | Not registered unless `RegisterOptions.ExternalLogs` is set |
| Backend | `noop` (empty results) unless configured |

```bash
# Default: no external log tool
jenkins-mcp serve --profile corp --read-only

# Enable framework with noop backend (smoke)
jenkins-mcp serve --profile corp --read-only --enable-adapter=ext-logs

# Mock backend (deterministic fake refs; tests / demos)
jenkins-mcp serve --profile corp --read-only \
  --enable-adapter=ext-logs \
  --adapter-ext-logs-backend=mock

# Optional HTTPS JSON stub (fail closed: https only, origin pin, no redirects)
jenkins-mcp serve --profile corp --read-only \
  --enable-adapter=ext-logs \
  --adapter-ext-logs-backend=http \
  --adapter-ext-logs-base-url=https://logs.example.corp/query
```

**Config holds paths/origins only — never secrets.** Credentials for a future
SaaS client must use a separate keyring namespace (residual).

## Backends

| Backend | Network | Behavior |
|---------|---------|----------|
| `noop` | No | Empty entry list + residual |
| `mock` | No | Up to 3 deterministic `mock:job#build:n` refs |
| `http` | Yes (HTTPS only) | POST JSON `{job,build,start,end,query,max_entries}` to pinned origin |

### HTTP fail-closed rules

- Scheme must be **https**
- **No userinfo** in BaseURL
- Origin pin (scheme + host[:port]); redirects refused
- Response body capped (1 MiB); entry excerpts capped (256 bytes) then redacted in tools

## Query bounds

| Bound | Default | Hard max |
|-------|---------|----------|
| Query string length | — | **256** runes |
| Time window | **24h** | **7d** |
| Entry refs | **20** | **50** |
| Excerpt bytes | — | **256** (pre-redaction) |

Inputs are **job full name + build number** (typed refs), not Jenkins log URLs.

## Adapter rate limit defaults

When serve enables `ext-logs` with a **non-noop** backend (`mock` or `http`),
the adapter registry applies a modest per-adapter token bucket if none is
already configured:

| Setting | Default |
|---------|---------|
| `RateCapacity` | **10** (`adapter.DefaultNetworkAdapterRateCapacity`) |
| `RateRefillPerS` | **1**/s (`adapter.DefaultNetworkAdapterRateRefillPerS`) |

`noop` (and empty) leave rate capacity at **0** (unlimited at the adapter
layer; host MCP budgets still apply). Residual: no dedicated CLI flag yet to
override; operators who need different values must wire `adapter.Config`
explicitly (tests / future flags).

## Response shape (`jenkins_query_external_logs`)

| Field | Notes |
|-------|--------|
| `entries[]` | `ref_id`, redacted `excerpt`, `timestamp`, `source_label`, `freshness`, `evidence_source` |
| `evidence_source` | `external_log_system` |
| `freshness` | `stub` (noop/mock) or `live` (http) |
| `residuals` | Always includes SaaS client residual text |
| `truncated` | Cap exceeded |

## Auth isolation

`ext-logs` receives `adapter.Host` only (clock/logger). It **never** receives a
Jenkins client, keyring, or Jenkins tokens. Serve bridges the adapter into tools
via a cmd-local type so `internal/tools` does not import `internal/adapter`.

Jenkins ACL preflight runs in the **tools** layer (`BuildAccessChecker` /
`GetBuildDetailsByJob`) with the serve-time Jenkins client — not inside the
adapter. Adapter auth for future SaaS clients remains a separate keyring
namespace residual.

## Related

- Framework: [adapters/README.md](README.md) (INT-001)
- Work items: [work-items.md](work-items.md) (INT-004)
- Tool contracts: [tool-contracts.md](../tool-contracts.md)
