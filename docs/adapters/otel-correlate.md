# OpenTelemetry correlation lite (INT-002 MVP)

Package: [`internal/otelx`](../../internal/otelx)  
Adapter ID: `otel-correlate` (built-in lifecycle marker)  
Tool: `jenkins_get_trace_refs` (optional; disabled by default)

## What this is

Extract **trace / span / service identifiers** that are **already present** on a
Jenkins build (parameters / env-style keys). Present them to the model/operator
with source and freshness labels.

## What this is not

| Residual | Status |
|----------|--------|
| Real OTLP/OTLP-HTTP protobuf collector clients | **Not implemented** (framework stub: [otel-export.md](otel-export.md)) |
| Querying Tempo / Jaeger / Honeycomb / Datadog APM APIs | **Not implemented** |
| Sending log text to telemetry to search it | **Forbidden** (never) |
| Separate adapter credentials for backends | Residual with INT-003-style secrets |

MVP responses always include a residual note that full OTLP backend work remains
open. Correlation IDs alone do **not** imply remote evidence was fetched.

## Disabled by default

| Path | Default |
|------|---------|
| Adapter | Off unless `serve --enable-adapter=otel-correlate` |
| Tool `jenkins_get_trace_refs` | Not registered unless `RegisterOptions.EnableTraceRefs` |
| Diagnose enrichment `trace_refs` | Omitted unless `EnableTraceRefs` |

Serve wires `EnableTraceRefs` when the `otel-correlate` adapter is successfully
registered (built-in; no allowlist file required when builtins are allowed).

```bash
# Default: no correlation tool
jenkins-mcp serve --profile corp --read-only

# Enable INT-002 correlation lite
jenkins-mcp serve --profile corp --read-only --enable-adapter=otel-correlate
```

## Well-known keys (allowlist)

Matching is **case-insensitive**; `-` and `.` normalize to `_`.

| Key | Meaning |
|-----|---------|
| `TRACEPARENT` | W3C `traceparent` (`00-{32hex}-{16hex}-{flags}`) |
| `TRACE_ID`, `TRACEID`, `OTEL_TRACE_ID` | 32-hex trace id |
| `SPAN_ID`, `SPANID`, `OTEL_SPAN_ID` | 16-hex span id |
| `SERVICE_NAME`, `OTEL_SERVICE_NAME`, `OTEL_SERVICE` | service label |
| `OTEL_RESOURCE_ATTRIBUTES` | parse `service.name=` only |
| `dd.trace_id`, `DD_TRACE_ID` | Datadog trace id (decimal or hex) |
| `dd.span_id`, `DD_SPAN_ID` | Datadog span id |

### Safety

- Values for **sensitive parameter names** (`password`, `token`, `secret`, …)
  are never read.
- Values that **fail format validation** are dropped (no arbitrary string leak).
- Max **8** refs per build by default (hard max **16**).
- Value length bounded before parse; service names length-bounded.

## Response shape (`jenkins_get_trace_refs`)

| Field | Notes |
|-------|--------|
| `trace_refs[]` | `trace_id`, `span_id`, `service_name`, `source_key`, `format`, `evidence_source` |
| `evidence_source` | Always `jenkins_build_metadata` in MVP |
| `freshness` | `live` (Jenkins build API) |
| `residuals` | Includes OTLP backend residual text |
| `truncated` | Cap exceeded |

Diagnose (`jenkins_diagnose_build`) may attach the same `trace_refs` array when
enabled, using parameters already loaded for build metadata (no extra call, no
log text).

## Adapter capabilities

`otel-correlate` declares `lifecycle` + `telemetry`. It holds **no** Jenkins
client, keyring, or network exporter. Extraction runs in `internal/tools` via
the normal Jenkins client path.

## Related

- Export stub: [otel-export.md](otel-export.md) (separate adapter; metadata-only)
- Framework: [adapters/README.md](README.md) (INT-001)
- Observability overview: [observability.md](../observability.md)
- Task: INT-002 in the enterprise backlog
