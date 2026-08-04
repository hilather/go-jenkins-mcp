# OpenTelemetry export framework stub (INT-002)

Package: [`internal/adapter`](../../internal/adapter) (`otelexport.go`, `otelexport_http.go`)  
Adapter ID: `otel-export` (built-in; disabled by default)  
Tool: `jenkins_export_trace_refs` (optional; registered only when adapter enabled)

## What this is

An **export framework stub** that takes **allowlisted correlation metadata**
already present on a Jenkins build (via `internal/otelx` extraction) and
“exports” it through a pluggable backend:

| Backend | Network | Behavior |
|---------|---------|----------|
| `noop` | **No** | Accepts envelopes; no side effects (default) |
| `mock` | **No** | Records in-memory export attempts (tests) |
| `http` | Yes (HTTPS only) | POST metadata-only JSON to a pinned origin |

Payload envelopes contain **only** allowlisted fields:

| Field | Notes |
|-------|--------|
| `trace_id` | Validated hex id |
| `span_id` | Optional validated hex id |
| `service` | Short service label (secretish labels dropped) |
| `job` / `build` | Typed Jenkins identity (forced from request) |
| `format` | Safe label (e.g. `w3c_traceparent`) |

## What this is not

| Residual | Status |
|----------|--------|
| Real **OTLP** / **OTLP-HTTP protobuf** collector clients | **Not implemented |
| Sending Jenkins **console log text** to telemetry | **Forbidden** |
| Exporting **tokens** or **full parameter maps** | **Forbidden** |
| Querying Tempo / Jaeger / Honeycomb / Datadog APM APIs | **Not implemented (see correlation lite) |
| Adapter credentials in config or URL userinfo | **Forbidden** (keyring namespace residual) |

MVP responses always include a residual note that real OTLP collector clients
remain open. Offline security self-check item `adapter_framework_residual`
(Wave 43) sets Details `production_otlp=false` so operators cannot mistake
framework stubs for a production collector client.

## Disabled by default

| Path | Default |
|------|---------|
| Adapter | Off unless `serve --enable-adapter=otel-export` |
| Tool `jenkins_export_trace_refs` | Not registered unless `RegisterOptions.TraceExporter` is set |
| Backend | `noop` unless configured |

```bash
# Default: no export tool
jenkins-mcp serve --profile corp --read-only

# Enable framework with noop backend (smoke; no network)
jenkins-mcp serve --profile corp --read-only --enable-adapter=otel-export

# Mock backend (in-memory recording; tests / demos)
jenkins-mcp serve --profile corp --read-only \
  --enable-adapter=otel-export \
  --adapter-otel-export-backend=mock

# Optional HTTPS JSON stub (fail closed: https only, origin pin, no redirects)
jenkins-mcp serve --profile corp --read-only \
  --enable-adapter=otel-export \
  --adapter-otel-export-backend=http \
  --adapter-otel-export-base-url=https://collector.example.corp/export
```

**Config holds paths/origins only — never secrets.**

## HTTP fail-closed rules

- Scheme must be **https**
- **No userinfo** in BaseURL
- Origin pin (scheme + host[:port]); redirects refused
- Response body capped (1 MiB)
- No `Authorization` header in MVP

Outbound JSON shape (stub contract, **not** OTLP protobuf):

```json
{
  "kind": "jenkins_mcp_trace_export_metadata_v1",
  "job": "folder/job",
  "build": 42,
  "envelopes": [
    {
      "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
      "span_id": "00f067aa0ba902b7",
      "service": "checkout",
      "job": "folder/job",
      "build": 42,
      "format": "w3c_traceparent"
    }
  ]
}
```

## Adapter rate limit defaults

When serve enables `otel-export` with a **non-noop** backend (`mock` or `http`),
the adapter registry applies a modest per-adapter token bucket (same defaults as
`ext-logs`) if none is already configured:

| Setting | Default |
|---------|---------|
| `RateCapacity` | **10** (`adapter.DefaultNetworkAdapterRateCapacity`) |
| `RateRefillPerS` | **1**/s (`adapter.DefaultNetworkAdapterRateRefillPerS`) |

`noop` leaves rate capacity at **0** (unlimited at the adapter layer; host MCP
budgets still apply).

## Response shape (`jenkins_export_trace_refs`)

| Field | Notes |
|-------|--------|
| `status` | `noop` / `recorded` / `exported` / `empty` |
| `backend` | `noop` / `mock` / `http` |
| `accepted` / `attempted` | Envelope counts after allowlist filter |
| `envelopes[]` | Allowlisted metadata (redacted string fields) |
| `evidence_source` | `otel_export_stub` |
| `residuals` | Always includes real OTLP client residual text |
| `extracted` | otelx ref count before export filter |

## Fail-closed Jenkins ACL

The tool loads the typed build via `GetBuildDetailsByJob` before any export
backend call. On **401** / **403** / **404** the exporter is **not** invoked.

## Auth isolation

`otel-export` receives `adapter.Host` only (clock/logger). It **never** receives
a Jenkins client, keyring, or Jenkins tokens. Serve bridges the adapter into
tools via a cmd-local type so `internal/tools` does not import `internal/adapter`.

## Relation to `otel-correlate`

| Adapter | Tool | Role |
|---------|------|------|
| `otel-correlate` | `jenkins_get_trace_refs` | Read/extract correlation IDs for the model |
| `otel-export` | `jenkins_export_trace_refs` | Optional export of the same metadata class |

They are **separate** so enabling export does not change correlate semantics.

## Related

- Correlation lite: [otel-correlate.md](otel-correlate.md)
- Framework: [adapters/README.md](README.md) (INT-001)
- Observability: [observability.md](../observability.md)
- Task: INT-002 in the enterprise backlog
