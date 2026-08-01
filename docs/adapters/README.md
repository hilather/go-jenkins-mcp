# Integration adapter framework (INT-001 MVP)

Package: [`internal/adapter`](../../internal/adapter)

Optional external-system integrations load **only when explicitly enabled** and
**approved**. The core Jenkins MCP path does not depend on any adapter.

## Principles

| Rule | Detail |
|------|--------|
| Deny by default | No adapters registered or started unless `--enable-adapter=<id>` |
| Approval | Built-in adapters may enable with the flag alone; other IDs require `--adapter-allowlist` JSON |
| Auth isolation | Factories receive `adapter.Host` only — **no** Jenkins client, keyring, or tokens by default |
| Panic isolation | `Start` / `Stop` / `Health` / `Call` recover panics → Health `unhealthy`; core process continues |
| Budgets | Optional per-adapter token bucket (`RateCapacity` / `RateRefillPerS`); serve defaults **10 / 1/s** for non-noop `ext-logs` / `otel-export` backends |
| Cross-system data | Tool contracts must label external evidence sources (INT-002+) |

## Built-in adapters

| ID | Capabilities | Purpose |
|----|--------------|---------|
| `noop` | `lifecycle` | Framework smoke; no side effects |
| `clock` | `lifecycle`, `clock` | Wall-clock example; **not** a production integration |
| `otel-correlate` | `lifecycle`, `telemetry` | INT-002 correlation lite: enables `jenkins_get_trace_refs` (build-metadata IDs only; **no OTLP**) |
| `otel-export` | `lifecycle`, `otel_export` | INT-002 metadata-only export stub (`noop`/`mock`/optional HTTPS JSON); enables `jenkins_export_trace_refs` (**no** OTLP protobuf) |
| `ext-logs` | `lifecycle`, `external_logs` | INT-003 external log query framework (`noop`/`mock`/optional HTTPS JSON); enables `jenkins_query_external_logs` |
| `work-items` | `lifecycle`, `work_item` | INT-004 ticket lookup stub (refs only); enables `jenkins_get_change_correlation` |

Production OTLP export / Splunk / ELK / Jira **SaaS clients** remain residual.
See [otel-correlate.md](otel-correlate.md), [otel-export.md](otel-export.md),
[ext-logs.md](ext-logs.md), [work-items.md](work-items.md).

**Offline security self-check (Wave 43–44 / INT-001 residual honesty):**

- `adapter_framework_residual` proves pure offline that `adapter.NewRegistry(Config{})`
  registers **zero** adapters (deny-by-default), that built-in factories exist
  (`noop`, `clock`, `otel-correlate`, `otel-export`, `ext-logs`, `work-items`),
  and that enabling `noop` can `Start`/`Health` without panic. Details mark
  `default_deny=true`, `builtins_present=true`, `production_otlp=false`,
  `production_ext_logs_saas=false`, `production_work_items_saas=false` — **does
  not** implement production backends.
- `adapter_allowlist_provenance_lite` proves sign+verify of a temp allowlist with
  ephemeral Ed25519 keys, wrong-sig fail-closed, signed-without-keys fail-closed,
  pilot unsigned acceptance, and dual-control MinSignatures lite (2-of-2 ok,
  1-of-2 fail-closed). Details mark `allowlist_min_signatures_lite=true`,
  `residual_cosign=false`, `residual_sbom=false`, `residual_hsm=false`,
  `residual_multi_party_provenance=false`, `residual_true_threshold=false`.

## CLI (serve)

```bash
# Default: zero adapters (recommended for pilot)
jenkins-mcp serve --profile corp --read-only

# Explicit enable of built-in test adapter (future/diagnostic)
jenkins-mcp serve --profile corp --enable-adapter=clock

# INT-002: enable build-metadata OTEL correlation tool (no OTLP export)
jenkins-mcp serve --profile corp --enable-adapter=otel-correlate

# INT-002: metadata-only export framework stub (noop by default; optional mock/http)
jenkins-mcp serve --profile corp --enable-adapter=otel-export \
  --adapter-otel-export-backend=mock

# INT-003: external log framework (noop by default; optional mock/http)
jenkins-mcp serve --profile corp --enable-adapter=ext-logs \
  --adapter-ext-logs-backend=mock

# INT-004: work-item / SCM host correlation from Jenkins metadata
jenkins-mcp serve --profile corp --enable-adapter=work-items

# Multiple IDs (comma or repeat)
jenkins-mcp serve --profile corp --enable-adapter=noop --enable-adapter=clock

# Non-builtin IDs require an allowlist file (fail closed if missing/invalid)
jenkins-mcp serve --profile corp \
  --adapter-allowlist /path/to/allowlist.json \
  --enable-adapter=my-approved-id
```

### Allowlist file shape

Pilot (unsigned — operator-controlled path):

```json
{
  "version": 1,
  "approved": ["noop", "clock"]
}
```

Signed (optional Ed25519 provenance lite):

```json
{
  "version": 1,
  "approved": ["noop", "clock"],
  "key_id": "adapter-ops-1",
  "signature": "<base64 raw 64-byte Ed25519 sig>"
}
```

Optional multi-sig array (same canonical body; **all listed entries must verify**,
and distinct trusted `key_id`s must meet **MinSignatures**):

```json
{
  "version": 1,
  "approved": ["noop", "clock"],
  "signatures": [
    {"key_id": "adapter-ops-1", "signature": "<base64>"},
    {"key_id": "adapter-ops-2", "signature": "<base64>"}
  ]
}
```

**MinSignatures dual-control lite (Wave 45):** when `signatures[]` is non-empty,
verification counts **distinct** trusted `key_id`s that verified successfully
and requires `distinct >= MinSignatures` (default **1**). Set **2** so an
editor who holds only one trusted private key cannot strip other signatures
and still pass. Single-sig top-level `key_id`+`signature` ignores MinSignatures
(always needs exactly one valid signature).

| Setting | Behavior |
|---------|----------|
| MinSignatures=1 (default) | Any one valid multi-sig entry is enough (stripping residual) |
| MinSignatures=2 | Dual-control lite: need 2 distinct trusted signatures |
| MinSignatures &gt; 16 | **Fail closed** at resolve (absolute max) |

**CLI / env:**

| Surface | Name |
|---------|------|
| Env | `JENKINS_MCP_ADAPTER_ALLOWLIST_MIN_SIGNATURES` |
| Flag | `--adapter-allowlist-min-signatures N` (wins over env) |
| API | `adapter.LoadAllowlistFileOpts` / `ResolveAllowlistMinSignatures` |

Empty/0 → 1; invalid or over max → **fail closed**. Meaningful only when the
allowlist uses multi-sig + trusted keys.

**Residual honesty (multi-sig):** MinSignatures is **lite dual-control** (count
of distinct Ed25519 keys), **not** true *t*-of-*n* threshold crypto, cosign,
SBOM, or HSM. With MinSignatures=1, stripping other `signatures[]` entries still
succeeds if one trusted key remains.

**Canonical signing payload:** deterministic JSON of only `{version, approved}`
with `approved` IDs lower-cased/trimmed, de-duplicated, and sorted. Signature
fields are never part of the signed payload.

**Trusted keys (env):** `JENKINS_MCP_ADAPTER_ALLOWLIST_TRUSTED_KEYS` → path to a
JSON trust store `{"keys":[{"key_id":"…","public_key":"<base64 32>"}]}` or a
directory of `key_id.pub` base64 files / JSON stores.

| Mode | Behavior |
|------|----------|
| No trusted keys + unsigned file | Pilot accept (current path) |
| No trusted keys + signature fields present | **Fail closed** (`signature present but no trusted keys configured`) |
| Trusted keys configured + unsigned file | **Fail closed** (serve sets require-signed when keys non-empty) |
| Trusted keys + valid Ed25519 signature | Accept approved IDs |
| Multi-sig + distinct trusted keys &lt; MinSignatures | **Fail closed** |
| Unknown `key_id` / bad signature | **Fail closed** (never log keys/sigs) |

**Residual honesty:** this is **Ed25519 allowlist provenance lite** + **MinSignatures
dual-control lite** only — **not** cosign, SBOM attachment, HSM-backed signing,
full SLSA provenance, or true multi-party threshold crypto. Treat unsigned pilot
allowlists as operator-controlled policy input.

## Lifecycle API (summary)

```text
Adapter: ID | Capabilities | Start(ctx) | Stop(ctx) | Health(ctx)
Registry: RegisterEnabled | StartAll | StopAll | Health | Get
Host:     Now?, Logger?   (no Jenkins)
```

See package docs and tests:

```bash
go test ./internal/adapter/ ./internal/diagnostics/ ./internal/depgraph/ -count=1
```

Coverage includes: disabled-by-default, unknown-id rejection, allowlist deny,
panic isolation on Start/Health/Call, rate-limit hook, core path independence
(`TestCoreJenkinsPathIndependentOfAdapters`), Wave 43 offline self-check
`adapter_framework_residual`, and Wave 44–45 `adapter_allowlist_provenance_lite`
(Ed25519 + MinSignatures dual-control lite; diagnostics → adapter; no import
cycle; adapter stays leaf w.r.t. policy).

## Credentials (future)

When a real integration needs secrets, they must be:

1. Namespaced separately from Jenkins API tokens (keyring scheme residual).
2. Never passed through Jenkins HTTP clients or MCP argv.
3. Redacted from logs, audit, support bundles, and telemetry.

## Related tasks

| ID | Topic |
|----|--------|
| INT-002 | OpenTelemetry correlation lite ([otel-correlate.md](otel-correlate.md)) + export stub ([otel-export.md](otel-export.md)); real OTLP protobuf residual |
| INT-003 | External log-system adapters ([ext-logs.md](ext-logs.md)); SaaS client residual |
| INT-004 | Work-item / source-host correlation ([work-items.md](work-items.md)); ticket API residual |
| POL-004 | Policy PEP at tool middleware (job `Target` from args; shared with core tools). Adapter-specific PEPs beyond that remain residual |
