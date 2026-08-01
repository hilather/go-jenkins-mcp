# Fleet health telemetry — privacy review notes (MGR-002)

**Audience:** security reviewers, privacy, platform owners.  
**Related:** [privacy-data-retention.md](privacy-data-retention.md), [observability](../observability.md), architecture §14

This document is the **privacy review pack** for the MVP fleet health telemetry
export schema. Telemetry is **disabled by default** and must not centralize
Jenkins content.

**Not production-ready for central analytics** without operator / privacy board
review of this schema and export destination. Local queue-only operation is
supported for inspection; remote export is optional and HTTPS-only.

---

## 1. Purpose

Measure adoption, errors, versions, and coarse security posture (policy denials,
auth method enum, read-only gate) **without** shipping logs, prompts, tokens,
artifact bodies, OAuth refresh tokens, Authorization headers, or raw job
parameters.

---

## 2. Enablement (fail closed)

| Control | Default | Notes |
|---------|---------|--------|
| `JENKINS_MCP_TELEMETRY` | **unset / off** | Truthy (`1`/`true`/`yes`/`on`) enables local snapshot + queue |
| `JENKINS_MCP_TELEMETRY_URL` | empty | Optional **HTTPS** POST endpoint; empty ⇒ **local queue only** (no network) |
| Overlay `fleet_telemetry_force_off` | **false** | When **true**, forces telemetry **off** regardless of env (MGR-002). Fail closed: env cannot re-enable while pin is true. Serve applies on load and hot-reload (`Collector.SetForceOff`). Admin pilot apply cannot clear a true pin (monotonic). Self-check: `fleet_telemetry_force_off_residual` (`policy_overlay_pin=true`) |

When disabled, no installation id is required for status, no export runs, and
serve does not start a collector.

When `fleet_telemetry_force_off` is true at serve bootstrap, the collector is
not started even if `JENKINS_MCP_TELEMETRY=1`. When a live collector exists and
reload sets force-off true, snapshots/export stop immediately. Clearing the pin
to false on reload re-allows env enable for a **live** collector; if force-off
was true at bootstrap (collector never started), **process restart** is required
to enable after clearing the pin.

When enabled **without** `JENKINS_MCP_TELEMETRY_URL`, `telemetry status` reports
a residual note: **local queue only (no network export)**.

---

## 3. Export schema (v1) — allowed field list

Package: `internal/telemetry/fleet`. Event type: `health_snapshot` only.

Closed set of top-level JSON keys (`AllowedJSONFields` — keep code + this table
in sync):

| Field | Type | Privacy notes |
|-------|------|----------------|
| `schema_version` | int | Always `1` for this binary |
| `event_type` | string | `health_snapshot` only in MVP |
| `installation_id` | UUID string | Random, stored once under XDG data; **not** derived from hostname; max 64 runes |
| `profile_id_hash` | hex SHA-256 | Optional; raw profile id never exported; non-hex values dropped |
| `version` | string | Binary version; **max 64** runes (oversize clamped/rejected) |
| `os` | string | `runtime.GOOS` (goos); max 32 |
| `arch` | string | `runtime.GOARCH` (goarch); max 32 |
| `auth_method` | enum | `api_token` \| `oidc_bearer` \| `agentcore_delegated` \| `legacy` \| `unknown` |
| `read_only` | bool | Effective global read-only gate |
| `counters` | map[string]int64 | **Allowlisted** metric names only (see below) |
| `error_codes` | map[string]int64 | **Stable `apperr.Code` values only** (error class, not free-text logs) |
| `ts` | RFC3339 | Snapshot time (UTC); max 40 |

Unknown top-level keys are **rejected** at validate time (fail closed).

### Allowlisted counters

`tool_calls`, `mcp_tool_ok`, `mcp_tool_error`, `mcp_tool_deny`,
`jenkins_http_requests_total`, `jenkins_http_errors_total`,
`jenkins_http_wire_bytes_total`, `jenkins_http_decoded_bytes_total`,
`jenkins_circuit_open_events_total`,
`cache_hits`, `mcp_bytes_out`, `duplicate_bytes_avoided`, and the
cache-maintenance counters from OBS-001 (see [observability.md](../observability.md)).
Unknown counter keys (including any free-text or secret-bearing labels) are
**dropped** at snapshot / sanitize time.

### Forbidden (never exported)

| Category | Enforcement |
|----------|-------------|
| Build / stage log text | Not in schema; canary tests |
| Prompts / model text | Not collected |
| API tokens / passwords | Not in schema; canary |
| OAuth refresh tokens | Not in schema; canary |
| Authorization headers | Not attached to export HTTP; not in counters |
| Artifact content | Not collected |
| Raw job parameters maps | Not collected; canary |
| Jenkins URLs with userinfo | Not collected; status shows export **host only** |
| Free-text error messages | Only stable apperr codes as keys |
| Oversize free-form strings | Max lengths at sanitize + `ValidateExportJSON` |

---

## 4. Local queue and storage

| Item | Location | Mode |
|------|----------|------|
| Installation id | `$XDG_DATA_HOME/jenkins-mcp/telemetry/installation_id` | `0600` / dir `0700` |
| Event queue | `…/telemetry/queue.jsonl` | Bounded; drop oldest |
| Last snapshot | `…/telemetry/last_snapshot.json` | For `telemetry show` |

**Bounds (MVP defaults):** max **64** events or **256 KiB** of JSON payloads
(whichever hits first). Overflow drops oldest. Enqueue is non-blocking and never
opens a network connection. Events are sanitized before enqueue.

**Encryption residual:** queue files use filesystem ACLs + `0600` only (same
posture as audit JSONL). Optional AEAD for the queue is residual if policy
requires it.

---

## 5. Exporter behavior

Mirrors gateway `HTTPTokenFetcher` discipline:

| Control | Behavior |
|---------|----------|
| Scheme | **HTTPS only** (`http://` rejected; use TLS in tests) |
| Userinfo | Rejected in export URL |
| Redirects | **Refused** (`CheckRedirect` fail-closed) |
| Request body | Cap **256 KiB** (`MaxExportRequestBodyBytes`) |
| Response body | Drain capped at **64 KiB**; **never** echoed in errors |
| Auth headers | **Never** attach ambient `Authorization` |
| Backoff | Short timeout; exponential backoff on failure (capped) |
| Serve path | **Network failures never fail or block MCP serve** |

Optional `POST` of `{ "schema_version": 1, "events": [ … ] }` to
`JENKINS_MCP_TELEMETRY_URL`. Failed batches are re-queued (may still drop under
bounds).

---

## 6. Operator CLI

```text
jenkins-mcp telemetry status [--json]
jenkins-mcp telemetry show [--json]
```

| Command | Contents |
|---------|----------|
| `status` | enabled?, export URL host (no userinfo), queue depth/bytes/dropped, categories exported vs forbidden, residual notes |
| `show` | Last aggregate snapshot (counters + error codes + read_only only) |

Residual notes include:

- enterprise `fleet_telemetry_force_off` overlay pin is **wired** (env cannot re-enable while true)
- central analytics requires operator privacy review
- when enabled without export URL: **local queue only**
- HSM / true multi-sig t-of-n policy residual unchanged

---

## 7. Residuals

- [x] In-process ForceOff lite (`CollectorConfig.ForceOff`, `EffectiveEnabled(true)`) — offline self-check `fleet_telemetry_force_off_residual` (Wave 46)
- [x] Enterprise overlay `fleet_telemetry_force_off` pin (serve load + hot-reload `SetForceOff`; show-effective / admin surfaces) — Details `policy_overlay_pin=true` (**lite**; not full production multi-sig/HSM claim)
- [ ] Formal privacy board sign-off of this schema before broad production enablement
- [ ] Optional queue AEAD / OS keyring-bound keys
- [ ] Per-tool cardinality-safe histograms (not free-text tool args)
- [ ] SIEM / remote retention SLA mapping
- [ ] HSM / true multi-sig t-of-n signed-bundle residual (MGR-001; separate from ForceOff pin)
- [ ] **Do not claim central analytics production-ready** without the above
- [ ] **Do not claim full MGR-002 production pin** (privacy board + formal enterprise distribution remain residual)

---

## 8. Verification canaries

```bash
export PATH="$HOME/.local/go/bin:$PATH"
go test ./internal/telemetry/ ./internal/telemetry/fleet/ ./cmd/jenkins-mcp/ -count=1
go test ./internal/telemetry/fleet/ -count=1 -run 'Canary|Oversize|HTTPS|Redirect|TLS'
go test ./internal/diagnostics/ ./internal/depgraph/ -count=1 -run 'SecuritySelfCheck|Boundaries'
```

Canaries plant sample API tokens, Authorization header values, job log text,
job parameter maps, and OAuth refresh tokens into metric labels / event fields
and assert they never appear in queue or export JSON.

Offline security self-check (QA-005 / MGR-002):

| Item | Proves |
|------|--------|
| `telemetry_default_off` | Ambient env not truthy (default off); warns if enabled |
| `fleet_telemetry_force_off_residual` | ForceOff + overlay pin: `EffectiveEnabled(true)` false; collector with `ForceOff` nil even when `Enabled=true`; overlay `fleet_telemetry_force_off` + ExplainEffective; `policy_overlay_pin=true` |

---

## Revision

| Date | Change |
|------|--------|
| 2026-08 | MGR-002 MVP: schema v1, local queue, optional HTTPS export, CLI |
| 2026-08 | Wave 20 polish: read_only, field caps, https-only/no-redirect/body caps, stronger canaries |
| 2026-08 | Wave 46: offline self-check `fleet_telemetry_force_off_residual` (ForceOff lite; signed-policy pin residual) |
| 2026-08 | MGR-002 ForceOff overlay lite: `fleet_telemetry_force_off` field, serve wire + hot-reload, show-effective/admin; `policy_overlay_pin=true` |
