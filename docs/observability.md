# Observability (AUD-001 / OBS-001)

Local privacy-preserving audit and structured diagnostics for the pilot binary.
Build-metadata OTEL **correlation lite** is **INT-002** (`internal/otelx`, optional
`--enable-adapter=otel-correlate`). Remote OTLP export / backend query remains residual.

## Audit (AUD-001)

Package: `internal/audit`.

**Agent rule:** security-relevant code paths must emit AUD-001 events (or document an
**AUD-T-*** residual). See root `AGENTS.md` → *Non-negotiable: audit trails when
security-relevant* and [security/audit-trail-review.md](security/audit-trail-review.md).

| Sink | Use |
|------|-----|
| `Memory` | Tests (ordered in-memory events; **no** type filter unless wrapped) |
| `File` | JSONL under `$profileDataDir/audit/audit.jsonl` (mode **0600**, dir **0700**) |
| `ReloadingFilterSink` | Wraps File via `OpenProfileSink`; drops disabled types; reloads `audit/type_filter.json` on mtime |
| `Nop` | Disabled / missing data dir |

### Event type catalog and operator enable/disable

| Piece | Role |
|-------|------|
| `audit.KnownEventTypes()` | Catalog SoT (`internal/audit/types_catalog.go`) — **extend when adding types** |
| `DefaultTypeFilter()` | Defaults when `type_filter.json` missing; `tool_success` off unless `JENKINS_MCP_AUDIT_TOOL_OK` truthy |
| `type_filter.json` | Per-profile under `$profileDataDir/audit/`; written by admin PUT settings |
| Admin BFF | `GET`/`PUT /admin/v1/profiles/{id}/audit/settings` (`gateway_ops` on write) |
| Admin SPA | Audit page **Event type settings** toggles (enable all / disable all / save) |

Agents: new security-relevant operations must emit AUD-001 **and** register new types in the catalog so operators can toggle them. See root `AGENTS.md`.

### Event schema (v1)

Stable fields only — **no** prompts, log bodies, job parameters, tokens, or Authorization headers:

| Field | Notes |
|-------|--------|
| `time` | RFC3339 UTC |
| `type` | Catalog SoT: `audit.KnownEventTypes()` — `login_*`, `serve_start`, `tool_*`, `auth_fail`, `audit_settings`, `policy_validate`/`policy_apply`, `admin_cache_evict`/`admin_support_bundle`/`admin_subject_invalidate`/`admin_consent_purge`/`admin_fleet_cache_purge`, `mutation_*` (high-volume `tool_success` filter-default off) |
| `profileId` | Connection profile id |
| `principalId` | Verified Jenkins user id (never a token) |
| `externalSubject` | Optional IdP subject label (gateway multi-user); redacted + length-capped like `principalId` — never a token |
| `subjectKeyHash` | Optional `audit.HashOpaque(tenant\|subject\|profile)` for multi-user correlation — **never** raw subject key, vault material, or tokens |
| `tool` / `action` | MCP tool name / short class |
| `decision` | `allow` / `deny` / `success` / `fail` / `error` |
| `reasonCode` | Stable code (policy reason, auth code) |
| `durationMs` | Optional |
| `bytesIn` / `bytesOut` | Optional counters (not content) |
| `requestId` | Optional correlation id |
| `targetHash` | Optional SHA-256 prefix of high-cardinality targets (`audit.HashOpaque`) |
| `schemaVersion` | `1` |

### Emit points (wired)

- `login` success / fail (profile data dir)
- `serve` start after identity bind; `auth_fail` on serve-time verify failure
- Tool dispatch **deny** (global read-only + deny-only MCP RBAC) and **tool_error**
  (handler / budget / subject limiter failures): multi-user tool dispatch
  attributes `profileId` / `principalId` from **effective** subject when wired,
  plus optional `externalSubject` + `subjectKeyHash` (opaque) when SubjectKey /
  ExternalSubject are available. Metrics tool_ok / tool_deny / tool_error remain
  separate (OBS-001). `tool_error` audit reason is the stable `apperr` code only
  (never ModelMessage / tokens).
- **tool_success** audit: emit always attempts; **persistence** defaults off via
  type filter (`tool_success` disabled unless `JENKINS_MCP_AUDIT_TOOL_OK`
  seeds defaults or operator enables via admin Audit settings). High volume.
  Metrics `mcp_tool_ok` always record regardless.
- **Mutation Manager** (`mutation_preview` / `mutation_confirm` / `mutation_deny`):
  ProfileID/PrincipalID from effective `mutation.Binding`; when Binding has
  ExternalSubject also `externalSubject` + `subjectKeyHash` =
  `audit.HashOpaque(tenant|external|profile)`. Never confirmation tokens or raw keys.
- Mid-serve **identity re-verify** fail-closed (`IdentityReverifyGate`, AUTH-004 / Wave 28):
  - `type=auth_fail`, `action=identity_reverify`, `decision=fail`
  - `reasonCode`: `identity_principal_drift` | `identity_reverify_fail` | `identity_unbound`
  - `principalId`: serve-time **bound** Jenkins user id only (never unexpected whoAmI id or tokens)
  - At most **one event per reason class** per gate lifetime (sticky transition / first 401-class fail — no flood on sticky re-Check)

Audit emit is **best-effort**: failures never authorize mutations and never elevate access.

### Multi-user correlation residual

| Surface | Status |
|---------|--------|
| Per-process tool_deny attribution (`externalSubject`, `subjectKeyHash`) | **implemented foundation |
| Per-process tool_error attribution (same multi-user identity fields) | **implemented foundation |
| tool_success audit (default filter off; admin toggle or `JENKINS_MCP_AUDIT_TOOL_OK` seed) | **implemented volume residual (opt-in persist) |
| Per-process mutation preview/confirm/deny attribution (`externalSubject`, `subjectKeyHash`) | **implemented foundation |
| Admin SPA audit table columns + type filter (`externalSubject` / `subjectKeyHash`; BFF `external_subject` exact match + client residual) | **implemented lite (same-host BFF filter; multi-pod aggregation still residual) |
| Admin SPA **event type enable/disable** (`…/audit/settings` + `type_filter.json` + ReloadingFilterSink) | **implemented lite (per-host file; multi-pod residual) |
| Admin BFF **same-host rotated sibling merge** (`ReadAuditFile` merges `audit.jsonl` + `audit.jsonl.N` / optional timestamped names) | **implemented lite — multi-user correlation more complete on one host after rotation |
| Multi-pod / multi-replica **audit aggregation** (central sink, fleet timeline) | **Residual** (HOST-008 checklist row 5) — per-pod / per-host JSONL only; no fleet merge |
| Shared durable vault + sticky sessions under multi-replica | **Residual** (see `docs/gateway/deployment.md` §9) |
| Subject quota metrics (`mcp_subject_rate_quota` / `mcp_subject_slot_quota`) | **implemented lite** process-local (HOST-006 CodeQuota); multi-pod metric aggregation residual |

### Rotation / retention

- Default max active file size: **8 MiB**, keep **3** rotated siblings (`audit.jsonl.1` …).
- Retention is size-based for the pilot; enterprise export/retention policy is residual.
- **Admin audit list (same-host lite):** `GET /admin/v1/profiles/{id}/audit` merges the active file with numbered rotates (`audit.jsonl.1` …) and optional timestamp-like siblings next to the active path; newest matching events first; corrupt lines skipped. **Not** multi-pod aggregation.

### Remote SIEM / syslog / Splunk (residual)

| Capability | Status |
|------------|--------|
| Local JSONL file sink + `audit.Multi` fan-out interface | **implemented |
| In-process **syslog** / **Splunk HEC** / webhook audit ship | **Residual** — not implemented (backlog **AUD-T-010…012** in [security/audit-trail-review.md](security/audit-trail-review.md)) |
| Host agent tail of `audit.jsonl` (Fluent Bit, Splunk UF, rsyslog `imfile`, Vector) | **Operator-owned** near-term path (runbook **AUD-T-013**) |
| `ext-logs` adapter (query external logs for Jenkins jobs) | **Separate** INT-003 — not audit export; real Splunk/ELK *clients* residual |

Industry mapping + task backlog: **[security/audit-trail-review.md](security/audit-trail-review.md)**.

## Metrics & logging (OBS-001)

Package: `internal/telemetry`.

### Structured logger

- JSON lines to **stderr** with `ts`, `level`, `msg`, plus low-cardinality fields.
- All string values pass through `internal/redact.Secrets`.
- Levels: `debug`, `info`, `warn`, `error` (default min = `info`).

### Serve log level (pilot offline analysis)

| Control | Value |
|---------|-------|
| Flag `--log-level` | Wins over env (`debug` \| `info` \| `warn` \| `error`) |
| Env `JENKINS_MCP_LOG_LEVEL` | Fallback when flag unset |
| Default | `info` |
| Invalid value | Fail closed at serve start |

At serve start the process builds a `telemetry.Logger` at the resolved min level
(fields `component=serve`, `profile=<id>` when known) and attaches it to:

1. Global registry (`telemetry.SetGlobal`) — maintenance / optional fleet paths  
2. Tool registration (`RegisterOptions.Logger`) — **tool dispatch** lines  

**Tool dispatch structured messages** (never args, tokens, job parameters, or log bodies):

| Level | `msg` | When |
|-------|--------|------|
| debug | `tool_dispatch_start` | Every tool call (tool name + effect only) |
| debug | `tool_dispatch_ok` | Successful handler + budget enforce (`duration_ms`) |
| warn | `tool_dispatch_deny` | RO / RBAC / session gate denial (`reason` code) |
| error | `tool_dispatch_error` | Handler/budget/session failure (`error_code` + ModelMessage) |

Also at **info**: `serve_observability_ready`, `mcp_transport_start`, clean `mcp_server_stopped`.  
Stdio server failures return an error to the CLI (no longer swallowed) and emit
`mcp_server_stopped` at **error** with `error_code` / redacted `error`.

**Capture for pilot tickets** (secret-free by design when using these paths):

```bash
jenkins-mcp serve --profile corp --stdio --read-only --log-level=debug \
  2> pilot-serve.stderr
# Human startup lines + JSON structured lines interleave on stderr.
```

Residual: many bootstrap status lines still use `log.Printf` (redacted via
`redact.NewWriter`); they are not JSON. Prefer `--log-level=debug` tool lines
for per-call offline analysis.

### Serve standard-library log hygiene (KD-004)

`serve` still uses many `log.Printf` sites for process startup status. At the
start of `runServe`, the binary installs:

```text
log.SetOutput(redact.NewWriter(os.Stderr))
```

so accidental token-shaped payloads (Bearer, `api_token=`, known detectors, and
**unlabeled high-entropy** hex/base64url via `CategoryBareToken`) are scrubbed
before they hit stderr. Username / principal id lines remain visible.

| Helper | Package | Role |
|--------|---------|------|
| `redact.NewWriter` | `internal/redact` | Line-buffered `io.Writer`: reassembles incomplete lines across Writes, runs `RedactText` on each complete line (and on Flush/Close remainder) |
| `telemetry.SafeServeLog` | `internal/telemetry` | format → redact → `log.Output` (explicit safe sites) |

Prefer `telemetry.Logger` for **new** structured diagnostics.

**Bare-token heuristic (Wave 25 / KD-004):** after labeled detectors, `RedactText`
scrubs maximal runs of `[A-Za-z0-9_+\-=]` that look high-entropy:
single-case pure hex ≥40 (nibble diversity); mixed-case pure hex ≥32; mixed
base64url-like ≥32 with ≥2 char classes / unique floor; shorter ≥24 only with
≥3 classes. `/` is excluded so `folder/job-name` paths do not merge. W3C
`trace_id` (exactly 32 lowercase hex) is preserved by design. Residual FP: full
git SHA-1/256 may redact. Residual FN: single-case 32–39 hex unlabeled tokens,
characters outside the alphabet, secrets that only reassemble across a
`redact.Writer` force-flush at 256 KiB pending without `\n` (normal multi-Write
log lines are reassembled). Do not print credentials intentionally.

**Writer line buffering (Wave 33 / KD-004 residual):** `redact.Writer` holds
bytes after the last `\n` until a later Write completes the line, or until
`Flush`/`Close`. Complete lines are redacted before the underlying write.
Concurrent `Write`/`Flush`/`Close` are mutex-serialized. On success `Write`
returns `n == len(p)` even when data remains buffered.

**Offline security self-check canary (Wave 34 / QA-005):** item
`writer_split_line_canary` plants an `Authorization: Bearer` token split across
two `Write` calls and asserts the canary is absent after `Flush` (same line
buffer as serve `log.SetOutput`). Overall report plant (`report_canary_leak`)
must never serialize the canary into JSON/text.

**Offline security self-check canary (Wave 38 / MCP-001):** item
`hard_max_resolve_residual` asserts `ResolveHardMaxBytes("", "")` equals
`DefaultHardMaxBytes` and that values above `AbsoluteMaxHardMaxBytes` (64 MiB)
fail closed. Serve logs only byte counts
(`hard_max_bytes=… serve_bootstrap_ceiling=… target_bytes=…`); never secrets.

**Offline security self-check canaries (Wave 39 / POL-004 + Wave 40 polish):**
pure policy package checks (no tools import cycle):
`listfilter_deny_only_residual` (`NameDeniedByPatterns` empty→false;
`Deny*FromEvaluator` copy-out for **nodes / jobs / views / artifacts / branches**
— documents list-row privacy helpers exist) and `policy_resource_deny_residual`
(`DocumentFromOverlay` copies `deny_view_names` / `deny_artifact_paths` /
`deny_branch_names` / `deny_node_names` without elevating; empty overlay ok).
Details are secret-free bools only.

**Offline security self-check canary (Wave 42 / MGR-001):** item
`policy_multisig_lite_residual` generates ephemeral dual Ed25519 keys (never
reported), verifies multi-sig lite `MinSignatures=2` (2-of-2 ok, 1-of-2 fail
closed), and sets Details `multi_sig_lite=true`, `residual_true_threshold=false`,
`residual_hsm=false`. Does not implement true *t*-of-*n* threshold crypto or HSM.

**Offline security self-check item (Wave 43 / MCP-001; Wave 44 body bytes; Wave 45
HTTP + identity TTL; Wave 46 NET-003 resilience; Wave 47 soft target; Wave 48
absolute retries/circuit + open duration; Wave 49 circuit open min/absolute +
MaxConcurrent honesty; Wave 50 absolute concurrent + backoff honesty; Wave 51
survey/diagnose hard ceilings; Wave 52 backoff resolve bounds + mutation
honesty; Wave 53 mutation resolve bounds):** item
`operator_caps_snapshot` reports a secret-free integer/bool map of process
operator caps from tools getters (`ListJobsCollectMaxPages`,
`NodesCollectMaxPages`, `ViewsCollectMaxPages`, `ArtifactsHardCap`) and
`jenkins.ArtifactListBodyBytes()` plus absolute ceilings
(`AbsoluteMaxHardMaxBytes`, `AbsoluteMaxArtifactsHardCap`,
`AbsoluteMaxArtifactListBodyBytes`, collect absolute max pages) and defaults
(`default_artifacts_list_body_bytes`, etc.). Offline hard-max uses
`DefaultHardMaxBytes` + `AbsoluteMaxHardMaxBytes` only
(`live_hard_max_available_offline=false` — mid-serve `LiveHardMax` is not
available without serve). Wave 47 soft target offline constants:
`default_target_bytes` (64 KiB) + `absolute_max_target_bytes` (64 MiB =
`AbsoluteMaxHardMaxBytes`) with `live_target_bytes_available_offline=false` (no
process-level live soft-target getter offline; serve resolves via
`--target-bytes` / `JENKINS_MCP_TARGET_BYTES`; soft still clamped to live hard
max at enforce). Wave 45 also reports package
constants only: `default_http_max_body_bytes` / `absolute_max_http_max_body_bytes`
(`mcpserver.DefaultMaxBodyBytes` 4 MiB / `AbsoluteMaxBodyBytes` 16 MiB) and
identity re-verify TTL bounds in seconds (`min_identity_reverify_ttl_seconds`,
`max_identity_reverify_ttl_seconds`, `default_identity_reverify_ttl_seconds` from
`auth.MinIdentityReverifyTTL` / `MaxIdentityReverifyTTL` /
`DefaultIdentityCacheTTL`). Wave 46–50 Track B report Jenkins NET-003 resilience
package constants only: `default_max_json_body_bytes` /
`absolute_max_json_body_bytes` (`jenkins.DefaultMaxJSONBodyBytes` 32 MiB /
`AbsoluteMaxJSONBodyBytes` 128 MiB), `default_max_retries` /
`absolute_max_retries` (`jenkins.DefaultMaxRetries` = 2 extra GET/HEAD attempts;
0 would disable auto-retry; `AbsoluteMaxRetries` = 10),
`default_circuit_failure_threshold` / `absolute_max_circuit_failure_threshold`
(`jenkins.DefaultCircuitFailureThreshold` = 5 /
`AbsoluteMaxCircuitFailureThreshold` = 50),
`default_circuit_open_duration_seconds`
(`int(jenkins.DefaultCircuitOpenDuration.Seconds())` = 15), Wave 49
`min_circuit_open_duration_seconds` (`MinCircuitOpenDuration` = 1s) /
`absolute_max_circuit_open_duration_seconds` (`AbsoluteMaxCircuitOpenDuration` =
5m = 300s), MaxConcurrent honesty: `default_max_concurrent` = 0 with
`max_concurrent_unlimited_default=true` (0 means unlimited, not a missing
value), Wave 50 `absolute_max_concurrent` (`jenkins.AbsoluteMaxConcurrent` =
256 — positive ceiling when a semaphore is installed; default remains
unlimited), and retry backoff honesty:
`default_initial_backoff_ms` (`int(jenkins.DefaultInitialBackoff.Milliseconds())`
= 100) / `default_max_backoff_ms`
(`int(jenkins.DefaultMaxBackoff.Milliseconds())` = 5000). Wave 52 Track B adds
Wave 51 resolve bounds (ms integers only): `min_initial_backoff_ms` = 10 /
`absolute_max_initial_backoff_ms` = 2000 / `min_max_backoff_ms` = 100 /
`absolute_max_max_backoff_ms` = 60000, validated as min ≤ default ≤ absolute for
both initial and max with absolute max ≥ absolute initial. Wave 52 also reports
mutation package honesty (offline constants only; no live Manager):
`default_mutation_confirm_cooldown_ms` = 5000 /
`default_mutation_max_previews_per_minute` = 30 /
`default_mutation_token_ttl_ms` = 120000 (cooldown < token TTL). Wave 53 Track B
adds Wave 52 mutation operator-resolve bounds (offline package constants only):
`min_mutation_confirm_cooldown_ms` = 1000 (`mutation.MinConfirmCooldown` 1s) /
`absolute_max_mutation_confirm_cooldown_ms` = 300000
(`mutation.AbsoluteMaxConfirmCooldown` 5m) /
`absolute_max_mutation_max_previews_per_minute` = 300
(`mutation.AbsoluteMaxPreviewsPerMinute`), validated as
min ≤ default ≤ absolute for confirm cooldown and
1 ≤ default max previews ≤ absolute. Wave 53 Track A TokenTTL bounds offline:
`min_mutation_token_ttl_ms` (10s) / `absolute_max_mutation_token_ttl_ms` (15m)
with min ≤ default ≤ absolute. Wave 51 Track B
survey/diagnose package hard ceilings (offline constants only; no serve flags):
`default_survey_max_total_builds` / `hard_survey_max_total_builds` (30 / 100),
`default_survey_max_jobs` / `hard_survey_max_jobs` (10 / 25),
`default_survey_max_log_bytes_total` / `hard_survey_max_log_bytes_total`
(1 MiB / 4 MiB), `default_survey_max_wall_seconds` /
`hard_survey_max_wall_seconds` (30 / 120),
`default_diagnose_log_bytes` / `hard_diagnose_log_bytes` (128 KiB / 512 KiB),
`default_diagnose_max_findings` / `hard_diagnose_max_findings` (10 / 25).
No live serve HTTP body, gate TTL, client circuit, concurrency semaphore, or
mutation Manager state offline (honesty like `live_hard_max_available_offline`).
Detail keys also include `artifacts_list_body_bytes`,
`default_artifacts_list_body_bytes`, `absolute_max_artifacts_list_body_bytes`.
Message: `operator caps snapshot (secret-free integers)`. No env token values.

### Core counters / gauges (Wave 24–27 OBS-001)

Low cardinality only — **no** free-form tool-name labels, job names, URLs, or
secrets. Constants live in `internal/telemetry` (`Metric*`).

| Name | Meaning | Wired by |
|------|---------|----------|
| `tool_calls` | MCP tool **dispatch attempts** (ok + error + deny) | `tools.addTool` |
| `mcp_tool_ok` | Handler completed (budget enforced) without error | `tools.addTool` |
| `mcp_tool_error` | Handler or budget returned an error (non-deny) | `tools.addTool` |
| `mcp_tool_deny` | RO / MCP RBAC / session-gate denial (registration or dispatch) | `tools.emitToolDeny` |
| `mcp_subject_rate_quota` | HOST-006 subject **rate** CodeQuota (token-bucket `Allow` deny) | `tools.addTool` (subject rate path) |
| `mcp_subject_slot_quota` | HOST-006 subject **concurrent slot** CodeQuota (`Hold` deny) | `tools.addTool` (subject limiter path) |
| `jenkins_http_requests_total` | Upstream HTTP attempts that reached `Do` (incl. retries) | `jenkins.Client` via `MetricsHook` |
| `jenkins_http_errors_total` | Transport failure or HTTP status ≥ 400 | `jenkins.Client` via `MetricsHook` |
| `jenkins_http_wire_bytes_total` | Encoded response bytes read from the wire | `MetricsHook` + `ByteCounters` |
| `jenkins_http_decoded_bytes_total` | Decoded body bytes (identity ⇒ same as wire) | `MetricsHook` + `ByteCounters` |
| `jenkins_circuit_open_events_total` | Circuit breaker **transitions into open** (NET-003 / Wave 27) | `MetricsHook.IncCircuitOpenEvent` via resilience |
| `cache_hits` | Cache hits (stub hook residual) | — |
| `mcp_bytes_out` | Optional MCP response bytes | residual |
| `duplicate_bytes_avoided` | Optional progressive-log dedupe | residual |
| `cache_maint_ticks` | Serve-time cache maintenance cycles (ARC-007 residual) | `app.Maintainer` |
| `cache_evict_items` | Objects removed by eviction / journal recovery | `app.Maintainer` |
| `cache_evict_bytes_reclaimed` | Estimated physical bytes reclaimed | `app.Maintainer` |
| `cache_packs_created` | L1→L2 packs published by background compaction | `app.Maintainer` |
| `cache_usage_bytes` | Gauge: last-seen total physical L1+L2 | `app.Maintainer` |
| `cache_quota_bytes` | Gauge: effective total quota | `app.Maintainer` |

**Aliases (same string value):** `MetricPolicyDenials` → `mcp_tool_deny`;
`MetricJenkinsRequests` → `jenkins_http_requests_total`;
`MetricBytesWire` → `jenkins_http_wire_bytes_total`.

**Subject quota (HOST-006 / OBS residual lite):** `mcp_subject_rate_quota` and
`mcp_subject_slot_quota` increment on CodeQuota from subject rate `Allow` or
slot `Hold` (also counted in `mcp_tool_error`). Process-local totals only —
**never** subject keys, principal ids, or tokens as labels. Multi-pod
aggregation residual (HOST-008); optional same-host file rate does not change
the metric surface.

**Circuit breaker state (Wave 27):** current state is **not** a labeled time
series. Doctor check `circuit_breaker` reports `Client.CircuitState()` when a
client is wired (`DoctorOptions.Circuit`); offline CLI doctor without a live
client **skips** the check. Open events are the only circuit counter (one
increment per open episode, including re-open after a failed half-open probe).

**Package boundary:** `internal/jenkins` defines `MetricsHook` only (no import of
`telemetry`). Serve wires `client.WithMetrics(tools.JenkinsMetricsHook(metrics))`.
Tools receive `RegisterOptions.Metrics` and count outcomes in the `addTool` wrapper.

`Registry.Snapshot()` returns a copy for `doctor` / `status` / support bundles
(**OPS-001**). Fleet export allowlists the same closed name set
([security/fleet-telemetry.md](security/fleet-telemetry.md)).

Prefer `context` values (`audit.WithSink`, `telemetry.WithRegistry`) over globals.
`telemetry.SetGlobal` is only a serve-process fallback.

## MCP protocol matrix evidence (FND-006)

Offline (no Cursor binary, no Docker) protocol matrix tests exercise Initialize,
ListTools, CallTool (success / invalid_argument / unknown / cancel) and loopback
Streamable HTTP Initialize/ListTools:

```bash
go test ./internal/tools/ ./internal/mcpserver/ -count=1 -run 'ProtocolMatrix|MCPProtocolMatrix'
```

Protocol versions and SDK pin: ADR [0006](adr/0006-mcp-go-sdk.md). Packaging /
operator residual: **Cursor host stdio CI** still open — see
[packaging.md](packaging.md) § MCP protocol pin and offline matrix.

## Doctor, cache status, support bundle (OPS-001)

| Surface | Command / tool | Notes |
|---------|----------------|--------|
| Doctor | `jenkins-mcp doctor --profile <id> [--offline] [--json] [--allow-mutations] [--read-only]` · MCP `jenkins_doctor` · admin `GET …/doctor?offline=1` | Local checks; never returns secrets; `mutations` reports register vs executable posture (Wave 32); `circuit_breaker` when client wired; optional pack verify (ARC-008). **`gateway_residual_status`**: embeds the same secret-free map as `gateway residual-status` / `BuildGatewayResidualStatus` (informational; does not drive overall fail; live `mode_*_qualified` stay false; pointer to [gateway/live-pin-blockers.md](gateway/live-pin-blockers.md)). Prefer `--json` for machine parse; text surfaces a `gateway_residual_status:` section. Requires `--profile` (no profile-less offline doctor). |
| Cache status | `jenkins-mcp cache status --profile <id>` | L1 store schema / counts only |
| Cache verify | `jenkins-mcp cache verify --profile <id> [--full] [--sample N]` | ARC-008 integrity; issue kinds pack/entry/checksum/catalog/index; support-safe |
| Cache repair | `jenkins-mcp cache repair --profile <id> [--index-only]` | Rebuild sidecar indexes only after pack verify; never mutates pack body |
| Support bundle | `jenkins-mcp support-bundle --profile <id> [--preview]` · `doctor --bundle` / `--bundle-preview` | Privacy-scrubbed zip under XDG cache. Always includes top-level **`gateway-residual-status.json`** (`BuildGatewayResidualStatus` + same sanitize as doctor) so residual honesty is present even when doctor fails or a prebuilt doctor report omits the nest. `doctor.json` also embeds `gateway_residual_status` when doctor ran successfully. Never tokens/subjects; live `mode_*_qualified` stay false; `ha_multi_replica` false; pointer to [gateway/live-pin-blockers.md](gateway/live-pin-blockers.md). |

### Support bundle path and redaction

- **Default path:** `$XDG_CACHE_HOME/jenkins-mcp/support-bundles/<profileId>/support-bundle-<id>-<timestamp>.zip` (file mode **0600**, dir **0700**).
- **Included (OPS-001 / Wave 23):** manifest, binary version/build, effective profile **without secrets**, doctor report, cache status, optional capability summary, metrics snapshot, recent error signature hashes (optional `ExtractCandidates` from a size-capped in-memory sample only — raw sample never zipped), `GOOS`/`GOARCH`/Go version, offline `security_self_check.json`, diagnostics-local `release_evidence_lite.json` (version/runtime only), offline `rs_qualification_summary.json`, always-on **`gateway-residual-status.json`** (unified residual honesty — same map as CLI `gateway residual-status` / doctor embed; independent of doctor success).
- **Explicitly excluded:** API tokens, keyring material, full build logs, raw log samples, artifact bodies, cookies, `Authorization` headers, private keys, raw HTTP transcripts, cache encryption keys.
- **Before write:** CLI prints included and excluded category lists (also with `--preview` / `--bundle-preview`, which write nothing).
- **Scrubbing:** secret-like JSON keys dropped; string values pass `redact.Secrets`; canary tests plant a token in keyring + capability map (+ log sample) and assert it never appears in the zip. Residual status map is additionally sanitized via the same `sanitizeResidualStatusMap` path as doctor.
- Doctor embedded in the bundle defaults to **offline** (no whoAmI) for the standalone `support-bundle` command.
- Wave 23 offline members default **on**; callers may disable via `SupportBundleOptions` include flags (`IncludeSecuritySelfCheck`, `IncludeReleaseEvidenceLite`, `IncludeRSQualification`). **`gateway-residual-status.json` is not optional** (always written for residual honesty).

### Health / queue diagnose tools (related)

| Tool | Task | Notes |
|------|------|--------|
| `jenkins_get_nodes` / `jenkins_get_node` / `jenkins_queue_pressure` | HEALTH-001 | Executor + queue depth |
| `jenkins_controller_health` | HEALTH-002 | Version, capability shortlist, queue/node summary, quiet-down |
| `jenkins_explain_queue_delay` | DIAG-007 | Why delayed; ETA always labeled **heuristic** (seconds omitted when unsupported) |

### Serve-time cache maintenance logs

Structured JSON on stderr (redacted): `cache_evict_applied`, `cache_evict_journal_recovered`,
`cache_compaction_packed`, `cache_compaction_skipped` with low-cardinality fields only
(`items`, `bytes_reclaimed`, `packs`, `members`, `reason`). Never log job names from
maintenance paths that could carry sensitive CI metadata in future extensions—prefer counts.

### Doctor check: `mutations` (Wave 32 / POL-001 + Wave 30)

Operators need visibility when mutation tools may be **registered** under
`--allow-mutations` while still **not executable** because effective read-only
is on (e.g. enterprise `force_read_only`). Doctor check name: **`mutations`**.

| Detail field | Meaning |
|--------------|---------|
| `read_only_effective` | `ReadOnlyGate.Effective()` |
| `allow_mutations_opt_in` | `--allow-mutations` / `Inputs.AllowMutations` |
| `mutations_should_register` | `ShouldRegisterMutations()` (register even under force when opt-in) |
| `mutations_executable` | `AllowMutationRegistration()` (`!Effective`) |
| `mutation_tool_catalog_count` | Catalog size only (non-secret); **does not** list tool names or schemas |
| `sources` | Same RO source ids as `read_only` check |

| Status | When |
|--------|------|
| **ok** | Mutations registered **and** executable (allow-mutations; no stronger RO) |
| **warn** | Registered under force/RO + allow-mutations but **not** executable until force/RO clears |
| **skip** | Pilot default RO / no allow-mutations — mutations not registered (expected) |

CLI: pass the same `--allow-mutations` / `--read-only` flags as serve to mirror
process posture. Serve wires `jenkins_doctor` with the **live** `ReadOnlyGate`
(so `DynamicForce` clear is visible without restart). Never prints secrets or
mutation tool argument schemas.


## Fleet health telemetry (MGR-002)

Package: `internal/telemetry/fleet`. **Disabled by default.**

| Control | Env |
|---------|-----|
| Enable | `JENKINS_MCP_TELEMETRY=1` |
| Export URL (optional HTTPS POST) | `JENKINS_MCP_TELEMETRY_URL` |

| CLI | Purpose |
|-----|---------|
| `jenkins-mcp telemetry status` | Enabled?, categories, queue depth (secret-free) |
| `jenkins-mcp telemetry show` | Last aggregate counter snapshot |

Local bounded queue under `$XDG_DATA_HOME/jenkins-mcp/telemetry/`. Network failures never affect MCP serve. Full privacy notes: [security/fleet-telemetry.md](security/fleet-telemetry.md).

## OpenTelemetry correlation lite (INT-002)

Package: `internal/otelx`. **Disabled by default.**

| Surface | When |
|---------|------|
| Adapter `otel-correlate` | `serve --enable-adapter=otel-correlate` |
| Tool `jenkins_get_trace_refs` | Registered when adapter enables `EnableTraceRefs` |
| Diagnose field `trace_refs` | Same flag; uses build parameters already fetched |

Extracts only well-known keys (`TRACEPARENT`, `TRACE_ID`, `OTEL_*`, `dd.trace_id`, …)
from Jenkins build parameters. Does **not** send log text to telemetry, does **not**
export OTLP, does **not** query remote collectors. Details and key list:
[adapters/otel-correlate.md](adapters/otel-correlate.md).

## MCP transport observability notes

| Transport | Logging | Risks / residual |
|-----------|---------|------------------|
| **stdio** (default) | MCP RPC traffic via SDK `LoggingTransport` → **stderr**; structured app logs also stderr (redacted) | Host owns process lifecycle; no listening port |
| **Streamable HTTP** (`--http`) | Start/stop on stderr: bind address, `loopback_enforced`, `max_body`, `http_token_required`, `http_token_configured` (bools only) | Loopback/origin/body/Host protections in `internal/mcpserver`; shared-secret optional on loopback unless `--http-require-token` / `JENKINS_MCP_HTTP_REQUIRE_TOKEN` / `JENKINS_MCP_HTTP_DENY_ANONYMOUS` (alias) or non-local (KD-008 residual: not per-user; deny-anonymous off by default). Offline self-check: `http_require_token_residual` (non-local empty-token fail-closed + loopback residual warn naming those envs); `http_allowed_hosts_residual` (non-local empty AllowedHosts fail-closed independent of token). Do not scrape HTTP MCP ports into multi-tenant monitoring without gateway auth |

HTTP request body oversize and forbidden Host/Origin return HTTP 4xx without processing tool dispatch. Prefer stdio metrics (`tool_calls` / `mcp_tool_*`, audit JSONL) over treating the optional HTTP port as a production SLI surface. HTTP serve logs `http_token_required` / `http_token_configured` (bool only — never the secret).



## Audit (AUD-001)

Package: `internal/audit`.

**Agent rule:** security-relevant code paths must emit AUD-001 events (or document an
**AUD-T-*** residual). See root `AGENTS.md` → *Non-negotiable: audit trails when
security-relevant* and [security/audit-trail-review.md](security/audit-trail-review.md).

| Sink | Use |
|------|-----|
| `Memory` | Tests (ordered in-memory events; **no** type filter unless wrapped) |
| `File` | JSONL under `$profileDataDir/audit/audit.jsonl` (mode **0600**, dir **0700**) |
| `ReloadingFilterSink` | Wraps File via `OpenProfileSink`; drops disabled types; reloads `audit/type_filter.json` on mtime |
| `Nop` | Disabled / missing data dir |

### Event type catalog and operator enable/disable

| Piece | Role |
|-------|------|
| `audit.KnownEventTypes()` | Catalog SoT (`internal/audit/types_catalog.go`) — **extend when adding types** |
| `DefaultTypeFilter()` | Defaults when `type_filter.json` missing; `tool_success` off unless `JENKINS_MCP_AUDIT_TOOL_OK` truthy |
| `type_filter.json` | Per-profile under `$profileDataDir/audit/`; written by admin PUT settings |
| Admin BFF | `GET`/`PUT /admin/v1/profiles/{id}/audit/settings` (`gateway_ops` on write) |
| Admin SPA | Audit page **Event type settings** toggles (enable all / disable all / save) |

Agents: new security-relevant operations must emit AUD-001 **and** register new types in the catalog so operators can toggle them. See root `AGENTS.md`.

### Event schema (v1)

Stable fields only — **no** prompts, log bodies, job parameters, tokens, or Authorization headers:

| Field | Notes |
|-------|--------|
| `time` | RFC3339 UTC |
| `type` | Catalog SoT: `audit.KnownEventTypes()` — `login_*`, `serve_start`, `tool_*`, `auth_fail`, `audit_settings`, `policy_validate`/`policy_apply`, `admin_cache_evict`/`admin_support_bundle`/`admin_subject_invalidate`/`admin_consent_purge`/`admin_fleet_cache_purge`, `mutation_*` (high-volume `tool_success` filter-default off) |
| `profileId` | Connection profile id |
| `principalId` | Verified Jenkins user id (never a token) |
| `externalSubject` | Optional IdP subject label (gateway multi-user); redacted + length-capped like `principalId` — never a token |
| `subjectKeyHash` | Optional `audit.HashOpaque(tenant\|subject\|profile)` for multi-user correlation — **never** raw subject key, vault material, or tokens |
| `tool` / `action` | MCP tool name / short class |
| `decision` | `allow` / `deny` / `success` / `fail` / `error` |
| `reasonCode` | Stable code (policy reason, auth code) |
| `durationMs` | Optional |
| `bytesIn` / `bytesOut` | Optional counters (not content) |
| `requestId` | Optional correlation id |
| `targetHash` | Optional SHA-256 prefix of high-cardinality targets (`audit.HashOpaque`) |
| `schemaVersion` | `1` |

### Emit points (wired)

- `login` success / fail (profile data dir)
- `serve` start after identity bind; `auth_fail` on serve-time verify failure
- Tool dispatch **deny** (global read-only + deny-only MCP RBAC) and **tool_error**
  (handler / budget / subject limiter failures): multi-user tool dispatch
  attributes `profileId` / `principalId` from **effective** subject when wired,
  plus optional `externalSubject` + `subjectKeyHash` (opaque) when SubjectKey /
  ExternalSubject are available. Metrics tool_ok / tool_deny / tool_error remain
  separate (OBS-001). `tool_error` audit reason is the stable `apperr` code only
  (never ModelMessage / tokens).
- **tool_success** audit: emit always attempts; **persistence** defaults off via
  type filter (`tool_success` disabled unless `JENKINS_MCP_AUDIT_TOOL_OK`
  seeds defaults or operator enables via admin Audit settings). High volume.
  Metrics `mcp_tool_ok` always record regardless.
- **Mutation Manager** (`mutation_preview` / `mutation_confirm` / `mutation_deny`):
  ProfileID/PrincipalID from effective `mutation.Binding`; when Binding has
  ExternalSubject also `externalSubject` + `subjectKeyHash` =
  `audit.HashOpaque(tenant|external|profile)`. Never confirmation tokens or raw keys.
- Mid-serve **identity re-verify** fail-closed (`IdentityReverifyGate`, AUTH-004 / Wave 28):
  - `type=auth_fail`, `action=identity_reverify`, `decision=fail`
  - `reasonCode`: `identity_principal_drift` | `identity_reverify_fail` | `identity_unbound`
  - `principalId`: serve-time **bound** Jenkins user id only (never unexpected whoAmI id or tokens)
  - At most **one event per reason class** per gate lifetime (sticky transition / first 401-class fail — no flood on sticky re-Check)

Audit emit is **best-effort**: failures never authorize mutations and never elevate access.

### Multi-user correlation residual

| Surface | Status |
|---------|--------|
| Per-process tool_deny attribution (`externalSubject`, `subjectKeyHash`) | **implemented foundation |
| Per-process tool_error attribution (same multi-user identity fields) | **implemented foundation |
| tool_success audit (default filter off; admin toggle or `JENKINS_MCP_AUDIT_TOOL_OK` seed) | **implemented volume residual (opt-in persist) |
| Per-process mutation preview/confirm/deny attribution (`externalSubject`, `subjectKeyHash`) | **implemented foundation |
| Admin SPA audit table columns + type filter (`externalSubject` / `subjectKeyHash`; BFF `external_subject` exact match + client residual) | **implemented lite (same-host BFF filter; multi-pod aggregation still residual) |
| Admin SPA **event type enable/disable** (`…/audit/settings` + `type_filter.json` + ReloadingFilterSink) | **implemented lite (per-host file; multi-pod residual) |
| Admin BFF **same-host rotated sibling merge** (`ReadAuditFile` merges `audit.jsonl` + `audit.jsonl.N` / optional timestamped names) | **implemented lite — multi-user correlation more complete on one host after rotation |
| Multi-pod / multi-replica **audit aggregation** (central sink, fleet timeline) | **Residual** (HOST-008 checklist row 5) — per-pod / per-host JSONL only; no fleet merge |
| Shared durable vault + sticky sessions under multi-replica | **Residual** (see `docs/gateway/deployment.md` §9) |
| Subject quota metrics (`mcp_subject_rate_quota` / `mcp_subject_slot_quota`) | **implemented lite** process-local (HOST-006 CodeQuota); multi-pod metric aggregation residual |

### Rotation / retention

- Default max active file size: **8 MiB**, keep **3** rotated siblings (`audit.jsonl.1` …).
- Retention is size-based for the pilot; enterprise export/retention policy is residual.
- **Admin audit list (same-host lite):** `GET /admin/v1/profiles/{id}/audit` merges the active file with numbered rotates (`audit.jsonl.1` …) and optional timestamp-like siblings next to the active path; newest matching events first; corrupt lines skipped. **Not** multi-pod aggregation.

### Remote SIEM / syslog / Splunk (residual)

| Capability | Status |
|------------|--------|
| Local JSONL file sink + `audit.Multi` fan-out interface | **implemented |
| In-process **syslog** / **Splunk HEC** / webhook audit ship | **Residual** — not implemented (backlog **AUD-T-010…012** in [security/audit-trail-review.md](security/audit-trail-review.md)) |
| Host agent tail of `audit.jsonl` (Fluent Bit, Splunk UF, rsyslog `imfile`, Vector) | **Operator-owned** near-term path (runbook **AUD-T-013**) |
| `ext-logs` adapter (query external logs for Jenkins jobs) | **Separate** INT-003 — not audit export; real Splunk/ELK *clients* residual |

Industry mapping + task backlog: **[security/audit-trail-review.md](security/audit-trail-review.md)**.

## Metrics & logging (OBS-001)

Package: `internal/telemetry`.

### Structured logger

- JSON lines to **stderr** with `ts`, `level`, `msg`, plus low-cardinality fields.
- All string values pass through `internal/redact.Secrets`.
- Levels: `debug`, `info`, `warn`, `error` (default min = `info`).

### Serve log level (pilot offline analysis)

| Control | Value |
|---------|-------|
| Flag `--log-level` | Wins over env (`debug` \| `info` \| `warn` \| `error`) |
| Env `JENKINS_MCP_LOG_LEVEL` | Fallback when flag unset |
| Default | `info` |
| Invalid value | Fail closed at serve start |

At serve start the process builds a `telemetry.Logger` at the resolved min level
(fields `component=serve`, `profile=<id>` when known) and attaches it to:

1. Global registry (`telemetry.SetGlobal`) — maintenance / optional fleet paths  
2. Tool registration (`RegisterOptions.Logger`) — **tool dispatch** lines  

**Tool dispatch structured messages** (never args, tokens, job parameters, or log bodies):

| Level | `msg` | When |
|-------|--------|------|
| debug | `tool_dispatch_start` | Every tool call (tool name + effect only) |
| debug | `tool_dispatch_ok` | Successful handler + budget enforce (`duration_ms`) |
| warn | `tool_dispatch_deny` | RO / RBAC / session gate denial (`reason` code) |
| error | `tool_dispatch_error` | Handler/budget/session failure (`error_code` + ModelMessage) |

Also at **info**: `serve_observability_ready`, `mcp_transport_start`, clean `mcp_server_stopped`.  
Stdio server failures return an error to the CLI (no longer swallowed) and emit
`mcp_server_stopped` at **error** with `error_code` / redacted `error`.

**Capture for pilot tickets** (secret-free by design when using these paths):

```bash
jenkins-mcp serve --profile corp --stdio --read-only --log-level=debug \
  2> pilot-serve.stderr
# Human startup lines + JSON structured lines interleave on stderr.
```

Residual: many bootstrap status lines still use `log.Printf` (redacted via
`redact.NewWriter`); they are not JSON. Prefer `--log-level=debug` tool lines
for per-call offline analysis.

### Serve standard-library log hygiene (KD-004)

`serve` still uses many `log.Printf` sites for process startup status. At the
start of `runServe`, the binary installs:

```text
log.SetOutput(redact.NewWriter(os.Stderr))
```

so accidental token-shaped payloads (Bearer, `api_token=`, known detectors, and
**unlabeled high-entropy** hex/base64url via `CategoryBareToken`) are scrubbed
before they hit stderr. Username / principal id lines remain visible.

| Helper | Package | Role |
|--------|---------|------|
| `redact.NewWriter` | `internal/redact` | Line-buffered `io.Writer`: reassembles incomplete lines across Writes, runs `RedactText` on each complete line (and on Flush/Close remainder) |
| `telemetry.SafeServeLog` | `internal/telemetry` | format → redact → `log.Output` (explicit safe sites) |

Prefer `telemetry.Logger` for **new** structured diagnostics.

**Bare-token heuristic (Wave 25 / KD-004):** after labeled detectors, `RedactText`
scrubs maximal runs of `[A-Za-z0-9_+\-=]` that look high-entropy:
single-case pure hex ≥40 (nibble diversity); mixed-case pure hex ≥32; mixed
base64url-like ≥32 with ≥2 char classes / unique floor; shorter ≥24 only with
≥3 classes. `/` is excluded so `folder/job-name` paths do not merge. W3C
`trace_id` (exactly 32 lowercase hex) is preserved by design. Residual FP: full
git SHA-1/256 may redact. Residual FN: single-case 32–39 hex unlabeled tokens,
characters outside the alphabet, secrets that only reassemble across a
`redact.Writer` force-flush at 256 KiB pending without `\n` (normal multi-Write
log lines are reassembled). Do not print credentials intentionally.

**Writer line buffering (Wave 33 / KD-004 residual):** `redact.Writer` holds
bytes after the last `\n` until a later Write completes the line, or until
`Flush`/`Close`. Complete lines are redacted before the underlying write.
Concurrent `Write`/`Flush`/`Close` are mutex-serialized. On success `Write`
returns `n == len(p)` even when data remains buffered.

**Offline security self-check canary (Wave 34 / QA-005):** item
`writer_split_line_canary` plants an `Authorization: Bearer` token split across
two `Write` calls and asserts the canary is absent after `Flush` (same line
buffer as serve `log.SetOutput`). Overall report plant (`report_canary_leak`)
must never serialize the canary into JSON/text.

**Offline security self-check canary (Wave 38 / MCP-001):** item
`hard_max_resolve_residual` asserts `ResolveHardMaxBytes("", "")` equals
`DefaultHardMaxBytes` and that values above `AbsoluteMaxHardMaxBytes` (64 MiB)
fail closed. Serve logs only byte counts
(`hard_max_bytes=… serve_bootstrap_ceiling=… target_bytes=…`); never secrets.

**Offline security self-check canaries (Wave 39 / POL-004 + Wave 40 polish):**
pure policy package checks (no tools import cycle):
`listfilter_deny_only_residual` (`NameDeniedByPatterns` empty→false;
`Deny*FromEvaluator` copy-out for **nodes / jobs / views / artifacts / branches**
— documents list-row privacy helpers exist) and `policy_resource_deny_residual`
(`DocumentFromOverlay` copies `deny_view_names` / `deny_artifact_paths` /
`deny_branch_names` / `deny_node_names` without elevating; empty overlay ok).
Details are secret-free bools only.

**Offline security self-check canary (Wave 42 / MGR-001):** item
`policy_multisig_lite_residual` generates ephemeral dual Ed25519 keys (never
reported), verifies multi-sig lite `MinSignatures=2` (2-of-2 ok, 1-of-2 fail
closed), and sets Details `multi_sig_lite=true`, `residual_true_threshold=false`,
`residual_hsm=false`. Does not implement true *t*-of-*n* threshold crypto or HSM.

**Offline security self-check item (Wave 43 / MCP-001; Wave 44 body bytes; Wave 45
HTTP + identity TTL; Wave 46 NET-003 resilience; Wave 47 soft target; Wave 48
absolute retries/circuit + open duration; Wave 49 circuit open min/absolute +
MaxConcurrent honesty; Wave 50 absolute concurrent + backoff honesty; Wave 51
survey/diagnose hard ceilings; Wave 52 backoff resolve bounds + mutation
honesty; Wave 53 mutation resolve bounds):** item
`operator_caps_snapshot` reports a secret-free integer/bool map of process
operator caps from tools getters (`ListJobsCollectMaxPages`,
`NodesCollectMaxPages`, `ViewsCollectMaxPages`, `ArtifactsHardCap`) and
`jenkins.ArtifactListBodyBytes()` plus absolute ceilings
(`AbsoluteMaxHardMaxBytes`, `AbsoluteMaxArtifactsHardCap`,
`AbsoluteMaxArtifactListBodyBytes`, collect absolute max pages) and defaults
(`default_artifacts_list_body_bytes`, etc.). Offline hard-max uses
`DefaultHardMaxBytes` + `AbsoluteMaxHardMaxBytes` only
(`live_hard_max_available_offline=false` — mid-serve `LiveHardMax` is not
available without serve). Wave 47 soft target offline constants:
`default_target_bytes` (64 KiB) + `absolute_max_target_bytes` (64 MiB =
`AbsoluteMaxHardMaxBytes`) with `live_target_bytes_available_offline=false` (no
process-level live soft-target getter offline; serve resolves via
`--target-bytes` / `JENKINS_MCP_TARGET_BYTES`; soft still clamped to live hard
max at enforce). Wave 45: HTTP body + identity
re-verify TTL package constants. Wave 46–50 Track B: Jenkins NET-003 resilience
package constants (`default_max_json_body_bytes` 32 MiB /
`absolute_max_json_body_bytes` 128 MiB, `default_max_retries` = 2 /
`absolute_max_retries` = 10, `default_circuit_failure_threshold` = 5 /
`absolute_max_circuit_failure_threshold` = 50,
`default_circuit_open_duration_seconds` = 15,
`min_circuit_open_duration_seconds` = 1,
`absolute_max_circuit_open_duration_seconds` = 300,
`default_max_concurrent` = 0 with `max_concurrent_unlimited_default=true`,
`absolute_max_concurrent` = 256, `default_initial_backoff_ms` = 100,
`default_max_backoff_ms` = 5000). Wave 52 Track B resolve bounds:
`min_initial_backoff_ms` = 10 / `absolute_max_initial_backoff_ms` = 2000 /
`min_max_backoff_ms` = 100 / `absolute_max_max_backoff_ms` = 60000; mutation
honesty: `default_mutation_confirm_cooldown_ms` = 5000 /
`default_mutation_max_previews_per_minute` = 30 /
`default_mutation_token_ttl_ms` = 120000. Wave 53 Track B mutation resolve bounds:
`min_mutation_confirm_cooldown_ms` = 1000 /
`absolute_max_mutation_confirm_cooldown_ms` = 300000 /
`absolute_max_mutation_max_previews_per_minute` = 300 (min ≤ default ≤ abs;
1 ≤ default previews ≤ abs). Wave 53 Track A TokenTTL bounds offline:
`min_mutation_token_ttl_ms` (10s) / `absolute_max_mutation_token_ttl_ms` (15m).
Wave 51 Track B
survey/diagnose package hard
ceilings (offline only): `default_survey_max_total_builds` /
`hard_survey_max_total_builds` (30 / 100), `default_survey_max_jobs` /
`hard_survey_max_jobs` (10 / 25), `default_survey_max_log_bytes_total` /
`hard_survey_max_log_bytes_total` (1 MiB / 4 MiB),
`default_survey_max_wall_seconds` / `hard_survey_max_wall_seconds` (30 / 120),
`default_diagnose_log_bytes` / `hard_diagnose_log_bytes` (128 KiB / 512 KiB),
`default_diagnose_max_findings` / `hard_diagnose_max_findings` (10 / 25).
No live client circuit, concurrency, or mutation Manager state offline. Detail
keys include `artifacts_list_body_bytes`, `default_artifacts_list_body_bytes`,
`absolute_max_artifacts_list_body_bytes`. Message: `operator caps snapshot
(secret-free integers)`. No env token values.

### Core counters / gauges (Wave 24–27 OBS-001)

Low cardinality only — **no** free-form tool-name labels, job names, URLs, or
secrets. Constants live in `internal/telemetry` (`Metric*`).

| Name | Meaning | Wired by |
|------|---------|----------|
| `tool_calls` | MCP tool **dispatch attempts** (ok + error + deny) | `tools.addTool` |
| `mcp_tool_ok` | Handler completed (budget enforced) without error | `tools.addTool` |
| `mcp_tool_error` | Handler or budget returned an error (non-deny) | `tools.addTool` |
| `mcp_tool_deny` | RO / MCP RBAC / session-gate denial (registration or dispatch) | `tools.emitToolDeny` |
| `mcp_subject_rate_quota` | HOST-006 subject **rate** CodeQuota (token-bucket `Allow` deny) | `tools.addTool` (subject rate path) |
| `mcp_subject_slot_quota` | HOST-006 subject **concurrent slot** CodeQuota (`Hold` deny) | `tools.addTool` (subject limiter path) |
| `jenkins_http_requests_total` | Upstream HTTP attempts that reached `Do` (incl. retries) | `jenkins.Client` via `MetricsHook` |
| `jenkins_http_errors_total` | Transport failure or HTTP status ≥ 400 | `jenkins.Client` via `MetricsHook` |
| `jenkins_http_wire_bytes_total` | Encoded response bytes read from the wire | `MetricsHook` + `ByteCounters` |
| `jenkins_http_decoded_bytes_total` | Decoded body bytes (identity ⇒ same as wire) | `MetricsHook` + `ByteCounters` |
| `jenkins_circuit_open_events_total` | Circuit breaker **transitions into open** (NET-003 / Wave 27) | `MetricsHook.IncCircuitOpenEvent` via resilience |
| `cache_hits` | Cache hits (stub hook residual) | — |
| `mcp_bytes_out` | Optional MCP response bytes | residual |
| `duplicate_bytes_avoided` | Optional progressive-log dedupe | residual |
| `cache_maint_ticks` | Serve-time cache maintenance cycles (ARC-007 residual) | `app.Maintainer` |
| `cache_evict_items` | Objects removed by eviction / journal recovery | `app.Maintainer` |
| `cache_evict_bytes_reclaimed` | Estimated physical bytes reclaimed | `app.Maintainer` |
| `cache_packs_created` | L1→L2 packs published by background compaction | `app.Maintainer` |
| `cache_usage_bytes` | Gauge: last-seen total physical L1+L2 | `app.Maintainer` |
| `cache_quota_bytes` | Gauge: effective total quota | `app.Maintainer` |

**Aliases (same string value):** `MetricPolicyDenials` → `mcp_tool_deny`;
`MetricJenkinsRequests` → `jenkins_http_requests_total`;
`MetricBytesWire` → `jenkins_http_wire_bytes_total`.

**Circuit breaker state (Wave 27):** current state is **not** a labeled time
series. Doctor check `circuit_breaker` reports `Client.CircuitState()` when a
client is wired (`DoctorOptions.Circuit`); offline CLI doctor without a live
client **skips** the check. Open events are the only circuit counter (one
increment per open episode, including re-open after a failed half-open probe).

**Offline security self-check canary (Wave 45 Track C / NET-003):** item
`jenkins_resilience_residual` proves offline that `DefaultResilienceConfig` is
constructible, the circuit starts closed (`Resilience.State` /
`Client.CircuitState`), GET/HEAD are retry-eligible via
`IsIdempotentRetryMethod`, and POST is **not** auto-retry eligible (fail closed
if broken). Details are bool/int only (`get_head_retry_eligible=true`,
`post_auto_retry=false`, `circuit_breaker_present=true`,
`residual_live_chaos=false`, `residual_live_network_matrix=false`). Message:
`NET-003 resilience lite offline canary (GET/HEAD retry + circuit); live chaos
matrix residual`. Does not run live multi-controller chaos.

**Package boundary:** `internal/jenkins` defines `MetricsHook` only (no import of
`telemetry`). Serve wires `client.WithMetrics(tools.JenkinsMetricsHook(metrics))`.
Tools receive `RegisterOptions.Metrics` and count outcomes in the `addTool` wrapper.

`Registry.Snapshot()` returns a copy for `doctor` / `status` / support bundles
(**OPS-001**). Fleet export allowlists the same closed name set
([security/fleet-telemetry.md](security/fleet-telemetry.md)).

Prefer `context` values (`audit.WithSink`, `telemetry.WithRegistry`) over globals.
`telemetry.SetGlobal` is only a serve-process fallback.




- KD-004 residual: migrate remaining `log.Printf` to `telemetry.Logger`; bare high-entropy detectors (Wave 25) + Writer line buffering (Wave 33) landed — residual sub-threshold hex FN / git-SHA FP / force-flush boundary only; Wave 34 self-check `writer_split_line_canary` guards line reassembly
- KD-008 residual: loopback HTTP without require-token / deny-anonymous still open to local processes (default for pilot); opt-in via `--http-require-token` or `JENKINS_MCP_HTTP_REQUIRE_TOKEN` / `JENKINS_MCP_HTTP_DENY_ANONYMOUS`; self-check warns (`http_require_token_residual`); Host allow-list fail-closed covered by `http_allowed_hosts_residual`


### Wave 46 / MGR-002 fleet ForceOff + overlay pin canary

Offline self-check item `fleet_telemetry_force_off_residual` (MGR-002) proves
`ForceOff` and overlay `fleet_telemetry_force_off` disable fleet telemetry
offline without network or export (`policy_overlay_pin=true` lite).
HSM / true multi-sig t-of-n and privacy board remain residual.
Env enable path (`JENKINS_MCP_TELEMETRY`) remains separate from force-off.

## Residual

| Surface | Status |
|---------|--------|
| Subject quota metrics (`mcp_subject_rate_quota` / `mcp_subject_slot_quota`) | **implemented lite** — process-local counters on HOST-006 CodeQuota (rate `Allow` / slot `Hold`); also counted in `mcp_tool_error`; **never** subject keys, tokens, or free-form labels. Fleet allowlist includes both names. Multi-pod aggregation / shared rate still **residual** (HOST-008). |
| Multi-pod / multi-replica audit aggregation (central sink) | **Residual** — per-pod JSONL only. **implemented lite:** same-host admin merge of rotated siblings (`audit.jsonl.N`) for a single profile path — not fleet timeline |
| tool-success audit summaries | **implemented opt-in persist (admin type filter / env seed default; metrics always on; high volume residual) |
| Per-tool allowlisted counters | **Residual** (only if a closed seed name set is required; default is total ok/error/deny + subject quota) |
| OTLP export / remote collector query | **Residual** (INT-002 approved backend adapter) |
| Per-request latency histograms / compression-ratio gauges / decoder CPU | **Residual** (OBS follow-on) |
| Circuit gauges / half-open+closed transition counters | **Residual** optional (Wave 27 ships open-events + doctor `State()` only) |
| Wire `DoctorOptions.Circuit` / metrics from serve into MCP `jenkins_doctor` | **Residual** when that tool is registered |
| Policy-controlled retention/export beyond size rotation | **Residual** |
| Support bundle: optional live capability attach; signed/encrypted export | **Residual** |
| Post-pack L1 release metrics (`cache_l1_released`, `cache_l1_release_bytes_reclaimed`) | Named residual (constants exist; wiring honesty in support/doctor paths as shipped) |
| Authenticated Streamable HTTP / gateway session binding | GWY-* residual |
| MGR-002 formal privacy board + HSM/multi-sig | **Residual** (overlay force-off pin is **implemented lite**) |
| KD-004 logging migration / bare high-entropy FN-FP | Residual sub-threshold hex FN / git-SHA FP / force-flush boundary only; Wave 34 `writer_split_line_canary` guards line reassembly |
| KD-008 loopback HTTP without require-token | Residual open to local processes (default pilot); opt-in `--http-require-token` / `JENKINS_MCP_HTTP_REQUIRE_TOKEN` / `JENKINS_MCP_HTTP_DENY_ANONYMOUS`; self-check `http_require_token_residual` / `http_allowed_hosts_residual` |

## Pilot evidence

`jenkins-mcp pilot-check` aggregates doctor, cache status, and sample verify into a secret-free evidence JSON document for REL-001.

## Cache encryption (ARC-009)

Optional L1 AEAD; see [security/cache-encryption.md](security/cache-encryption.md). Metrics never include key material.

ured diagnostics.

**Enterprise patterns (Wave 27 / SEC-002):** optional JSON list via
`JENKINS_MCP_REDACT_PATTERNS_FILE` is loaded at serve start
(`ApplyEnterprisePatternsFromEnviron`). Invalid file fails closed. Success
logs **count only** (`enterprise redact patterns loaded: count=N`). Operators
validate offline with `jenkins-mcp redact validate-patterns --file PATH`.
Reports expose category counts; **never** log match samples or secrets.
See [`security/operator-guide.md`](security/operator-guide.md) §5.

**Bare-token heuristic (Wave 25 / KD-004):** after labeled detectors, `RedactText`
scr

### Wave 43 adapter residual canary

Offline self-check item `adapter_framework_residual` documents deny-by-default adapters and residual production OTLP/Splunk/ELK/Jira SaaS clients.

