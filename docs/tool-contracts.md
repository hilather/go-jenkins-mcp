# MCP tool contracts (DOC-002)

**Source of registration:** `internal/tools/register.go` (+ `jen_pipe_test_tools.go`, `health.go`, diagnose/compare/regression/graph/survey, `search_logs.go`, `mirror_logs.go`, `doctor.go`, mutations).  
**Keep in sync** when adding or renaming tools.

## Global budgets (MCP-001 / ADR 0010)

| Limit | Default | Notes |
|-------|---------|--------|
| Soft structured target | **64 KiB** | Over-target may be accepted under hard max; serve may raise via `--target-bytes` / `JENKINS_MCP_TARGET_BYTES` |
| Soft target absolute cap | **64 MiB** | Wave 51 `AbsoluteMaxTargetBytes` (= `AbsoluteMaxHardMaxBytes`); oversize flag/env fail closed; still clamped to live hard max at enforce (resolve may exceed bootstrap hard — serve clamps after Normalize) |
| Hard structured max | **1 MiB** | Exceed → truncated summary or `quota` (strict); serve may raise via `--hard-max-bytes` / env |
| Process absolute hard-max cap | **64 MiB** | Wave 38 `AbsoluteMaxHardMaxBytes`; flag/env above this fail closed at serve start |
| Coarse list cap | **500** items | Last-resort `ClampListLen` only; list tools use opaque page tokens |
| Policy overlay | may set hard max within serve-bootstrap ceiling (Wave 31) | never above ceiling; never elevates Jenkins |

Log/diagnose tools apply **additional** server-side byte/finding ceilings (documented per tool). Enterprise overlay cannot raise them.

### Opaque list pagination (MCP-001)

List-style tools expose **opaque** continuation tokens. Tokens are not a multi-tenant security boundary (stdio pilot); they encode version, offset, page limit, and a filter fingerprint only — **never secrets**.

| Field | Direction | Meaning |
|-------|-----------|---------|
| `page_token` | request | Continue from a prior `next_page_token` |
| `next_page_token` | response | Present when more items exist beyond the current page |
| `offset` / `limit` | request | Backward-compatible page controls |

**Precedence:** prefer `page_token`. When both `page_token` and `offset`/`limit` are set, **`page_token` wins**. Invalid, tampered, or filter-mismatched non-empty tokens fail closed as `invalid_argument` (never silently ignored). Token limits cannot raise past per-tool hard maxes (clamped server-side). Full responses still pass through `EnforceBudget`.

## Side-effect classes

| Class | Meaning |
|-------|---------|
| **read** | No Jenkins mutation; may poll/wait; may write local cache/mirror |
| **mutate** | Requires RO gate off + registration; preview/confirm (MUT-001) |

Default `Register` / pilot serve: **mutations omitted** (POL-001). **Wave 30:** with
`--allow-mutations` / `AllowMutations`, mutations **register** even under Effective RO
(e.g. `force_read_only`) so force clear re-lists without restart; ListTools + dispatch
still hide/deny while RO.

Optional registration (needs `RegisterOptions`):

- `jenkins_search_logs` — requires `LogSearch`
- `jenkins_mirror_logs` — requires multi-log Coordinator (`RegisterOptions.MultiLog` or `*MirrorLogAccess` with `Coord`; serve: `--profile` store+mirror)
- `jenkins_doctor` — requires `Doctor` func
- `jenkins_get_trace_refs` — requires `EnableTraceRefs` (INT-002; serve: `--enable-adapter=otel-correlate`)
- `jenkins_export_trace_refs` — requires `TraceExporter` (INT-002; serve: `--enable-adapter=otel-export`; metadata-only; no OTLP protobuf)
- `jenkins_query_external_logs (Jenkins ACL preflight before external query)` — requires `ExternalLogs` (INT-003; serve: `--enable-adapter=ext-logs`)
- `jenkins_get_change_correlation` — requires `EnableChangeCorrelation` (INT-004; serve: `--enable-adapter=work-items`)

---

## Tool inventory

### Seed / core job & log (always registered when RO)

| Tool | Purpose | Key args | Budgets / bounds | Class |
|------|---------|----------|------------------|-------|
| `jenkins_get_jobs` | Root job list + status (paginated) | `offset`/`limit` (default 50, max 200) or `page_token` | page token; result budget | read |
| `jenkins_get_job` | Job detail + recent builds | `name` (seed) or `job_name` (alias; preferred when both set), `max_builds` (20) | result budget | read |
| `jenkins_get_running_builds` | Running + best-effort queue | — | result budget | read |
| `jenkins_get_build` | Build details | `job_name`, `build_number` | result budget; params scrubbed | read |
| `jenkins_get_build_logs` | Log range | `job_name`, `build_number`, `offset`, `length` (default 8192) | length bound; redaction; optional L1 mirror | read |
| `jenkins_get_build_log_tail` | Log tail | `job_name`, `build_number`, `max_length` (8192) | max_length bound; redaction | read |
| `jenkins_get_queue_item` | Queue item state | `queue_id`, optional `profile` | result budget | read |
| `jenkins_wait_for_queue_item` | Poll until assigned/cancel/timeout | `queue_id`, `timeout_seconds` (30), `poll_interval_seconds` (2) | wall timeout | read |
| `jenkins_search_builds` | Search by result/params | `job_name`, filters, `limit` (5), `max_lookback` (100) | lookback/limit; secret params never returned | read |
| `jenkins_wait_for_running_build` | Poll until complete | `job_name`, `build_number`, `timeout_seconds` (600) | wall timeout | read |

### Mutations (omit under RO; opt-in `--allow-mutations`)

| Tool | Purpose | Key args | Class |
|------|---------|----------|-------|
| `jenkins_start_job` | Preview or trigger parameterized build | `job_name`, optional `parameters`, `confirmation_token` | **mutate** |
| `jenkins_stop_build` | Preview or stop running build | `job_name`, `build_number`, `confirmation_token` | **mutate** |
| `jenkins_cancel_queue_item` | Preview or cancel a queue item | `queue_id`, `confirmation_token` | **mutate** |
| `jenkins_interrupt_build` | Preview or interrupt running build (MUT-010) | `job_name`, `build_number`, `mode` (`stop`\|`term`\|`kill`), `confirmation_token` | **mutate** |
| `jenkins_rebuild_build` | Rebuild using parameters from a prior build (MUT-011) | `job_name`, `build_number` (source), `confirmation_token` | **mutate** |
| `jenkins_replay_pipeline` | Replay Pipeline same definition (MUT-012; no script-edit) | `job_name`, `build_number`, `confirmation_token` | **mutate** |
| `jenkins_set_job_buildable` | Enable or disable a job (MUT-013) | `job_name`, `buildable`, `confirmation_token` | **mutate** |
| `jenkins_set_build_keep_forever` | Toggle keep-forever on a build (MUT-014) | `job_name`, `build_number`, `keep_forever`, `confirmation_token` | **mutate** |
| `jenkins_set_build_description` | Set build description (MUT-014; max 4096) | `job_name`, `build_number`, `description`, `confirmation_token` | **mutate** |
| `jenkins_cancel_queue_items_for_job` | Cancel waiting queue items for one job (MUT-016; cap 20) | `job_name`, optional `stuck_only`, `confirmation_token` | **mutate** |

Without `confirmation_token` → preview token only. With valid token → single execute.  
**MUT-017:** optional overlay `allow_mutation_tools` / `allow_interrupt_modes` / `allow_mutation_job_prefixes` further restrict registration and targets.  
**Not tools:** `/scriptText`, `config.xml` POST, pluginManager write, quietDown — classifier **unclassified**, fail closed.

**MUT-001 rate limit and confirm cooldown** (process-local `mutation.Manager`)

| Control | Default | Zero config | Negative config | On exceed |
|---------|---------|-------------|-----------------|-----------|
| Preview rate | **30 / sliding minute** | production default | unlimited | `throttled` + audit reason `preview_rate_limited` |
| Confirm cooldown | **5s** per (profile, action, targetHash) after successful confirm | production default | off | `policy_denial` + audit reason `confirm_cooldown` (token not consumed) |
| Confirmation token TTL | **2m** single-use | production default | production default | `policy_denial` + `token_expired` / `token_reused` |

Successful execute remains single-use (token discarded). Cooldown does not re-authorize a consumed token; issue a new preview after cooldown if needed. Confirmation tokens are bound to `mutation.Binding` (profile + principal + ExternalSubject + tenant); multi-user `BindingFromContext` rejects Alice preview tokens under Bob (reason `binding_mismatch`). Cooldown keys include the full binding so subjects do not share cooldowns. Audit preview/confirm/deny events carry reason codes and effective ProfileID/PrincipalID; when Binding has ExternalSubject they also include `externalSubject` and opaque `subjectKeyHash` (`audit.HashOpaque(tenant|external|profile)`) — no secrets, no raw confirmation tokens, no raw subject keys. **Residual:** multi-pod / multi-replica audit aggregation (central sink / fleet timeline) is not provided — per-process JSONL only (see `docs/observability.md`). Offline self-check canary `mutation_confirm_cooldown_residual` (MUT-001) proves default TTL/cooldown and fail-closed re-confirm deny without network; mutations remain opt-in (`--allow-mutations`).

**`jenkins_start_job` (MUT-002) validation**

| Rule | Behavior |
|------|----------|
| Parameter definitions | Loaded from the job (`property.parameterDefinitions`) on **preview and confirm** |
| Unknown names | `invalid_argument` — must match a definition |
| Choice values | Must be one of the definition’s `choices` |
| Boolean | bool or `"true"`/`"false"` string only |
| Secret types | `Password` / `Credentials` / `Secret*` definition types always rejected on the model path |
| Sensitive names | Additional heuristic (`PASSWORD`, `*TOKEN*`, …) via `NormalizeParams` |
| Unsupported types | File / Run / Git / Node / Label (and unknown plugin types) rejected when supplied |
| Preview == execute | Normalized params in the preview are the same map bound for the single non-retried POST |
| No auto-retry | Enqueue POST is never auto-retried (NET-003) |

**Residuals (start_job / MUT-015):** When a definition is marked `Required` (rare; residual honesty only when Jenkins exposes it), missing params fail closed. Most definitions leave Required false — omitted optional params are allowed so Jenkins can apply defaults. Active Choices / dynamic choice plugins are not fully modeled (unsupported types rejected when supplied). Client-generated correlation parameters are not injected. Non-buildable jobs refuse start before minting a preview token.

Queue cancel and build stop are **separate** actions (MUT-003). Missing, already-cancelled, or already-assigned queue items return a clear error (not success). Finished builds refuse stop/term/kill the same way. Bulk queue cancel (MUT-016) is capped at 20 ids per confirm and never cancels the whole controller queue.

### Discovery / pipeline / test / artifact / SCM (`registerJenPipeTestTools`)

| Tool | Purpose | Key args | Bounds | Class |
|------|---------|----------|--------|-------|
| `jenkins_get_capabilities` | Version + Pipeline REST + JUnit | optional `refresh` | capability cache TTL | read |
| `jenkins_list_jobs` | Paginated jobs | `folder_prefix`, filters, `offset`/`limit` (default 50, max 200) or `page_token` | opaque page token; filter fingerprint; policy collect+filter when denies live | read |
| `jenkins_list_builds` | Build history | `job_name`, `offset`/`limit` (default 20, max 100) or `page_token`, since/result | opaque page token; secret params stripped | read |
| `jenkins_resolve_baseline` | last successful/failed/… | `job_name`, `baseline` | — | read |
| `jenkins_get_build_graph` | Upstream/downstream | `job_name`, `build_number`, depth limits | depth/node/cycle caps | read |
| `jenkins_get_pipeline_stages` | Pipeline stage graph | `job_name`, `build_number` | capability_missing if no PIPE | read |
| `jenkins_get_test_report` | JUnit summary + failed cases | `job_name`, `build_number`, `max_failed` | max_failed | read |
| `jenkins_get_stage_log` | Stage/node log | `job_name`, `build_number`, `stage_id`/`stage_name`, `max_length`, `mirror` | max_length; optional stage mirror key | read |
| `jenkins_analyze_tests` | new/flaky/known/duration | `job_name`, `build_number`, `lookback`, `max_results` | lookback/results | read |
| `jenkins_list_artifacts` | Artifact metadata only | `job_name`, `build_number`, `max_artifacts` | no body download | read |
| `jenkins_get_artifact_text` | Small text artifact | `job_name`, `build_number`, `path`, `max_bytes` | ≤256 KiB; path traversal blocked | read |
| `jenkins_inspect_artifact` | Safe inspect / archive inventory | `job_name`, `build_number`, `path`, `max_bytes`, `max_members` | zip-slip/bomb blocked; never execute | read |
| `jenkins_get_build_changes` | SCM changes | `job_name`, `build_number`, optional baseline | credentials stripped from URLs | read |

#### `jenkins_list_jobs` (JEN-002 + Wave 37/39/40 policy filter)

| Surface | Behavior |
|---------|----------|
| Args | `folder_prefix`, `name_contains`, `view`, `offset`/`limit` (default 50, max 200) or `page_token`, `max_depth`, `include_folders` |
| Response | `jobs[]` (`fullName`, `name`, `kind`, …), `total`, `offset`/`limit`, optional `truncated` / `next_page_token` / `message`, `scanned`, `source` |
| Pagination | Opaque `page_token` / `next_page_token` bound to user filter fingerprint (folder/name/view/depth/include_folders). Token wins over offset/limit; filter mismatch → `invalid_argument` |
| **MCP deny patterns (Wave 37 + Wave 39)** | When live evaluator Document has non-empty `deny_job_prefixes` and/or `deny_branch_names`, the handler **collects** the full ListJobs result (paged internally up to a safety page cap), **drops** matching rows (`ApplyJobPolicyFilters`: job FullName vs `deny_job_prefixes`; `kind=branch`/`matrix_child` Name/FullName vs `deny_branch_names`), recomputes `total` = kept count, then re-applies the caller's offset/limit or `page_token`. Omitting rows never fails the whole call. |
| **Policy-bound page tokens (Wave 40)** | On the collect path only, fingerprint also includes **live** sorted `deny_job_prefixes` + `deny_branch_names` material. Mid-session policy tighten (or empty vs non-empty deny) invalidates prior tokens fail-closed (`invalid_argument` filter mismatch) instead of silently skewing pages. Empty patterns path keeps Jenkins user-filter-only fingerprint (no policy applied after). Tokens never embed pattern cleartext or secrets. |
| Filter metadata | `policy_filtered: true` and `policy_omitted_count` (integer, **stable across pages**) when ≥1 job dropped; denied names are **not** listed in payload |
| Empty policy | Nil evaluator or both pattern lists empty → single ListJobs (no multi-fetch collect cost) |
| Empty after filter | `jobs=[]`, `total=0`, no crash; next_page_token empty |
| Collection cap | With filter on, full list is collected with a safety page cap (~50 × max page 200); if hit while more jobs remain, response forces `truncated=true` and a non-secret `message` (e.g. `job list collection capped; results may be incomplete`) — honesty; may be incomplete |
| Kind gate (branch) | `deny_branch_names` only omits `kind=branch` / `matrix_child` (folder named `main` is not hidden by branch deny) |
| Secrets | No credentials; lastBuild URL stripped; messages/tokens never list denied names or secrets |

### Health (`registerHealthTools`)

| Tool | Purpose | Key args | Class |
|------|---------|----------|-------|
| `jenkins_get_nodes` | Node/executor summary (list) | `offset`, `limit` | read |
| `jenkins_get_node` | Single node/executor by name | `node_name` (required) | read |
| `jenkins_queue_pressure` | Queue depth / stuck / oldest | — | read |
| `jenkins_controller_health` | Version + caps + queue/nodes + quiet-down | optional flags | read |
| `jenkins_explain_queue_delay` | Why item/job delayed | `queue_item_id` and/or `job_name` | read |

### Discovery views (`registerViewsTools`)

| Tool | Purpose | Key args | Class |
|------|---------|----------|-------|
| `jenkins_list_views` | List Jenkins views (name/description/class) | `offset`, `limit` (default 50, max 200) | read |

#### `jenkins_list_views` (Wave 38 + `deny_view_names` policy filter)

| Surface | Behavior |
|---------|----------|
| Args | `offset`, `limit` (default 50, max 200); pagination only — no `view_name` |
| Response | `views[]` (`name`, sanitized `description`, optional `class`), `summary.totalViews`, `offset`/`limit`, optional `truncated`/`nextOffset` |
| Unauthorized | Jenkins HTTP 403 → `unauthorized=true`, empty `views` (not a tool error) |
| Tree | Root `/api/json?tree=views[name,description,_class]` only — **no** job graphs or nested view contents |
| **MCP `deny_view_names` (Wave 38)** | When the live evaluator Document has non-empty `deny_view_names`, the handler collects the full view list, **drops** matching rows (`MatchDenyJobPattern`), recomputes `summary` over kept views, then applies `offset`/`limit`. Omitting rows never fails the whole call. |
| Filter metadata | `policy_filtered: true` and `policy_omitted_count` (integer) when ≥1 view dropped; denied names are **not** listed in message/payload |
| Empty policy | Nil evaluator or empty `deny_view_names` → Jenkins-authorized list as-is |
| Name source | Filter matches `ViewSummary.Name` from Jenkins view **name** (same string used by seed `view` on `jenkins_list_jobs`) |
| Collection cap | With filter on, full list is collected with a safety page cap (default **50** pages × max 200). Operators may raise via `--views-collect-max-pages` or `JENKINS_MCP_VIEWS_COLLECT_MAX_PAGES` up to absolute **200** (fail-closed). Cap hit → `truncated=true` + non-secret incomplete `message` |
| Secrets | Description sanitized (control strip + length cap); no credentials or job lists |

#### `jenkins_get_nodes` (HEALTH-001 + Wave 36 policy filter)

| Surface | Behavior |
|---------|----------|
| Args | `offset`, `limit` (default 50, max 200); pagination only — no `node_name` |
| Response | `nodes[]` (`name`, online/offline, executors, labels, …), `summary` totals, `offset`/`limit`, optional `truncated`/`nextOffset` |
| Unauthorized | Jenkins HTTP 403 → `unauthorized=true`, empty `nodes` (not a tool error) |
| **MCP `deny_node_names` (Wave 36)** | When the live evaluator Document has non-empty `deny_node_names`, the handler collects the full node list, **drops** matching rows (`MatchDenyJobPattern`), recomputes `summary` over kept nodes, then applies `offset`/`limit`. Omitting rows never fails the whole call. |
| Filter metadata | `policy_filtered: true` and `policy_omitted_count` (integer) when ≥1 node dropped; denied names are **not** listed in message/payload |
| Empty policy | Nil evaluator or empty `deny_node_names` → pre-Wave-36 behavior (Jenkins-authorized list as-is) |
| Name source | Filter matches `NodeSummary.Name` from Jenkins **displayName**. Call-time `jenkins_get_node` uses the computer **path** name (e.g. `(master)` vs display `Built-In Node`) — operators may need both forms in `deny_node_names` |
| Collection cap | With filter on, full list is collected with a safety page cap (default **50** pages × max 200 ≈ 10k nodes). Operators may raise via `--nodes-collect-max-pages` or `JENKINS_MCP_NODES_COLLECT_MAX_PAGES` up to absolute **200** (fail-closed). Cap hit → `truncated=true` + non-secret incomplete `message` |
| Secrets | No environment/systemProperties; offline cause / description sanitized |

#### `jenkins_get_node` (Wave 36)

| Surface | Behavior |
|---------|----------|
| Args | `node_name` (required) — Jenkins computer **path** name (e.g. `agent-1`). Built-in is historically `(master)` or `built-in`, not only the display name. |
| Response | One `NodeSummary` (online/offline, executors busy/idle, labels, sanitized description/offline cause). **No** environment or system properties. |
| Errors | Empty name → `invalid_argument`; HTTP 404 → `not_found`; 403 → `authorization`; 401 → `authentication`. |
| Policy | `node_name` binds `Target.NodeName` so overlay `deny_node_names` denies at call time (handler never runs). |

### Diagnostics (always registered)

| Tool | Purpose | Key args | Extra budgets | Class |
|------|---------|----------|---------------|-------|
| `jenkins_diagnose_build` | One-build triage | `job_name`, `build_number`, optional max findings/log | default log **128 KiB** (hard 512 KiB); findings ≤10 (hard 25); remote call budget | read |
| `jenkins_compare_builds` | Diff two builds | `job_name`, `build_a`, `build_b`, caps | test/artifact/stage/SCM caps; remote call budget | read |
| `jenkins_find_regression_window` | Bisect-ish fail window | `job_name`, builds/range | server lookback/wall caps | read |
| `jenkins_trace_failure_graph` | Failure + related graph | `job_name`, `build_number` | graph + diagnose residuals | read |
| `jenkins_survey_recent_failures` | Multi-build signature survey | `job_names` / `job_prefix`, `allow_cross_job`, max_* | jobs/builds/log/cluster/wall caps; cross-job off by default | read |

#### `jenkins_compare_builds` (DIAG-003 / SCM-001 wire-up)

Compares two builds of the **same job** and returns **differences only** by default
(result, duration, non-secret parameters, stages, tests, error signatures, artifact
paths, **SCM changes/revisions**). Identical under budgets → compact
`material_difference=false`.

| Surface | Behavior |
|---------|----------|
| Args | `job_name`, `build_a`, `build_b`; optional `max_findings`, `max_log_bytes`, `max_test_diffs` (server hard-caps) |
| SCM (`scm_diff`) | Prefer **range** mode: `GetBuildChanges` with baseline=min(a,b), target=max(a,b) when span ≤ **5** builds; else **per_build** summaries. Commits capped (default **10**, hard **20**); messages redacted. |
| SCM residual | On missing changeSet/BuildData: residual *“SCM: no changeSet… (nothing invented)”* — never invents commits. On remote budget: residual *“SCM compare skipped (remote budget…)”* without failing the whole compare. |
| Removed residual | Hardcoded *“SCM changesets/revisions not wired (SCM-001 residual)”* is **gone** when the wire-up path runs. |
| Budgets | Shared `DiagSession` remote call/byte/wall ceilings (default compare: 24 calls / 2 MiB / 45s); PERF-003 FetchCache for build meta, stages, tests, artifacts, SCM changes. |
| Secrets | Parameter names matching secret patterns excluded; commit messages via `redact.SanitizeForModel`. |
| **MCP `deny_artifact_paths` (Wave 39 + Wave 41)** | When the live evaluator Document has non-empty `deny_artifact_paths`, diagnose/compare **artifact list cache** (`getCachedArtifactList`) fetches via `listArtifactsWithPolicyFilter` and **always** re-applies live path filter on return. Cache keys include sorted non-secret `deny_artifact_paths` fingerprint (+ max) so entries are not reused across different deny policies. Path diffs never include denied paths (raw **or** Target-style cleaned path, same as `jenkins_list_artifacts`). Omitting never fails the whole compare. Job deny remains call-time separate (`job_name`). |
| Artifact filter metadata | `artifacts_policy_filtered: true` and `artifacts_policy_omitted_count` (integer) when ≥1 path was omitted (list-level and/or residual diff filter); denied paths are **not** listed in diffs, confidence notes, or residuals (integer-only omit note). Empty evaluator / empty patterns → pre-Wave-39 behavior (full path diffs). |

#### `jenkins_survey_recent_failures` (DIAG-006 + durable cache)

Summarizes recurring failure signatures across an approved job scope (failed/unstable only; exact then normalized signature clusters). Never dumps full logs.

| Surface | Detail |
|---------|--------|
| Scope | `job_names` and/or `job_prefix`; multi-job requires `allow_cross_job=true` |
| Budgets | `max_jobs`, `max_builds_per_job`, `max_total_builds`, `max_log_bytes_per_build`, `max_log_bytes_total`, `max_clusters`, `max_wall_seconds` (server hard caps) |
| Response budgets | `cache_hits` / `cache_misses`, `log_bytes_scanned`, `builds_extracted`, `budget_exhausted` |
| Sources | may include `list_builds`, `list_jobs`, `survey_cache` (process L1), `survey_cache_durable` (Meta L2) |
| Process cache (L1) | TTL **5m**, max **256** compact build summaries; key = profile + job + build + `max_log_bytes` |
| Durable cache (L2) | When serve opens profile `metadata.sqlite` (**schema v7** `survey_summary_cache`) and wires `RegisterOptions.Meta`, compact summaries survive process restart under the **same profile** |
| Durable value | Signature hashes, result, log byte counts, optional **short redacted** message/normalized/excerpt (≤256 chars); **never** log tails/bodies/secrets |
| Incomplete extracts | Budget/cancel/partial tails are **not** written to L1 or L2 (avoids sticky under-clustering for full TTL) |
| Fail closed | Corrupt / expired / oversized durable rows are skipped (deleted) and re-fetched |
| Residuals | Without Meta/data dir: process-scoped TTL only. Cross-process durable cache only when profile store is open |

#### DIAG-001 extract pattern ids (Wave 23)

Log extractors in `internal/diagnostics` use **pluggable first-match rules** (higher confidence / more specific first). Pattern ids returned on findings:

| Pattern id | Strong markers (conservative) | Confidence |
|------------|-------------------------------|------------|
| `build_failure` | `BUILD FAILURE` | 0.95 |
| `gradle_failure` | `FAILURE: Build failed with an exception` | 0.95 |
| `junit_surefire` | `<<< FAILURE!`, `<<< ERROR!`, `There are test failures`, `Tests run:` with nonzero `Failures:`/`Errors:` | 0.93 |
| `go_test_fail` | `--- FAIL:`, `FAIL\t` package summary | 0.92 |
| `npm_error` | `npm ERR!`, `ELIFECYCLE` | 0.91 |
| `maven_error_header` | `### Error` | 0.90 |
| `panic` | `panic:` | 0.90 |
| `oom` | `OutOfMemoryError`, `Out of memory: Killed process`, `cannot allocate memory` | 0.90 |
| `docker_daemon` | `Error response from daemon` | 0.89 |
| `k8s_crashloop` | `CrashLoopBackOff` | 0.89 |
| `fatal` | leading `FATAL` / `FATAL:` | 0.88 |
| `exception` | `Exception`, `exception:`, Python traceback header | 0.85 |
| `assertion` | `AssertionError`, `assert … failed` | 0.80 |
| `clang_error` | `: error: ` (GCC/Clang style only) | 0.78 |
| `error_prefix` | leading `Error:` / `ERROR` | 0.75 |
| `exit_nonzero` | exit code / exited with / command failed | 0.70 |
| `failed_marker` | `FAILED`, leading `failed`, `failures=` | 0.60 |
| `search_hit` | SEARCH hit that matched no failure rule (fallback; no data loss) | 0.40 |

**Signature normalization (documented):** timestamps → `<ts>`, UUIDs → `<uuid>`, long hex → `<hex>`, Windows drive paths → **basename only**, digit runs → `<n>`, whitespace collapse, ASCII lowercasing.

**Residuals / false-positive risk notes:**

- Clean Surefire lines (`Failures: 0, Errors: 0`) do **not** match; only nonzero counts.
- Bare shell `Killed` is **not** matched (OOM requires the Linux killer phrase or `OutOfMemoryError`).
- `clang_error` requires the `: error: ` substring (avoids free-text “error:” spam); non-GCC compilers may fall through to generics.
- Unix absolute paths and UNC shares are **not** reduced to basenames (signature may still include workspace prefixes).
- Generic `failed_marker` / `error_prefix` remain low-confidence catch-alls and can still false-positive on noisy CI banners; prefer specialized ids when present.
- Rules are offline/literal only — **no network**, no ML.

### Optional

| Tool | Purpose | When registered | Class |
|------|---------|-----------------|-------|
| `jenkins_search_logs` | Local L1 log search; policy re-eval + `CheckStoreRead` on resolved job before frames (Wave 19/33) | `LogSearch` set | read |
| `jenkins_mirror_logs` | Multi-log L1 mirror into a collection (LOG-004); **status + refs only** — never full log bodies | `MultiLog` or `*MirrorLogAccess` with Coordinator (`--profile`) | read |
| `jenkins_get_trace_refs` | OTEL/Datadog IDs from build params (INT-002) | `EnableTraceRefs` | read |
| `jenkins_export_trace_refs` | Metadata-only export of correlation IDs via otel-export stub (INT-002); **no log text**; real OTLP residual | `TraceExporter` | read |
| `jenkins_query_external_logs` | External log refs by job/build (INT-003); **Jenkins Job/Read preflight** before backend (401/403/404 fail closed) | `ExternalLogs` | read |
| `jenkins_get_change_correlation` | Work-item/SCM host refs from params+changeSets (INT-004) | `EnableChangeCorrelation` | read |
| `jenkins_doctor` | Doctor report via MCP | `Doctor` set | read |

#### `jenkins_mirror_logs` (LOG-004 / Wave 26–27 + Wave 30 related discovery)

Bounded multi-build progressive mirror into independent L1 frames under a **collection id**.

| Arg | Required | Notes |
|-----|----------|--------|
| `logs` | one of logs / residual | Array of `{job_name, build_number, relation?}` — max **16** after dedup (+ related extras). Unset `relation` defaults to `primary` for explicit logs. |
| `collection_id` | optional | Prior collection: re-acquire **unsealed residual** members and merge with `logs`. Membership is **durable in SQLite** (schema v6 `log_collections` / `log_collection_members`) when `--profile` store is open — survives process restart (same profile only). |
| `include_related` | optional | **Wave 30:** when true, call `GetBuildGraph` from the **first primary** log and add related builds as extra members (API edges only; never invents jobs). Default false. |
| `related_max` | optional | Max **extra** related builds beyond primaries (default **4**, hard max **8**). Values above 8 fail closed (`invalid_argument`). |
| `related_direction` | optional | `upstream` \| `downstream` \| `both` (default `both`). Invalid values fail closed. |

| Response field | Meaning |
|----------------|---------|
| `collection_id` | Opaque session id for membership / continue residual / later pack selection |
| `logs[]` | Per-log `status` (`sealed` \| `mirrored` \| `denied` \| `error` \| `skipped`), `relation` (`primary` / `upstream` / `downstream` / `related`), `error_code`, `bytes_fetched`, `generation`, `durable_bytes`, `residual` |
| `total_bytes` | Progressive body bytes accepted across the acquire |
| `truncated_budget` | Collection total byte budget hit (`quota` / `skipped` rows) |
| `residuals` | Short notes (budget, cancel, continue path, related discovery) — **no log text** |

**Related discovery (Wave 30 / LOG+GRAPH):**

- Seed = first explicit `logs[]` entry only when multiple primaries (cost bound); residual-only `collection_id` continues skip discovery with a residual note.
- Graph soft-fails: network/API/graph errors or root-only graphs add a residual note and **still acquire primaries**.
- Related jobs get relation labels from graph roles (`upstream` / `downstream` / `related`).
- Dedup by `(job, build)`; extras stop at `related_max` and the absolute list hard max of **16**.
- Graph depth is server-bounded (depth 2); only nodes returned by Jenkins API edges are considered.

**Policy:** each job (primary **and** related) is evaluated for `deny_job_prefixes` and `CheckStoreRead`; denied jobs return `status=denied` / `policy_denial` and are **not** fetched; other jobs still acquire (partial success). MCP policy never elevates.

**Budgets:** Coordinator collection bounds (default 64 MiB total / 16 MiB per log / concurrency 4); tool list hard-capped at 16; related extras hard-capped at 8.

**Durability (Wave 27 / LOG-004 catalog):** collection membership (id, profile, job, build, optional generation_id, state, relation) is persisted in the profile Meta DB — **never log bodies**. Corrupt catalog rows fail closed (`corrupt_cache`). Without `--profile`/Catalog, membership is in-process only.

**L2 pack affinity (Wave 31/32):** maintenance L1→L2 compaction prefers co-packing sealed generations that share a durable `collection_id` (catalog affinity `profile=<id>|collection=<id>`). When all members of a pack share the same non-empty catalog relation, the label includes `|relation=<label>` (Wave 32); mixed or empty relations omit the suffix. Generations without collection membership still pack by job affinity. Investigation-collection rollover volumes (ARC full) remain residual. Use `get_build_logs` / `search_logs` for evidence ranges after mirror.

---

## Error codes

Stable machine codes (`internal/apperr`):

| Code | Meaning | Agent / operator action |
|------|---------|-------------------------|
| `authentication` | Missing/rejected credentials | Re-login; check keyring |
| `authorization` | Jenkins denied | Use personal principal with Job/Read |
| `not_found` | Missing job/build/item | Fix typed full name / number |
| `capability_missing` | Plugin/API absent | Degrade; use alternate tool |
| `throttled` | Rate limited | Back off |
| `timeout` | Deadline exceeded | Narrow scope / raise only if policy allows |
| `cancelled` | Context cancel | Stop fan-out |
| `corrupt_cache` | Local store bad | `cache verify` / repair / doctor |
| `quota` | Size/disk quota | Truncate requests; free cache |
| `policy_denial` | RO / RBAC deny | Expected; do not bypass |
| `upstream_protocol` | Bad Jenkins HTTP/JSON | Retry once; report |
| `invalid_argument` | Bad tool args | Fix schema (no URLs as job names) |
| `internal` | Local unexpected | doctor / support-bundle |

Errors must never include tokens. Prefer structured codes over scraping free text.

---

## Typed refs (MCP-002)

- Job names are **folder/job full names**, not `http://…` URLs.
- Builds: `job_name` + `build_number`.
- Logs: offset/length evidence, not raw Jenkins progressive URLs as the primary contract.

---

## Compatibility / deprecation

| Surface | Policy |
|---------|--------|
| Seed tool names | Stable for pilot; renames require ADR + DOC-002 update |
| Legacy `-auth` / `JENKINS_MCP_AUTH` | Deprecated bootstrap (KD-003); warn + retire |
| `jenkins_get_jobs` vs `jenkins_list_jobs` | Prefer `list_jobs` for folder-aware discovery; both support opaque `page_token` |
| Mutation registration | Always gated; never “enabled by default” in docs |
| Single-frame `.tar.zst` as “random access” | **Rejected** terminology; L2 is multi-frame seekable only |

When a tool is removed, keep a deprecation note here for at least one release train.

### PERF-003 diagnose fetch cache (Wave 27 + Wave 41)

High-level diagnose/compare tools share a process-local `FetchCache` (build meta, stages, tests, artifacts, SCM) with single-flight under session budgets. See [perf-baseline.md](perf-baseline.md#perf-003--diagnostics-session-cache-mvp--wave-27-single-flight).

**Artifact lists (Wave 41):** `getCachedArtifactList` does **not** call raw `ListArtifacts`. Fetch uses `listArtifactsWithPolicyFilter` (hard-cap when `deny_artifact_paths` live). Cache extras include `max=<n>` and sorted `deny_artifact_paths` fingerprint material (operator patterns only — never secrets). On every return (hit or miss) the list is cloned and live `FilterDeniedArtifacts` is applied so a previously cached fuller list cannot surface denied paths after policy tighten.


### list_jobs collect safety (Wave 41)

When deny patterns force collect+filter, page collection is capped (default **50** pages × max limit). Operators may raise via `--list-jobs-collect-max-pages` or `JENKINS_MCP_LIST_JOBS_COLLECT_MAX_PAGES` up to absolute **200** (fail-closed). Incomplete collection sets `truncated` + non-secret `message`.

### nodes / views collect safety (Wave 42)

Same pattern as list_jobs for policy-collect caps when deny patterns force full-list collect+filter:

| Surface | Env | Flag | Default | Absolute max |
|---------|-----|------|---------|--------------|
| `jenkins_get_nodes` | `JENKINS_MCP_NODES_COLLECT_MAX_PAGES` | `--nodes-collect-max-pages` | 50 | 200 |
| `jenkins_list_views` | `JENKINS_MCP_VIEWS_COLLECT_MAX_PAGES` | `--views-collect-max-pages` | 50 | 200 |

Flag wins over env; empty/0 = default; invalid or over absolute fail closed at serve start. Incomplete collection sets `truncated` + non-secret `message` (not silent under-count).


### Artifacts hard cap (Wave 42)

Process hard stop for `jenkins_list_artifacts` (default **500**, absolute **2000**): `--artifacts-hard-cap` / `JENKINS_MCP_ARTIFACTS_HARD_CAP`. Deny-path hard-cap fetch uses the live process cap; caller `max_artifacts` still re-slices after filter.

### Artifacts list JSON body bound (Wave 43)

Raw Jenkins list JSON body for `jenkins_list_artifacts` is hard-capped at the live process bound (default **2 MiB**, absolute **8 MiB**): `--artifacts-list-body-bytes` / `JENKINS_MCP_ARTIFACTS_LIST_BODY_BYTES` (flag wins; empty/0 = default; over absolute fail-closed at serve start). Truncation yields fail-closed invalid JSON (not a silent partial list). Residual: inventories with very long paths near AbsoluteMax count hard cap may still need the body bound raised (≤ 8 MiB); transport-level `MaxJSONBodyBytes` (default **32 MiB**, absolute **128 MiB** via `--max-json-body-bytes` / `JENKINS_MCP_MAX_JSON_BODY_BYTES`) remains a separate ceiling.
