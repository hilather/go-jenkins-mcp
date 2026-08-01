# Seed MCP tool inventory (FND-003)

Frozen against upstream `83f66a9c57c0bc26044f654e589b6361787f0c89` / `README.upstream.md`.

| Tool | Required args | Optional (defaults) | Side effects | Contract coverage |
|------|---------------|---------------------|--------------|-------------------|
| `jenkins_get_jobs` | — | — | read | yes |
| `jenkins_get_job` | `name` (or `job_name` alias) | `max_builds` (20) | read | yes |
| `jenkins_get_running_builds` | — | — | read | yes |
| `jenkins_get_build` | `job_name`, `build_number` | — | read | yes |
| `jenkins_get_build_logs` | `job_name`, `build_number` | `offset` (0), `length` (8192) | read; **bounded** (LOG-001; residual wire until close) | yes |
| `jenkins_get_build_log_tail` | `job_name`, `build_number` | `max_length` (8192) | read; may probe from 0 (KD-002) | yes |
| `jenkins_start_job` | `job_name` | `parameters` | **mutate** (enqueue) | yes |
| `jenkins_get_queue_item` | `queue_id` | — | read | yes |
| `jenkins_wait_for_queue_item` | `queue_id` | `timeout_seconds` (30), `poll_interval_seconds` (2) | read/poll | yes (short timeout) |
| `jenkins_wait_for_running_build` | `job_name`, `build_number` | `timeout_seconds` (600) | read/poll | yes (short timeout) |
| `jenkins_search_builds` | `job_name` | result/params filters, `limit` (5), `max_lookback` (100) | read | yes |
| `jenkins_stop_build` | `job_name`, `build_number` | `confirmation_token` | **mutate** (stop) | yes |
| `jenkins_cancel_queue_item` | `queue_id` | `confirmation_token` | **mutate** (cancelItem) | yes |

## Nested folders

Job names with `/` map to Jenkins path `/job/a/job/b` via `buildJobPath`.

## Errors

Typical shapes: `missing required argument: …`, `job '…' build #N not found`,
`jenkins api returned status N: …`. Credentials must not appear in errors
(canary tests).
