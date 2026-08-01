# ADR 0010: Tool response budgets (64 KiB target / 1 MiB hard)

- **Status:** Accepted (enforcement **partial** — MCP-001 hard max + soft target via `internal/tools.EnforceBudget`; operator-tunable soft target Wave 47; opaque `page_token` on get_jobs / list_jobs / list_builds; other list/excerpt pagers residual)  
- **Date:** 2026-07-31  
- **Owner:** engineering  
- **Related:** architecture §8.6, §15; FND-008; MCP-001

## Context

Unbounded tool results blow model context, memory, and support cost. Logs and job graphs can dwarf useful triage evidence. Budgets must be central policy, not per-tool courtesy.

## Decision

Adopt architecture §8.6 as binding product policy:

| Limit | Default |
|-------|---------|
| Structured result **target** | **64 KiB** |
| Log evidence per excerpt | **8 KiB** (small number of excerpts) |
| Total tool response **hard stop** | **1 MiB** |
| Lists | Always paginated |
| Large text | Stable **continuation handles** |
| Oversized fields | Summarize with counts + retrieval handles; **never silently drop** without truncation metadata |

Responses should report truncation, returned byte count, total known size, and continuation state where applicable. High-level diagnosis returns evidence references and bounded excerpts, not full logs.

Budgets are **configuration policy** with enterprise-adjustable values, but the hard ceiling concept remains; raising ceilings requires performance and security review.

### Operator-tunable soft target (Wave 47 Track B; absolute lift Wave 51 Track C)

| Surface | Detail |
|---------|--------|
| Default | `DefaultTargetBytes` = **64 KiB** |
| Env | `JENKINS_MCP_TARGET_BYTES` |
| Flag | `--target-bytes N` (wins over env) |
| Resolve | `tools.ResolveTargetBytes` — default → env → flag; empty/0 → default; invalid fail closed |
| Absolute soft-target ceiling | `AbsoluteMaxTargetBytes` = `AbsoluteMaxHardMaxBytes` (**64 MiB**); oversize fail closed |
| Enforce clamp | Soft target never silently exceeds live hard max (`Normalize` / `effectiveBudget`) |
| Serve clamp honesty (Wave 53 Track C) | `tools.SoftTargetClampApplied`; serve logs non-secret `target_bytes_clamped` + `target_bytes_resolved` |

**Honesty (Wave 51):** soft-target absolute matches the hard-max absolute (64 MiB), so operators who raise `--hard-max-bytes` may also raise `--target-bytes` up to the same bound. Resolve does **not** require target ≤ bootstrap hard max; when resolve yields target > bootstrap/live hard max, serve clamps after `Normalize` (soft never exceeds hard at enforce). Defaults remain 64 KiB soft / 1 MiB hard. Live resolved soft target is not exposed in offline `operator_caps_snapshot` (`live_target_bytes_available_offline=false`).

**Operator-visible clamp (Wave 53 Track C):** when resolved soft target exceeds the serve bootstrap hard max, `Normalize` clamps `TargetBytes ≤ HardMaxBytes`. Serve records that on the existing result-budget log line as `target_bytes_clamped=true|false` and `target_bytes_resolved=N` (byte counts only; never secrets). `target_bytes=` remains the post-clamp effective soft target. Absolute fail-closed ceilings (`AbsoluteMaxTargetBytes` / `AbsoluteMaxHardMaxBytes`) are unchanged.

## Alternatives

| Alternative | Why not |
|-------------|---------|
| Unlimited results | Context blowups; OOM risk; non-triage UX. |
| Soft guidance only | Ineffective under model pressure to “get everything.” |
| Per-tool ad hoc limits only | Inconsistent; bypass via new tools/aliases. |

## Consequences

- Central enforcement lives in `internal/tools` (`EnforceBudget`, wired through `Register`/`addTool`).  
- Hard max exceeds → truncation summary with metadata (or `quota` error in strict mode); never silent drop.  
- Soft target is operator-tunable at serve bootstrap (`ResolveTargetBytes`, absolute ≤ 64 MiB); over-target results under hard max report `over_target` metadata without truncation.  
- Opaque list pagination (`page_token` / `next_page_token`) is implemented for `jenkins_get_jobs`, `jenkins_list_jobs`, and `jenkins_list_builds` in `internal/jenkins` (filter fingerprint; not a multi-tenant security boundary for stdio pilot).  
- Residual: per-field excerpt budgets on diagnosis tools; other list surfaces (e.g. nodes) still use numeric offset only. Soft-target absolute is aligned with hard-max absolute (Wave 51); soft still clamped to live hard at enforce.
