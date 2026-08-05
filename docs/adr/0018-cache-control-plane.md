# ADR 0018 — Unified cache control plane

## Status

Accepted

## Context

The product now has multiple specialized caches (progressive console logs in
`internal/store`, typed non-log resources in `internal/resourcecache` / ADR 0017,
diagnostic fetch and survey summary auxiliaries). Operators need independent
modes, effective configuration, typed telemetry, and safe lifecycle operations
without forcing one physical storage format or rewriting existing engines.

A temporary implementation pack proposed a typed registry, four-mode control,
declarative + runtime override configuration, shared adminops, and plan/confirm
dump/purge. That pack is **not** product documentation; durable residuals stay
in GitHub Issues.

## Decision

1. **Add `internal/cachecontrol`** as the process-local control plane: type
   registry, descriptors/capabilities, configuration resolution, mode
   enforcement helpers, telemetry vocabulary, and operation plan types.
2. **Stable type IDs** (closed set for v1):
   `console_log`, `stage_log`, `artifact_blob`, `artifact_catalog`,
   `artifact_text`, `artifact_inspection`, `test_report`, `pipeline_stages`,
   `build_changes`, `diagnostic_fetch`, `survey_summary`, `ratarmount_index`.
3. **Modes** (every managed type): `off` | `read_only` | `write_only` |
   `read_write`. Mode changes **never** delete data; purge is a separate
   plan/confirm operation.
4. **Config precedence** (highest first): emergency/startup safety → runtime
   override → profile config → optional server cache config file → built-in
   compatibility defaults.
5. **Absent new config = pre-feature behavior** for types already in tree
   (resource kinds + console log when their stores are open). Defaults:
   available types `read_write`; `ratarmount_index` `off` / `unqualified`;
   fleet share off for non-log object classes; raw dump gated off.
6. **Cache hits never bypass** authentication, Jenkins authorization, MCP
   policy, path policy, redaction, or request budgets. Mode gates apply
   **after** authorization intent and **before** serving/fill; re-auth remains
   mandatory on hits (ADR 0017).
7. **Adapters wrap stores** — do not replace L1 frames or resource blob
   formats. Unsupported settings/ops are **rejected**, not silently ignored.
8. **Admin HTTP, admin MCP, CLI, and UI** call one shared service (extend
   `internal/adminops` / thin handlers). Existing `admin_cache_status` /
   evict tools remain compatible; typed inventory/config APIs are additive.
9. **Telemetry labels** are low-cardinality (type id, mode, layer, outcome
   reason codes). Never job names, paths, URLs, subjects, or free-form errors.
10. **Raw dumps, new fleet object classes, and ratarmount** stay default-off /
    unqualified until explicitly qualified (Issues #7 / #8 and startup gates).
11. **No permanent Markdown implementation backlog** in product docs for this
    program; open work is GitHub Issues only.

## Alternatives

| Option | Why rejected |
|--------|----------------|
| Per-store one-off toggles without registry | Divergent admin/MCP behavior; no inventory |
| Single physical format for all caches | Contradicts progressive logs vs immutable blobs |
| Config rewrite on every profile read | Breaks config-as-code and gitops |
| Enable ratarmount/raw dump by default | Supply-chain and data-exfil risk |

## Consequences

- Tools and stores gain optional mode checks via the control plane without
  changing default open behavior when config is absent.
- Operators can disable a type without purge; late fills must respect purge
  epoch / config revision when those fields exist.
- Residual: full metadata object-ref graph polish, full free-lab matrix, SPA
  polish, fleet v2 object classes, ratarmount production go — Issues, not
  silent Done claims.

## Related

- ADR 0017 (typed resource cache data plane)
- ADR 0005 / 0007 (console log L1/L2)
- ADR 0016 (fleet; distribution capability, not a payload type)
- `docs/caching.md`
- `internal/cachecontrol/`
- GitHub Issues #7 (fleet v2), #8 (ratarmount)

## Owner

Engineering (+ security review for dump/export and telemetry canaries)
