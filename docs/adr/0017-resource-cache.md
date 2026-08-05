# ADR 0017 — Typed resource cache (non-log)

## Status

Accepted

## Context

Console logs use progressive Zstd frames and L2 packs (`metadata.sqlite`). Expanding cache to artifacts, test reports, pipeline stages, SCM changes, and stage logs must not repack into the log schema or weaken authorization.

## Decision

1. **Separate control plane** `internal/resourcecache` with per-profile `resource-cache/resources.sqlite` and `objects/` under the profile data directory.
2. **Storage classes:** `immutable_blob`, `structured_resource`, `derived_result`; stage logs stored as structured text with complete/partial completeness.
3. **Console log store unchanged** (frames, packs, fleet log protocol v1).
4. **Every hit re-authorizes** via `AccessContext` + `AuthorizationVerifier` (tools pass live MCP policy).
5. **Incomplete never sealed as complete**; partial is variant-scoped only.
6. **Fleet object classes for non-log resources default off** until protocol v2 (residual Issue).
7. **`ratarmount-rs` optional** — core path works without FUSE; pin/qualification residual.

## Consequences

- Tools optionally receive `RegisterOptions.ResourceCache` opened at serve when a profile data dir exists.
- Older binaries ignore `resource-cache/` trees.
- New fleet classes must not break log v1.

## Related

- `docs/caching.md`
- `internal/resourcecache/`
