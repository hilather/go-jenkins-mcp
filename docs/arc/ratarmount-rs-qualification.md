# ARC-000 — `ratarmount-rs` qualification (go / no-go)

| Field | Value |
|-------|--------|
| **Task** | ARC-000 |
| **Status** | **Deferred / no-go** until engineering supplies the exact repository + commit/release |
| **Date** | 2026-07-31 |
| **Owner** | engineering (+ security for supply-chain approval) |
| **Related** | ADR 0007, architecture §10, ARC-001–ARC-004 |

## Decision summary

| Question | Result |
|----------|--------|
| Exact public repo named `ratarmount-rs` found and verified? | **No** — preferred name not found as an authoritative public repository in prior research and this qualification pass |
| Adopt a similarly named public project (e.g. Python `ratarmount` / other `*ratarmount*` crates) as the intended dependency? | **No** — do **not** silently substitute |
| Product impact | **Native Go seekable multi-frame reader remains the mandatory supported path** (`ARC-003`) |
| Optional FUSE / Rust adapter (`ARC-004`) | **Blocked** on supply of exact repo + commit + license + support model |

This is an explicit **no-go for binding the product to an un-supplied dependency**, not a rejection of the long-term product preference for a `ratarmount-rs`-class L2 engine after qualification.

## What engineering must supply before re-open

A re-qualification package must name **all** of:

1. Repository URL (HTTPS), owner/org, and visibility (public / private / internal mirror)
2. Exact commit SHA and/or signed release tag
3. License and provenance (including transitive crate licenses)
4. Expected integration mode: direct library/FFI, managed local sidecar/CLI, and/or native Linux FUSE
5. Support / CVE-response owner and update-rollback plan
6. SBOM or reproducible `cargo` lock inputs used for the pin
7. Supported seekable-Zstandard dialect and index format documentation

Until those exist in writing, agents and packagers **must not** vendor, wrap, or document any substitute as “the” `ratarmount-rs` dependency.

## Research notes (non-authoritative)

| Observation | Implication |
|-------------|-------------|
| Preferred string `ratarmount-rs` was **not** verified as an authoritative public project name | Cannot pin, SBOM, or security-review a phantom crate |
| Public **Python** [ratarmount](https://github.com/mxmlnkn/ratarmount) documents multi-frame/seekable Zstd requirements | Useful prior art for **format** expectations only; **not** the approved Rust engine |
| Similarly named crates/repos must not be assumed equivalent | Silent adoption would violate ARC-000 acceptance criteria |

No link above is adopted as a production dependency by this document.

## Platform and product constraints (unchanged)

- **Tier-1:** Rocky Linux + Ubuntu; native Linux FUSE may be used for *optional* human inspection after a future go decision.
- **Windows / WinFsp:** out of scope.
- **MCP core reads** (log range, search, evidence) must work via **direct API + native Go** when FUSE or any Rust adapter is absent, failed, or policy-disabled.
- Durable on-disk contract is the **versioned multi-frame pack format** (`docs/arc/pack-format-v1.md`), not any particular reader implementation.
- Ordinary **single-frame** `.tar.zst` is **never** accepted as performant random-access storage.

## Acceptance criteria (ARC-000)

| Criterion | Evidence |
|-----------|----------|
| Approved go/no-go names exact repo, commit, license, … | **No-go / deferred** — dependency not supplied; see Decision summary |
| If not accessible, explicit deferred + native path | **This document** + ADR 0007 + `internal/archive` native reader |
| No silent substitution of similarly named projects | Stated policy above; `ARC-004` blocked |
| Rocky/Ubuntu FUSE qualify when adapter exists | **N/A** until pin; native path has no FUSE requirement |
| Direct API / sidecar / FUSE measured | **Deferred** with adapter |
| Golden bytes match adapter vs native | **Deferred** (adapter absent); native golden fixtures in `internal/archive` |
| Warm/cold / corruption measurements for adapter | **Deferred** |
| Adapter failure does not invalidate `ArchiveStore` / format | Interface + format isolated; native reader independent |
| No single-frame `.tar.zst` as random access | Pack format v1 + native validator reject |

## Re-open checklist (future go)

When engineering supplies the pin package:

1. Record pin in this file (or a superseding ADR) with SHA, license, SBOM path.
2. Security review: unsafe Rust, parser boundaries, fuzzing, CVE process.
3. Prototype Tier-1: library/FFI vs sidecar vs FUSE; measure index, range, concurrency, cancel, SELinux/AppArmor.
4. Golden multi-member packs: byte-identical ranges vs native Go reader.
5. Only then implement `ARC-004` adapter behind `ArchiveStore`.

## Residual

- **ARC-004** (qualified `ratarmount-rs` adapter) remains **blocked** on supply.
- Native Go path (`ARC-003`) and `ArchiveStore` (`ARC-001`) proceed without the Rust engine.
- Preferred product name `ratarmount-rs` may remain in architecture language as a **preference**, never as an implied implemented dependency.
