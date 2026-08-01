# ADR 0007: Seekable multi-frame tar.zst for L2 + dual readers

- **Status:** Accepted  
- **Date:** 2026-07-31  
- **Owner:** engineering  
- **Related:** architecture §1 KD 7–8, §9–10; ARC-000; FND-008; [ADR 0005](0005-independent-zstd-frames-l1.md)  

## Context

L1 independent frames handle hot/recent logs. Cold capacity and inode pressure need **immutable packs** of related build logs. A single-frame `.tar.zst` is not random-access. Engineering prefers a `ratarmount-rs`-class engine for FUSE inspection on Linux; public research has not verified an authoritative repo under that exact name, so qualification is mandatory.

## Decision

1. **L2 format:** immutable **seekable multi-frame** `.tar.zst` volumes with:  
   - many **independent Zstandard frames** (not one huge frame),  
   - TAR members for related logs,  
   - seek table / checkpoint index compatible with the chosen reader stack,  
   - manifest recording pack schema and indexes.  

2. **Never** claim a single-frame `.tar.zst` provides random access.  

3. **Readers:**  
   - **Mandatory:** native **Go** reader path for non-mount, CI, and fallback (no FUSE required).  
   - **Preferred L2 engine:** `ratarmount-rs` (or the exact internal dependency engineering supplies), behind an `ArchiveStore` interface, **after** pin, license, supply-chain, Tier-1 FUSE, recovery, and performance qualification (`ARC-000`).  

4. **Do not** double-compress `.zst` members inside an outer `.tar.zst` as the baseline.  

5. If the preferred Rust/FUSE engine is unavailable, packs remain readable via the native Go path.

## Alternatives

| Alternative | Why not |
|-------------|---------|
| Single-frame tar.zst | No frame-level seek; full decompress for small ranges. |
| Zip / plain tar.gz only | Weaker alignment with independent-frame design and ratarmount preference. |
| FUSE-only reader | Breaks headless CI, non-FUSE hosts, and macOS Tier-2 story. |
| Bind to un-audited ratarmount binary now | Supply-chain and compatibility risk before ARC-000. |

## Consequences

- Writer and index code must speak frames/checkpoints; tests cover corruption and amplification.  
- Packaging may ship an optional FUSE helper only on Tier-1 Linux after qualification.  
- Residual: exact `ratarmount-rs` repository/revision not yet supplied; treat name as product preference until pinned.
