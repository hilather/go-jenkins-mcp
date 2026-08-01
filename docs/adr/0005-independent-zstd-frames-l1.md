# ADR 0005: Independent Zstandard frames for L1 logs

- **Status:** Accepted  
- **Date:** 2026-07-31  
- **Owner:** engineering  
- **Related:** architecture §1 KD 6–7, §9; FND-008; LOG / PERF tasks  

## Context

Progressive Jenkins logs can be large. Unbounded `ReadAll` and single giant compressed blobs force full download/decompression for small evidence ranges. Zstandard **frames** are independently decodable; **blocks inside one frame** are not safe random-access boundaries.

## Decision

1. Mirror progressive logs incrementally and compress **immediately** into **independently decodable Zstandard frames/chunks** (L1), with indexes for line/offset mapping.  
2. Product language, metrics, and tests use **frame** (and uncompressed checkpoint size), not “random access by internal block.”  
3. A normal **single-frame** `.tar.zst` or single-frame log blob is **not** acceptable as a random-access design.  
4. Never stage a complete decoded remote copy on disk as the primary path; stream through counting/sanitizing readers into the frame writer.  
5. Download each remote log byte **once per generation**; subsequent search/diagnosis is local.

## Alternatives

| Alternative | Why not |
|-------------|---------|
| Single-frame zstd of entire log | No efficient range read; decompression amplification. |
| Store raw progressive text only | Disk bloat; no bounded read story. |
| gzip whole-file only | Weaker random access; still full-inflate patterns. |

## Consequences

- LOG/PERF work must prove frame-bounded reads and no over-download regressions (see KNOWN_DEFECTS KD-001).  
- Frame size is a tuning/policy parameter with amplification budgets (architecture §15).  
- L2 packs reuse independent frames; see [ADR 0007](0007-seekable-multiframe-tar-zst-l2.md).
