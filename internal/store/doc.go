// Package store is local durable state: secure data directories, SQLite
// metadata indexes, L1 independent Zstandard frames (STO-003/004), quotas,
// retention, and recovery. Archive packs are behind ArchiveStore in the
// archive package (ARC-*).
//
// L1 frame schema (STO-003):
//
//	frames/<generation_id>/<seq>.zst  — one independent zstd frame (no dict)
//	SQLite chunks row — raw/line ranges, SHA-256 content+frame, codec, path
//
// Commit order (STO-004): write *.zst.tmp → fsync → atomic rename → dir fsync
// → SQLite chunk insert → caller advances log_generations.jenkins_offset.
// Incomplete frames are invisible (no meta). Recover removes orphan temps/files.
//
// Bounded reads (LOG-003): LogReader.ReadRange / ReadLineRange / TailBytes /
// TailLines decompress only intersecting frames and report requested vs
// decompressed bytes. UTF-8: raw bytes are authoritative; multi-byte runes may
// split at range edges.
//
// L2 packs live under archives/ (see ArchivesDirName). QuotaManager (ARC-007)
// tracks L1/L2 physical/logical bytes, pins, active-reader leases, dry-run
// EvictPlan, and interrupt-safe journal-lite eviction. Serve-time auto-evict,
// L1→L2 packing, and L1 release after verified pack live in
// internal/app.Maintainer.
//
// L1 release (ARC-005 residual): ReleaseManager.ReleasePackedL1 requires a
// sealed generation with packed_pack_id, injects PackVerifier (logmirror
// VerifyPackForRelease), blocks on pins/leases, journals via
// release-journal.json, then marks l1_released, deletes chunk meta and frame
// files. The L2 pack is never deleted. Crash recovery finishes pending items
// only when the pack still verifies. Reads after release use L2 pack members
// (logmirror Machine.ArchiveRoot). Dual ratarmount reader remains residual.
//
// Boundaries (FND-004 / ADR 0001): store must not import tools, mcpserver, or
// archive (PackVerifier is injected). Secrets never live under data directories
// (see package keyring).
//
// Schema v6 (LOG-004 durable catalog): log_collections + log_collection_members
// hold multi-log membership/refs only (never log bodies) so collection_id
// residual continue survives restart under the same profile.
//
// Schema v7 (survey PERF residual): survey_summary_cache holds compact signature
// summaries for jenkins_survey_recent_failures (hashes, result, byte counts,
// optional short redacted text). Never log tails or secrets. TTL + max-entry
// eviction; corrupt rows fail closed (deleted, re-fetch).
//
// Tasks: STO-001 (secure dirs), STO-002 (SQLite metadata), STO-003/004 (frames),
// LOG-003 (bounded local reads), LOG-004 collection catalog, ARC-005 residual
// (L1 release), ARC-007 (quota/retention/pins/eviction), survey durable cache.
package store
