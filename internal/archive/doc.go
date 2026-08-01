// Package archive implements ArchiveStore: L2 seekable multi-frame .tar.zst packs
// with a native Go reader (ARC-003) and object model (ARC-001).
//
// Format: docs/arc/pack-format-v1.md (ARC-002). Single-frame .tar.zst is never
// accepted as random-access storage.
//
// PackFromGenerations (ARC-005-lite) builds packs from sealed L1 generation
// members, preferring zero-recompression copy of independent L1 .zst frames via
// WritePackWithPayloadFrames / multi-payload assembly. Journal-lite publish
// (temp → verify → atomic rename; L1 mark-packed without delete) is wired from
// logmirror; full lease/compaction remains ARC-005 residual.
//
// ARC-006: sibling .idx.json indexes bind to pack checksum/size/schema. Stale
// indexes are never trusted; OpenPack (embedded seek table) is the bounded
// fallback. RebuildIndex / RepairIndex / VerifyPack / QuarantinePack are explicit
// library APIs — MCP reads must not unbounded-sync rebuild huge packs.
//
// ratarmount-rs adapter (ARC-004) is blocked until ARC-000 supplies an exact
// repository+commit; see docs/arc/ratarmount-rs-qualification.md.
//
// Package boundaries: may use internal/apperr only among first-party packages.
// Must not import MCP, tools, store, or jenkins.
package archive
