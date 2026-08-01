// Package logmirror implements progressive log fetch with hard byte caps and
// multi-frame Zstandard compression into the local store (no unbounded ReadAll).
//
// LOG-002 owns the progressive log-generation state machine: committed offset,
// Jenkins next offset / more-data, build completion, generation IDs, rewrite
// detection, sealing, and crash-safe resume via the store metadata layer.
//
// STO-003/004: when Machine.Frames is set, Append streams bytes into independent
// Zstandard frames (crash-safe commit). LOG-003 reads use Machine.Reader for
// bounded local range/tail APIs without decompressing unrelated frames.
//
// LOG-004: Coordinator fans out multi-log acquisition under concurrency and
// byte budgets; each log streams into its own generation/frames. Access exposes
// EnsureMirrored / ReadRange / Tail for MCP tool wiring (same profile only).
// When Catalog (*store.Meta) is set, collection membership is durable in SQLite
// (schema v6) so collection_id residual continue survives restart (same profile).
// Wave 30: optional related-build discovery (include_related) is tools-layer
// via GetBuildGraph → extra LogRequests; Coordinator still acquires under bounds.
//
// ARC-011: PlanPackBatches groups sealed logs by AffinityDomain isolation
// (profile + optional retention/sensitivity/policy) and rolls over on member
// count, uncompressed bytes, or frame bounds. PackCollectionBatches publishes
// one pack per batch; never co-packs different profiles.
//
// ARC-011 lite + Wave 31 (maintenance L1→L2): SelectCollectionAwarePackBatches
// prefers profile=<id>|collection=<id> from Meta.ListGenerationCollections when
// generation_id is set on durable members; otherwise AffinityGroupKey job
// affinity (profile=<id>|job=<fullName>). PackGenerations derives AffinityGroup
// from member keys / collection when unset. Optional relation-label affinity
// suffix, full investigation-collection rollover volumes, eviction-by-affinity,
// and heat metrics remain residual.
//
// ARC-005 journal-lite: PackGenerations verifies via OpenPack before PutPack,
// then optional PackMarker.MarkGenerationPacked. L1 frames are retained until
// store.ReleaseManager releases them after re-verify (app.Maintainer). After
// l1_released, Machine.ReadRange/TailBytes fall back to L2 pack members via
// ArchiveRoot (ReadRangeFromPack). Dual ratarmount reader remains residual.
//
// Boundaries: may import jenkins + store + archive + apperr; must not import
// tools or mcpserver. Tool handlers never call progressiveText directly.
package logmirror
