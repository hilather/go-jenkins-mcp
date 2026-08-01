# Pack affinity lite (ARC-011)

| Field | Value |
|-------|--------|
| **Task** | ARC-011 (lite / Wave 24 + Wave 31 collection + Wave 32 relation suffix) |
| **Status** | Implemented for maintenance L1→L2 |
| **Related** | Architecture §9.4, `internal/logmirror` affinity, ARC-005 packing, LOG-004 catalog |

## Affinity format

Catalog `AffinityGroup` labels for maintenance packs are derived from sealed log identity **or** durable collection membership (Wave 31), with an optional shared relation suffix (Wave 32):

```text
profile=<id>|collection=<collectionID>|relation=<label>  # collection + shared non-empty relation (Wave 32)
profile=<id>|collection=<collectionID>   # collection member (preferred); mixed/empty relation
collection=<collectionID>[|relation=<label>]  # empty profile
profile=<id>|job=<fullName>              # no collection mapping (job fallback)
job=<fullName>                           # job fallback, empty profile
mixed                                    # only if a pack is forced with multiple affinities
```

| Rule | Detail |
|------|--------|
| **Collection inputs** | Profile + opaque collection id from schema v6 `log_collection_members` (generation_id &gt; 0) — no log body, credentials, or build numbers in the key |
| **Relation suffix (Wave 32)** | When **all** gens in a pack batch share the same non-empty catalog `relation`, append `\|relation=<label>` (normalized, max 64-byte part, whole key ≤ 256). Differing or empty relations → **omit** suffix (collection key only). Selection keys never include relation (mixed relations still co-pack under one collection) |
| **Job inputs** | Profile + Jenkins job fullName only (no build number, no log body, no credentials, no relation) |
| **Normalize** | Trim; strip controls; replace `\|` and newlines in parts with `_` |
| **Bound** | Max **256** bytes; oversize keys keep a head prefix + `#` + 8-hex SHA-256 of the full string |
| **Empty job** | `job=_` placeholder so empty affinity still packs |
| **Same collection** | Co-pack sealed gens that share a collection id (may span different jobs / relations) |
| **Same job, many builds** | Share one job affinity key when no collection mapping (locality for related builds of one job) |
| **Profile isolation** | Collection keys always include profile; mismatch between collection member profile and generation profile is fail-closed (mapping ignored or catalog error) |

Helpers: `logmirror.AffinityGroupKey`, `CollectionAffinityKey`, `CollectionAffinityKeyWithRelation`, `AffinityGroupFromKeys`, `AffinityGroupFromGenerationsWithCollections`, `SelectAffinityPackBatches`, `SelectCollectionAwarePackBatches`. Store: `Meta.ListGenerationCollections` (carries `Relation` when present).

## Candidate selection (lite + Wave 31/32)

Maintenance compaction (`app.Maintainer`) no longer fills packs in arrival order across jobs.

1. Partition sealed unpinned candidates into force-aged vs rest (unchanged age/headroom gates).
2. Load `Meta.ListGenerationCollections` (genID → collection; empty profile = all rows in the store). Fail closed on corrupt catalog.
3. Within each partition, **group by collection-aware affinity key** (`SelectCollectionAwarePackBatches` — collection id only, **no** relation in the selection key), sort groups and members deterministically.
4. Fill packs up to `MaxMembersPerPack` **inside** one affinity only.
5. `PackGenerations` / `defaultPackWithCollections` sets `PackDescriptor.AffinityGroup` from `AffinityGroupFromGenerationsWithCollections` (collection key + optional shared `|relation=`), else job keys.

Effects:

- Sealed gens in the same durable collection co-pack (cross-job investigation locality).
- Two different collection ids produce separate packs even if jobs overlap.
- Gens without collection membership still job-affinity pack.
- Different profiles never co-pack (profile is part of every key; collection profile mismatch fails closed).
- Single-affinity shortfall waits for more same-affinity gens or force-age (min size 1) rather than mixing affinities.
- When every member of a collection pack shares e.g. `relation=primary`, the catalog label is `profile=…|collection=…|relation=primary` (Wave 32). Mixed relations keep the collection-only label.

Collection packing (`PlanPackBatches` / investigation collections) remains the broader ARC-011 path (isolation domain + rollover bounds); Wave 31/32 wire the **maintenance** path to the durable catalog.

## Residuals (full ARC-011)

Not done in this lite pass:

| Residual | Notes |
|----------|--------|
| Full investigation / root-build / stage-downstream affinity beyond catalog | Graph discovery + collection session already feed members; maintenance uses catalog only |
| Pack rollover by uncompressed bytes / frames on maintenance path | Collection packing has bounds; maint uses member count only |
| Eviction / release prefer by affinity locality | Quota still score-based; no affinity-aware eviction |
| Heat / access metrics for locality | PERF / telemetry residual |
| Late-member continuation volumes + relationship manifests | Architecture §9.4 volume sequence |
| Binary artifact co-pack policy | Explicitly out of log packs |
| Optional tiny adjacent-build co-pack across jobs without collection | Disallowed (job affinity only when no collection) |

### Wave 32 note

Relation-label suffix on catalog `AffinityGroup` is implemented for maintenance packing labels only:

- Shared non-empty relation → `|relation=<normalized label>`
- Mixed or empty → omit suffix
- Job-affinity fallback unchanged (never appends relation)
- Selection / co-pack grouping still keys on `profile|collection` only so mixed-relation members of one collection stay co-packed

## Verify

```bash
export PATH="$HOME/.local/go/bin:$PATH"
go test ./internal/logmirror/ ./internal/store/ ./internal/app/ -count=1
make test && make lint
```
}