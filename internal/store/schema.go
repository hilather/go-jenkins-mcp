package store

// CurrentSchemaVersion is the latest SQLite metadata schema.
// Bump only with an explicit migration and tests.
// v1: STO-002 generations + stub chunks
// v2: STO-003/004 full independent Zstd frame metadata + line checkpoints
// v3: ARC-005-lite packed_pack_id / packed_at on generations (L1 mark after L2 verify)
// v4: ARC-007 pins + generation outcome (success/failed retention)
// v5: ARC-005 residual L1 release (l1_released) + ARC-009 AEAD chunk metadata (enc_*)
// v6: LOG-004 durable multi-log collection catalog (membership only; no log bodies)
// v7: PERF residual — durable compact survey signature summaries (hashes + short
//
//	redacted text only; never log bodies / secrets)
//
// v8: FLC-020 pure-Zstd wire size/hash on chunks (zstd_size / zstd_sha256) for
//
//	peer export without treating local AEAD ciphertext as portable
const CurrentSchemaVersion = 8

// MetaDBFile is the SQLite filename under a profile data directory.
const MetaDBFile = "metadata.sqlite"

// migration is one transactional schema step applied in order.
type migration struct {
	Version int
	SQL     string
}

// migrations is the ordered list of schema upgrades. Each step runs in its
// own transaction; version is recorded only after the step succeeds.
var migrations = []migration{
	{
		Version: 1,
		SQL: `
CREATE TABLE IF NOT EXISTS schema_version (
	version INTEGER NOT NULL PRIMARY KEY,
	applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS log_generations (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	profile TEXT NOT NULL,
	job TEXT NOT NULL,
	build INTEGER NOT NULL,
	generation INTEGER NOT NULL,
	sealed INTEGER NOT NULL DEFAULT 0,
	jenkins_offset INTEGER NOT NULL DEFAULT 0,
	more_data INTEGER NOT NULL DEFAULT 1,
	build_complete INTEGER NOT NULL DEFAULT 0,
	updated_at TEXT NOT NULL,
	UNIQUE(profile, job, build, generation)
);

CREATE INDEX IF NOT EXISTS idx_log_generations_lookup
	ON log_generations(profile, job, build, generation DESC);

-- Optional stub for STO-003 frame/chunk metadata (no payload yet).
CREATE TABLE IF NOT EXISTS chunks (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	generation_id INTEGER NOT NULL REFERENCES log_generations(id) ON DELETE CASCADE,
	seq INTEGER NOT NULL,
	raw_start INTEGER NOT NULL,
	raw_end INTEGER NOT NULL,
	UNIQUE(generation_id, seq)
);
`,
	},
	{
		Version: 2,
		SQL: `
-- STO-003: replace stub chunks with full independent-frame metadata.
-- Early pilot: no production rows expected; drop+recreate is safe.
DROP TABLE IF EXISTS line_checkpoints;
DROP TABLE IF EXISTS chunks;

CREATE TABLE chunks (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	generation_id INTEGER NOT NULL REFERENCES log_generations(id) ON DELETE CASCADE,
	seq INTEGER NOT NULL,
	raw_start INTEGER NOT NULL,
	raw_end INTEGER NOT NULL,
	line_start INTEGER NOT NULL,
	line_end INTEGER NOT NULL,
	uncompressed_size INTEGER NOT NULL,
	compressed_size INTEGER NOT NULL,
	content_sha256 TEXT NOT NULL,
	frame_sha256 TEXT NOT NULL,
	codec TEXT NOT NULL DEFAULT 'zstd',
	codec_level INTEGER NOT NULL DEFAULT 3,
	format_version INTEGER NOT NULL DEFAULT 1,
	dict_id TEXT,
	rel_path TEXT NOT NULL,
	created_at TEXT NOT NULL,
	UNIQUE(generation_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_chunks_generation_raw
	ON chunks(generation_id, raw_start, raw_end);

CREATE INDEX IF NOT EXISTS idx_chunks_generation_line
	ON chunks(generation_id, line_start, line_end);

-- Sparse line→offset samples within a frame (absolute generation coordinates).
CREATE TABLE line_checkpoints (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	chunk_id INTEGER NOT NULL REFERENCES chunks(id) ON DELETE CASCADE,
	line_no INTEGER NOT NULL,
	raw_offset INTEGER NOT NULL,
	UNIQUE(chunk_id, line_no)
);

CREATE INDEX IF NOT EXISTS idx_line_checkpoints_chunk
	ON line_checkpoints(chunk_id, line_no);
`,
	},
	{
		Version: 3,
		SQL: `
-- ARC-005-lite: record L2 pack publish without deleting L1 frames.
-- packed_pack_id is set only after pack verify + atomic publish.
ALTER TABLE log_generations ADD COLUMN packed_pack_id TEXT;
ALTER TABLE log_generations ADD COLUMN packed_at TEXT;

CREATE INDEX IF NOT EXISTS idx_log_generations_packed
	ON log_generations(packed_pack_id);
`,
	},
	{
		Version: 4,
		SQL: `
-- ARC-007: pins (never evicted) + optional build outcome for retention ages.
ALTER TABLE log_generations ADD COLUMN outcome TEXT;

CREATE TABLE IF NOT EXISTS pins (
	kind TEXT NOT NULL,
	target_id TEXT NOT NULL,
	pinned_at TEXT NOT NULL,
	PRIMARY KEY (kind, target_id)
);

CREATE INDEX IF NOT EXISTS idx_log_generations_outcome
	ON log_generations(outcome);
`,
	},
	{
		Version: 5,
		SQL: `
-- ARC-005 residual: L1 frames may be released after verified L2 pack publish.
-- Generation row + packed_pack_id remain so reads fall back to L2; chunk meta
-- and frames/<id>/ are purged when l1_released=1.
ALTER TABLE log_generations ADD COLUMN l1_released INTEGER NOT NULL DEFAULT 0;
ALTER TABLE log_generations ADD COLUMN l1_released_at TEXT;

CREATE INDEX IF NOT EXISTS idx_log_generations_l1_released
	ON log_generations(l1_released);

-- ARC-009: optional application-level AEAD metadata (key material never here).
-- enc_key_version 0 / empty enc_alg = plaintext independent zstd frame.
ALTER TABLE chunks ADD COLUMN enc_alg TEXT;
ALTER TABLE chunks ADD COLUMN enc_key_version INTEGER NOT NULL DEFAULT 0;
`,
	},
	{
		Version: 6,
		SQL: `
-- LOG-004 durable collection catalog: membership/refs only (never log bodies).
-- collection_id survives process restart so jenkins_mirror_logs can continue
-- residual unsealed members via Meta (same profile isolation).
CREATE TABLE IF NOT EXISTS log_collections (
	id TEXT NOT NULL PRIMARY KEY,
	profile TEXT NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	sealed INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_log_collections_profile
	ON log_collections(profile);

CREATE TABLE IF NOT EXISTS log_collection_members (
	collection_id TEXT NOT NULL REFERENCES log_collections(id) ON DELETE CASCADE,
	profile TEXT NOT NULL,
	job TEXT NOT NULL,
	build INTEGER NOT NULL,
	generation_id INTEGER,
	state TEXT NOT NULL DEFAULT '',
	relation TEXT NOT NULL DEFAULT '',
	updated_at TEXT NOT NULL,
	UNIQUE(collection_id, profile, job, build)
);

CREATE INDEX IF NOT EXISTS idx_log_collection_members_collection
	ON log_collection_members(collection_id);
`,
	},
	{
		Version: 7,
		SQL: `
-- PERF residual: durable compact survey summary cache for jenkins_survey_recent_failures.
-- Stores signature hashes, result status, byte counts, and optional short redacted
-- signature text only — NEVER log tails, full messages, or secrets.
CREATE TABLE IF NOT EXISTS survey_summary_cache (
	profile TEXT NOT NULL,
	job TEXT NOT NULL,
	build INTEGER NOT NULL,
	max_log_bytes INTEGER NOT NULL,
	result TEXT NOT NULL DEFAULT '',
	source TEXT NOT NULL DEFAULT '',
	log_bytes INTEGER NOT NULL DEFAULT 0,
	incomplete INTEGER NOT NULL DEFAULT 0,
	findings_json TEXT NOT NULL DEFAULT '[]',
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	PRIMARY KEY (profile, job, build, max_log_bytes)
);

CREATE INDEX IF NOT EXISTS idx_survey_summary_cache_expires
	ON survey_summary_cache(expires_at);

CREATE INDEX IF NOT EXISTS idx_survey_summary_cache_created
	ON survey_summary_cache(created_at);
`,
	},
	{
		Version: 8,
		SQL: `
-- FLC-020: pure compressed (pre-AEAD) frame identity for peer export/import.
-- NULL = legacy row; lazy backfill via OpenFrameCompressed + hash is allowed.
-- On-disk envelope remains compressed_size / frame_sha256 (may be AEAD).
ALTER TABLE chunks ADD COLUMN zstd_size INTEGER;
ALTER TABLE chunks ADD COLUMN zstd_sha256 TEXT;
`,
	},
}
