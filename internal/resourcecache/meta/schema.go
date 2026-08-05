package meta

// SchemaVersion is the resources.sqlite schema version (independent of log metadata.sqlite).
const SchemaVersion = 1

const schemaSQL = `
CREATE TABLE IF NOT EXISTS schema_version (
  version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS entries (
  key_digest TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  profile_id TEXT NOT NULL,
  controller_id TEXT NOT NULL,
  job_full_name TEXT NOT NULL,
  build_number INTEGER NOT NULL,
  selector TEXT NOT NULL DEFAULT '',
  variant TEXT NOT NULL DEFAULT 'v1',
  state TEXT NOT NULL,
  completeness TEXT NOT NULL,
  content_digest TEXT NOT NULL DEFAULT '',
  content_size INTEGER NOT NULL DEFAULT 0,
  object_rel_path TEXT NOT NULL DEFAULT '',
  source_etag TEXT NOT NULL DEFAULT '',
  build_building INTEGER NOT NULL DEFAULT 0,
  fetched_at_unix INTEGER NOT NULL DEFAULT 0,
  expires_at_unix INTEGER NOT NULL DEFAULT 0,
  share TEXT NOT NULL DEFAULT 'subject_private',
  subject_key_hash TEXT NOT NULL DEFAULT '',
  created_at_unix INTEGER NOT NULL,
  updated_at_unix INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_entries_kind_job ON entries(kind, job_full_name, build_number);
CREATE INDEX IF NOT EXISTS idx_entries_state ON entries(state);

CREATE TABLE IF NOT EXISTS leases (
  lease_id TEXT PRIMARY KEY,
  key_digest TEXT NOT NULL,
  created_at_unix INTEGER NOT NULL,
  expires_at_unix INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tombstones (
  key_digest TEXT PRIMARY KEY,
  reason TEXT NOT NULL,
  created_at_unix INTEGER NOT NULL
);
`
