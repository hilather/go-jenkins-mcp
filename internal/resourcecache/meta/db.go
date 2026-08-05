package meta

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	_ "modernc.org/sqlite"
)

// DB is the resources.sqlite handle.
type DB struct {
	sql *sql.DB
	dir string
}

// Row is a disk entry without importing resourcecache (avoids cycles).
type Row struct {
	KeyDigest      string
	Kind           string
	ProfileID      string
	ControllerID   string
	JobFullName    string
	BuildNumber    int64
	Selector       string
	Variant        string
	State          string
	Completeness   string
	ContentDigest  string
	ContentSize    int64
	ObjectRelPath  string
	SourceETag     string
	BuildBuilding  bool
	FetchedAtUnix  int64
	ExpiresAtUnix  int64
	Share          string
	SubjectKeyHash string
}

// Open creates/opens resources.sqlite under cacheDir (profile cache root).
func Open(cacheDir string) (*DB, error) {
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "resource cache dir", err)
	}
	path := filepath.Join(cacheDir, "resources.sqlite")
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "open resources.sqlite", err)
	}
	db.SetMaxOpenConns(1)
	d := &DB{sql: db, dir: cacheDir}
	if err := d.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return d, nil
}

// Close closes the database.
func (d *DB) Close() error {
	if d == nil || d.sql == nil {
		return nil
	}
	return d.sql.Close()
}

// Dir returns the cache directory root.
func (d *DB) Dir() string { return d.dir }

func (d *DB) migrate(ctx context.Context) error {
	if _, err := d.sql.ExecContext(ctx, schemaSQL); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "resource schema", err)
	}
	var n int
	err := d.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_version`).Scan(&n)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "schema_version count", err)
	}
	if n == 0 {
		if _, err := d.sql.ExecContext(ctx, `INSERT INTO schema_version(version) VALUES (?)`, SchemaVersion); err != nil {
			return apperr.Wrap(apperr.CodeInternal, "insert schema_version", err)
		}
		return nil
	}
	var ver int
	if err := d.sql.QueryRowContext(ctx, `SELECT version FROM schema_version LIMIT 1`).Scan(&ver); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "read schema_version", err)
	}
	if ver > SchemaVersion {
		return apperr.New(apperr.CodeCorruptCache,
			fmt.Sprintf("resources.sqlite schema %d newer than binary %d", ver, SchemaVersion))
	}
	if ver < SchemaVersion {
		if _, err := d.sql.ExecContext(ctx, `UPDATE schema_version SET version = ?`, SchemaVersion); err != nil {
			return apperr.Wrap(apperr.CodeInternal, "bump schema_version", err)
		}
	}
	return nil
}

// SchemaVersion returns the applied schema version.
func (d *DB) SchemaVersion(ctx context.Context) (int, error) {
	var ver int
	err := d.sql.QueryRowContext(ctx, `SELECT version FROM schema_version LIMIT 1`).Scan(&ver)
	if err != nil {
		return 0, apperr.Wrap(apperr.CodeInternal, "schema version", err)
	}
	return ver, nil
}

// PutRow upserts an entry row.
func (d *DB) PutRow(ctx context.Context, r Row) error {
	now := time.Now().Unix()
	building := 0
	if r.BuildBuilding {
		building = 1
	}
	_, err := d.sql.ExecContext(ctx, `
INSERT INTO entries(
  key_digest, kind, profile_id, controller_id, job_full_name, build_number,
  selector, variant, state, completeness, content_digest, content_size,
  object_rel_path, source_etag, build_building, fetched_at_unix, expires_at_unix,
  share, subject_key_hash, created_at_unix, updated_at_unix
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(key_digest) DO UPDATE SET
  state=excluded.state,
  completeness=excluded.completeness,
  content_digest=excluded.content_digest,
  content_size=excluded.content_size,
  object_rel_path=excluded.object_rel_path,
  source_etag=excluded.source_etag,
  build_building=excluded.build_building,
  fetched_at_unix=excluded.fetched_at_unix,
  expires_at_unix=excluded.expires_at_unix,
  share=excluded.share,
  subject_key_hash=excluded.subject_key_hash,
  updated_at_unix=excluded.updated_at_unix
`, r.KeyDigest, r.Kind, r.ProfileID, r.ControllerID, r.JobFullName, r.BuildNumber,
		r.Selector, r.Variant, r.State, r.Completeness, r.ContentDigest, r.ContentSize,
		r.ObjectRelPath, r.SourceETag, building, r.FetchedAtUnix, r.ExpiresAtUnix,
		r.Share, r.SubjectKeyHash, now, now)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "put resource entry", err)
	}
	return nil
}

// GetRow loads metadata by key digest.
func (d *DB) GetRow(ctx context.Context, keyDigest string) (Row, bool, error) {
	var r Row
	var building int
	err := d.sql.QueryRowContext(ctx, `
SELECT key_digest, kind, profile_id, controller_id, job_full_name, build_number,
  selector, variant, state, completeness, content_digest, content_size,
  object_rel_path, source_etag, build_building, fetched_at_unix, expires_at_unix,
  share, subject_key_hash
FROM entries WHERE key_digest = ?`, keyDigest).Scan(
		&r.KeyDigest, &r.Kind, &r.ProfileID, &r.ControllerID, &r.JobFullName, &r.BuildNumber,
		&r.Selector, &r.Variant, &r.State, &r.Completeness, &r.ContentDigest, &r.ContentSize,
		&r.ObjectRelPath, &r.SourceETag, &building, &r.FetchedAtUnix, &r.ExpiresAtUnix,
		&r.Share, &r.SubjectKeyHash,
	)
	if err == sql.ErrNoRows {
		return Row{}, false, nil
	}
	if err != nil {
		return Row{}, false, apperr.Wrap(apperr.CodeInternal, "get resource entry", err)
	}
	r.BuildBuilding = building != 0
	return r, true, nil
}

// DeleteEntry removes metadata.
func (d *DB) DeleteEntry(ctx context.Context, keyDigest string) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM entries WHERE key_digest = ?`, keyDigest)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "delete resource entry", err)
	}
	return nil
}

// QuarantineIncomplete marks incomplete/fetching rows.
func (d *DB) QuarantineIncomplete(ctx context.Context) (int64, error) {
	res, err := d.sql.ExecContext(ctx, `
UPDATE entries SET state = ?, updated_at_unix = ?
WHERE completeness = ? OR state = ?`,
		"quarantined", time.Now().Unix(), "incomplete", "fetching")
	if err != nil {
		return 0, apperr.Wrap(apperr.CodeInternal, "quarantine incomplete", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
