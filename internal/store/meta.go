package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"

	_ "modernc.org/sqlite"
)

// Meta is the versioned SQLite metadata store for one profile data directory.
// It holds non-secret indexes only (log generations, chunk stubs, etc.).
// Tokens and authorization headers must never be written here.
//
// writeMu serializes writers so multi-log fan-out (LOG-004) does not hit
// SQLITE_BUSY under concurrent generation/frame commits. WAL still allows
// concurrent readers with one writer.
type Meta struct {
	db      *sql.DB
	path    string
	writeMu sync.Mutex
}

// Open opens (or creates) the metadata database under dataDir, ensuring the
// directory is secure (STO-001) and applying migrations transactionally (STO-002).
func Open(dataDir string) (*Meta, error) {
	if err := EnsureDir(dataDir); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(dataDir, MetaDBFile)
	// modernc.org/sqlite; pure Go for easy CI. WAL for concurrent readers.
	dsn := "file:" + filepath.ToSlash(dbPath) + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "failed to open metadata database", err)
	}
	// Single writer; allow multiple readers via WAL after migrate.
	db.SetMaxOpenConns(1)

	m := &Meta{db: db, path: dbPath}
	if err := m.configure(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := m.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	// After migrate, allow a small pool for concurrent read tests.
	db.SetMaxOpenConns(4)
	return m, nil
}

// Path returns the on-disk SQLite path.
func (m *Meta) Path() string {
	if m == nil {
		return ""
	}
	return m.path
}

// Close releases the database handle.
func (m *Meta) Close() error {
	if m == nil || m.db == nil {
		return nil
	}
	err := m.db.Close()
	m.db = nil
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to close metadata database", err)
	}
	return nil
}

// SchemaVersion returns the highest applied schema version (0 if empty).
func (m *Meta) SchemaVersion(ctx context.Context) (int, error) {
	if m == nil || m.db == nil {
		return 0, apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	var ver sql.NullInt64
	err := m.db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_version`).Scan(&ver)
	if err != nil {
		// Table missing should not happen after migrate; treat as corrupt.
		return 0, apperr.Wrap(apperr.CodeCorruptCache, "failed to read schema_version", err)
	}
	if !ver.Valid {
		return 0, nil
	}
	return int(ver.Int64), nil
}

// DB exposes the underlying *sql.DB for package-internal advanced ops/tests.
// Callers outside store should use typed methods.
func (m *Meta) DB() *sql.DB {
	if m == nil {
		return nil
	}
	return m.db
}

func (m *Meta) configure() error {
	// journal_mode=WAL + synchronous=NORMAL is a good default for local cache.
	// foreign_keys is also set via DSN pragma.
	pragmas := []string{
		`PRAGMA journal_mode=WAL`,
		`PRAGMA synchronous=NORMAL`,
		`PRAGMA foreign_keys=ON`,
		`PRAGMA busy_timeout=5000`,
	}
	for _, p := range pragmas {
		if _, err := m.db.Exec(p); err != nil {
			return apperr.Wrap(apperr.CodeInternal, "failed to configure sqlite", err)
		}
	}
	return nil
}

// migrate applies pending schema versions in order, each in a transaction.
func (m *Meta) migrate() error {
	ctx := context.Background()
	// Ensure schema_version exists before reading (bootstrap for empty DB).
	if _, err := m.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS schema_version (
	version INTEGER NOT NULL PRIMARY KEY,
	applied_at TEXT NOT NULL
)`); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to bootstrap schema_version", err)
	}

	cur, err := m.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	// Fail closed on future schemas: never rewrite or "downgrade" the file.
	// Clear message so operators upgrade the binary rather than delete cache.
	if cur > CurrentSchemaVersion {
		return apperr.New(apperr.CodeCorruptCache,
			fmt.Sprintf("metadata schema version %d is newer than this binary supports (%d); upgrade jenkins-mcp (database left unchanged)",
				cur, CurrentSchemaVersion))
	}
	for _, step := range migrations {
		if step.Version <= cur {
			continue
		}
		if step.Version != cur+1 {
			return apperr.New(apperr.CodeCorruptCache,
				fmt.Sprintf("migration gap: at %d, next step is %d", cur, step.Version))
		}
		if err := m.applyMigration(ctx, step); err != nil {
			return err
		}
		cur = step.Version
	}
	if cur != CurrentSchemaVersion {
		return apperr.New(apperr.CodeCorruptCache,
			fmt.Sprintf("schema version %d after migrate; want %d", cur, CurrentSchemaVersion))
	}
	return nil
}

func (m *Meta) applyMigration(ctx context.Context, step migration) error {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to begin migration transaction", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, step.SQL); err != nil {
		return apperr.Wrap(apperr.CodeInternal,
			fmt.Sprintf("migration v%d failed", step.Version), err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_version(version, applied_at) VALUES(?, ?)`,
		step.Version, now); err != nil {
		return apperr.Wrap(apperr.CodeInternal,
			fmt.Sprintf("failed to record schema version %d", step.Version), err)
	}
	if err := tx.Commit(); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to commit migration", err)
	}
	return nil
}

// Generation outcome values for ARC-007 retention (optional).
const (
	OutcomeSuccess = "success"
	OutcomeFailed  = "failed"
)

// LogGeneration is non-secret progressive-log mirror metadata for one generation.
type LogGeneration struct {
	ID            int64
	Profile       string
	Job           string
	Build         int64
	Generation    int64
	Sealed        bool
	JenkinsOffset int64
	MoreData      bool
	BuildComplete bool
	UpdatedAt     time.Time
	// PackedPackID is set after L2 pack verify+publish (ARC-005-lite). Empty = not packed.
	// When set and L1Released is false, L1 frames still exist alongside the pack.
	PackedPackID string
	// PackedAt is RFC3339 when packed (empty if not packed).
	PackedAt time.Time
	// Outcome is optional ARC-007 retention class: success | failed | empty (unknown).
	Outcome string
	// L1Released is true after ReleasePackedL1 deleted L1 frames (pack remains).
	// Reads must fall back to L2 when true (ARC-005 residual).
	L1Released bool
	// L1ReleasedAt is when L1 was released (zero if not released).
	L1ReleasedAt time.Time
}

// LogKey identifies a build console log within a profile.
type LogKey struct {
	Profile string
	Job     string
	Build   int64
}

// Validate checks LogKey fields.
func (k LogKey) Validate() error {
	if strings.TrimSpace(k.Profile) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "profile is required")
	}
	if strings.TrimSpace(k.Job) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "job is required")
	}
	if k.Build <= 0 {
		return apperr.New(apperr.CodeInvalidArgument, "build number must be positive")
	}
	return nil
}

// String returns a stable key for maps/locks (no secrets).
func (k LogKey) String() string {
	return fmt.Sprintf("%s|%s|%d", k.Profile, k.Job, k.Build)
}

// GetLatestGeneration returns the highest generation for key, or nil if none.
func (m *Meta) GetLatestGeneration(ctx context.Context, key LogKey) (*LogGeneration, error) {
	if err := key.Validate(); err != nil {
		return nil, err
	}
	if m == nil || m.db == nil {
		return nil, apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	row := m.db.QueryRowContext(ctx, `
SELECT id, profile, job, build, generation, sealed, jenkins_offset, more_data, build_complete, updated_at,
	COALESCE(packed_pack_id, ''), COALESCE(packed_at, ''), COALESCE(outcome, ''),
	COALESCE(l1_released, 0), COALESCE(l1_released_at, '')
FROM log_generations
WHERE profile = ? AND job = ? AND build = ?
ORDER BY generation DESC
LIMIT 1`, key.Profile, key.Job, key.Build)
	g, err := scanGeneration(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeCorruptCache, "failed to load log generation", err)
	}
	return g, nil
}

// GetGeneration loads a specific generation number for key.
func (m *Meta) GetGeneration(ctx context.Context, key LogKey, generation int64) (*LogGeneration, error) {
	if err := key.Validate(); err != nil {
		return nil, err
	}
	if generation <= 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument, "generation must be positive")
	}
	if m == nil || m.db == nil {
		return nil, apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	row := m.db.QueryRowContext(ctx, `
SELECT id, profile, job, build, generation, sealed, jenkins_offset, more_data, build_complete, updated_at,
	COALESCE(packed_pack_id, ''), COALESCE(packed_at, ''), COALESCE(outcome, ''),
	COALESCE(l1_released, 0), COALESCE(l1_released_at, '')
FROM log_generations
WHERE profile = ? AND job = ? AND build = ? AND generation = ?`,
		key.Profile, key.Job, key.Build, generation)
	g, err := scanGeneration(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeCorruptCache, "failed to load log generation", err)
	}
	return g, nil
}

// InsertGeneration creates a new generation row. Generation must be unique for the key.
func (m *Meta) InsertGeneration(ctx context.Context, g *LogGeneration) error {
	if g == nil {
		return apperr.New(apperr.CodeInvalidArgument, "generation is nil")
	}
	key := LogKey{Profile: g.Profile, Job: g.Job, Build: g.Build}
	if err := key.Validate(); err != nil {
		return err
	}
	if g.Generation <= 0 {
		return apperr.New(apperr.CodeInvalidArgument, "generation must be positive")
	}
	if g.JenkinsOffset < 0 {
		return apperr.New(apperr.CodeInvalidArgument, "jenkins_offset must be non-negative")
	}
	if m == nil || m.db == nil {
		return apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	now := time.Now().UTC()
	if g.UpdatedAt.IsZero() {
		g.UpdatedAt = now
	}
	res, err := m.db.ExecContext(ctx, `
INSERT INTO log_generations(
	profile, job, build, generation, sealed, jenkins_offset, more_data, build_complete, updated_at
) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		g.Profile, g.Job, g.Build, g.Generation,
		boolToInt(g.Sealed), g.JenkinsOffset, boolToInt(g.MoreData), boolToInt(g.BuildComplete),
		g.UpdatedAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to insert log generation", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to read generation id", err)
	}
	g.ID = id
	return nil
}

// UpdateGenerationOffset transactionally advances jenkins_offset and flags.
// Offsets must not go backward for a sealed generation; callers enforce rewrite policy.
func (m *Meta) UpdateGenerationOffset(ctx context.Context, id int64, offset int64, moreData, buildComplete, sealed bool) error {
	if id <= 0 {
		return apperr.New(apperr.CodeInvalidArgument, "generation id is required")
	}
	if offset < 0 {
		return apperr.New(apperr.CodeInvalidArgument, "jenkins_offset must be non-negative")
	}
	if m == nil || m.db == nil {
		return apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to begin offset update", err)
	}
	defer func() { _ = tx.Rollback() }()

	var curOffset int64
	var curSealed int
	err = tx.QueryRowContext(ctx,
		`SELECT jenkins_offset, sealed FROM log_generations WHERE id = ?`, id).
		Scan(&curOffset, &curSealed)
	if err == sql.ErrNoRows {
		return apperr.New(apperr.CodeNotFound, "log generation not found")
	}
	if err != nil {
		return apperr.Wrap(apperr.CodeCorruptCache, "failed to load generation for update", err)
	}
	if curSealed != 0 {
		return apperr.New(apperr.CodeInvalidArgument, "cannot update sealed log generation")
	}
	// Within a generation, committed offset must not regress (crash-safe append).
	if offset < curOffset {
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("jenkins_offset cannot regress within generation (%d < %d)", offset, curOffset))
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := tx.ExecContext(ctx, `
UPDATE log_generations
SET jenkins_offset = ?, more_data = ?, build_complete = ?, sealed = ?, updated_at = ?
WHERE id = ? AND sealed = 0`,
		offset, boolToInt(moreData), boolToInt(buildComplete), boolToInt(sealed), now, id)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to update log generation", err)
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return apperr.New(apperr.CodeInternal, "log generation update affected unexpected row count")
	}
	if err := tx.Commit(); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to commit generation update", err)
	}
	return nil
}

// SealGeneration marks the generation sealed when complete and no more data.
func (m *Meta) SealGeneration(ctx context.Context, id int64) error {
	if id <= 0 {
		return apperr.New(apperr.CodeInvalidArgument, "generation id is required")
	}
	if m == nil || m.db == nil {
		return apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := m.db.ExecContext(ctx, `
UPDATE log_generations
SET sealed = 1, more_data = 0, build_complete = 1, updated_at = ?
WHERE id = ?`, now, id)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to seal log generation", err)
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return apperr.New(apperr.CodeNotFound, "log generation not found")
	}
	return nil
}

// MarkGenerationPacked records that a sealed generation was published into packID
// after L2 verify (ARC-005 journal-lite). Does not delete L1 frames.
func (m *Meta) MarkGenerationPacked(ctx context.Context, id int64, packID string) error {
	if id <= 0 {
		return apperr.New(apperr.CodeInvalidArgument, "generation id is required")
	}
	packID = strings.TrimSpace(packID)
	if packID == "" {
		return apperr.New(apperr.CodeInvalidArgument, "pack_id is required")
	}
	if m == nil || m.db == nil {
		return apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	var sealed int
	err := m.db.QueryRowContext(ctx, `SELECT sealed FROM log_generations WHERE id = ?`, id).Scan(&sealed)
	if err == sql.ErrNoRows {
		return apperr.New(apperr.CodeNotFound, "log generation not found")
	}
	if err != nil {
		return apperr.Wrap(apperr.CodeCorruptCache, "failed to load generation for pack mark", err)
	}
	if sealed == 0 {
		return apperr.New(apperr.CodeInvalidArgument, "cannot mark unsealed generation as packed")
	}
	now := time.Now().UTC()
	res, err := m.db.ExecContext(ctx, `
UPDATE log_generations
SET packed_pack_id = ?, packed_at = ?, updated_at = ?
WHERE id = ? AND sealed = 1`,
		packID, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), id)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to mark generation packed", err)
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return apperr.New(apperr.CodeNotFound, "log generation not found")
	}
	return nil
}

// WithTx runs fn inside a transaction (for crash/recovery tests and multi-row ops).
// Serializes with other Meta writers (LOG-004 multi-log fan-out).
func (m *Meta) WithTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	if m == nil || m.db == nil {
		return apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to begin transaction", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to commit transaction", err)
	}
	return nil
}

type scannable interface {
	Scan(dest ...any) error
}

func scanGeneration(row scannable) (*LogGeneration, error) {
	var g LogGeneration
	var sealed, more, complete, l1Released int
	var updated string
	var packedID, packedAt, outcome, l1ReleasedAt string
	err := row.Scan(
		&g.ID, &g.Profile, &g.Job, &g.Build, &g.Generation,
		&sealed, &g.JenkinsOffset, &more, &complete, &updated,
		&packedID, &packedAt, &outcome,
		&l1Released, &l1ReleasedAt,
	)
	if err != nil {
		return nil, err
	}
	g.Sealed = sealed != 0
	g.MoreData = more != 0
	g.BuildComplete = complete != 0
	g.PackedPackID = packedID
	g.Outcome = strings.TrimSpace(outcome)
	g.L1Released = l1Released != 0
	if t, err := time.Parse(time.RFC3339Nano, updated); err == nil {
		g.UpdatedAt = t
	} else if t, err := time.Parse(time.RFC3339, updated); err == nil {
		g.UpdatedAt = t
	}
	if packedAt != "" {
		if t, err := time.Parse(time.RFC3339Nano, packedAt); err == nil {
			g.PackedAt = t
		} else if t, err := time.Parse(time.RFC3339, packedAt); err == nil {
			g.PackedAt = t
		}
	}
	if l1ReleasedAt != "" {
		if t, err := time.Parse(time.RFC3339Nano, l1ReleasedAt); err == nil {
			g.L1ReleasedAt = t
		} else if t, err := time.Parse(time.RFC3339, l1ReleasedAt); err == nil {
			g.L1ReleasedAt = t
		}
	}
	return &g, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
