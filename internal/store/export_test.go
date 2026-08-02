package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"

	_ "modernc.org/sqlite"
)

// CreateMetaDBAtVersion builds metadata.sqlite under dataDir at exact schema
// version through (1..CurrentSchemaVersion). Does not auto-migrate to current.
// Used by QA-004 migration fixtures (store_test).
func CreateMetaDBAtVersion(dataDir string, through int) (dbPath string, err error) {
	if through < 1 || through > CurrentSchemaVersion {
		return "", apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("through must be 1..%d", CurrentSchemaVersion))
	}
	if err := EnsureDir(dataDir); err != nil {
		return "", err
	}
	dbPath = filepath.Join(dataDir, MetaDBFile)
	dsn := "file:" + filepath.ToSlash(dbPath) + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return "", err
	}
	defer db.Close()
	if _, err := db.Exec(`PRAGMA foreign_keys=ON`); err != nil {
		return "", err
	}
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS schema_version (
	version INTEGER NOT NULL PRIMARY KEY,
	applied_at TEXT NOT NULL
)`); err != nil {
		return "", err
	}
	ctx := context.Background()
	for _, step := range migrations {
		if step.Version > through {
			break
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return "", err
		}
		if _, err := tx.ExecContext(ctx, step.SQL); err != nil {
			_ = tx.Rollback()
			return "", fmt.Errorf("apply v%d: %w", step.Version, err)
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_version(version, applied_at) VALUES(?, ?)`,
			step.Version, now); err != nil {
			_ = tx.Rollback()
			return "", fmt.Errorf("record v%d: %w", step.Version, err)
		}
		if err := tx.Commit(); err != nil {
			return "", err
		}
	}
	var ver sql.NullInt64
	if err := db.QueryRow(`SELECT MAX(version) FROM schema_version`).Scan(&ver); err != nil {
		return "", err
	}
	if !ver.Valid || int(ver.Int64) != through {
		return "", fmt.Errorf("fixture version: got %v want %d", ver, through)
	}
	return dbPath, nil
}

// OpenRawMetaDB opens the metadata SQLite file without migrate (QA-004 interrupt tests).
func OpenRawMetaDB(dbPath string) (*sql.DB, error) {
	dsn := "file:" + filepath.ToSlash(dbPath) + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`PRAGMA foreign_keys=ON`); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// MigrationStepSQL returns the SQL body for schema version v (test fixtures).
func MigrationStepSQL(v int) (string, bool) {
	for _, step := range migrations {
		if step.Version == v {
			return step.SQL, true
		}
	}
	return "", false
}
