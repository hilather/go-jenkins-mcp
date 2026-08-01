package store_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/store"
)

func openTestMeta(t *testing.T) *store.Meta {
	t.Helper()
	dir := t.TempDir()
	// Nested absolute path under temp (EnsureDir requires absolute).
	dataDir := filepath.Join(dir, "profiles", "corp")
	m, err := store.Open(dataDir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func TestMeta_OpenMigrateReopen(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "profiles", "corp")

	m1, err := store.Open(dataDir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()
	ver, err := m1.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if ver != store.CurrentSchemaVersion {
		t.Fatalf("version: got %d want %d", ver, store.CurrentSchemaVersion)
	}
	dbPath := m1.Path()
	if err := m1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopen same path; migrate is a no-op.
	m2, err := store.Open(dataDir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer m2.Close()
	ver2, err := m2.SchemaVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ver2 != store.CurrentSchemaVersion {
		t.Fatalf("reopen version: %d", ver2)
	}
	if m2.Path() != dbPath {
		t.Fatalf("path changed: %q vs %q", m2.Path(), dbPath)
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("db file missing: %v", err)
	}
}

func TestMeta_InsertGenerationAndLoad(t *testing.T) {
	m := openTestMeta(t)
	ctx := context.Background()
	key := store.LogKey{Profile: "corp", Job: "demo/job", Build: 7}
	g := &store.LogGeneration{
		Profile:       key.Profile,
		Job:           key.Job,
		Build:         key.Build,
		Generation:    1,
		JenkinsOffset: 0,
		MoreData:      true,
	}
	if err := m.InsertGeneration(ctx, g); err != nil {
		t.Fatalf("InsertGeneration: %v", err)
	}
	if g.ID == 0 {
		t.Fatal("expected non-zero id")
	}

	got, err := m.GetLatestGeneration(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected generation")
	}
	if got.ID != g.ID || got.Generation != 1 || got.JenkinsOffset != 0 {
		t.Fatalf("got %+v", got)
	}
	if got.Sealed || !got.MoreData {
		t.Fatalf("flags: sealed=%v more=%v", got.Sealed, got.MoreData)
	}

	if err := m.UpdateGenerationOffset(ctx, g.ID, 100, true, false, false); err != nil {
		t.Fatalf("UpdateGenerationOffset: %v", err)
	}
	got, err = m.GetGeneration(ctx, key, 1)
	if err != nil || got == nil {
		t.Fatalf("GetGeneration: %v %+v", err, got)
	}
	if got.JenkinsOffset != 100 {
		t.Fatalf("offset: %d", got.JenkinsOffset)
	}

	if err := m.SealGeneration(ctx, g.ID); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, _ = m.GetLatestGeneration(ctx, key)
	if !got.Sealed || got.MoreData || !got.BuildComplete {
		t.Fatalf("after seal: %+v", got)
	}
}

func TestMeta_OffsetRegressionRejected(t *testing.T) {
	m := openTestMeta(t)
	ctx := context.Background()
	g := &store.LogGeneration{
		Profile: "corp", Job: "j", Build: 1, Generation: 1, JenkinsOffset: 50, MoreData: true,
	}
	if err := m.InsertGeneration(ctx, g); err != nil {
		t.Fatal(err)
	}
	err := m.UpdateGenerationOffset(ctx, g.ID, 40, true, false, false)
	if err == nil {
		t.Fatal("expected regression error")
	}
	if !apperr.IsCode(err, apperr.CodeInvalidArgument) {
		t.Fatalf("code: %s", apperr.CodeOf(err))
	}
}

func TestMeta_MarkGenerationPacked(t *testing.T) {
	m := openTestMeta(t)
	ctx := context.Background()
	g := &store.LogGeneration{
		Profile: "corp", Job: "demo", Build: 1, Generation: 1,
		Sealed: false, JenkinsOffset: 10, MoreData: true,
	}
	if err := m.InsertGeneration(ctx, g); err != nil {
		t.Fatal(err)
	}
	if err := m.MarkGenerationPacked(ctx, g.ID, "pack-1"); err == nil {
		t.Fatal("expected reject unsealed")
	}
	if err := m.SealGeneration(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	if err := m.MarkGenerationPacked(ctx, g.ID, "pack-1"); err != nil {
		t.Fatal(err)
	}
	got, err := m.GetGenerationByID(ctx, g.ID)
	if err != nil || got == nil {
		t.Fatalf("load: %v", err)
	}
	if got.PackedPackID != "pack-1" || got.PackedAt.IsZero() {
		t.Fatalf("packed fields: id=%q at=%v", got.PackedPackID, got.PackedAt)
	}
}

func TestMeta_SealedCannotUpdate(t *testing.T) {
	m := openTestMeta(t)
	ctx := context.Background()
	g := &store.LogGeneration{
		Profile: "corp", Job: "j", Build: 2, Generation: 1, JenkinsOffset: 10,
	}
	if err := m.InsertGeneration(ctx, g); err != nil {
		t.Fatal(err)
	}
	if err := m.SealGeneration(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	err := m.UpdateGenerationOffset(ctx, g.ID, 20, false, true, true)
	if err == nil {
		t.Fatal("expected sealed update error")
	}
}

func TestMeta_TransactionalConsistency(t *testing.T) {
	// Injected "crash": begin tx, write, rollback — durable state unchanged.
	m := openTestMeta(t)
	ctx := context.Background()
	g := &store.LogGeneration{
		Profile: "corp", Job: "j", Build: 3, Generation: 1, JenkinsOffset: 0, MoreData: true,
	}
	if err := m.InsertGeneration(ctx, g); err != nil {
		t.Fatal(err)
	}

	err := m.WithTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
UPDATE log_generations SET jenkins_offset = 999, updated_at = ? WHERE id = ?`,
			time.Now().UTC().Format(time.RFC3339Nano), g.ID)
		if err != nil {
			return err
		}
		// Simulate crash before commit.
		return apperr.New(apperr.CodeInternal, "injected crash")
	})
	if err == nil {
		t.Fatal("expected injected error")
	}

	got, err := m.GetGeneration(ctx, store.LogKey{Profile: "corp", Job: "j", Build: 3}, 1)
	if err != nil || got == nil {
		t.Fatalf("load: %v", err)
	}
	if got.JenkinsOffset != 0 {
		t.Fatalf("offset advanced after rolled-back tx: %d", got.JenkinsOffset)
	}
}

func TestMeta_ConcurrentReadWrite(t *testing.T) {
	m := openTestMeta(t)
	ctx := context.Background()
	g := &store.LogGeneration{
		Profile: "corp", Job: "j", Build: 4, Generation: 1, JenkinsOffset: 0, MoreData: true,
	}
	if err := m.InsertGeneration(ctx, g); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 32)
	// Writers advance offset sequentially via mutex in UpdateGenerationOffset txs.
	// Readers load latest concurrently.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if _, err := m.GetLatestGeneration(ctx, store.LogKey{Profile: "corp", Job: "j", Build: 4}); err != nil {
					errCh <- err
					return
				}
			}
		}()
	}
	// Single writer stream to avoid offset conflicts.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for off := int64(1); off <= 50; off++ {
			if err := m.UpdateGenerationOffset(ctx, g.ID, off, true, false, false); err != nil {
				errCh <- err
				return
			}
		}
	}()
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent: %v", err)
	}
	got, _ := m.GetLatestGeneration(ctx, store.LogKey{Profile: "corp", Job: "j", Build: 4})
	if got.JenkinsOffset != 50 {
		t.Fatalf("final offset: %d", got.JenkinsOffset)
	}
}

func TestMeta_NoSecretColumns(t *testing.T) {
	// Schema canary: table names / column names must not look like secret stores.
	m := openTestMeta(t)
	rows, err := m.DB().Query(`SELECT name FROM sqlite_master WHERE type='table'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	forbidden := []string{"token", "password", "secret", "authorization", "refresh"}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		lower := name
		for _, f := range forbidden {
			if containsFold(lower, f) {
				t.Fatalf("table name %q looks secret-related", name)
			}
		}
		cols, err := m.DB().Query(`PRAGMA table_info(` + name + `)`)
		if err != nil {
			t.Fatal(err)
		}
		for cols.Next() {
			var cid int
			var cname, ctype string
			var notnull, pk int
			var dflt sql.NullString
			if err := cols.Scan(&cid, &cname, &ctype, &notnull, &dflt, &pk); err != nil {
				t.Fatal(err)
			}
			for _, f := range forbidden {
				if containsFold(cname, f) {
					t.Fatalf("column %s.%s looks secret-related", name, cname)
				}
			}
		}
		cols.Close()
	}
}

func containsFold(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub ||
		len(sub) > 0 && (containsASCII(s, sub)))
}

func containsASCII(s, sub string) bool {
	// simple case-insensitive contains for canary
	ls, lsub := make([]byte, len(s)), make([]byte, len(sub))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		ls[i] = c
	}
	for i := 0; i < len(sub); i++ {
		c := sub[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		lsub[i] = c
	}
	return stringContains(string(ls), string(lsub))
}

func stringContains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestMeta_NewGenerationAfterSeal(t *testing.T) {
	m := openTestMeta(t)
	ctx := context.Background()
	key := store.LogKey{Profile: "corp", Job: "j", Build: 9}
	g1 := &store.LogGeneration{Profile: key.Profile, Job: key.Job, Build: key.Build, Generation: 1, JenkinsOffset: 100}
	if err := m.InsertGeneration(ctx, g1); err != nil {
		t.Fatal(err)
	}
	if err := m.SealGeneration(ctx, g1.ID); err != nil {
		t.Fatal(err)
	}
	g2 := &store.LogGeneration{Profile: key.Profile, Job: key.Job, Build: key.Build, Generation: 2, JenkinsOffset: 0, MoreData: true}
	if err := m.InsertGeneration(ctx, g2); err != nil {
		t.Fatal(err)
	}
	latest, err := m.GetLatestGeneration(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if latest.Generation != 2 || latest.JenkinsOffset != 0 {
		t.Fatalf("latest: %+v", latest)
	}
}
