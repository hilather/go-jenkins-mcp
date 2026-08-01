package app_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/app"
	"github.com/simonfxr/go-jenkins-mcp/internal/archive"
	"github.com/simonfxr/go-jenkins-mcp/internal/logmirror"
	"github.com/simonfxr/go-jenkins-mcp/internal/store"
)

func TestMaintainer_ReleaseAfterPack(t *testing.T) {
	// ReleaseAfterPack: pack during compaction then release L1 same tick.
	dir := filepath.Join(t.TempDir(), "profiles", "corp")
	meta, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = meta.Close() })
	fr, err := store.NewFrames(meta, dir)
	if err != nil {
		t.Fatal(err)
	}
	fr.TargetBytes = 48
	fr.MaxBytes = 128
	t.Cleanup(func() { _ = fr.Close() })
	if _, err := fr.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	reader, err := fr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	machine := logmirror.NewMachine(meta, nil)
	machine.Frames = fr
	machine.Reader = reader
	machine.ArchiveRoot = filepath.Join(dir, store.ArchivesDirName)

	ctx := context.Background()
	keys := []store.LogKey{
		{Profile: "corp", Job: "a", Build: 1},
		{Profile: "corp", Job: "b", Build: 2},
	}
	bodies := map[string][]byte{}
	for _, key := range keys {
		body := []byte("body-" + key.Job + "\n" + strings.Repeat("x\n", 30))
		bodies[key.Job] = body
		st, err := machine.Append(ctx, key, logmirror.Segment{
			Data: body, ReportedNextOffset: int64(len(body)), MoreData: false, BuildComplete: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !st.Sealed {
			if _, err := machine.Seal(ctx, key); err != nil {
				t.Fatal(err)
			}
		}
		// Force-age so packing runs under headroom.
		_, _ = meta.DB().ExecContext(ctx,
			`UPDATE log_generations SET updated_at = ? WHERE profile = ? AND job = ? AND build = ?`,
			time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
			key.Profile, key.Job, key.Build)
	}

	qm, err := store.NewQuotaManager(meta, dir, store.QuotaConfig{TotalQuotaBytes: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	maint, err := app.NewMaintainer(qm, meta, dir, app.MaintenanceConfig{
		EnableEviction:         false,
		EnableCompaction:       true,
		EnableL1Release:        true,
		ReleaseAfterPack:       true,
		MinSealedMembers:       2,
		ForcePackAfter:         time.Hour,
		CompactionHeadroomFrac: 0.99,
		Now:                    func() time.Time { return time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	// Real defaultPack → FS L2.
	res, err := maint.Tick(ctx)
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if res.PacksCreated < 1 {
		t.Fatalf("expected pack: %+v", res)
	}
	if res.L1Released < 1 {
		t.Fatalf("expected L1 release after pack: %+v", res)
	}

	for _, key := range keys {
		g, err := meta.GetLatestGeneration(ctx, key)
		if err != nil || g == nil {
			t.Fatalf("gen %s: %v", key.Job, err)
		}
		if g.PackedPackID == "" {
			t.Fatalf("not packed: %s", key.Job)
		}
		if !g.L1Released {
			t.Fatalf("L1 not released: %s", key.Job)
		}
		chunks, _ := meta.ListChunks(ctx, g.ID)
		if len(chunks) != 0 {
			t.Fatalf("L1 chunks remain for %s", key.Job)
		}
		packPath := filepath.Join(dir, store.ArchivesDirName, g.PackedPackID+".tar.zst")
		if _, err := os.Stat(packPath); err != nil {
			t.Fatalf("pack missing: %v", err)
		}
		// L2 read path.
		rr, err := machine.ReadRange(ctx, key, 0, int64(len(bodies[key.Job])))
		if err != nil {
			t.Fatalf("ReadRange L2 %s: %v", key.Job, err)
		}
		if string(rr.Data) != string(bodies[key.Job]) {
			t.Fatalf("body mismatch for %s", key.Job)
		}
	}
}

func TestMaintainer_ReleaseAgeGate(t *testing.T) {
	// Without ReleaseAfterPack, fresh packed gens are not released until min age
	// (unless high pressure — not simulated here).
	dir := filepath.Join(t.TempDir(), "profiles", "corp")
	meta, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = meta.Close() })
	fr, err := store.NewFrames(meta, dir)
	if err != nil {
		t.Fatal(err)
	}
	fr.TargetBytes = 64
	fr.MaxBytes = 256
	t.Cleanup(func() { _ = fr.Close() })
	_, _ = fr.Recover(context.Background())
	reader, _ := fr.Reader()
	machine := logmirror.NewMachine(meta, nil)
	machine.Frames = fr
	machine.Reader = reader

	ctx := context.Background()
	key := store.LogKey{Profile: "corp", Job: "aged", Build: 1}
	body := []byte(strings.Repeat("age\n", 40))
	st, err := machine.Append(ctx, key, logmirror.Segment{
		Data: body, ReportedNextOffset: int64(len(body)), MoreData: false, BuildComplete: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !st.Sealed {
		_, _ = machine.Seal(ctx, key)
	}
	dest, err := archive.NewFSStore(filepath.Join(dir, store.ArchivesDirName))
	if err != nil {
		t.Fatal(err)
	}
	_, err = logmirror.PackGenerations(ctx, []store.LogKey{key}, meta, dir, dest, logmirror.PackOptions{
		PackID: "pack-age", Marker: meta,
	})
	if err != nil {
		t.Fatal(err)
	}

	qm, err := store.NewQuotaManager(meta, dir, store.QuotaConfig{TotalQuotaBytes: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	// packed_at is "now" relative to Mark — set packed_at recent via DB.
	g, _ := meta.GetLatestGeneration(ctx, key)
	_, _ = meta.DB().ExecContext(ctx,
		`UPDATE log_generations SET packed_at = ? WHERE id = ?`,
		now.Add(-10*time.Minute).Format(time.RFC3339Nano), g.ID)

	maint, err := app.NewMaintainer(qm, meta, dir, app.MaintenanceConfig{
		EnableEviction:         false,
		EnableCompaction:       false,
		EnableL1Release:        true,
		ReleaseAfterPack:       false,
		ReleaseMinAge:          time.Hour,
		CompactionHeadroomFrac: 0.5,
		Now:                    func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := maint.Tick(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.L1Released != 0 {
		t.Fatalf("should not release under min age: %+v", res)
	}
	g2, _ := meta.GetGenerationByID(ctx, g.ID)
	if g2.L1Released {
		t.Fatal("L1 released too early")
	}

	// Age past threshold → release.
	maint.Config.Now = func() time.Time { return now.Add(2 * time.Hour) }
	res, err = maint.Tick(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.L1Released < 1 {
		t.Fatalf("expected age-based release: %+v", res)
	}
}
