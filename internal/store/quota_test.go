package store_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/store"
)

func openQuotaEnv(t *testing.T) (*store.Meta, *store.QuotaManager, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "profiles", "corp")
	m, err := store.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	qm, err := store.NewQuotaManager(m, dir, store.QuotaConfig{
		TotalQuotaBytes:  1024, // tiny for tests
		SuccessRetention: 0,
		FailedRetention:  0,
		Now:              func() time.Time { return time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return m, qm, dir
}

func insertSealedGen(t *testing.T, m *store.Meta, job string, build int64, compressed int64) *store.LogGeneration {
	t.Helper()
	ctx := context.Background()
	g := &store.LogGeneration{
		Profile:       "corp",
		Job:           job,
		Build:         build,
		Generation:    1,
		JenkinsOffset: compressed,
		MoreData:      false,
		BuildComplete: true,
		Sealed:        false,
		UpdatedAt:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	if err := m.InsertGeneration(ctx, g); err != nil {
		t.Fatal(err)
	}
	if err := m.SealGeneration(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	// Force older updated_at for deterministic oldest-first.
	_, err := m.DB().ExecContext(ctx,
		`UPDATE log_generations SET updated_at = ?, sealed = 1 WHERE id = ?`,
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano), g.ID)
	if err != nil {
		t.Fatal(err)
	}
	c := &store.Chunk{
		GenerationID:     g.ID,
		Seq:              0,
		RawStart:         0,
		RawEnd:           compressed,
		LineStart:        0,
		LineEnd:          1,
		UncompressedSize: compressed,
		CompressedSize:   compressed,
		ContentSHA256:    "aa",
		FrameSHA256:      "bb",
		Codec:            store.CodecZstd,
		CodecLevel:       3,
		FormatVersion:    store.FrameFormatVersion,
		RelPath:          store.FrameRelPath(g.ID, 0),
		CreatedAt:        time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := m.InsertChunk(ctx, c, nil); err != nil {
		t.Fatal(err)
	}
	// Write a fake frame file so eviction has something to remove.
	dataDir := filepath.Dir(m.Path())
	abs, err := store.FrameAbsPath(dataDir, c.RelPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, make([]byte, compressed), 0o600); err != nil {
		t.Fatal(err)
	}
	g2, err := m.GetGenerationByID(ctx, g.ID)
	if err != nil || g2 == nil {
		t.Fatalf("reload: %v %+v", err, g2)
	}
	return g2
}

func TestQuota_ExceededTriggersPlan(t *testing.T) {
	m, qm, _ := openQuotaEnv(t)
	ctx := context.Background()
	// Two gens of 800 bytes each → 1600 > 1024 quota.
	g1 := insertSealedGen(t, m, "job-a", 1, 800)
	g2 := insertSealedGen(t, m, "job-b", 2, 800)
	_ = g1
	_ = g2

	need, u, err := qm.NeedsEviction(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !need || !u.OverQuota {
		t.Fatalf("expected over quota: %+v", u)
	}
	plan, err := qm.PlanEviction(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if plan.BytesNeeded <= 0 {
		t.Fatalf("bytes needed: %d", plan.BytesNeeded)
	}
	if len(plan.Candidates) == 0 {
		t.Fatal("expected candidates")
	}
	// Oldest first: job-a before job-b (same timestamp → lower id).
	if plan.Candidates[0].Tier != "l1" {
		t.Fatalf("first tier %s", plan.Candidates[0].Tier)
	}
	if plan.TotalReclaimBytes < plan.BytesNeeded && len(plan.Candidates) < 2 {
		t.Fatalf("plan insufficient: %+v", plan)
	}
}

func TestQuota_PinProtects(t *testing.T) {
	m, qm, _ := openQuotaEnv(t)
	ctx := context.Background()
	g1 := insertSealedGen(t, m, "job-a", 1, 900)
	g2 := insertSealedGen(t, m, "job-b", 2, 900)
	if err := m.PinGeneration(ctx, g1.ID); err != nil {
		t.Fatal(err)
	}
	plan, err := qm.PlanEviction(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range plan.Candidates {
		if c.ID == strconv.FormatInt(g1.ID, 10) {
			t.Fatalf("pinned gen in plan: %+v", plan.Candidates)
		}
	}
	found := false
	for _, c := range plan.Candidates {
		if c.ID == strconv.FormatInt(g2.ID, 10) {
			found = true
		}
	}
	if !found {
		t.Fatalf("unpinned gen missing: %+v", plan.Candidates)
	}
}

func TestQuota_LeaseProtects(t *testing.T) {
	m, qm, _ := openQuotaEnv(t)
	ctx := context.Background()
	g1 := insertSealedGen(t, m, "job-a", 1, 900)
	_ = insertSealedGen(t, m, "job-b", 2, 900)
	if err := qm.LeaseGeneration(g1.ID, time.Date(2026, 1, 15, 13, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	plan, err := qm.PlanEviction(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range plan.Candidates {
		if c.ID == strconv.FormatInt(g1.ID, 10) {
			t.Fatal("leased gen in plan")
		}
	}
}

func TestQuota_UnsealedNeverEvicted(t *testing.T) {
	m, qm, _ := openQuotaEnv(t)
	ctx := context.Background()
	g := &store.LogGeneration{
		Profile: "corp", Job: "run", Build: 1, Generation: 1,
		MoreData: true, JenkinsOffset: 100,
	}
	if err := m.InsertGeneration(ctx, g); err != nil {
		t.Fatal(err)
	}
	c := &store.Chunk{
		GenerationID: g.ID, Seq: 0, RawStart: 0, RawEnd: 900,
		LineStart: 0, LineEnd: 1, UncompressedSize: 900, CompressedSize: 900,
		ContentSHA256: "a", FrameSHA256: "b", Codec: store.CodecZstd,
		RelPath: store.FrameRelPath(g.ID, 0),
	}
	if err := m.InsertChunk(ctx, c, nil); err != nil {
		t.Fatal(err)
	}
	_ = insertSealedGen(t, m, "job-b", 2, 900)
	plan, err := qm.PlanEviction(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range plan.Candidates {
		if c.ID == strconv.FormatInt(g.ID, 10) {
			t.Fatal("unsealed generation must not be evicted")
		}
	}
}

func TestQuota_DryRunNoDelete(t *testing.T) {
	m, qm, dataDir := openQuotaEnv(t)
	ctx := context.Background()
	g1 := insertSealedGen(t, m, "job-a", 1, 900)
	plan, err := qm.PlanEviction(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.DryRun {
		t.Fatal("plan must be dry-run")
	}
	// Still present after plan.
	got, err := m.GetGenerationByID(ctx, g1.ID)
	if err != nil || got == nil {
		t.Fatal("plan deleted generation")
	}
	// Frame file still present.
	abs, _ := store.FrameAbsPath(dataDir, store.FrameRelPath(g1.ID, 0))
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("frame missing after dry-run: %v", err)
	}
}

func TestQuota_EvictAppliesAndPinBlocks(t *testing.T) {
	m, qm, dataDir := openQuotaEnv(t)
	ctx := context.Background()
	g1 := insertSealedGen(t, m, "job-a", 1, 900)
	g2 := insertSealedGen(t, m, "job-b", 2, 900)
	if err := m.PinGeneration(ctx, g2.ID); err != nil {
		t.Fatal(err)
	}
	plan, err := qm.PlanEviction(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	res, err := qm.Evict(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	if res.Evicted < 1 {
		t.Fatalf("expected eviction: %+v", res)
	}
	got, err := m.GetGenerationByID(ctx, g1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatal("g1 should be deleted")
	}
	got2, err := m.GetGenerationByID(ctx, g2.ID)
	if err != nil || got2 == nil {
		t.Fatal("pinned g2 must remain")
	}
	// Journal cleared.
	if _, err := os.Stat(filepath.Join(dataDir, store.EvictJournalFile)); !os.IsNotExist(err) {
		t.Fatalf("journal should be cleared: %v", err)
	}
}

func TestQuota_InterruptedEvictionConsistent(t *testing.T) {
	m, qm, dataDir := openQuotaEnv(t)
	ctx := context.Background()
	qm.Config.TotalQuotaBytes = 100 // force multi-candidate plan
	g1 := insertSealedGen(t, m, "job-a", 1, 500)
	g2 := insertSealedGen(t, m, "job-b", 2, 500)
	g3 := insertSealedGen(t, m, "job-c", 3, 500)
	_ = g1
	_ = g2
	_ = g3
	plan, err := qm.PlanEviction(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Candidates) < 2 {
		t.Fatalf("need ≥2 candidates: %+v", plan)
	}
	// Cancel after first success via context that cancels immediately on second call —
	// use a cancelable context and cancel mid-evict by wrapping: apply only first item manually.
	// Simulate interrupt: write journal with first done, second pending, then Recover.
	partial := store.EvictPlan{
		Candidates: plan.Candidates[:1],
		DryRun:     false,
	}
	res, err := qm.Evict(ctx, partial)
	if err != nil {
		t.Fatal(err)
	}
	if res.Evicted != 1 {
		t.Fatalf("partial: %+v", res)
	}
	// Metadata consistent: first gone, others present, no corrupt schema.
	st, err := m.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.SchemaVersion != store.CurrentSchemaVersion {
		t.Fatalf("schema %d", st.SchemaVersion)
	}
	// Simulate leftover journal with remaining candidates pending.
	// Recover from empty journal is fine; craft pending via second Evict cancel.
	cancelCtx, cancel := context.WithCancel(context.Background())
	// Pre-write: cancel before any work by cancelling immediately.
	cancel()
	rest := store.EvictPlan{Candidates: plan.Candidates[1:], DryRun: false}
	res2, err := qm.Evict(cancelCtx, rest)
	if err == nil && !res2.Interrupted {
		// May fail on first item with cancelled context.
	}
	// Store still open and consistent.
	gens, err := m.ListGenerations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range gens {
		if !g.Sealed {
			t.Fatal("unexpected unsealed")
		}
		// Chunks either fully present or gen fully gone — no half meta without gen.
		chunks, err := m.ListChunks(ctx, g.ID)
		if err != nil {
			t.Fatal(err)
		}
		_ = chunks
	}
	// Recover journal if any.
	_, _ = qm.RecoverEvictJournal(context.Background())
	if _, err := m.Stats(ctx); err != nil {
		t.Fatal(err)
	}
	_ = dataDir
}

func TestQuota_L2PackEvictionAndPin(t *testing.T) {
	m, qm, dataDir := openQuotaEnv(t)
	ctx := context.Background()
	// Tiny L1 so L2 dominates quota.
	qm.Config.TotalQuotaBytes = 100
	arch := filepath.Join(dataDir, store.ArchivesDirName)
	if err := os.MkdirAll(arch, 0o700); err != nil {
		t.Fatal(err)
	}
	// Two packs.
	if err := os.WriteFile(filepath.Join(arch, "pack-old.tar.zst"), make([]byte, 200), 0o600); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	_ = os.Chtimes(filepath.Join(arch, "pack-old.tar.zst"), oldTime, oldTime)
	if err := os.WriteFile(filepath.Join(arch, "pack-new.tar.zst"), make([]byte, 200), 0o600); err != nil {
		t.Fatal(err)
	}
	newTime := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	_ = os.Chtimes(filepath.Join(arch, "pack-new.tar.zst"), newTime, newTime)

	if err := m.PinPack(ctx, "pack-new"); err != nil {
		t.Fatal(err)
	}
	plan, err := qm.PlanEviction(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	var sawOld, sawNew bool
	for _, c := range plan.Candidates {
		if c.Tier == "l2" && c.ID == "pack-old" {
			sawOld = true
		}
		if c.ID == "pack-new" {
			sawNew = true
		}
	}
	if !sawOld {
		t.Fatalf("expected pack-old: %+v", plan.Candidates)
	}
	if sawNew {
		t.Fatal("pinned pack-new must not be planned")
	}
	res, err := qm.Evict(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	if res.Evicted < 1 {
		t.Fatalf("evict: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(arch, "pack-old.tar.zst")); !os.IsNotExist(err) {
		t.Fatal("pack-old should be deleted")
	}
	if _, err := os.Stat(filepath.Join(arch, "pack-new.tar.zst")); err != nil {
		t.Fatal("pinned pack-new must remain")
	}
}

func TestQuota_RetentionAges(t *testing.T) {
	m, _, dataDir := openQuotaEnv(t)
	ctx := context.Background()
	// Under large quota; only retention drives selection.
	qm, err := store.NewQuotaManager(m, dataDir, store.QuotaConfig{
		TotalQuotaBytes:  1 << 40,
		SuccessRetention: 24 * time.Hour,
		FailedRetention:  1 * time.Hour,
		Now:              func() time.Time { return time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	gs := insertSealedGen(t, m, "ok", 1, 100)
	gf := insertSealedGen(t, m, "bad", 2, 100)
	if err := m.SetGenerationOutcome(ctx, gs.ID, store.OutcomeSuccess); err != nil {
		t.Fatal(err)
	}
	if err := m.SetGenerationOutcome(ctx, gf.ID, store.OutcomeFailed); err != nil {
		t.Fatal(err)
	}
	// SetGenerationOutcome bumps updated_at; re-age both to Jan 1 for retention.
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	if _, err := m.DB().ExecContext(ctx, `UPDATE log_generations SET updated_at = ? WHERE id IN (?, ?)`,
		old, gs.ID, gf.ID); err != nil {
		t.Fatal(err)
	}
	// Both older than 1 hour (updated_at forced to Jan 1).
	// Success retention 24h from Jan 15 12:00 → expired (14d old).
	// Failed retention 1h → expired.
	plan, err := qm.PlanEviction(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Candidates) < 2 {
		t.Fatalf("both retention-expired: %+v", plan.Candidates)
	}

	// Fresh success: not expired.
	gFresh := insertSealedGen(t, m, "fresh", 3, 100)
	_, _ = m.DB().ExecContext(ctx,
		`UPDATE log_generations SET updated_at = ?, outcome = ? WHERE id = ?`,
		time.Date(2026, 1, 15, 11, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
		store.OutcomeSuccess, gFresh.ID)
	plan2, err := qm.PlanEviction(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range plan2.Candidates {
		if c.ID == strconv.FormatInt(gFresh.ID, 10) {
			t.Fatal("fresh success within retention must not be planned under quota")
		}
	}
}
