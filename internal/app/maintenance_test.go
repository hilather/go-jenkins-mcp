package app_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/app"
	"github.com/simonfxr/go-jenkins-mcp/internal/logmirror"
	"github.com/simonfxr/go-jenkins-mcp/internal/store"
	"github.com/simonfxr/go-jenkins-mcp/internal/telemetry"
)

func openMaintEnv(t *testing.T, quotaBytes int64) (*store.Meta, *store.QuotaManager, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "profiles", "corp")
	m, err := store.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	qm, err := store.NewQuotaManager(m, dir, store.QuotaConfig{
		TotalQuotaBytes: quotaBytes,
		Now:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return m, qm, dir
}

func insertSealedGen(t *testing.T, m *store.Meta, job string, build int64, compressed int64, updatedAt time.Time) *store.LogGeneration {
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
		UpdatedAt:     updatedAt,
	}
	if err := m.InsertGeneration(ctx, g); err != nil {
		t.Fatal(err)
	}
	if err := m.SealGeneration(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	_, err := m.DB().ExecContext(ctx,
		`UPDATE log_generations SET updated_at = ?, sealed = 1 WHERE id = ?`,
		updatedAt.Format(time.RFC3339Nano), g.ID)
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

func TestMaintainer_EvictWhenOverQuota(t *testing.T) {
	// Tiny quota fixture: two 800-byte gens → over 1024.
	m, qm, dir := openMaintEnv(t, 1024)
	ctx := context.Background()
	g1 := insertSealedGen(t, m, "job-a", 1, 800, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	g2 := insertSealedGen(t, m, "job-b", 2, 800, time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC))
	_ = g2

	metrics := telemetry.NewMetrics()
	maint, err := app.NewMaintainer(qm, m, dir, app.MaintenanceConfig{
		EnableEviction:   true,
		EnableCompaction: false,
		Now:              func() time.Time { return time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	maint.Metrics = metrics

	res, err := maint.Tick(ctx)
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if !res.NeedsEviction {
		t.Fatalf("expected NeedsEviction: %+v", res)
	}
	if res.Evicted < 1 {
		t.Fatalf("expected eviction: %+v", res)
	}
	if res.EvictReclaimed <= 0 {
		t.Fatalf("expected reclaim bytes: %+v", res)
	}
	// g1 (oldest) should be gone.
	got, err := m.GetGenerationByID(ctx, g1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("expected g1 evicted, still present id=%d", g1.ID)
	}
	if metrics.GetCounter(telemetry.MetricCacheEvictItems) < 1 {
		t.Fatalf("metrics items=%d", metrics.GetCounter(telemetry.MetricCacheEvictItems))
	}
	if metrics.GetCounter(telemetry.MetricCacheEvictBytes) <= 0 {
		t.Fatalf("metrics bytes=%d", metrics.GetCounter(telemetry.MetricCacheEvictBytes))
	}
}

func TestMaintainer_RecoverJournal(t *testing.T) {
	// Two gens over tiny quota; cancel mid-Evict so journal has pending items;
	// next Tick RecoverEvictJournal completes reclaim.
	m, qm, dir := openMaintEnv(t, 1024)
	ctx := context.Background()
	g1 := insertSealedGen(t, m, "job-a", 1, 800, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	g2 := insertSealedGen(t, m, "job-b", 2, 800, time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC))
	plan, err := qm.PlanEviction(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Candidates) == 0 {
		t.Fatal("expected candidates for journal")
	}
	// Cancelled context: Evict writes journal then fails before finishing all items.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	er, err := qm.Evict(cctx, plan)
	if err == nil && !er.Interrupted && er.Evicted == len(plan.Candidates) {
		// If implementation finishes before checking ctx, still ok — Tick is no-op reclaim.
		t.Logf("Evict completed despite cancel: %+v", er)
	}

	maint, err := app.NewMaintainer(qm, m, dir, app.MaintenanceConfig{
		EnableEviction:   true,
		EnableCompaction: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := maint.Tick(ctx)
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	// After tick we must not remain over quota (journal recover and/or fresh evict).
	need, u, nerr := qm.NeedsEviction(ctx)
	if nerr != nil {
		t.Fatal(nerr)
	}
	if need {
		t.Fatalf("still over quota after tick: res=%+v usage=%+v g1=%d g2=%d", res, u, g1.ID, g2.ID)
	}
	if res.JournalRecovered+res.Evicted < 1 && er.Evicted < 1 {
		t.Fatalf("expected some reclaim path: res=%+v priorEvict=%+v", res, er)
	}
}

func TestMaintainer_CompactionMarksPackedKeepsL1(t *testing.T) {
	// Large quota so eviction does not fire; force headroom low so compaction runs.
	// Same job so ARC-011 lite co-packs into one affinity pack.
	m, qm, dir := openMaintEnv(t, 1<<30)
	ctx := context.Background()
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	g1 := insertSealedGen(t, m, "job-a", 1, 100, old)
	g2 := insertSealedGen(t, m, "job-a", 2, 100, old)

	var packCalls atomic.Int32
	var lastAffinity string
	maint, err := app.NewMaintainer(qm, m, dir, app.MaintenanceConfig{
		EnableEviction:         false,
		EnableCompaction:       true,
		MinSealedMembers:       2,
		MaxMembersPerPack:      8,
		MaxPacksPerTick:        2,
		ForcePackAfter:         time.Hour,
		CompactionHeadroomFrac: 0.01, // almost never skip for headroom
		Now:                    func() time.Time { return time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	// Inject pack: mark packed without real zstd frames (quota fixture uses fake files).
	maint.Pack = func(ctx context.Context, keys []store.LogKey) (logmirror.PackResult, error) {
		packCalls.Add(1)
		ids := make([]int64, 0, len(keys))
		packID := "maint-pack-1"
		aff := logmirror.AffinityGroupFromKeys(keys)
		lastAffinity = aff
		for _, k := range keys {
			g, err := m.GetLatestGeneration(ctx, k)
			if err != nil || g == nil {
				t.Fatalf("GetLatestGeneration: %v %v", err, g)
			}
			if err := m.MarkGenerationPacked(ctx, g.ID, packID); err != nil {
				return logmirror.PackResult{}, err
			}
			ids = append(ids, g.ID)
		}
		return logmirror.PackResult{
			PackID:        packID,
			MemberCount:   len(keys),
			GenerationIDs: ids,
			AffinityGroup: aff,
			MarkedPacked:  true,
		}, nil
	}

	res, err := maint.Tick(ctx)
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if res.PacksCreated != 1 {
		t.Fatalf("packs=%d skip=%q full=%+v", res.PacksCreated, res.CompactionSkipped, res)
	}
	if res.PackMembers != 2 {
		t.Fatalf("members=%d", res.PackMembers)
	}
	if packCalls.Load() != 1 {
		t.Fatalf("pack calls=%d", packCalls.Load())
	}
	if lastAffinity != "profile=corp|job=job-a" {
		t.Fatalf("affinity %q", lastAffinity)
	}

	for _, id := range []int64{g1.ID, g2.ID} {
		g, err := m.GetGenerationByID(ctx, id)
		if err != nil || g == nil {
			t.Fatalf("gen %d: %v", id, err)
		}
		if g.PackedPackID != "maint-pack-1" {
			t.Fatalf("gen %d packed_pack_id=%q", id, g.PackedPackID)
		}
		// L1 chunks + files still present (never deleted by pack).
		chunks, err := m.ListChunks(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if len(chunks) != 1 {
			t.Fatalf("gen %d chunks=%d", id, len(chunks))
		}
		abs, err := store.FrameAbsPath(dir, chunks[0].RelPath)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(abs); err != nil {
			t.Fatalf("L1 frame missing for gen %d: %v", id, err)
		}
	}
}

func TestMaintainer_CompactionAffinitySeparatesJobs(t *testing.T) {
	// Regression: different jobs not forced into same pack when enough candidates.
	m, qm, dir := openMaintEnv(t, 1<<30)
	ctx := context.Background()
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Two sealed gens per job (meets minMembers within affinity).
	insertSealedGen(t, m, "job-a", 1, 50, old)
	insertSealedGen(t, m, "job-a", 2, 50, old)
	insertSealedGen(t, m, "job-b", 1, 50, old)
	insertSealedGen(t, m, "job-b", 2, 50, old)

	var packJobs [][]string
	maint, err := app.NewMaintainer(qm, m, dir, app.MaintenanceConfig{
		EnableEviction:         false,
		EnableCompaction:       true,
		MinSealedMembers:       2,
		MaxMembersPerPack:      8,
		MaxPacksPerTick:        4,
		ForcePackAfter:         time.Hour,
		CompactionHeadroomFrac: 0.01,
		Now:                    func() time.Time { return time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	maint.Pack = func(ctx context.Context, keys []store.LogKey) (logmirror.PackResult, error) {
		jobs := make([]string, 0, len(keys))
		packID := "p-" + logmirror.AffinityGroupFromKeys(keys)
		for _, k := range keys {
			jobs = append(jobs, k.Job)
			g, _ := m.GetLatestGeneration(ctx, k)
			if g != nil {
				_ = m.MarkGenerationPacked(ctx, g.ID, packID)
			}
		}
		packJobs = append(packJobs, jobs)
		return logmirror.PackResult{
			PackID:        packID,
			MemberCount:   len(keys),
			AffinityGroup: logmirror.AffinityGroupFromKeys(keys),
			MarkedPacked:  true,
		}, nil
	}

	res, err := maint.Tick(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.PacksCreated != 2 {
		t.Fatalf("want 2 affinity packs, got %d skip=%q", res.PacksCreated, res.CompactionSkipped)
	}
	if res.PackMembers != 4 {
		t.Fatalf("members=%d", res.PackMembers)
	}
	for i, jobs := range packJobs {
		if len(jobs) != 2 {
			t.Fatalf("pack %d members %v", i, jobs)
		}
		if jobs[0] != jobs[1] {
			t.Fatalf("pack %d mixed jobs %v", i, jobs)
		}
	}
}

func TestMaintainer_CompactionCollectionAffinityCoPacksJobs(t *testing.T) {
	// Wave 31: sealed gens sharing a durable collection co-pack even across jobs.
	// Wave 32: shared relation → AffinityGroup |relation= suffix; mixed → omit.
	m, qm, dir := openMaintEnv(t, 1<<30)
	ctx := context.Background()
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	g1 := insertSealedGen(t, m, "root-job", 1, 50, old)
	g2 := insertSealedGen(t, m, "child-job", 2, 50, old)
	// Different collection must not merge into the first pack.
	g3 := insertSealedGen(t, m, "other-root", 1, 50, old)
	g4 := insertSealedGen(t, m, "other-child", 2, 50, old)

	const collA = "coll-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const collB = "coll-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := m.CreateCollection(ctx, &store.LogCollection{ID: collA, Profile: "corp"}); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateCollection(ctx, &store.LogCollection{ID: collB, Profile: "corp"}); err != nil {
		t.Fatal(err)
	}
	for _, mem := range []store.LogCollectionMember{
		// collA: mixed relations → no relation suffix on label.
		{CollectionID: collA, Profile: "corp", Job: "root-job", Build: 1, GenerationID: g1.ID, State: store.CollectionMemberSealed, Relation: "primary"},
		{CollectionID: collA, Profile: "corp", Job: "child-job", Build: 2, GenerationID: g2.ID, State: store.CollectionMemberSealed, Relation: "downstream"},
		// collB: shared relation → |relation=related on catalog label.
		{CollectionID: collB, Profile: "corp", Job: "other-root", Build: 1, GenerationID: g3.ID, State: store.CollectionMemberSealed, Relation: "related"},
		{CollectionID: collB, Profile: "corp", Job: "other-child", Build: 2, GenerationID: g4.ID, State: store.CollectionMemberSealed, Relation: "related"},
	} {
		mem := mem
		if err := m.UpsertMember(ctx, &mem); err != nil {
			t.Fatal(err)
		}
	}

	var packJobs [][]string
	var packAffs []string
	maint, err := app.NewMaintainer(qm, m, dir, app.MaintenanceConfig{
		EnableEviction:         false,
		EnableCompaction:       true,
		MinSealedMembers:       2,
		MaxMembersPerPack:      8,
		MaxPacksPerTick:        4,
		ForcePackAfter:         time.Hour,
		CompactionHeadroomFrac: 0.01,
		Now:                    func() time.Time { return time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	// Simulate defaultPackWithCollections labeling using the same collection map.
	genToColl, err := m.ListGenerationCollections(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	maint.Pack = func(ctx context.Context, keys []store.LogKey) (logmirror.PackResult, error) {
		jobs := make([]string, 0, len(keys))
		gens := make([]store.LogGeneration, 0, len(keys))
		packID := "pcoll-" + strconv.Itoa(len(packJobs))
		for _, k := range keys {
			jobs = append(jobs, k.Job)
			g, _ := m.GetLatestGeneration(ctx, k)
			if g != nil {
				gens = append(gens, *g)
				_ = m.MarkGenerationPacked(ctx, g.ID, packID)
			}
		}
		aff := logmirror.AffinityGroupFromGenerationsWithCollections(gens, genToColl)
		packJobs = append(packJobs, jobs)
		packAffs = append(packAffs, aff)
		return logmirror.PackResult{
			PackID:        packID,
			MemberCount:   len(keys),
			AffinityGroup: aff,
			MarkedPacked:  true,
		}, nil
	}

	res, err := maint.Tick(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.PacksCreated != 2 {
		t.Fatalf("want 2 collection packs, got %d skip=%q jobs=%v", res.PacksCreated, res.CompactionSkipped, packJobs)
	}
	if res.PackMembers != 4 {
		t.Fatalf("members=%d", res.PackMembers)
	}
	// Each pack should mix the two jobs of one collection (not same-job only).
	for i, jobs := range packJobs {
		if len(jobs) != 2 {
			t.Fatalf("pack %d members %v", i, jobs)
		}
		if jobs[0] == jobs[1] {
			t.Fatalf("pack %d expected cross-job collection co-pack, got %v", i, jobs)
		}
	}
	// Wave 32 labels: collA mixed relations → no suffix; collB shared → |relation=related.
	wantMixed := "profile=corp|collection=" + collA
	wantShared := "profile=corp|collection=" + collB + "|relation=related"
	seen := map[string]bool{}
	for _, a := range packAffs {
		seen[a] = true
	}
	if !seen[wantMixed] {
		t.Fatalf("expected mixed-relation label %q among %v", wantMixed, packAffs)
	}
	if !seen[wantShared] {
		t.Fatalf("expected shared-relation label %q among %v", wantShared, packAffs)
	}
}

func TestMaintainer_SkipCompactionUnderHeadroom(t *testing.T) {
	// Huge free headroom + young gens (not force-aged) ⇒ skip compaction.
	m, qm, dir := openMaintEnv(t, 1<<30)
	ctx := context.Background()
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	// Young gens (updated 1 minute ago).
	insertSealedGen(t, m, "job-a", 1, 50, now.Add(-time.Minute))
	insertSealedGen(t, m, "job-b", 2, 50, now.Add(-time.Minute))

	var packCalls atomic.Int32
	maint, err := app.NewMaintainer(qm, m, dir, app.MaintenanceConfig{
		EnableEviction:         false,
		EnableCompaction:       true,
		MinSealedMembers:       2,
		ForcePackAfter:         24 * time.Hour,
		CompactionHeadroomFrac: 0.25, // free >> 25% of quota
		Now:                    func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	maint.Pack = func(ctx context.Context, keys []store.LogKey) (logmirror.PackResult, error) {
		packCalls.Add(1)
		return logmirror.PackResult{PackID: "x", MemberCount: len(keys)}, nil
	}

	res, err := maint.Tick(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.PacksCreated != 0 {
		t.Fatalf("expected skip under headroom, got packs=%d", res.PacksCreated)
	}
	if res.CompactionSkipped != "under_quota_headroom" {
		t.Fatalf("skip reason=%q", res.CompactionSkipped)
	}
	if packCalls.Load() != 0 {
		t.Fatalf("pack should not run")
	}
}

func TestMaintainer_PinnedSkipped(t *testing.T) {
	m, qm, dir := openMaintEnv(t, 1<<30)
	ctx := context.Background()
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	g1 := insertSealedGen(t, m, "job-a", 1, 100, old)
	g2 := insertSealedGen(t, m, "job-b", 2, 100, old)
	if err := m.PinGeneration(ctx, g1.ID); err != nil {
		t.Fatal(err)
	}

	var packed []int64
	maint, err := app.NewMaintainer(qm, m, dir, app.MaintenanceConfig{
		EnableEviction:         false,
		EnableCompaction:       true,
		MinSealedMembers:       1,
		ForcePackAfter:         time.Hour,
		CompactionHeadroomFrac: 0.01,
		MaxPacksPerTick:        4,
		Now:                    func() time.Time { return time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	maint.Pack = func(ctx context.Context, keys []store.LogKey) (logmirror.PackResult, error) {
		ids := make([]int64, 0, len(keys))
		for _, k := range keys {
			g, _ := m.GetLatestGeneration(ctx, k)
			if g != nil {
				_ = m.MarkGenerationPacked(ctx, g.ID, "p")
				ids = append(ids, g.ID)
				packed = append(packed, g.ID)
			}
		}
		return logmirror.PackResult{PackID: "p", MemberCount: len(keys), GenerationIDs: ids, MarkedPacked: true}, nil
	}

	res, err := maint.Tick(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.PacksCreated < 1 {
		t.Fatalf("expected pack of unpinned: %+v", res)
	}
	for _, id := range packed {
		if id == g1.ID {
			t.Fatalf("pinned gen packed: %v", packed)
		}
	}
	g1b, _ := m.GetGenerationByID(ctx, g1.ID)
	if g1b == nil || g1b.PackedPackID != "" {
		t.Fatalf("pinned should stay unpacked: %+v", g1b)
	}
	g2b, _ := m.GetGenerationByID(ctx, g2.ID)
	if g2b == nil || g2b.PackedPackID == "" {
		t.Fatalf("unpinned should pack: %+v", g2b)
	}
}

func TestMaintainer_RunCancelsOnContext(t *testing.T) {
	m, qm, dir := openMaintEnv(t, 1<<30)
	maint, err := app.NewMaintainer(qm, m, dir, app.MaintenanceConfig{
		Interval:         20 * time.Millisecond,
		EnableEviction:   true,
		EnableCompaction: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	metrics := telemetry.NewMetrics()
	maint.Metrics = metrics

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		maint.Run(ctx)
	}()
	// Allow at least the immediate tick + one interval.
	time.Sleep(60 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after cancel")
	}
	if metrics.GetCounter(telemetry.MetricCacheMaintTicks) < 1 {
		t.Fatalf("expected at least one tick, got %d", metrics.GetCounter(telemetry.MetricCacheMaintTicks))
	}
}

func TestMaintainer_DefaultPackRealFrames(t *testing.T) {
	// End-to-end: real L1 zstd frames → defaultPack → packed_pack_id; L1 remains.
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

	ctx := context.Background()
	// Force age: seal then backdate updated_at so force-pack applies even under headroom.
	for i, job := range []string{"demo-a", "demo-b"} {
		key := store.LogKey{Profile: "corp", Job: job, Build: int64(i + 1)}
		body := []byte("line-" + job + "\nline2\nline3\n")
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
		_, err = meta.DB().ExecContext(ctx,
			`UPDATE log_generations SET updated_at = ? WHERE profile = ? AND job = ? AND build = ?`,
			time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
			key.Profile, key.Job, key.Build)
		if err != nil {
			t.Fatal(err)
		}
	}

	qm, err := store.NewQuotaManager(meta, dir, store.QuotaConfig{TotalQuotaBytes: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	// Tiny free headroom threshold so bulk path would skip, but force-age still packs.
	maint, err := app.NewMaintainer(qm, meta, dir, app.MaintenanceConfig{
		EnableEviction:         false,
		EnableCompaction:       true,
		MinSealedMembers:       2,
		ForcePackAfter:         time.Hour,
		CompactionHeadroomFrac: 0.99, // under headroom → only force-aged
		Now:                    func() time.Time { return time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	// Use default Pack (real FSStore + PackGenerations).
	res, err := maint.Tick(ctx)
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if res.PacksCreated < 1 {
		t.Fatalf("expected real pack: %+v", res)
	}
	gens, err := meta.ListGenerations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range gens {
		if g.PackedPackID == "" {
			t.Fatalf("gen %d missing packed_pack_id", g.ID)
		}
		chunks, err := meta.ListChunks(ctx, g.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(chunks) == 0 {
			t.Fatalf("L1 chunks lost for gen %d", g.ID)
		}
		abs, err := store.FrameAbsPath(dir, chunks[0].RelPath)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(abs); err != nil {
			t.Fatalf("L1 frame gone for gen %d: %v", g.ID, err)
		}
		// Pack file on disk.
		packPath := filepath.Join(dir, store.ArchivesDirName, g.PackedPackID+".tar.zst")
		if _, err := os.Stat(packPath); err != nil {
			t.Fatalf("L2 pack missing %s: %v", packPath, err)
		}
	}
}

func TestAffinityPackBatches_Bounds(t *testing.T) {
	// Same job: MaxMembersPerPack + MaxPacksPerTick bound fills within affinity.
	m, qm, dir := openMaintEnv(t, 1<<30)
	ctx := context.Background()
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 1; i <= 5; i++ {
		insertSealedGen(t, m, "same-job", int64(i), 20, old)
	}
	var packs atomic.Int32
	var members atomic.Int32
	maint, err := app.NewMaintainer(qm, m, dir, app.MaintenanceConfig{
		EnableEviction:         false,
		EnableCompaction:       true,
		MinSealedMembers:       2,
		MaxMembersPerPack:      2,
		MaxPacksPerTick:        2, // only 2 packs even though 5 gens
		ForcePackAfter:         time.Hour,
		CompactionHeadroomFrac: 0.01,
		Now:                    func() time.Time { return time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	maint.Pack = func(ctx context.Context, keys []store.LogKey) (logmirror.PackResult, error) {
		packs.Add(1)
		members.Add(int32(len(keys)))
		for _, k := range keys {
			g, _ := m.GetLatestGeneration(ctx, k)
			if g != nil {
				_ = m.MarkGenerationPacked(ctx, g.ID, "p"+strconv.Itoa(int(packs.Load())))
			}
		}
		return logmirror.PackResult{
			PackID: "p", MemberCount: len(keys), MarkedPacked: true,
			AffinityGroup: logmirror.AffinityGroupFromKeys(keys),
		}, nil
	}
	res, err := maint.Tick(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.PacksCreated != 2 {
		t.Fatalf("max packs: got %d", res.PacksCreated)
	}
	if res.PackMembers != 4 {
		t.Fatalf("members: got %d want 4", res.PackMembers)
	}
}
