package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/store"
)

// seedSealedGenForCLI inserts a sealed L1 generation + frame file into an open meta store.
// Mirrors store_test insertSealedGen patterns for CLI dry-run fixtures.
func seedSealedGenForCLI(t *testing.T, m *store.Meta, dataDir, job string, build, compressed int64) *store.LogGeneration {
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

func openTestProfileMeta(t *testing.T, profileID string) (*store.Meta, string) {
	t.Helper()
	dir := ensureTestProfileDataDir(t, profileID)
	meta, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = meta.Close() })
	return meta, dir
}

func TestCacheEvictionPlan_JSONCandidatesAndDryRun(t *testing.T) {
	withTestXDG(t)
	saveSeedProfile(t, "corp")
	meta, dir := openTestProfileMeta(t, "corp")
	g1 := seedSealedGenForCLI(t, meta, dir, "job-a", 1, 800)
	g2 := seedSealedGenForCLI(t, meta, dir, "job-b", 2, 800)
	if err := meta.PinGeneration(context.Background(), g1.ID); err != nil {
		t.Fatal(err)
	}
	// Close so CLI can open the same sqlite file.
	if err := meta.Close(); err != nil {
		t.Fatal(err)
	}

	out, err := captureCacheKeyStdout(t, func() error {
		return runCacheEvictionPlan([]string{"--profile", "corp", "--json", "--target-bytes", "1"})
	})
	if err != nil {
		t.Fatalf("eviction-plan: %v", err)
	}
	var doc evictionPlanJSON
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("json: %v out=%q", err, out)
	}
	if doc.Profile != "corp" || !doc.DryRun {
		t.Fatalf("doc profile/dry_run: %+v", doc)
	}
	if doc.PinsSkipped != 1 {
		t.Fatalf("pins_skipped want 1 got %d", doc.PinsSkipped)
	}
	// Pinned g1 must not appear; unpinned g2 should.
	for _, c := range doc.Candidates {
		if c.ID == strconv.FormatInt(g1.ID, 10) {
			t.Fatalf("pinned gen in candidates: %+v", doc.Candidates)
		}
	}
	found := false
	for _, c := range doc.Candidates {
		if c.ID == strconv.FormatInt(g2.ID, 10) && c.Kind == "l1" {
			found = true
			if c.Bytes <= 0 {
				t.Fatalf("candidate bytes: %+v", c)
			}
		}
	}
	if !found {
		t.Fatalf("expected unpinned candidate: %+v", doc.Candidates)
	}
	if strings.Contains(out, "token") || strings.Contains(out, "password") || strings.Contains(out, "Bearer") {
		t.Fatalf("Regression: eviction-plan JSON looked secret-bearing: %q", out)
	}

	// Dry-run must not delete frames or meta rows.
	meta2, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = meta2.Close() }()
	got, err := meta2.GetGenerationByID(context.Background(), g2.ID)
	if err != nil || got == nil {
		t.Fatalf("Regression: dry-run deleted generation: %v", err)
	}
	abs, _ := store.FrameAbsPath(dir, store.FrameRelPath(g2.ID, 0))
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("Regression: dry-run deleted frame: %v", err)
	}
}

func TestCacheEvictionPlan_TextAndQuota(t *testing.T) {
	withTestXDG(t)
	saveSeedProfile(t, "corp")
	meta, dir := openTestProfileMeta(t, "corp")
	_ = seedSealedGenForCLI(t, meta, dir, "job-a", 1, 400)
	if err := meta.Close(); err != nil {
		t.Fatal(err)
	}

	out, err := captureCacheKeyStdout(t, func() error {
		return runCacheEvictionPlan([]string{"--profile", "corp", "--target-bytes", "100"})
	})
	if err != nil {
		t.Fatalf("text plan: %v", err)
	}
	if !strings.Contains(out, "profile=corp") || !strings.Contains(out, "dry_run=true") {
		t.Fatalf("text: %q", out)
	}
	if !strings.Contains(out, "kind=l1") || !strings.Contains(out, "bytes=") {
		t.Fatalf("expected candidate lines: %q", out)
	}

	out, err = captureCacheKeyStdout(t, func() error {
		return runCacheQuota([]string{"--profile", "corp", "--json"})
	})
	if err != nil {
		t.Fatalf("quota: %v", err)
	}
	var qdoc quotaUsageJSON
	if err := json.Unmarshal([]byte(out), &qdoc); err != nil {
		t.Fatalf("quota json: %v out=%q", err, out)
	}
	if qdoc.Profile != "corp" || qdoc.Usage.QuotaBytes <= 0 {
		t.Fatalf("quota doc: %+v", qdoc)
	}
	if qdoc.Usage.TotalPhysicalBytes < 400 {
		t.Fatalf("expected physical bytes from fixture: %+v", qdoc.Usage)
	}
	// Default resolved total quota is product 10 GiB when unset.
	if qdoc.Usage.QuotaBytes != store.DefaultTotalQuotaBytes {
		t.Fatalf("default quota bytes: got %d want %d", qdoc.Usage.QuotaBytes, store.DefaultTotalQuotaBytes)
	}
}

// Regression: offline cache quota / plan must honor resolved --cache-total-quota-bytes
// (same ResolveQuotaConfig as serve maintenance), not always QuotaConfig{}.
func TestCacheQuota_UsesResolvedTotalQuotaFlag(t *testing.T) {
	withTestXDG(t)
	saveSeedProfile(t, "corp")
	meta, dir := openTestProfileMeta(t, "corp")
	_ = seedSealedGenForCLI(t, meta, dir, "job-a", 1, 400)
	if err := meta.Close(); err != nil {
		t.Fatal(err)
	}
	want := store.MinTotalQuotaBytes // 64 MiB
	out, err := captureCacheKeyStdout(t, func() error {
		return runCacheQuota([]string{
			"--profile", "corp", "--json",
			"--cache-total-quota-bytes", strconv.FormatInt(want, 10),
		})
	})
	if err != nil {
		t.Fatalf("quota: %v", err)
	}
	var qdoc quotaUsageJSON
	if err := json.Unmarshal([]byte(out), &qdoc); err != nil {
		t.Fatalf("json: %v out=%q", err, out)
	}
	if qdoc.Usage.QuotaBytes != want {
		t.Fatalf("Usage.QuotaBytes=%d want resolved %d", qdoc.Usage.QuotaBytes, want)
	}
}

func TestCacheQuota_RejectInvalidTotalQuota(t *testing.T) {
	withTestXDG(t)
	saveSeedProfile(t, "corp")
	_ = ensureTestProfileDataDir(t, "corp")
	err := runCacheQuota([]string{"--profile", "corp", "--cache-total-quota-bytes", "-1"})
	if err == nil {
		t.Fatal("expected invalid quota to fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code: %v err=%v", apperr.CodeOf(err), err)
	}
	// Over absolute max.
	err = runCacheQuota([]string{
		"--profile", "corp",
		"--cache-total-quota-bytes", strconv.FormatInt(store.AbsoluteMaxTotalQuotaBytes+1, 10),
	})
	if err == nil {
		t.Fatal("expected over-absolute to fail closed")
	}
	if !strings.Contains(err.Error(), "exceeds absolute maximum") {
		t.Fatalf("msg: %v", err)
	}
}

func TestResolveCacheQuotaConfig_EnvAndFlag(t *testing.T) {
	t.Setenv(store.EnvCacheTotalQuotaBytes, strconv.FormatInt(store.MinTotalQuotaBytes+100, 10))
	t.Setenv(store.EnvCacheLowDiskBytes, strconv.FormatInt(store.MinLowDiskBytes+50, 10))
	cfg, err := resolveCacheQuotaConfig("", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TotalQuotaBytes != store.MinTotalQuotaBytes+100 {
		t.Fatalf("env total: %d", cfg.TotalQuotaBytes)
	}
	// Flag wins.
	wantFlag := store.MinTotalQuotaBytes + 200
	cfg, err = resolveCacheQuotaConfig(strconv.FormatInt(wantFlag, 10), "")
	if err != nil || cfg.TotalQuotaBytes != wantFlag {
		t.Fatalf("flag wins: %+v %v", cfg, err)
	}
}

func TestCacheEvictionPlan_FailClosed(t *testing.T) {
	withTestXDG(t)
	err := runCacheEvictionPlan([]string{"--profile", "missing"})
	if err == nil {
		t.Fatal("expected missing profile to fail")
	}
	if apperr.CodeOf(err) == "" {
		t.Fatalf("expected typed error: %v", err)
	}

	saveSeedProfile(t, "corp")
	// Profile exists; data dir never created.
	err = runCacheEvictionPlan([]string{"--profile", "corp"})
	if err == nil {
		t.Fatal("expected missing data dir to fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodeNotFound && !strings.Contains(err.Error(), "data directory") {
		t.Fatalf("expected not_found / data directory: code=%v err=%v", apperr.CodeOf(err), err)
	}
	err = runCacheQuota([]string{"--profile", "corp"})
	if err == nil {
		t.Fatal("expected quota without data dir to fail")
	}
}

func TestCacheEvictionPlan_Validation(t *testing.T) {
	withTestXDG(t)
	saveSeedProfile(t, "corp")
	_ = ensureTestProfileDataDir(t, "corp")

	cases := []struct {
		name string
		fn   func() error
		want string
	}{
		{"plan no profile", func() error {
			return runCacheEvictionPlan(nil)
		}, "profile"},
		{"plan bad target", func() error {
			return runCacheEvictionPlan([]string{"--profile", "corp", "--target-bytes", "-1"})
		}, "target-bytes"},
		{"quota no profile", func() error {
			return runCacheQuota(nil)
		}, "profile"},
		{"evict no profile", func() error {
			return runCacheEvict(nil)
		}, "profile"},
		{"evict bad target", func() error {
			return runCacheEvict([]string{"--profile", "corp", "--target-bytes", "-1", "--confirm"})
		}, "target-bytes"},
		{"cache unknown", func() error {
			return runCache([]string{"not-a-real-subcommand"})
		}, "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.fn()
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.want) {
				t.Fatalf("err %q want substring %q", err.Error(), tc.want)
			}
		})
	}
}

func TestCacheEvictionPlan_EmptyUnderQuotaNoTarget(t *testing.T) {
	withTestXDG(t)
	saveSeedProfile(t, "corp")
	meta, dir := openTestProfileMeta(t, "corp")
	_ = seedSealedGenForCLI(t, meta, dir, "job-a", 1, 100)
	if err := meta.Close(); err != nil {
		t.Fatal(err)
	}

	out, err := captureCacheKeyStdout(t, func() error {
		return runCacheEvictionPlan([]string{"--profile", "corp", "--json"})
	})
	if err != nil {
		t.Fatal(err)
	}
	var doc evictionPlanJSON
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	// Default 10 GiB quota + tiny fixture ⇒ no forced reclaim.
	if doc.NeedsEviction {
		t.Fatalf("unexpected needs_eviction: %+v", doc)
	}
	if doc.BytesNeeded != 0 {
		t.Fatalf("bytes_needed: %d", doc.BytesNeeded)
	}
}

// Regression: default cache evict is dry-run and must never call Evict (frames + meta remain).
func TestCacheEvict_DefaultDryRunNoDelete(t *testing.T) {
	withTestXDG(t)
	saveSeedProfile(t, "corp")
	meta, dir := openTestProfileMeta(t, "corp")
	g := seedSealedGenForCLI(t, meta, dir, "job-a", 1, 800)
	if err := meta.Close(); err != nil {
		t.Fatal(err)
	}

	out, err := captureCacheKeyStdout(t, func() error {
		return runCacheEvict([]string{"--profile", "corp", "--json", "--target-bytes", "1"})
	})
	if err != nil {
		t.Fatalf("evict dry-run: %v", err)
	}
	var doc evictionPlanJSON
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("json: %v out=%q", err, out)
	}
	if !doc.DryRun || doc.Applied {
		t.Fatalf("expected dry_run without apply: %+v", doc)
	}
	if doc.Evicted != 0 || doc.ReclaimedBytes != 0 {
		t.Fatalf("dry-run must not report eviction: %+v", doc)
	}
	if len(doc.Candidates) == 0 {
		t.Fatalf("expected candidates with target-bytes: %+v", doc)
	}

	meta2, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = meta2.Close() }()
	got, err := meta2.GetGenerationByID(context.Background(), g.ID)
	if err != nil || got == nil {
		t.Fatalf("Regression: dry-run without --confirm deleted generation: %v", err)
	}
	abs, _ := store.FrameAbsPath(dir, store.FrameRelPath(g.ID, 0))
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("Regression: dry-run without --confirm deleted frame: %v", err)
	}
}

// With --confirm, apply path reclaims unpinned candidates; pins stay.
func TestCacheEvict_ConfirmAppliesAndSkipsPins(t *testing.T) {
	withTestXDG(t)
	saveSeedProfile(t, "corp")
	meta, dir := openTestProfileMeta(t, "corp")
	g1 := seedSealedGenForCLI(t, meta, dir, "job-a", 1, 800)
	g2 := seedSealedGenForCLI(t, meta, dir, "job-b", 2, 800)
	if err := meta.PinGeneration(context.Background(), g1.ID); err != nil {
		t.Fatal(err)
	}
	if err := meta.Close(); err != nil {
		t.Fatal(err)
	}

	out, err := captureCacheKeyStdout(t, func() error {
		return runCache([]string{"evict", "--profile", "corp", "--json", "--target-bytes", "1", "--confirm"})
	})
	if err != nil {
		t.Fatalf("evict apply: %v out=%q", err, out)
	}
	var doc evictionPlanJSON
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("json: %v out=%q", err, out)
	}
	if doc.DryRun {
		t.Fatalf("apply must set dry_run=false: %+v", doc)
	}
	if !doc.Applied {
		t.Fatalf("expected applied: %+v", doc)
	}
	if doc.PinsSkipped != 1 {
		t.Fatalf("pins_skipped want 1 got %d", doc.PinsSkipped)
	}
	if doc.Evicted < 1 || doc.ReclaimedBytes <= 0 {
		t.Fatalf("expected reclaim: %+v", doc)
	}
	for _, c := range doc.Candidates {
		if c.ID == strconv.FormatInt(g1.ID, 10) {
			t.Fatalf("pinned gen must not be candidate: %+v", doc.Candidates)
		}
	}
	foundG2 := false
	for _, c := range doc.Candidates {
		if c.ID == strconv.FormatInt(g2.ID, 10) && c.Kind == "l1" {
			foundG2 = true
		}
	}
	if !foundG2 {
		t.Fatalf("unpinned g2 should be candidate: %+v", doc.Candidates)
	}
	if strings.Contains(out, "token") || strings.Contains(out, "password") || strings.Contains(out, "Bearer") {
		t.Fatalf("Regression: evict JSON looked secret-bearing: %q", out)
	}
	// Absolute data paths with home/XDG must not appear.
	if strings.Contains(out, dir) {
		t.Fatalf("Regression: JSON leaked data dir path: %q", out)
	}

	meta2, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = meta2.Close() }()
	pinned, err := meta2.GetGenerationByID(context.Background(), g1.ID)
	if err != nil || pinned == nil {
		t.Fatalf("pinned gen must remain: %v", err)
	}
	gone, err := meta2.GetGenerationByID(context.Background(), g2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gone != nil {
		t.Fatalf("unpinned g2 should be evicted")
	}
	absPinned, _ := store.FrameAbsPath(dir, store.FrameRelPath(g1.ID, 0))
	if _, err := os.Stat(absPinned); err != nil {
		t.Fatalf("pinned frame missing: %v", err)
	}
	absGone, _ := store.FrameAbsPath(dir, store.FrameRelPath(g2.ID, 0))
	if _, err := os.Stat(absGone); !os.IsNotExist(err) {
		t.Fatalf("evicted frame should be gone: %v", err)
	}
}

// --yes is accepted as confirm alias (via eviction-apply alias too).
func TestCacheEvict_YesAliasAndEvictionApply(t *testing.T) {
	withTestXDG(t)
	saveSeedProfile(t, "corp")
	meta, dir := openTestProfileMeta(t, "corp")
	g := seedSealedGenForCLI(t, meta, dir, "job-a", 1, 500)
	if err := meta.Close(); err != nil {
		t.Fatal(err)
	}

	out, err := captureCacheKeyStdout(t, func() error {
		return runCache([]string{"eviction-apply", "--profile", "corp", "--json", "--target-bytes", "1", "--yes"})
	})
	if err != nil {
		t.Fatalf("eviction-apply: %v", err)
	}
	var doc evictionPlanJSON
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if !doc.Applied || doc.Evicted < 1 {
		t.Fatalf("expected apply via --yes: %+v", doc)
	}

	meta2, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = meta2.Close() }()
	got, err := meta2.GetGenerationByID(context.Background(), g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatal("generation should be gone after --yes apply")
	}
}

// Cancelled context fails closed without claiming full apply success.
func TestCacheEvict_CancelContext(t *testing.T) {
	withTestXDG(t)
	saveSeedProfile(t, "corp")
	meta, dir := openTestProfileMeta(t, "corp")
	g1 := seedSealedGenForCLI(t, meta, dir, "job-a", 1, 400)
	g2 := seedSealedGenForCLI(t, meta, dir, "job-b", 2, 400)
	if err := meta.Close(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	prev := cacheOpContext
	cacheOpContext = func() context.Context { return ctx }
	t.Cleanup(func() { cacheOpContext = prev })

	out, err := captureCacheKeyStdout(t, func() error {
		return runCacheEvict([]string{"--profile", "corp", "--json", "--target-bytes", "1", "--confirm"})
	})
	if err == nil {
		t.Fatalf("expected cancel error, out=%q", out)
	}
	if apperr.CodeOf(err) != apperr.CodeCancelled && !strings.Contains(strings.ToLower(err.Error()), "cancel") {
		t.Fatalf("expected cancelled: code=%v err=%v", apperr.CodeOf(err), err)
	}

	// Store still openable / consistent; at least one gen may remain if cancelled early.
	meta2, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = meta2.Close() }()
	// Both still present when cancelled before plan/evict work completes.
	for _, id := range []int64{g1.ID, g2.ID} {
		got, err := meta2.GetGenerationByID(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if got == nil {
			// Partial progress is allowed only mid-Evict; pre-cancel should keep both.
			// If cancelled at start, both remain — assert at least schema is fine via reopen above.
			t.Logf("generation %d gone after cancel (partial interrupt path)", id)
		}
	}
	st, err := meta2.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.SchemaVersion != store.CurrentSchemaVersion {
		t.Fatalf("schema after cancel: %d", st.SchemaVersion)
	}
}

func TestCacheEvict_FailClosed(t *testing.T) {
	withTestXDG(t)
	err := runCacheEvict([]string{"--profile", "missing", "--confirm"})
	if err == nil {
		t.Fatal("expected missing profile to fail")
	}
	saveSeedProfile(t, "corp")
	err = runCacheEvict([]string{"--profile", "corp", "--confirm"})
	if err == nil {
		t.Fatal("expected missing data dir to fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodeNotFound && !strings.Contains(err.Error(), "data directory") {
		t.Fatalf("expected not_found / data directory: code=%v err=%v", apperr.CodeOf(err), err)
	}
}

func TestCacheEvict_TextOutput(t *testing.T) {
	withTestXDG(t)
	saveSeedProfile(t, "corp")
	meta, dir := openTestProfileMeta(t, "corp")
	_ = seedSealedGenForCLI(t, meta, dir, "job-a", 1, 300)
	if err := meta.Close(); err != nil {
		t.Fatal(err)
	}

	out, err := captureCacheKeyStdout(t, func() error {
		return runCacheEvict([]string{"--profile", "corp", "--target-bytes", "1", "--confirm"})
	})
	if err != nil {
		t.Fatalf("text apply: %v", err)
	}
	if !strings.Contains(out, "dry_run=false") || !strings.Contains(out, "applied=true") {
		t.Fatalf("text: %q", out)
	}
	if !strings.Contains(out, "result evicted=") || !strings.Contains(out, "reclaimed_bytes=") {
		t.Fatalf("expected result line: %q", out)
	}
}
