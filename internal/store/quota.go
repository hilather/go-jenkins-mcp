package store

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// DefaultTotalQuotaBytes is the default per-profile total physical cache budget (10 GiB).
const DefaultTotalQuotaBytes int64 = 10 << 30

// DefaultLowDiskBytes is the free-space threshold that triggers eviction planning (1 GiB).
// When DiskFree is unset, low-disk checks are skipped.
const DefaultLowDiskBytes int64 = 1 << 30

// ArchivesDirName is the L2 pack directory under a profile data dir.
const ArchivesDirName = "archives"

// EvictJournalFile is the interrupt-safe eviction journal under the data dir.
const EvictJournalFile = "evict-journal.json"

// QuotaConfig bounds cache disk use (ARC-007 MVP).
type QuotaConfig struct {
	// TotalQuotaBytes is the max physical L1+L2 bytes for the profile (0 ⇒ DefaultTotalQuotaBytes).
	TotalQuotaBytes int64
	// LowDiskBytes triggers planning when free space on the volume falls below this
	// (0 ⇒ DefaultLowDiskBytes). Ignored when DiskFree is nil.
	LowDiskBytes int64
	// SuccessRetention is max age for sealed generations with outcome=success or unknown.
	// Zero disables age-based selection (quota/low-disk only).
	SuccessRetention time.Duration
	// FailedRetention is max age for sealed generations with outcome=failed.
	// Zero disables age-based selection for failed builds.
	FailedRetention time.Duration
	// DiskFree optionally reports free bytes for dataDir's volume. Nil skips low-disk.
	DiskFree func(dataDir string) (freeBytes int64, err error)
	// Now is optional clock for tests.
	Now func() time.Time
}

// EffectiveTotalQuota returns the configured or default total quota.
func (c QuotaConfig) EffectiveTotalQuota() int64 {
	if c.TotalQuotaBytes > 0 {
		return c.TotalQuotaBytes
	}
	return DefaultTotalQuotaBytes
}

// EffectiveLowDisk returns the configured or default low-disk threshold.
func (c QuotaConfig) EffectiveLowDisk() int64 {
	if c.LowDiskBytes > 0 {
		return c.LowDiskBytes
	}
	return DefaultLowDiskBytes
}

func (c QuotaConfig) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}

// UsageStats is a non-secret physical/logical byte summary by tier (ARC-007).
type UsageStats struct {
	Profile            string `json:"profile,omitempty"`
	L1PhysicalBytes    int64  `json:"l1_physical_bytes"`
	L1LogicalBytes     int64  `json:"l1_logical_bytes"`
	L2PhysicalBytes    int64  `json:"l2_physical_bytes"`
	L2LogicalBytes     int64  `json:"l2_logical_bytes"`
	TotalPhysicalBytes int64  `json:"total_physical_bytes"`
	Generations        int64  `json:"generations"`
	Packs              int64  `json:"packs"`
	QuotaBytes         int64  `json:"quota_bytes"`
	OverQuota          bool   `json:"over_quota"`
	FreeBytes          int64  `json:"free_bytes,omitempty"`
	LowDisk            bool   `json:"low_disk,omitempty"`
}

// PackDiskInfo is one on-disk L2 pack under archives/.
type PackDiskInfo struct {
	PackID    string
	SizeBytes int64
	ModTime   time.Time
	Path      string
}

// EvictCandidate is one object selected for reclaim (dry-run / apply).
type EvictCandidate struct {
	// Tier is "l1" or "l2".
	Tier string `json:"tier"`
	// ID is generation id (decimal) or pack id.
	ID string `json:"id"`
	// Reason explains selection (quota, retention, low_disk).
	Reason string `json:"reason"`
	// ReclaimBytes is estimated physical reclaim.
	ReclaimBytes int64 `json:"reclaim_bytes"`
	// Protected is true when the candidate would be skipped (pin/lease/unsealed).
	// Plan only includes non-protected candidates; used in diagnostics.
	Protected bool `json:"protected,omitempty"`
	// Age is approximate age of the object.
	Age string `json:"age,omitempty"`
}

// EvictPlan is a dry-run eviction plan with reclaim estimates (ARC-007).
type EvictPlan struct {
	Usage             UsageStats       `json:"usage"`
	BytesNeeded       int64            `json:"bytes_needed"`
	Candidates        []EvictCandidate `json:"candidates"`
	TotalReclaimBytes int64            `json:"total_reclaim_bytes"`
	// DryRun is always true for Plan results; Evict sets Applied.
	DryRun  bool `json:"dry_run"`
	Applied bool `json:"applied,omitempty"`
}

// EvictResult is the outcome of applying a plan.
type EvictResult struct {
	Plan              EvictPlan `json:"plan"`
	Evicted           int       `json:"evicted"`
	Failed            int       `json:"failed"`
	ReclaimedBytes    int64     `json:"reclaimed_bytes"`
	Interrupted       bool      `json:"interrupted,omitempty"`
	Errors            []string  `json:"errors,omitempty"`
	JournalConsistent bool      `json:"journal_consistent"`
}

// QuotaManager tracks usage, pins/leases, and deterministic eviction (ARC-007).
//
// Eviction order: oldest sealed unpinned L1 first, then unpinned L2 packs
// (oldest mtime / least recently used). Never deletes unsealed/running
// generations, pinned objects, or leased generations.
type QuotaManager struct {
	Meta        *Meta
	DataDir     string
	Config      QuotaConfig
	leasesMu    sync.Mutex
	leases      map[int64]time.Time // generation id → lease until
	journalPath string
}

// NewQuotaManager constructs a manager for a profile data directory.
func NewQuotaManager(meta *Meta, dataDir string, cfg QuotaConfig) (*QuotaManager, error) {
	if meta == nil {
		return nil, apperr.New(apperr.CodeInvalidArgument, "meta is required")
	}
	dataDir, err := cleanDataPath(dataDir)
	if err != nil {
		return nil, err
	}
	return &QuotaManager{
		Meta:        meta,
		DataDir:     dataDir,
		Config:      cfg,
		leases:      make(map[int64]time.Time),
		journalPath: filepath.Join(dataDir, EvictJournalFile),
	}, nil
}

// ArchiveRoot returns the L2 archives directory path.
func (q *QuotaManager) ArchiveRoot() string {
	if q == nil {
		return ""
	}
	return filepath.Join(q.DataDir, ArchivesDirName)
}

// LeaseGeneration holds an active-reader lease until expiry (in-memory only).
// Not expired ⇒ not evicted. Zero until uses a short default (5 minutes).
func (q *QuotaManager) LeaseGeneration(generationID int64, until time.Time) error {
	if q == nil {
		return apperr.New(apperr.CodeInternal, "quota manager is nil")
	}
	if generationID <= 0 {
		return apperr.New(apperr.CodeInvalidArgument, "generation id is required")
	}
	if until.IsZero() {
		until = q.Config.now().Add(5 * time.Minute)
	}
	q.leasesMu.Lock()
	defer q.leasesMu.Unlock()
	if q.leases == nil {
		q.leases = make(map[int64]time.Time)
	}
	q.leases[generationID] = until.UTC()
	return nil
}

// ReleaseLease drops an active-reader lease.
func (q *QuotaManager) ReleaseLease(generationID int64) {
	if q == nil {
		return
	}
	q.leasesMu.Lock()
	defer q.leasesMu.Unlock()
	delete(q.leases, generationID)
}

// IsLeased reports whether generationID has a non-expired lease.
func (q *QuotaManager) IsLeased(generationID int64) bool {
	if q == nil {
		return false
	}
	q.leasesMu.Lock()
	defer q.leasesMu.Unlock()
	until, ok := q.leases[generationID]
	if !ok {
		return false
	}
	if q.Config.now().After(until) {
		delete(q.leases, generationID)
		return false
	}
	return true
}

// Usage computes physical/logical L1 (meta) + L2 (archive dir sizes).
func (q *QuotaManager) Usage(ctx context.Context) (UsageStats, error) {
	if err := ctx.Err(); err != nil {
		return UsageStats{}, apperr.Wrap(apperr.CodeCancelled, "usage cancelled", err)
	}
	if q == nil || q.Meta == nil {
		return UsageStats{}, apperr.New(apperr.CodeInternal, "quota manager is closed")
	}
	st, err := q.Meta.Stats(ctx)
	if err != nil {
		return UsageStats{}, err
	}
	l1p, l1l, err := q.Meta.SumL1Bytes(ctx)
	if err != nil {
		return UsageStats{}, err
	}
	packs, err := ListArchivePacks(q.ArchiveRoot())
	if err != nil {
		return UsageStats{}, err
	}
	var l2p, l2l int64
	for _, p := range packs {
		l2p += p.SizeBytes
		// Logical ≈ physical when no index; index logical residual ARC-008.
		l2l += p.SizeBytes
	}
	u := UsageStats{
		L1PhysicalBytes:    l1p,
		L1LogicalBytes:     l1l,
		L2PhysicalBytes:    l2p,
		L2LogicalBytes:     l2l,
		TotalPhysicalBytes: l1p + l2p,
		Generations:        st.Generations,
		Packs:              int64(len(packs)),
		QuotaBytes:         q.Config.EffectiveTotalQuota(),
	}
	u.OverQuota = u.TotalPhysicalBytes > u.QuotaBytes
	if q.Config.DiskFree != nil {
		free, ferr := q.Config.DiskFree(q.DataDir)
		if ferr == nil {
			u.FreeBytes = free
			u.LowDisk = free < q.Config.EffectiveLowDisk()
		}
	}
	return u, nil
}

// NeedsEviction reports whether quota or low-disk thresholds are exceeded.
func (q *QuotaManager) NeedsEviction(ctx context.Context) (bool, UsageStats, error) {
	u, err := q.Usage(ctx)
	if err != nil {
		return false, u, err
	}
	return u.OverQuota || u.LowDisk, u, nil
}

// PlanEviction builds a deterministic dry-run plan. Does not delete anything.
// targetBytes is additional bytes to free beyond bringing usage under quota;
// when 0, plans enough to reach TotalQuotaBytes (and clear low-disk if set).
func (q *QuotaManager) PlanEviction(ctx context.Context, targetBytes int64) (EvictPlan, error) {
	if err := ctx.Err(); err != nil {
		return EvictPlan{}, apperr.Wrap(apperr.CodeCancelled, "plan cancelled", err)
	}
	u, err := q.Usage(ctx)
	if err != nil {
		return EvictPlan{}, err
	}
	quota := u.QuotaBytes
	needed := targetBytes
	if u.TotalPhysicalBytes > quota {
		over := u.TotalPhysicalBytes - quota
		if over > needed {
			needed = over
		}
	}
	if u.LowDisk && q.Config.DiskFree != nil {
		// Free enough to clear low-disk threshold (best-effort estimate).
		gap := q.Config.EffectiveLowDisk() - u.FreeBytes
		if gap > needed {
			needed = gap
		}
	}
	// Age-based: still plan candidates even when under quota if retention is set
	// and objects are past age — but only when needed==0 we may still free retention.
	plan := EvictPlan{
		Usage:       u,
		BytesNeeded: needed,
		DryRun:      true,
	}

	pins, err := q.Meta.pinnedSet(ctx)
	if err != nil {
		return plan, err
	}
	gens, err := q.Meta.ListGenerations(ctx)
	if err != nil {
		return plan, err
	}
	now := q.Config.now()

	// Phase 1: oldest sealed unpinned L1 first.
	// Over quota / low-disk: any sealed unpinned/unleased.
	// Under quota: only retention-expired sealed gens.
	overBudget := needed > 0
	for _, g := range gens {
		if err := ctx.Err(); err != nil {
			return plan, apperr.Wrap(apperr.CodeCancelled, "plan cancelled", err)
		}
		if !g.Sealed {
			continue // never running/unsealed
		}
		if g.L1Released {
			// L1 frames already reclaimed; pack eviction is phase 2.
			continue
		}
		idStr := strconv.FormatInt(g.ID, 10)
		if _, ok := pins[pinKey(PinKindGeneration, idStr)]; ok {
			continue
		}
		if q.IsLeased(g.ID) {
			continue
		}
		expired := q.retentionExpired(g, now)
		if !overBudget && !expired {
			continue
		}
		usage, err := q.Meta.GenerationBytes(ctx, g.ID)
		if err != nil {
			return plan, err
		}
		c := EvictCandidate{
			Tier:         "l1",
			ID:           idStr,
			Reason:       q.candidateReason(g, now, overBudget),
			ReclaimBytes: usage.PhysicalBytes,
			Age:          ageString(now.Sub(g.UpdatedAt)),
		}
		plan.Candidates = append(plan.Candidates, c)
		plan.TotalReclaimBytes += c.ReclaimBytes
		if overBudget && plan.TotalReclaimBytes >= needed {
			return plan, nil
		}
	}

	// Phase 2: unpinned L2 packs, oldest mtime first (not recently used).
	packs, err := ListArchivePacks(q.ArchiveRoot())
	if err != nil {
		return plan, err
	}
	// Already oldest-first from ListArchivePacks.
	for _, p := range packs {
		if err := ctx.Err(); err != nil {
			return plan, apperr.Wrap(apperr.CodeCancelled, "plan cancelled", err)
		}
		if _, ok := pins[pinKey(PinKindPack, p.PackID)]; ok {
			continue
		}
		// Age retention for packs: use SuccessRetention as default pack age when set.
		if q.Config.SuccessRetention > 0 && needed <= 0 {
			if now.Sub(p.ModTime) < q.Config.SuccessRetention {
				continue
			}
		}
		c := EvictCandidate{
			Tier:         "l2",
			ID:           p.PackID,
			Reason:       "l2_lru_or_quota",
			ReclaimBytes: p.SizeBytes,
			Age:          ageString(now.Sub(p.ModTime)),
		}
		if needed > 0 {
			c.Reason = "quota_or_low_disk"
		} else if q.Config.SuccessRetention > 0 {
			c.Reason = "retention_age"
		}
		plan.Candidates = append(plan.Candidates, c)
		plan.TotalReclaimBytes += c.ReclaimBytes
		if needed > 0 && plan.TotalReclaimBytes >= needed {
			break
		}
	}
	return plan, nil
}

func (q *QuotaManager) retentionExpired(g LogGeneration, now time.Time) bool {
	var maxAge time.Duration
	switch g.Outcome {
	case OutcomeFailed:
		maxAge = q.Config.FailedRetention
	default:
		maxAge = q.Config.SuccessRetention
	}
	if maxAge <= 0 {
		return false
	}
	if g.UpdatedAt.IsZero() {
		return true
	}
	return now.Sub(g.UpdatedAt) >= maxAge
}

func (q *QuotaManager) candidateReason(g LogGeneration, now time.Time, overQuota bool) string {
	if overQuota {
		if q.retentionExpired(g, now) {
			return "quota_and_retention"
		}
		return "quota"
	}
	if g.Outcome == OutcomeFailed {
		return "failed_retention"
	}
	return "success_retention"
}

func ageString(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < time.Minute {
		return d.Round(time.Second).String()
	}
	if d < time.Hour {
		return d.Round(time.Minute).String()
	}
	return d.Round(time.Hour).String()
}

// evictJournal is the on-disk interrupt-safe journal lite.
type evictJournal struct {
	StartedAt string             `json:"started_at"`
	Items     []evictJournalItem `json:"items"`
}

type evictJournalItem struct {
	Tier   string `json:"tier"`
	ID     string `json:"id"`
	Bytes  int64  `json:"bytes"`
	Status string `json:"status"` // pending | done
}

// Evict applies plan with interrupt-safe journal lite. Safe to cancel mid-way:
// metadata remains consistent (meta deleted before/with files; Recover cleans orphans).
// Pass a plan from PlanEviction (or any candidate list). Does not re-check pins
// unless recheck is true.
func (q *QuotaManager) Evict(ctx context.Context, plan EvictPlan) (EvictResult, error) {
	res := EvictResult{Plan: plan, JournalConsistent: true}
	if q == nil || q.Meta == nil {
		return res, apperr.New(apperr.CodeInternal, "quota manager is closed")
	}
	if len(plan.Candidates) == 0 {
		return res, nil
	}

	// Build journal with all pending items.
	j := evictJournal{
		StartedAt: q.Config.now().Format(time.RFC3339Nano),
	}
	for _, c := range plan.Candidates {
		if c.Protected || c.Tier == "" || c.ID == "" {
			continue
		}
		j.Items = append(j.Items, evictJournalItem{
			Tier: c.Tier, ID: c.ID, Bytes: c.ReclaimBytes, Status: "pending",
		})
	}
	if err := q.writeJournal(j); err != nil {
		return res, err
	}
	defer func() {
		// Leave journal only if incomplete (interrupt); clear when fully done.
		if res.Interrupted || res.Failed > 0 {
			return
		}
		_ = q.clearJournal()
	}()

	for i := range j.Items {
		if err := ctx.Err(); err != nil {
			res.Interrupted = true
			// Rewrite journal with progress so resume/recover sees consistent state.
			_ = q.writeJournal(j)
			return res, apperr.Wrap(apperr.CodeCancelled, "eviction cancelled", err)
		}
		item := &j.Items[i]
		if item.Status == "done" {
			continue
		}
		var err error
		switch item.Tier {
		case "l1":
			err = q.evictL1(ctx, item.ID)
		case "l2":
			err = q.evictL2(ctx, item.ID)
		default:
			err = apperr.New(apperr.CodeInvalidArgument, "unknown eviction tier")
		}
		if err != nil {
			res.Failed++
			res.Errors = append(res.Errors, fmt.Sprintf("%s:%s: %s", item.Tier, item.ID, apperr.ModelMessage(err)))
			// Keep pending; metadata may already be consistent for partial step.
			_ = q.writeJournal(j)
			continue
		}
		item.Status = "done"
		res.Evicted++
		res.ReclaimedBytes += item.Bytes
		_ = q.writeJournal(j)
	}
	res.Plan.Applied = true
	res.Plan.DryRun = false
	return res, nil
}

// RecoverEvictJournal completes or cleans a leftover journal (startup / after interrupt).
// Leaves metadata consistent; does not invent new candidates.
func (q *QuotaManager) RecoverEvictJournal(ctx context.Context) (EvictResult, error) {
	res := EvictResult{JournalConsistent: true}
	j, err := q.readJournal()
	if err != nil {
		return res, err
	}
	if j == nil || len(j.Items) == 0 {
		_ = q.clearJournal()
		return res, nil
	}
	plan := EvictPlan{DryRun: false}
	for _, it := range j.Items {
		if it.Status == "done" {
			continue
		}
		plan.Candidates = append(plan.Candidates, EvictCandidate{
			Tier: it.Tier, ID: it.ID, ReclaimBytes: it.Bytes, Reason: "journal_resume",
		})
	}
	if len(plan.Candidates) == 0 {
		_ = q.clearJournal()
		return res, nil
	}
	return q.Evict(ctx, plan)
}

func (q *QuotaManager) evictL1(ctx context.Context, idStr string) error {
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		return apperr.New(apperr.CodeInvalidArgument, "invalid generation id")
	}
	// Re-check protections.
	if pinned, _ := q.Meta.IsPinned(ctx, PinKindGeneration, idStr); pinned {
		return apperr.New(apperr.CodePolicyDenial, "generation is pinned")
	}
	if q.IsLeased(id) {
		return apperr.New(apperr.CodePolicyDenial, "generation is leased")
	}
	g, err := q.Meta.GetGenerationByID(ctx, id)
	if err != nil {
		return err
	}
	if g == nil {
		// Already gone — consistent.
		return nil
	}
	if !g.Sealed {
		return apperr.New(apperr.CodeInvalidArgument, "cannot evict unsealed generation")
	}
	// List chunk paths before meta delete.
	chunks, err := q.Meta.ListChunks(ctx, id)
	if err != nil {
		return err
	}
	// Journal-lite: delete metadata first (CASCADE chunks) so readers never see
	// partial state; then remove frame files. Orphans cleaned by Recover.
	if err := q.Meta.DeleteGeneration(ctx, id); err != nil {
		return err
	}
	for _, c := range chunks {
		abs, err := FrameAbsPath(q.DataDir, c.RelPath)
		if err != nil {
			continue
		}
		_ = os.Remove(abs)
	}
	// Remove empty generation frames dir.
	_ = os.Remove(filepath.Join(q.DataDir, FramesDirName, strconv.FormatInt(id, 10)))
	return nil
}

func (q *QuotaManager) evictL2(ctx context.Context, packID string) error {
	packID = strings.TrimSpace(packID)
	if packID == "" {
		return apperr.New(apperr.CodeInvalidArgument, "pack_id is required")
	}
	if pinned, _ := q.Meta.IsPinned(ctx, PinKindPack, packID); pinned {
		return apperr.New(apperr.CodePolicyDenial, "pack is pinned")
	}
	// Clear meta refs first so catalog does not point at a deleted pack mid-way
	// in a way that looks trusted; then delete files.
	if err := q.Meta.ClearPackedPackID(ctx, packID); err != nil {
		return err
	}
	root := q.ArchiveRoot()
	packPath := filepath.Join(root, packID+".tar.zst")
	idxPath := filepath.Join(root, packID+".idx.json")
	_ = os.Remove(packPath)
	_ = os.Remove(idxPath)
	// Pin cleanup.
	_ = q.Meta.Unpin(ctx, PinKindPack, packID)
	return nil
}

func (q *QuotaManager) writeJournal(j evictJournal) error {
	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to marshal evict journal", err)
	}
	tmp := q.journalPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to write evict journal", err)
	}
	if err := os.Rename(tmp, q.journalPath); err != nil {
		_ = os.Remove(tmp)
		return apperr.Wrap(apperr.CodeInternal, "failed to publish evict journal", err)
	}
	return nil
}

func (q *QuotaManager) readJournal() (*evictJournal, error) {
	data, err := os.ReadFile(q.journalPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, apperr.Wrap(apperr.CodeInternal, "failed to read evict journal", err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	var j evictJournal
	if err := json.Unmarshal(data, &j); err != nil {
		// Corrupt journal: remove to restore consistency (no in-flight deletes).
		_ = q.clearJournal()
		return nil, nil
	}
	return &j, nil
}

func (q *QuotaManager) clearJournal() error {
	if err := os.Remove(q.journalPath); err != nil && !os.IsNotExist(err) {
		return apperr.Wrap(apperr.CodeInternal, "failed to clear evict journal", err)
	}
	_ = os.Remove(q.journalPath + ".tmp")
	return nil
}

// ListArchivePacks lists *.tar.zst packs under archiveRoot (oldest mtime first).
func ListArchivePacks(archiveRoot string) ([]PackDiskInfo, error) {
	archiveRoot = filepath.Clean(strings.TrimSpace(archiveRoot))
	if archiveRoot == "" || archiveRoot == "." {
		return nil, nil
	}
	entries, err := os.ReadDir(archiveRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, apperr.Wrap(apperr.CodeInternal, "failed to list archive packs", err)
	}
	var out []PackDiskInfo
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".tar.zst") {
			continue
		}
		packID := strings.TrimSuffix(name, ".tar.zst")
		if packID == "" || strings.Contains(packID, "..") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, PackDiskInfo{
			PackID:    packID,
			SizeBytes: fi.Size(),
			ModTime:   fi.ModTime().UTC(),
			Path:      filepath.Join(archiveRoot, name),
		})
	}
	// Sort oldest first (stable deterministic).
	sortPacksOldestFirst(out)
	return out, nil
}

func sortPacksOldestFirst(packs []PackDiskInfo) {
	// Small N; insertion-style for zero deps.
	for i := 1; i < len(packs); i++ {
		j := i
		for j > 0 {
			a, b := packs[j-1], packs[j]
			if a.ModTime.Before(b.ModTime) || (a.ModTime.Equal(b.ModTime) && a.PackID <= b.PackID) {
				break
			}
			packs[j-1], packs[j] = packs[j], packs[j-1]
			j--
		}
	}
}

// DirPhysicalSize walks path and returns total file bytes (non-secret).
func DirPhysicalSize(root string) (int64, error) {
	var total int64
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsNotExist(walkErr) {
				return nil
			}
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		total += fi.Size()
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return total, apperr.Wrap(apperr.CodeInternal, "failed to measure directory size", err)
	}
	return total, nil
}
