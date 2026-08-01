package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// ReleaseJournalFile is the interrupt-safe L1 release journal under the data dir.
const ReleaseJournalFile = "release-journal.json"

// PackVerifier confirms an L2 pack is present and readable before L1 is deleted.
// Callers inject archive.VerifyPackFile / sample OpenPack reads (store must not
// import archive — FND-004). Must never delete the pack.
type PackVerifier func(ctx context.Context, packID string, g *LogGeneration) error

// LeaseChecker reports active-reader leases (optional; *QuotaManager).
type LeaseChecker interface {
	IsLeased(generationID int64) bool
}

// ReleaseConfig configures L1 release after verified L2 pack (ARC-005 residual).
type ReleaseConfig struct {
	// Now optional clock for tests.
	Now func() time.Time
}

func (c ReleaseConfig) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}

// ReleaseResult is the outcome of ReleasePackedL1 (non-secret).
type ReleaseResult struct {
	GenerationID   int64  `json:"generation_id"`
	PackID         string `json:"pack_id,omitempty"`
	Released       bool   `json:"released"`
	Already        bool   `json:"already,omitempty"`
	ReclaimedBytes int64  `json:"reclaimed_bytes,omitempty"`
	// Skipped is a stable reason when release did not proceed (pin, lease, …).
	Skipped string `json:"skipped,omitempty"`
	// Interrupted is true when ctx cancelled mid-release; journal may remain.
	Interrupted bool `json:"interrupted,omitempty"`
}

// ReleaseManager deletes L1 frames for packed generations after dual-check
// pack verification. Crash journal ensures either L1 remains or pack is valid
// and L1 is gone — never both missing (pack is never deleted here).
type ReleaseManager struct {
	Meta     *Meta
	DataDir  string
	Verify   PackVerifier
	Leases   LeaseChecker // optional
	Config   ReleaseConfig
	journalP string
}

// NewReleaseManager builds a manager for one profile data directory.
func NewReleaseManager(meta *Meta, dataDir string, verify PackVerifier, cfg ReleaseConfig) (*ReleaseManager, error) {
	if meta == nil {
		return nil, apperr.New(apperr.CodeInvalidArgument, "meta is required")
	}
	if verify == nil {
		return nil, apperr.New(apperr.CodeInvalidArgument, "pack verifier is required")
	}
	dataDir, err := cleanDataPath(dataDir)
	if err != nil {
		return nil, err
	}
	return &ReleaseManager{
		Meta:     meta,
		DataDir:  dataDir,
		Verify:   verify,
		Config:   cfg,
		journalP: filepath.Join(dataDir, ReleaseJournalFile),
	}, nil
}

// releaseJournal is the on-disk interrupt-safe journal lite for L1 release.
type releaseJournal struct {
	StartedAt string               `json:"started_at"`
	Items     []releaseJournalItem `json:"items"`
}

type releaseJournalItem struct {
	GenerationID int64    `json:"generation_id"`
	PackID       string   `json:"pack_id"`
	Bytes        int64    `json:"bytes"`
	RelPaths     []string `json:"rel_paths,omitempty"`
	// Status: pending | meta_done | done
	// pending: L1 may still exist; meta_done: released flag+chunks cleared, files may remain.
	Status string `json:"status"`
}

// ReleasePackedL1 deletes L1 frames/chunks for a sealed, packed generation after
// pack verify. Pins and active-reader leases block release.
//
// Journal order (safe at every crash point):
//  1. Preconditions + PackVerify (pack must be OK)
//  2. Write journal pending (L1 still present)
//  3. Mark l1_released + delete chunk meta (readers fall back to L2)
//  4. Delete frame files (orphans cleaned on recover if interrupted)
//  5. Clear journal item
//
// Pack bytes are never modified. Cancel mid-way leaves journal for Recover.
func (r *ReleaseManager) ReleasePackedL1(ctx context.Context, generationID int64) (ReleaseResult, error) {
	res := ReleaseResult{GenerationID: generationID}
	if r == nil || r.Meta == nil {
		return res, apperr.New(apperr.CodeInternal, "release manager is not configured")
	}
	if err := ctx.Err(); err != nil {
		return res, apperr.Wrap(apperr.CodeCancelled, "L1 release cancelled", err)
	}
	if generationID <= 0 {
		return res, apperr.New(apperr.CodeInvalidArgument, "generation id is required")
	}

	g, err := r.Meta.GetGenerationByID(ctx, generationID)
	if err != nil {
		return res, err
	}
	if g == nil {
		return res, apperr.New(apperr.CodeNotFound, "log generation not found")
	}
	res.PackID = g.PackedPackID

	if skip, reason := r.precheck(ctx, g); skip {
		res.Skipped = reason
		if reason == "already_released" {
			res.Already = true
			res.Released = true
		}
		return res, nil
	}

	// Dual-check: pack must be present and verify/sample OK before touching L1.
	if err := r.Verify(ctx, g.PackedPackID, g); err != nil {
		return res, apperr.Wrap(apperr.CodeCorruptCache, "pack verify failed; refusing L1 release", err)
	}
	if err := ctx.Err(); err != nil {
		return res, apperr.Wrap(apperr.CodeCancelled, "L1 release cancelled", err)
	}

	usage, err := r.Meta.GenerationBytes(ctx, generationID)
	if err != nil {
		return res, err
	}
	chunks, err := r.Meta.ListChunks(ctx, generationID)
	if err != nil {
		return res, err
	}
	relPaths := make([]string, 0, len(chunks))
	for _, c := range chunks {
		if c.RelPath != "" {
			relPaths = append(relPaths, c.RelPath)
		}
	}

	item := releaseJournalItem{
		GenerationID: generationID,
		PackID:       g.PackedPackID,
		Bytes:        usage.PhysicalBytes,
		RelPaths:     relPaths,
		Status:       "pending",
	}
	if err := r.writeJournal(releaseJournal{
		StartedAt: r.Config.now().Format(time.RFC3339Nano),
		Items:     []releaseJournalItem{item},
	}); err != nil {
		return res, err
	}

	// Apply release steps with journal updates.
	applied, err := r.applyReleaseItem(ctx, &item)
	if err != nil {
		if apperr.IsCancelled(err) {
			res.Interrupted = true
			_ = r.writeJournal(releaseJournal{
				StartedAt: r.Config.now().Format(time.RFC3339Nano),
				Items:     []releaseJournalItem{item},
			})
			return res, err
		}
		// Leave journal for recover; return error.
		_ = r.writeJournal(releaseJournal{
			StartedAt: r.Config.now().Format(time.RFC3339Nano),
			Items:     []releaseJournalItem{item},
		})
		return res, err
	}
	_ = r.clearJournal()
	res.Released = applied
	res.ReclaimedBytes = item.Bytes
	return res, nil
}

// RecoverReleaseJournal finishes incomplete L1 releases after crash/interrupt.
// Re-verifies pack before deleting remaining L1; never deletes packs.
func (r *ReleaseManager) RecoverReleaseJournal(ctx context.Context) (ReleaseResult, error) {
	res := ReleaseResult{}
	if r == nil || r.Meta == nil {
		return res, apperr.New(apperr.CodeInternal, "release manager is not configured")
	}
	j, err := r.readJournal()
	if err != nil {
		return res, err
	}
	if j == nil || len(j.Items) == 0 {
		_ = r.clearJournal()
		return res, nil
	}
	var last ReleaseResult
	for i := range j.Items {
		if err := ctx.Err(); err != nil {
			_ = r.writeJournal(*j)
			return last, apperr.Wrap(apperr.CodeCancelled, "L1 release recover cancelled", err)
		}
		item := &j.Items[i]
		if item.Status == "done" {
			continue
		}
		// Re-verify pack before continuing (never both missing).
		g, gerr := r.Meta.GetGenerationByID(ctx, item.GenerationID)
		if gerr != nil {
			return last, gerr
		}
		packID := item.PackID
		if g != nil && g.PackedPackID != "" {
			packID = g.PackedPackID
		}
		if packID == "" {
			// Cannot safely release without pack id — leave L1 if still present, clear item.
			item.Status = "done"
			continue
		}
		if g == nil {
			// Generation gone (evicted): just clean leftover frame paths from journal.
			r.deleteFramePaths(item.RelPaths)
			item.Status = "done"
			continue
		}
		// Pin/lease on pending: abort without deleting L1 (clear journal item).
		// meta_done: L1 already logically released — finish file purge despite pin.
		if item.Status == "pending" {
			if pinned, _ := r.Meta.IsPinned(ctx, PinKindGeneration, strconv.FormatInt(item.GenerationID, 10)); pinned {
				item.Status = "done"
				last.Skipped = "pinned"
				continue
			}
			if r.Leases != nil && r.Leases.IsLeased(item.GenerationID) {
				item.Status = "done"
				last.Skipped = "leased"
				continue
			}
		}
		if err := r.Verify(ctx, packID, g); err != nil {
			// Pack bad: do not delete remaining L1; clear journal item to avoid loop.
			item.Status = "done"
			last.Skipped = "pack_verify_failed"
			continue
		}
		if _, err := r.applyReleaseItem(ctx, item); err != nil {
			_ = r.writeJournal(*j)
			return last, err
		}
		last.GenerationID = item.GenerationID
		last.PackID = packID
		last.Released = true
		last.ReclaimedBytes += item.Bytes
		_ = r.writeJournal(*j)
	}
	_ = r.clearJournal()
	return last, nil
}

// ListReleaseCandidates returns sealed packed gens eligible for L1 release.
// Callers filter by age / pressure; this only applies pin/lease/state gates.
func (r *ReleaseManager) ListReleaseCandidates(ctx context.Context) ([]LogGeneration, error) {
	if r == nil || r.Meta == nil {
		return nil, apperr.New(apperr.CodeInternal, "release manager is not configured")
	}
	gens, err := r.Meta.ListGenerations(ctx)
	if err != nil {
		return nil, err
	}
	var out []LogGeneration
	for _, g := range gens {
		if skip, _ := r.precheck(ctx, &g); skip {
			continue
		}
		out = append(out, g)
	}
	return out, nil
}

func (r *ReleaseManager) precheck(ctx context.Context, g *LogGeneration) (skip bool, reason string) {
	if g == nil {
		return true, "not_found"
	}
	if !g.Sealed {
		return true, "unsealed"
	}
	if g.L1Released {
		return true, "already_released"
	}
	if strings.TrimSpace(g.PackedPackID) == "" {
		return true, "not_packed"
	}
	idStr := strconv.FormatInt(g.ID, 10)
	if pinned, _ := r.Meta.IsPinned(ctx, PinKindGeneration, idStr); pinned {
		return true, "pinned"
	}
	if r.Leases != nil && r.Leases.IsLeased(g.ID) {
		return true, "leased"
	}
	return false, ""
}

// applyReleaseItem advances one journal item toward done. Updates item.Status.
func (r *ReleaseManager) applyReleaseItem(ctx context.Context, item *releaseJournalItem) (bool, error) {
	if item == nil {
		return false, apperr.New(apperr.CodeInternal, "release item is nil")
	}
	if item.Status == "done" {
		return true, nil
	}

	// Re-check pin/lease before destructive steps.
	if pinned, _ := r.Meta.IsPinned(ctx, PinKindGeneration, strconv.FormatInt(item.GenerationID, 10)); pinned {
		return false, apperr.New(apperr.CodePolicyDenial, "generation is pinned")
	}
	if r.Leases != nil && r.Leases.IsLeased(item.GenerationID) {
		return false, apperr.New(apperr.CodePolicyDenial, "generation is leased")
	}

	if item.Status == "pending" {
		if err := ctx.Err(); err != nil {
			return false, apperr.Wrap(apperr.CodeCancelled, "L1 release cancelled", err)
		}
		// Mark released + drop chunk meta first so readers use L2 immediately.
		// L1 files may still exist until the next step (orphans cleaned by recover).
		g, err := r.Meta.GetGenerationByID(ctx, item.GenerationID)
		if err != nil {
			return false, err
		}
		if g == nil {
			// Already gone; clean files and done.
			r.deleteFramePaths(item.RelPaths)
			item.Status = "done"
			return true, nil
		}
		if !g.L1Released {
			if err := r.Meta.MarkGenerationL1Released(ctx, item.GenerationID); err != nil {
				return false, err
			}
		}
		if err := r.Meta.DeleteChunksForGeneration(ctx, item.GenerationID); err != nil {
			return false, err
		}
		item.Status = "meta_done"
	}

	if item.Status == "meta_done" {
		if err := ctx.Err(); err != nil {
			return false, apperr.Wrap(apperr.CodeCancelled, "L1 release cancelled", err)
		}
		// Prefer paths from journal; also remove generation frames dir.
		paths := item.RelPaths
		if len(paths) == 0 {
			// Best-effort: remove whole frames/<id>/ tree.
			_ = os.RemoveAll(filepath.Join(r.DataDir, FramesDirName, strconv.FormatInt(item.GenerationID, 10)))
		} else {
			r.deleteFramePaths(paths)
			_ = os.Remove(filepath.Join(r.DataDir, FramesDirName, strconv.FormatInt(item.GenerationID, 10)))
		}
		item.Status = "done"
	}
	return true, nil
}

func (r *ReleaseManager) deleteFramePaths(relPaths []string) {
	for _, rel := range relPaths {
		abs, err := FrameAbsPath(r.DataDir, rel)
		if err != nil {
			continue
		}
		_ = os.Remove(abs)
	}
}

func (r *ReleaseManager) writeJournal(j releaseJournal) error {
	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to marshal release journal", err)
	}
	tmp := r.journalP + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to write release journal", err)
	}
	if err := os.Rename(tmp, r.journalP); err != nil {
		_ = os.Remove(tmp)
		return apperr.Wrap(apperr.CodeInternal, "failed to publish release journal", err)
	}
	return nil
}

func (r *ReleaseManager) readJournal() (*releaseJournal, error) {
	data, err := os.ReadFile(r.journalP)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, apperr.Wrap(apperr.CodeInternal, "failed to read release journal", err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	var j releaseJournal
	if err := json.Unmarshal(data, &j); err != nil {
		// Corrupt journal: remove; L1/pack state is independently consistent.
		_ = r.clearJournal()
		return nil, nil
	}
	return &j, nil
}

func (r *ReleaseManager) clearJournal() error {
	if err := os.Remove(r.journalP); err != nil && !os.IsNotExist(err) {
		return apperr.Wrap(apperr.CodeInternal, "failed to clear release journal", err)
	}
	_ = os.Remove(r.journalP + ".tmp")
	return nil
}

// FormatReleaseSummary is a short non-secret operator line.
func FormatReleaseSummary(res ReleaseResult) string {
	if res.Skipped != "" {
		return fmt.Sprintf("release skipped=%s gen=%d pack=%s", res.Skipped, res.GenerationID, res.PackID)
	}
	return fmt.Sprintf("release gen=%d pack=%s released=%v reclaim=%d",
		res.GenerationID, res.PackID, res.Released, res.ReclaimedBytes)
}
