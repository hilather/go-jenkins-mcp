package diagnostics

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/archive"
	"github.com/simonfxr/go-jenkins-mcp/internal/config"
	"github.com/simonfxr/go-jenkins-mcp/internal/profile"
	"github.com/simonfxr/go-jenkins-mcp/internal/redact"
	"github.com/simonfxr/go-jenkins-mcp/internal/store"
)

// DefaultVerifySample is the default number of packs sampled when --full is not set.
const DefaultVerifySample = 3

// CacheVerifyOptions configures cache verify (ARC-008).
type CacheVerifyOptions struct {
	Profile *profile.Profile
	Paths   *config.Paths
	// Full verifies every pack under archives/ (cancellable).
	Full bool
	// Sample limits packs when !Full (0 ⇒ DefaultVerifySample).
	Sample int
	// Quarantine moves corrupt packs when true (default false for verify CLI).
	Quarantine bool
}

// CacheVerifyReport is a support-safe integrity report (no secrets, no paths with tokens).
type CacheVerifyReport struct {
	ProfileID    string `json:"profileId"`
	Mode         string `json:"mode"` // full | sample
	PacksTotal   int    `json:"packs_total"`
	PacksChecked int    `json:"packs_checked"`
	PackOK       int    `json:"pack_ok"`
	PackFail     int    `json:"pack_fail"`
	// Issue counts by kind: pack | entry | checksum | catalog | index
	IssueCounts map[string]int      `json:"issue_counts"`
	Results     []PackVerifySummary `json:"results,omitempty"`
	Cancelled   bool                `json:"cancelled,omitempty"`
	Message     string              `json:"message,omitempty"`
}

// PackVerifySummary is one pack's verify outcome (support-safe).
type PackVerifySummary struct {
	PackID        string                `json:"pack_id"`
	PackOK        bool                  `json:"pack_ok"`
	IndexOK       bool                  `json:"index_ok"`
	IndexTrusted  bool                  `json:"index_trusted"`
	RebuildNeeded bool                  `json:"rebuild_needed"`
	Quarantined   bool                  `json:"quarantined,omitempty"`
	SizeBytes     int64                 `json:"size_bytes"`
	Issues        []archive.VerifyIssue `json:"issues,omitempty"`
	Error         string                `json:"error,omitempty"`
}

// CacheRepairOptions configures cache repair (ARC-008).
type CacheRepairOptions struct {
	Profile *profile.Profile
	Paths   *config.Paths
	// IndexOnly rebuilds sidecar indexes only (never mutates pack bytes).
	IndexOnly bool
}

// CacheRepairReport is a support-safe repair summary.
type CacheRepairReport struct {
	ProfileID      string   `json:"profileId"`
	IndexOnly      bool     `json:"index_only"`
	PacksSeen      int      `json:"packs_seen"`
	IndexesRebuilt int      `json:"indexes_rebuilt"`
	Skipped        int      `json:"skipped"`
	Failed         int      `json:"failed"`
	Messages       []string `json:"messages,omitempty"`
	Cancelled      bool     `json:"cancelled,omitempty"`
}

// RunCacheVerify verifies L2 packs under the profile archives dir (ARC-008).
// Results are safe for support sharing (no secrets; pack ids and issue kinds only).
func RunCacheVerify(ctx context.Context, opts CacheVerifyOptions) (CacheVerifyReport, error) {
	if opts.Profile == nil {
		return CacheVerifyReport{}, apperr.New(apperr.CodeInvalidArgument, "profile is required")
	}
	rep := CacheVerifyReport{
		ProfileID:   string(opts.Profile.ID),
		IssueCounts: map[string]int{},
	}
	if opts.Full {
		rep.Mode = "full"
	} else {
		rep.Mode = "sample"
	}

	dataDir, archiveRoot, err := resolveArchiveRoot(opts.Profile, opts.Paths)
	if err != nil {
		rep.Message = apperr.ModelMessage(err)
		return rep, nil
	}
	_ = dataDir

	packs, err := store.ListArchivePacks(archiveRoot)
	if err != nil {
		rep.Message = apperr.ModelMessage(err)
		return rep, nil
	}
	rep.PacksTotal = len(packs)
	if len(packs) == 0 {
		rep.Message = "no packs under archives/"
		return rep, nil
	}

	limit := len(packs)
	if !opts.Full {
		n := opts.Sample
		if n <= 0 {
			n = DefaultVerifySample
		}
		if n < limit {
			limit = n
		}
	}

	for i := 0; i < limit; i++ {
		if err := ctx.Err(); err != nil {
			rep.Cancelled = true
			rep.Message = "verify cancelled"
			return rep, apperr.Wrap(apperr.CodeCancelled, "verify cancelled", err)
		}
		p := packs[i]
		vrep, verr := archive.VerifyPackFile(ctx, p.PackID, p.Path, archiveRoot, opts.Quarantine)
		sum := PackVerifySummary{
			PackID:        p.PackID,
			PackOK:        vrep.PackOK,
			IndexOK:       vrep.IndexOK,
			IndexTrusted:  vrep.IndexTrusted,
			RebuildNeeded: vrep.RebuildNeeded,
			Quarantined:   vrep.Quarantined,
			SizeBytes:     vrep.SizeBytes,
			Issues:        sanitizeIssues(vrep.Issues),
		}
		if verr != nil {
			sum.Error = redact.Secrets(apperr.ModelMessage(verr))
			// Ensure pack-level issue recorded.
			if sum.PackOK {
				sum.PackOK = false
			}
		}
		for _, iss := range sum.Issues {
			kind := strings.TrimSpace(iss.Kind)
			if kind == "" {
				kind = "pack"
			}
			rep.IssueCounts[kind]++
		}
		if sum.PackOK {
			rep.PackOK++
		} else {
			rep.PackFail++
		}
		rep.Results = append(rep.Results, sum)
		rep.PacksChecked++
	}
	return rep, nil
}

// RunCacheRepair rebuilds sidecar indexes for packs that verify (ARC-008).
// Never overwrites pack bytes. Index-only is the MVP path; full dual-reader
// re-fetch remains residual.
func RunCacheRepair(ctx context.Context, opts CacheRepairOptions) (CacheRepairReport, error) {
	if opts.Profile == nil {
		return CacheRepairReport{}, apperr.New(apperr.CodeInvalidArgument, "profile is required")
	}
	rep := CacheRepairReport{
		ProfileID: string(opts.Profile.ID),
		// MVP always rebuilds indexes only; pack body mutation is residual.
		IndexOnly: true,
	}
	_ = opts.IndexOnly

	_, archiveRoot, err := resolveArchiveRoot(opts.Profile, opts.Paths)
	if err != nil {
		rep.Messages = append(rep.Messages, apperr.ModelMessage(err))
		return rep, nil
	}
	packs, err := store.ListArchivePacks(archiveRoot)
	if err != nil {
		rep.Messages = append(rep.Messages, apperr.ModelMessage(err))
		return rep, nil
	}
	rep.PacksSeen = len(packs)
	if len(packs) == 0 {
		rep.Messages = append(rep.Messages, "no packs under archives/")
		return rep, nil
	}

	for _, p := range packs {
		if err := ctx.Err(); err != nil {
			rep.Cancelled = true
			rep.Messages = append(rep.Messages, "repair cancelled")
			return rep, apperr.Wrap(apperr.CodeCancelled, "repair cancelled", err)
		}
		data, err := os.ReadFile(p.Path)
		if err != nil {
			rep.Failed++
			rep.Messages = append(rep.Messages, fmt.Sprintf("pack %s: read failed", p.PackID))
			continue
		}
		// Only repair index when pack content verifies — never overwrite the
		// only known-good copy without validation (acceptance).
		vrep, verr := archive.VerifyPack(ctx, p.PackID, data, nil)
		if verr != nil || !vrep.PackOK {
			rep.Skipped++
			rep.Messages = append(rep.Messages, fmt.Sprintf("pack %s: skipped (pack verify failed)", p.PackID))
			continue
		}
		idx, rerr := archive.RepairIndex(ctx, p.PackID, "", p.Path, data)
		if rerr != nil {
			rep.Failed++
			rep.Messages = append(rep.Messages, fmt.Sprintf("pack %s: repair failed: %s",
				p.PackID, redact.Secrets(apperr.ModelMessage(rerr))))
			continue
		}
		if idx == nil {
			rep.Failed++
			continue
		}
		rep.IndexesRebuilt++
		rep.Messages = append(rep.Messages, fmt.Sprintf("pack %s: index rebuilt", p.PackID))
	}
	return rep, nil
}

func resolveArchiveRoot(p *profile.Profile, paths *config.Paths) (dataDir, archiveRoot string, err error) {
	rp, err := resolvePaths(paths)
	if err != nil {
		return "", "", err
	}
	dataDir, err = resolveDataDir(p, rp)
	if err != nil {
		return "", "", err
	}
	archiveRoot = filepath.Join(dataDir, store.ArchivesDirName)
	return dataDir, archiveRoot, nil
}

func sanitizeIssues(in []archive.VerifyIssue) []archive.VerifyIssue {
	if len(in) == 0 {
		return nil
	}
	out := make([]archive.VerifyIssue, 0, len(in))
	for _, iss := range in {
		out = append(out, archive.VerifyIssue{
			Kind:    strings.TrimSpace(iss.Kind),
			Message: redact.Secrets(strings.TrimSpace(iss.Message)),
		})
	}
	return out
}
