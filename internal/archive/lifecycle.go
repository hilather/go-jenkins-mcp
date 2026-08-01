package archive

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// QuarantineDirName is the subdirectory under an FS store root for corrupt packs.
const QuarantineDirName = "quarantine"

// VerifyIssue is one non-secret diagnostic from VerifyPack (ARC-006 / ARC-008-lite).
type VerifyIssue struct {
	// Kind is pack | entry | checksum | catalog | index.
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

// VerifyReport is the outcome of VerifyPack (library surface for later cache verify).
type VerifyReport struct {
	PackID        string        `json:"pack_id"`
	PackOK        bool          `json:"pack_ok"`
	IndexOK       bool          `json:"index_ok"`
	IndexTrusted  bool          `json:"index_trusted"`
	RebuildNeeded bool          `json:"rebuild_needed"`
	Quarantined   bool          `json:"quarantined"`
	PackSHA256    string        `json:"pack_sha256,omitempty"`
	FileSHA256    string        `json:"file_sha256,omitempty"`
	SizeBytes     int64         `json:"size_bytes"`
	Issues        []VerifyIssue `json:"issues,omitempty"`
}

func (r *VerifyReport) add(kind, msg string) {
	r.Issues = append(r.Issues, VerifyIssue{Kind: kind, Message: msg})
}

// VerifyPack validates pack bytes and optional sibling index (no quarantine).
// Full dual-reader repair CLI remains ARC-008 residual.
func VerifyPack(ctx context.Context, packID string, data []byte, index *PackIndex) (VerifyReport, error) {
	rep := VerifyReport{
		PackID:        strings.TrimSpace(packID),
		RebuildNeeded: true,
		SizeBytes:     int64(len(data)),
	}
	if err := ctx.Err(); err != nil {
		return rep, apperr.Wrap(apperr.CodeCancelled, "verify cancelled", err)
	}
	if rep.PackID == "" {
		return rep, apperr.New(apperr.CodeInvalidArgument, "pack_id is required")
	}
	if len(data) == 0 {
		rep.add("pack", "pack data is empty")
		return rep, apperr.New(apperr.CodeInvalidArgument, "pack data is empty")
	}
	rep.FileSHA256 = sha256Hex(data)

	p, err := OpenPack(data)
	if err != nil {
		rep.add("pack", "native open failed")
		return rep, err
	}
	defer p.Close()
	if err := ctx.Err(); err != nil {
		return rep, apperr.Wrap(apperr.CodeCancelled, "verify cancelled", err)
	}
	if err := p.VerifyContentFrames(); err != nil {
		rep.add("checksum", "content frame verification failed")
		return rep, err
	}
	st := p.SeekTable()
	if st != nil {
		rep.PackSHA256 = st.PackSHA256
	}
	rep.PackOK = true

	if index == nil {
		rep.add("index", "index not provided")
		rep.RebuildNeeded = true
		return rep, nil
	}
	if err := index.BindMatches(rep.PackID, int64(len(data)), rep.PackSHA256, rep.FileSHA256, FormatVersion); err != nil {
		rep.add("index", "index binding mismatch; never trust")
		rep.IndexOK = false
		rep.IndexTrusted = false
		rep.RebuildNeeded = true
		return rep, nil // pack OK; index not trusted
	}
	if index.MemberCount != len(st.Members) {
		rep.add("catalog", "index member count mismatch")
		rep.RebuildNeeded = true
		return rep, nil
	}
	rep.IndexOK = true
	rep.IndexTrusted = true
	rep.RebuildNeeded = false
	return rep, nil
}

// VerifyPackFile reads pack (and sibling index) from disk, verifies, and
// optionally quarantines when pack checksum/open fails and quarantineRoot is set.
// quarantineRoot is typically the FS store root (quarantine/ is created under it).
func VerifyPackFile(ctx context.Context, packID, packPath, quarantineRoot string, doQuarantine bool) (VerifyReport, error) {
	rep := VerifyReport{PackID: strings.TrimSpace(packID), RebuildNeeded: true}
	if err := ctx.Err(); err != nil {
		return rep, apperr.Wrap(apperr.CodeCancelled, "verify cancelled", err)
	}
	data, err := os.ReadFile(packPath)
	if err != nil {
		if os.IsNotExist(err) {
			return rep, apperr.New(apperr.CodeNotFound, "pack not found")
		}
		return rep, apperr.Wrap(apperr.CodeInternal, "failed to read pack", err)
	}
	rep.SizeBytes = int64(len(data))

	var idx *PackIndex
	if raw, err := os.ReadFile(IndexPath(packPath)); err == nil {
		if parsed, perr := ParseIndex(raw); perr == nil {
			idx = parsed
		} else {
			rep.add("index", "index parse failed")
		}
	} else if !os.IsNotExist(err) {
		rep.add("index", "index read failed")
	} else {
		rep.add("index", "index missing")
	}

	vrep, verr := VerifyPack(ctx, packID, data, idx)
	// Merge issues from pre-verify index problems.
	vrep.Issues = append(rep.Issues, vrep.Issues...)
	if verr != nil {
		// Pack corrupt: quarantine when requested.
		if doQuarantine && quarantineRoot != "" {
			if qerr := QuarantinePack(quarantineRoot, packID, packPath); qerr == nil {
				vrep.Quarantined = true
			} else {
				vrep.add("pack", "quarantine failed")
			}
		}
		return vrep, verr
	}
	return vrep, nil
}

// QuarantinePack moves a pack (and sibling index if present) into
// <root>/quarantine/<packID>-<timestamp>.tar.zst. Leaves no trusted catalog entry.
func QuarantinePack(root, packID, packPath string) error {
	root = filepath.Clean(strings.TrimSpace(root))
	if root == "" || root == "." {
		return apperr.New(apperr.CodeInvalidArgument, "quarantine root is required")
	}
	packID = strings.TrimSpace(packID)
	if packID == "" {
		return apperr.New(apperr.CodeInvalidArgument, "pack_id is required")
	}
	if strings.Contains(packID, "..") || strings.ContainsAny(packID, `/\`) {
		return apperr.New(apperr.CodeInvalidArgument, "pack_id must be a single path segment")
	}
	qdir := filepath.Join(root, QuarantineDirName)
	if err := os.MkdirAll(qdir, 0o700); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to create quarantine dir", err)
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	dest := filepath.Join(qdir, fmt.Sprintf("%s-%s.tar.zst", packID, stamp))
	if err := os.Rename(packPath, dest); err != nil {
		// Cross-device fallback: copy+remove not required on Tier-1 same FS.
		return apperr.Wrap(apperr.CodeInternal, "failed to quarantine pack", err)
	}
	// Best-effort move index with the pack.
	idxSrc := IndexPath(packPath)
	idxDest := filepath.Join(qdir, fmt.Sprintf("%s-%s.idx.json", packID, stamp))
	if _, err := os.Stat(idxSrc); err == nil {
		_ = os.Rename(idxSrc, idxDest)
	}
	return nil
}

// IsQuarantined reports whether packID has any file under quarantine/.
func IsQuarantined(root, packID string) bool {
	root = filepath.Clean(strings.TrimSpace(root))
	packID = strings.TrimSpace(packID)
	if root == "" || packID == "" {
		return false
	}
	qdir := filepath.Join(root, QuarantineDirName)
	entries, err := os.ReadDir(qdir)
	if err != nil {
		return false
	}
	prefix := packID + "-"
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".tar.zst") {
			return true
		}
	}
	return false
}
