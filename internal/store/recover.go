package store

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// RecoverResult summarizes startup recovery (STO-004).
type RecoverResult struct {
	// OrphanTempsRemoved are deleted *.zst.tmp files.
	OrphanTempsRemoved int
	// OrphanFramesRemoved are committed-looking .zst files with no SQLite row.
	OrphanFramesRemoved int
	// MissingFiles are chunk rows whose frame file was absent (rows deleted).
	MissingFiles int
}

// Recover cleans incomplete frame commits and reconciles metadata with disk.
//
// Rules:
//  1. Delete any *.zst.tmp (never durable / never visible).
//  2. Delete .zst files under frames/ with no matching chunks.rel_path (orphan
//     after rename-before-meta crash).
//  3. Delete chunk rows whose file is missing (meta-without-file).
//
// Recovery is metadata + directory walk only — not a full log byte scan.
// Incomplete frames are never visible to readers (no meta ⇒ no read).
func (f *Frames) Recover(ctx context.Context) (RecoverResult, error) {
	if f == nil {
		return RecoverResult{}, apperr.New(apperr.CodeInternal, "frames store is nil")
	}
	return recoverDataDir(ctx, f.meta, f.dataDir)
}

// RecoverMeta is package-level recovery when Frames is not constructed yet.
func RecoverMeta(ctx context.Context, meta *Meta, dataDir string) (RecoverResult, error) {
	dataDir, err := cleanDataPath(dataDir)
	if err != nil {
		return RecoverResult{}, err
	}
	return recoverDataDir(ctx, meta, dataDir)
}

func recoverDataDir(ctx context.Context, meta *Meta, dataDir string) (RecoverResult, error) {
	if meta == nil {
		return RecoverResult{}, apperr.New(apperr.CodeInvalidArgument, "meta is required")
	}
	var res RecoverResult
	framesRoot := filepath.Join(dataDir, FramesDirName)
	if _, err := os.Stat(framesRoot); os.IsNotExist(err) {
		// Nothing on disk; still drop chunk rows with missing files (none expected).
		return res, nil
	} else if err != nil {
		return res, apperr.Wrap(apperr.CodeInternal, "failed to stat frames dir", err)
	}

	known, err := meta.ListAllChunkRelPaths(ctx)
	if err != nil {
		return res, err
	}
	// Normalize keys.
	knownNorm := make(map[string]int64, len(known))
	for rel, id := range known {
		knownNorm[filepath.ToSlash(rel)] = id
	}

	// Walk frames/ for tmp + orphan zst.
	err = filepath.WalkDir(framesRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if strings.HasSuffix(name, FrameTmpExt) || strings.HasSuffix(name, ".tmp") {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return apperr.Wrap(apperr.CodeInternal, "failed to remove orphan temp frame", err)
			}
			res.OrphanTempsRemoved++
			return nil
		}
		if !strings.HasSuffix(name, FrameExt) {
			return nil
		}
		rel, err := filepath.Rel(dataDir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if _, ok := knownNorm[rel]; ok {
			return nil
		}
		// Orphan committed-looking file without meta.
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return apperr.Wrap(apperr.CodeInternal, "failed to remove orphan frame", err)
		}
		res.OrphanFramesRemoved++
		return nil
	})
	if err != nil {
		return res, err
	}

	// Meta rows without files.
	for rel, id := range knownNorm {
		abs, err := FrameAbsPath(dataDir, rel)
		if err != nil {
			// Bad path in DB: drop row.
			_ = meta.DeleteChunkRow(ctx, id)
			res.MissingFiles++
			continue
		}
		if _, err := os.Stat(abs); os.IsNotExist(err) {
			if err := meta.DeleteChunkRow(ctx, id); err != nil {
				return res, err
			}
			res.MissingFiles++
		}
	}
	return res, nil
}
