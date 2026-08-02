package store

import (
	"context"
	"database/sql"
	"os"
	"sort"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// GenerationHealth is a secret-free health verdict for a local generation (FLC-024).
// No job names, paths, tokens, or log bodies.
type GenerationHealth struct {
	Healthy bool
	// Residual is a low-cardinality reason when unhealthy (empty when healthy).
	Residual string
	// ChunkCount is number of chunk rows for the generation.
	ChunkCount int
}

// FleetRecoverResult summarizes fleet import recovery (FLC-024).
// Secret-free: counts + residual codes only.
type FleetRecoverResult struct {
	// StagingAborted is how many staging journals were aborted.
	StagingAborted int
	// MappingsQuarantined is how many committed mappings lost hit eligibility.
	MappingsQuarantined int
	// HealthyMappings is committed mappings that remain hit-eligible.
	HealthyMappings int
	// Residuals lists secret-free residual codes (bounded, de-duplicated by kind).
	Residuals []string
}

// CheckGenerationHealth verifies chunk completeness and on-disk frame files
// without decoding full log content (metadata + file stat/hash only).
// expectFrames < 1 means "any contiguous sealed frame set" (infer from chunks).
func (m *Meta) CheckGenerationHealth(ctx context.Context, dataDir string, generationID int64, expectFrames int) (GenerationHealth, error) {
	if m == nil || m.db == nil {
		return GenerationHealth{}, apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	if generationID <= 0 {
		return GenerationHealth{Healthy: false, Residual: "invalid_generation"}, nil
	}
	g, err := m.GetGenerationByID(ctx, generationID)
	if err != nil {
		if apperr.CodeOf(err) == apperr.CodeNotFound {
			return GenerationHealth{Healthy: false, Residual: "generation_missing"}, nil
		}
		return GenerationHealth{}, err
	}
	if g == nil {
		return GenerationHealth{Healthy: false, Residual: "generation_missing"}, nil
	}
	if !g.Sealed {
		return GenerationHealth{Healthy: false, Residual: "generation_unsealed"}, nil
	}
	chunks, err := m.ListChunks(ctx, generationID)
	if err != nil {
		return GenerationHealth{}, err
	}
	n := len(chunks)
	if n < 1 {
		return GenerationHealth{Healthy: false, Residual: "no_chunks", ChunkCount: 0}, nil
	}
	if expectFrames > 0 && n != expectFrames {
		return GenerationHealth{Healthy: false, Residual: "chunk_count_mismatch", ChunkCount: n}, nil
	}
	// Contiguous seq 0..n-1.
	seen := make(map[int]struct{}, n)
	for _, c := range chunks {
		if c.Seq < 0 || c.Seq >= n {
			return GenerationHealth{Healthy: false, Residual: "seq_out_of_range", ChunkCount: n}, nil
		}
		if _, dup := seen[c.Seq]; dup {
			return GenerationHealth{Healthy: false, Residual: "seq_duplicate", ChunkCount: n}, nil
		}
		seen[c.Seq] = struct{}{}
	}
	for i := 0; i < n; i++ {
		if _, ok := seen[i]; !ok {
			return GenerationHealth{Healthy: false, Residual: "seq_gap", ChunkCount: n}, nil
		}
	}
	// File presence + FrameSHA256 of on-disk bytes (no decode of log content).
	for _, c := range chunks {
		abs, err := FrameAbsPath(dataDir, c.RelPath)
		if err != nil {
			return GenerationHealth{Healthy: false, Residual: "bad_rel_path", ChunkCount: n}, nil
		}
		onDisk, err := os.ReadFile(abs)
		if err != nil {
			if os.IsNotExist(err) {
				return GenerationHealth{Healthy: false, Residual: "frame_file_missing", ChunkCount: n}, nil
			}
			return GenerationHealth{}, apperr.Wrap(apperr.CodeInternal, "frame file read", err)
		}
		if len(onDisk) == 0 {
			return GenerationHealth{Healthy: false, Residual: "frame_file_empty", ChunkCount: n}, nil
		}
		if c.FrameSHA256 != "" {
			sum := sha256Hex(onDisk)
			if !hmacEqualHex(strings.ToLower(c.FrameSHA256), sum) {
				return GenerationHealth{Healthy: false, Residual: "frame_hash_mismatch", ChunkCount: n}, nil
			}
		}
	}
	return GenerationHealth{Healthy: true, ChunkCount: n}, nil
}

// ListStagingFleetImports returns staging journal rows (bounded scan).
func (m *Meta) ListStagingFleetImports(ctx context.Context) ([]FleetImportJournal, error) {
	return m.listFleetImportsByStatus(ctx, FleetImportStaging)
}

// ListCommittedFleetMappings returns committed mappings (hit-eligible candidates).
func (m *Meta) ListCommittedFleetMappings(ctx context.Context) ([]FleetObjectMapping, error) {
	return m.listFleetMappingsByStatus(ctx, FleetMappingCommitted)
}

// ListQuarantinedFleetMappings returns quarantined mappings (not hit-eligible).
func (m *Meta) ListQuarantinedFleetMappings(ctx context.Context) ([]FleetObjectMapping, error) {
	return m.listFleetMappingsByStatus(ctx, FleetMappingQuarantined)
}

func (m *Meta) listFleetImportsByStatus(ctx context.Context, status string) ([]FleetImportJournal, error) {
	if m == nil || m.db == nil {
		return nil, apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	rows, err := m.db.QueryContext(ctx, `
SELECT id, locator_hash, manifest_digest, status, COALESCE(generation_id, 0),
	frames_done, frames_total, created_at, updated_at
FROM fleet_import_journal WHERE status = ?
ORDER BY id ASC`, status)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeCorruptCache, "list fleet imports", err)
	}
	defer rows.Close()
	var out []FleetImportJournal
	for rows.Next() {
		var j FleetImportJournal
		if err := rows.Scan(&j.ID, &j.LocatorHash, &j.ManifestDigest, &j.Status, &j.GenerationID,
			&j.FramesDone, &j.FramesTotal, &j.CreatedAt, &j.UpdatedAt); err != nil {
			return nil, apperr.Wrap(apperr.CodeCorruptCache, "scan fleet import", err)
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func (m *Meta) listFleetMappingsByStatus(ctx context.Context, status string) ([]FleetObjectMapping, error) {
	if m == nil || m.db == nil {
		return nil, apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	rows, err := m.db.QueryContext(ctx, `
SELECT locator_hash, manifest_digest, fleet_id, cache_pool, controller_id,
	generation_id, status, created_at
FROM fleet_object_mapping WHERE status = ?
ORDER BY created_at ASC`, status)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeCorruptCache, "list fleet mappings", err)
	}
	defer rows.Close()
	var out []FleetObjectMapping
	for rows.Next() {
		var o FleetObjectMapping
		if err := rows.Scan(&o.LocatorHash, &o.ManifestDigest, &o.FleetID, &o.CachePool,
			&o.ControllerID, &o.GenerationID, &o.Status, &o.CreatedAt); err != nil {
			return nil, apperr.Wrap(apperr.CodeCorruptCache, "scan fleet mapping", err)
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// QuarantineFleetMapping moves a committed mapping to quarantine (not hit-eligible).
// residual is secret-free and not persisted as free text in this schema (status only);
// callers record residual codes on FleetRecoverResult.
func (m *Meta) QuarantineFleetMapping(ctx context.Context, locatorHash string) error {
	if m == nil || m.db == nil {
		return apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	locatorHash = strings.ToLower(strings.TrimSpace(locatorHash))
	if len(locatorHash) != 64 {
		return apperr.New(apperr.CodeInvalidArgument, "locator_hash invalid")
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	res, err := m.db.ExecContext(ctx, `
UPDATE fleet_object_mapping SET status = ? WHERE locator_hash = ? AND status = ?`,
		FleetMappingQuarantined, locatorHash, FleetMappingCommitted)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "fleet mapping quarantine", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// Already quarantined or missing — idempotent success for recovery.
		return nil
	}
	return nil
}

// RecoverFleetImports aborts incomplete staging journals and quarantines unhealthy
// committed mappings (FLC-024). Does not full-decode logs; journal/mapping + frame files only.
// Idempotent: second call finds no staging and re-checks quarantine (no double damage).
func (m *Meta) RecoverFleetImports(ctx context.Context, dataDir string) (FleetRecoverResult, error) {
	if m == nil || m.db == nil {
		return FleetRecoverResult{}, apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	dataDir, err := cleanDataPath(dataDir)
	if err != nil {
		return FleetRecoverResult{}, err
	}
	var out FleetRecoverResult
	residualSet := make(map[string]struct{})

	// 1) Abort all staging journals (incomplete never becomes committed mapping).
	staging, err := m.ListStagingFleetImports(ctx)
	if err != nil {
		return out, err
	}
	for _, j := range staging {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if err := m.AbortFleetImport(ctx, j.ID); err != nil {
			return out, err
		}
		out.StagingAborted++
		residualSet["staging_aborted"] = struct{}{}
	}

	// 2) Health-check committed mappings; quarantine unhealthy.
	committed, err := m.ListCommittedFleetMappings(ctx)
	if err != nil {
		return out, err
	}
	for _, mapping := range committed {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		// Prefer frames_total from a committed journal if present; else infer.
		expect := 0
		var ft sql.NullInt64
		_ = m.db.QueryRowContext(ctx, `
SELECT frames_total FROM fleet_import_journal
WHERE locator_hash = ? AND manifest_digest = ? AND status = ?
ORDER BY id DESC LIMIT 1`,
			mapping.LocatorHash, mapping.ManifestDigest, FleetImportCommitted).Scan(&ft)
		if ft.Valid && ft.Int64 > 0 {
			expect = int(ft.Int64)
		}
		h, err := m.CheckGenerationHealth(ctx, dataDir, mapping.GenerationID, expect)
		if err != nil {
			return out, err
		}
		if h.Healthy {
			out.HealthyMappings++
			continue
		}
		if err := m.QuarantineFleetMapping(ctx, mapping.LocatorHash); err != nil {
			return out, err
		}
		out.MappingsQuarantined++
		code := h.Residual
		if code == "" {
			code = "quarantined"
		}
		residualSet[code] = struct{}{}
	}

	for code := range residualSet {
		out.Residuals = append(out.Residuals, code)
	}
	sort.Strings(out.Residuals)
	return out, nil
}

// GetFleetMappingAny returns mapping by locator regardless of status (tests/operators).
// Hit eligibility still requires status=committed via GetCommittedFleetMapping.
func (m *Meta) GetFleetMappingAny(ctx context.Context, locatorHash string) (FleetObjectMapping, bool, error) {
	if m == nil || m.db == nil {
		return FleetObjectMapping{}, false, apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	locatorHash = strings.ToLower(strings.TrimSpace(locatorHash))
	if len(locatorHash) != 64 {
		return FleetObjectMapping{}, false, apperr.New(apperr.CodeInvalidArgument, "locator_hash invalid")
	}
	row := m.db.QueryRowContext(ctx, `
SELECT locator_hash, manifest_digest, fleet_id, cache_pool, controller_id,
	generation_id, status, created_at
FROM fleet_object_mapping WHERE locator_hash = ?`, locatorHash)
	var out FleetObjectMapping
	err := row.Scan(&out.LocatorHash, &out.ManifestDigest, &out.FleetID, &out.CachePool,
		&out.ControllerID, &out.GenerationID, &out.Status, &out.CreatedAt)
	if err == sql.ErrNoRows {
		return FleetObjectMapping{}, false, nil
	}
	if err != nil {
		return FleetObjectMapping{}, false, apperr.Wrap(apperr.CodeCorruptCache, "fleet mapping any", err)
	}
	return out, true, nil
}
