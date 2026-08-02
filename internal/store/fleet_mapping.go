package store

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Fleet mapping / import journal statuses (FLC-023).
const (
	FleetMappingCommitted   = "committed"
	FleetMappingQuarantined = "quarantined"

	FleetImportStaging   = "staging"
	FleetImportCommitted = "committed"
	FleetImportAborted   = "aborted"
)

// FleetObjectMapping is a lookup-visible sealed fleet object (committed only).
type FleetObjectMapping struct {
	LocatorHash    string
	ManifestDigest string
	FleetID        string
	CachePool      string
	ControllerID   string
	GenerationID   int64
	Status         string
	CreatedAt      string
}

// FleetImportJournal is a staging import row (not lookup-visible until committed mapping).
type FleetImportJournal struct {
	ID             int64
	LocatorHash    string
	ManifestDigest string
	Status         string
	GenerationID   int64
	FramesDone     int
	FramesTotal    int
	CreatedAt      string
	UpdatedAt      string
}

// GetCommittedFleetMapping returns a committed mapping or ok=false.
// Incomplete/quarantined/aborted imports are not returned.
func (m *Meta) GetCommittedFleetMapping(ctx context.Context, locatorHash string) (FleetObjectMapping, bool, error) {
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
FROM fleet_object_mapping
WHERE locator_hash = ? AND status = ?`, locatorHash, FleetMappingCommitted)
	var out FleetObjectMapping
	err := row.Scan(&out.LocatorHash, &out.ManifestDigest, &out.FleetID, &out.CachePool,
		&out.ControllerID, &out.GenerationID, &out.Status, &out.CreatedAt)
	if err == sql.ErrNoRows {
		return FleetObjectMapping{}, false, nil
	}
	if err != nil {
		return FleetObjectMapping{}, false, apperr.Wrap(apperr.CodeCorruptCache, "fleet mapping lookup", err)
	}
	return out, true, nil
}

// BeginFleetImport inserts a staging journal row and a new unsealed local generation.
// Profile is "fleet-import"; job is the locator hash (no peer path control).
func (m *Meta) BeginFleetImport(ctx context.Context, locatorHash, manifestDigest, fleetID, cachePool, controllerID string, framesTotal int) (importID, generationID int64, err error) {
	if m == nil || m.db == nil {
		return 0, 0, apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	locatorHash = strings.ToLower(strings.TrimSpace(locatorHash))
	manifestDigest = strings.ToLower(strings.TrimSpace(manifestDigest))
	if len(locatorHash) != 64 || len(manifestDigest) != 64 {
		return 0, 0, apperr.New(apperr.CodeInvalidArgument, "locator/manifest hash invalid")
	}
	if framesTotal < 1 {
		return 0, 0, apperr.New(apperr.CodeInvalidArgument, "frames_total invalid")
	}
	// Local generation: profile fleet-import, job=locator, build=1, generation=import seq.
	g := &LogGeneration{
		Profile:    "fleet-import",
		Job:        locatorHash,
		Build:      1,
		Generation: 1,
		MoreData:   true,
	}
	// Allow multiple imports over time by bumping generation number.
	if existing, e := m.GetLatestGeneration(ctx, LogKey{Profile: "fleet-import", Job: locatorHash, Build: 1}); e == nil && existing != nil {
		g.Generation = existing.Generation + 1
	}
	if err := m.InsertGeneration(ctx, g); err != nil {
		return 0, 0, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	res, err := m.db.ExecContext(ctx, `
INSERT INTO fleet_import_journal(
	locator_hash, manifest_digest, status, generation_id, frames_done, frames_total, created_at, updated_at
) VALUES(?, ?, ?, ?, 0, ?, ?, ?)`,
		locatorHash, manifestDigest, FleetImportStaging, g.ID, framesTotal, now, now)
	if err != nil {
		return 0, 0, apperr.Wrap(apperr.CodeInternal, "fleet import journal insert", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, 0, apperr.Wrap(apperr.CodeInternal, "fleet import journal id", err)
	}
	return id, g.ID, nil
}

// AdvanceFleetImportFrames bumps frames_done after a successful staged frame write.
func (m *Meta) AdvanceFleetImportFrames(ctx context.Context, importID int64, framesDone int) error {
	if m == nil || m.db == nil {
		return apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	if importID <= 0 || framesDone < 0 {
		return apperr.New(apperr.CodeInvalidArgument, "import progress invalid")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	res, err := m.db.ExecContext(ctx, `
UPDATE fleet_import_journal SET frames_done = ?, updated_at = ?
WHERE id = ? AND status = ?`, framesDone, now, importID, FleetImportStaging)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "fleet import progress", err)
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return apperr.New(apperr.CodeNotFound, "fleet import not staging")
	}
	return nil
}

// CommitFleetImport seals generation, writes committed mapping, marks journal committed.
// Partial imports without this call are never lookup-visible.
//
// Fail closed (FLC-023 completeness):
//   - journal must be staging with matching generation/digest
//   - frames_done must equal frames_total
//   - committed chunk count for generation must equal frames_total
//
// Incomplete progress is rejected before seal/mapping so a truncated object cannot
// become lookup-visible or freeze behind same-digest idempotent short-circuit.
func (m *Meta) CommitFleetImport(ctx context.Context, importID, generationID int64, locatorHash, manifestDigest, fleetID, cachePool, controllerID string, totalRaw int64) error {
	if m == nil || m.db == nil {
		return apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	locatorHash = strings.ToLower(strings.TrimSpace(locatorHash))
	manifestDigest = strings.ToLower(strings.TrimSpace(manifestDigest))
	if importID <= 0 || generationID <= 0 {
		return apperr.New(apperr.CodeInvalidArgument, "import/generation id required")
	}

	// Completeness gate before any seal/publish (must hold writeMu for journal+chunk read).
	m.writeMu.Lock()
	var jStatus string
	var jGen int64
	var jDigest string
	var framesDone, framesTotal int
	err := m.db.QueryRowContext(ctx, `
SELECT status, COALESCE(generation_id, 0), manifest_digest, frames_done, frames_total
FROM fleet_import_journal WHERE id = ?`, importID).
		Scan(&jStatus, &jGen, &jDigest, &framesDone, &framesTotal)
	if err == sql.ErrNoRows {
		m.writeMu.Unlock()
		return apperr.New(apperr.CodeNotFound, "fleet import not found")
	}
	if err != nil {
		m.writeMu.Unlock()
		return apperr.Wrap(apperr.CodeInternal, "fleet import read", err)
	}
	if jStatus != FleetImportStaging || jGen != generationID || !strings.EqualFold(jDigest, manifestDigest) {
		m.writeMu.Unlock()
		return apperr.New(apperr.CodePolicyDenial, "fleet import not staging for commit")
	}
	if framesTotal < 1 || framesDone != framesTotal {
		m.writeMu.Unlock()
		return apperr.New(apperr.CodePolicyDenial, "fleet import incomplete: frames_done != frames_total")
	}
	var chunkCount int
	err = m.db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM chunks WHERE generation_id = ?`, generationID).Scan(&chunkCount)
	if err != nil {
		m.writeMu.Unlock()
		return apperr.Wrap(apperr.CodeInternal, "fleet import chunk count", err)
	}
	if chunkCount != framesTotal {
		m.writeMu.Unlock()
		return apperr.New(apperr.CodePolicyDenial, "fleet import incomplete: chunk count mismatch")
	}
	// Contiguous seq 0..frames_total-1 required.
	var minSeq, maxSeq, distinct int
	err = m.db.QueryRowContext(ctx, `
SELECT COALESCE(MIN(seq), -1), COALESCE(MAX(seq), -1), COUNT(DISTINCT seq)
FROM chunks WHERE generation_id = ?`, generationID).Scan(&minSeq, &maxSeq, &distinct)
	if err != nil {
		m.writeMu.Unlock()
		return apperr.Wrap(apperr.CodeInternal, "fleet import chunk seq scan", err)
	}
	if minSeq != 0 || maxSeq != framesTotal-1 || distinct != framesTotal {
		m.writeMu.Unlock()
		return apperr.New(apperr.CodePolicyDenial, "fleet import incomplete: frame seq not contiguous")
	}
	m.writeMu.Unlock()

	// Seal + offset only after completeness (still no mapping → not lookup-visible).
	if err := m.UpdateGenerationOffset(ctx, generationID, totalRaw, false, true, false); err != nil {
		return err
	}
	if err := m.SealGeneration(ctx, generationID); err != nil {
		return err
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "fleet commit begin", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Re-check staging under the same tx (race: concurrent abort).
	err = tx.QueryRowContext(ctx, `
SELECT status, COALESCE(generation_id, 0), manifest_digest, frames_done, frames_total
FROM fleet_import_journal WHERE id = ?`, importID).
		Scan(&jStatus, &jGen, &jDigest, &framesDone, &framesTotal)
	if err == sql.ErrNoRows {
		return apperr.New(apperr.CodeNotFound, "fleet import not found")
	}
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "fleet import re-read", err)
	}
	if jStatus != FleetImportStaging || jGen != generationID || !strings.EqualFold(jDigest, manifestDigest) {
		return apperr.New(apperr.CodePolicyDenial, "fleet import not staging for commit")
	}
	if framesDone != framesTotal || framesTotal < 1 {
		return apperr.New(apperr.CodePolicyDenial, "fleet import incomplete: frames_done != frames_total")
	}

	// Mapping by locator_hash (PK): committed conflict, quarantined replace, or insert.
	// FLC-024: quarantine must not permanently block complete re-import (UPSERT path).
	var existingDigest, existingStatus string
	var existingGen int64
	err = tx.QueryRowContext(ctx, `
SELECT manifest_digest, generation_id, status FROM fleet_object_mapping WHERE locator_hash = ?`,
		locatorHash).Scan(&existingDigest, &existingGen, &existingStatus)
	if err == nil && existingStatus == FleetMappingCommitted {
		if !strings.EqualFold(existingDigest, manifestDigest) {
			return apperr.New(apperr.CodePolicyDenial, "conflicting fleet object version")
		}
		// Same digest already published: only mark journal committed if existing
		// generation is complete (do not freeze a truncated prior publish).
		var existingChunks int
		if err := tx.QueryRowContext(ctx, `
SELECT COUNT(*) FROM chunks WHERE generation_id = ?`, existingGen).Scan(&existingChunks); err != nil {
			return apperr.Wrap(apperr.CodeInternal, "existing mapping chunk count", err)
		}
		if existingChunks != framesTotal {
			return apperr.New(apperr.CodeCorruptCache, "existing mapping incomplete; refuse idempotent commit")
		}
		_, err = tx.ExecContext(ctx, `
UPDATE fleet_import_journal SET status = ?, updated_at = ? WHERE id = ?`,
			FleetImportCommitted, now, importID)
		if err != nil {
			return apperr.Wrap(apperr.CodeInternal, "fleet import journal commit", err)
		}
		return tx.Commit()
	}
	if err != nil && err != sql.ErrNoRows {
		return apperr.Wrap(apperr.CodeInternal, "fleet mapping check", err)
	}
	if err == nil {
		// Row exists as quarantined (or non-committed): replace with healthy complete import.
		// New generation/digest becomes committed hit-eligible again.
		_, err = tx.ExecContext(ctx, `
UPDATE fleet_object_mapping SET
	manifest_digest = ?, fleet_id = ?, cache_pool = ?, controller_id = ?,
	generation_id = ?, status = ?, created_at = ?
WHERE locator_hash = ?`,
			manifestDigest, fleetID, cachePool, controllerID,
			generationID, FleetMappingCommitted, now, locatorHash)
		if err != nil {
			return apperr.Wrap(apperr.CodeInternal, "fleet mapping replace quarantined", err)
		}
	} else {
		// No row: insert committed mapping.
		_, err = tx.ExecContext(ctx, `
INSERT INTO fleet_object_mapping(
	locator_hash, manifest_digest, fleet_id, cache_pool, controller_id,
	generation_id, status, created_at
) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
			locatorHash, manifestDigest, fleetID, cachePool, controllerID,
			generationID, FleetMappingCommitted, now)
		if err != nil {
			return apperr.Wrap(apperr.CodeInternal, "fleet mapping insert", err)
		}
	}
	_, err = tx.ExecContext(ctx, `
UPDATE fleet_import_journal SET status = ?, updated_at = ? WHERE id = ?`,
		FleetImportCommitted, now, importID)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "fleet import journal commit", err)
	}
	if err := tx.Commit(); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "fleet commit", err)
	}
	return nil
}

// AbortFleetImport marks the journal aborted. Does not create mapping.
// Local generation may remain unsealed (invisible to fleet mapping).
func (m *Meta) AbortFleetImport(ctx context.Context, importID int64) error {
	if m == nil || m.db == nil {
		return apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	if importID <= 0 {
		return apperr.New(apperr.CodeInvalidArgument, "import id required")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	_, err := m.db.ExecContext(ctx, `
UPDATE fleet_import_journal SET status = ?, updated_at = ?
WHERE id = ? AND status = ?`, FleetImportAborted, now, importID, FleetImportStaging)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "fleet import abort", err)
	}
	return nil
}

// GetStagingFleetImport returns the latest staging journal for locator+digest (FLC-043 resume).
// presentSeqs are durable chunk sequences already written for the journal generation.
// ok=false when no open staging import matches.
func (m *Meta) GetStagingFleetImport(ctx context.Context, locatorHash, manifestDigest string) (FleetImportJournal, []int, bool, error) {
	if m == nil || m.db == nil {
		return FleetImportJournal{}, nil, false, apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	locatorHash = strings.ToLower(strings.TrimSpace(locatorHash))
	manifestDigest = strings.ToLower(strings.TrimSpace(manifestDigest))
	if len(locatorHash) != 64 || len(manifestDigest) != 64 {
		return FleetImportJournal{}, nil, false, apperr.New(apperr.CodeInvalidArgument, "locator/manifest hash invalid")
	}
	row := m.db.QueryRowContext(ctx, `
SELECT id, locator_hash, manifest_digest, status, COALESCE(generation_id, 0),
	frames_done, frames_total, created_at, updated_at
FROM fleet_import_journal
WHERE locator_hash = ? AND LOWER(manifest_digest) = ? AND status = ?
ORDER BY id DESC LIMIT 1`, locatorHash, manifestDigest, FleetImportStaging)
	var j FleetImportJournal
	err := row.Scan(&j.ID, &j.LocatorHash, &j.ManifestDigest, &j.Status, &j.GenerationID,
		&j.FramesDone, &j.FramesTotal, &j.CreatedAt, &j.UpdatedAt)
	if err == sql.ErrNoRows {
		return FleetImportJournal{}, nil, false, nil
	}
	if err != nil {
		return FleetImportJournal{}, nil, false, apperr.Wrap(apperr.CodeCorruptCache, "staging fleet import lookup", err)
	}
	if j.GenerationID <= 0 {
		return j, nil, true, nil
	}
	rows, err := m.db.QueryContext(ctx, `
SELECT seq FROM chunks WHERE generation_id = ? ORDER BY seq ASC`, j.GenerationID)
	if err != nil {
		return FleetImportJournal{}, nil, false, apperr.Wrap(apperr.CodeCorruptCache, "staging chunk seq list", err)
	}
	defer rows.Close()
	var seqs []int
	for rows.Next() {
		var seq int
		if err := rows.Scan(&seq); err != nil {
			return FleetImportJournal{}, nil, false, apperr.Wrap(apperr.CodeCorruptCache, "staging chunk seq scan", err)
		}
		seqs = append(seqs, seq)
	}
	if err := rows.Err(); err != nil {
		return FleetImportJournal{}, nil, false, err
	}
	return j, seqs, true, nil
}

// GetFleetImport returns a journal row by id.
func (m *Meta) GetFleetImport(ctx context.Context, importID int64) (FleetImportJournal, error) {
	if m == nil || m.db == nil {
		return FleetImportJournal{}, apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	row := m.db.QueryRowContext(ctx, `
SELECT id, locator_hash, manifest_digest, status, COALESCE(generation_id, 0),
	frames_done, frames_total, created_at, updated_at
FROM fleet_import_journal WHERE id = ?`, importID)
	var j FleetImportJournal
	err := row.Scan(&j.ID, &j.LocatorHash, &j.ManifestDigest, &j.Status, &j.GenerationID,
		&j.FramesDone, &j.FramesTotal, &j.CreatedAt, &j.UpdatedAt)
	if err == sql.ErrNoRows {
		return FleetImportJournal{}, apperr.New(apperr.CodeNotFound, "fleet import not found")
	}
	if err != nil {
		return FleetImportJournal{}, apperr.Wrap(apperr.CodeCorruptCache, "fleet import scan", err)
	}
	return j, nil
}
