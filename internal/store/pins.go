package store

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// Pin kinds for ARC-007 (durable; never evicted while pinned).
const (
	PinKindGeneration = "generation"
	PinKindPack       = "pack"
)

// Pin is a durable pin on a generation or pack ID.
type Pin struct {
	Kind     string
	TargetID string
	PinnedAt time.Time
}

// PinGeneration pins a log generation by SQLite id. Pinned objects are never
// selected for eviction (ARC-007).
func (m *Meta) PinGeneration(ctx context.Context, generationID int64) error {
	if generationID <= 0 {
		return apperr.New(apperr.CodeInvalidArgument, "generation id is required")
	}
	return m.Pin(ctx, PinKindGeneration, strconv.FormatInt(generationID, 10))
}

// UnpinGeneration removes a generation pin.
func (m *Meta) UnpinGeneration(ctx context.Context, generationID int64) error {
	if generationID <= 0 {
		return apperr.New(apperr.CodeInvalidArgument, "generation id is required")
	}
	return m.Unpin(ctx, PinKindGeneration, strconv.FormatInt(generationID, 10))
}

// PinPack pins an L2 pack id (never evicted while pinned).
func (m *Meta) PinPack(ctx context.Context, packID string) error {
	return m.Pin(ctx, PinKindPack, packID)
}

// UnpinPack removes a pack pin.
func (m *Meta) UnpinPack(ctx context.Context, packID string) error {
	return m.Unpin(ctx, PinKindPack, packID)
}

// Pin records a pin for kind/target. Idempotent.
func (m *Meta) Pin(ctx context.Context, kind, targetID string) error {
	kind, targetID, err := normalizePin(kind, targetID)
	if err != nil {
		return err
	}
	if m == nil || m.db == nil {
		return apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = m.db.ExecContext(ctx, `
INSERT INTO pins(kind, target_id, pinned_at) VALUES(?, ?, ?)
ON CONFLICT(kind, target_id) DO UPDATE SET pinned_at = excluded.pinned_at`,
		kind, targetID, now)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to pin object", err)
	}
	return nil
}

// Unpin removes a pin. No-op if absent.
func (m *Meta) Unpin(ctx context.Context, kind, targetID string) error {
	kind, targetID, err := normalizePin(kind, targetID)
	if err != nil {
		return err
	}
	if m == nil || m.db == nil {
		return apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	_, err = m.db.ExecContext(ctx, `DELETE FROM pins WHERE kind = ? AND target_id = ?`, kind, targetID)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to unpin object", err)
	}
	return nil
}

// IsPinned reports whether kind/target is pinned.
func (m *Meta) IsPinned(ctx context.Context, kind, targetID string) (bool, error) {
	kind, targetID, err := normalizePin(kind, targetID)
	if err != nil {
		return false, err
	}
	if m == nil || m.db == nil {
		return false, apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	var n int
	err = m.db.QueryRowContext(ctx,
		`SELECT COUNT(1) FROM pins WHERE kind = ? AND target_id = ?`, kind, targetID).Scan(&n)
	if err != nil {
		return false, apperr.Wrap(apperr.CodeCorruptCache, "failed to read pin", err)
	}
	return n > 0, nil
}

// ListPins returns all pins (non-secret ids only).
func (m *Meta) ListPins(ctx context.Context) ([]Pin, error) {
	if m == nil || m.db == nil {
		return nil, apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	rows, err := m.db.QueryContext(ctx, `
SELECT kind, target_id, pinned_at FROM pins
ORDER BY kind ASC, target_id ASC`)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeCorruptCache, "failed to list pins", err)
	}
	defer rows.Close()
	var out []Pin
	for rows.Next() {
		var p Pin
		var at string
		if err := rows.Scan(&p.Kind, &p.TargetID, &at); err != nil {
			return nil, apperr.Wrap(apperr.CodeCorruptCache, "failed to scan pin", err)
		}
		if t, err := time.Parse(time.RFC3339Nano, at); err == nil {
			p.PinnedAt = t
		} else if t, err := time.Parse(time.RFC3339, at); err == nil {
			p.PinnedAt = t
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// pinnedSet returns a set of "kind|target" for O(1) eviction checks.
func (m *Meta) pinnedSet(ctx context.Context) (map[string]struct{}, error) {
	pins, err := m.ListPins(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]struct{}, len(pins))
	for _, p := range pins {
		out[p.Kind+"|"+p.TargetID] = struct{}{}
	}
	return out, nil
}

func pinKey(kind, targetID string) string {
	return kind + "|" + targetID
}

func normalizePin(kind, targetID string) (string, string, error) {
	kind = strings.TrimSpace(strings.ToLower(kind))
	targetID = strings.TrimSpace(targetID)
	if kind != PinKindGeneration && kind != PinKindPack {
		return "", "", apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("pin kind must be %q or %q", PinKindGeneration, PinKindPack))
	}
	if targetID == "" {
		return "", "", apperr.New(apperr.CodeInvalidArgument, "pin target id is required")
	}
	if strings.Contains(targetID, "..") || strings.ContainsAny(targetID, `/\`) {
		return "", "", apperr.New(apperr.CodeInvalidArgument, "pin target id must be a single path segment")
	}
	return kind, targetID, nil
}

// SetGenerationOutcome records success/failed for retention (ARC-007). Empty clears.
func (m *Meta) SetGenerationOutcome(ctx context.Context, id int64, outcome string) error {
	if id <= 0 {
		return apperr.New(apperr.CodeInvalidArgument, "generation id is required")
	}
	outcome = strings.TrimSpace(strings.ToLower(outcome))
	switch outcome {
	case "", OutcomeSuccess, OutcomeFailed:
	default:
		return apperr.New(apperr.CodeInvalidArgument, "outcome must be success, failed, or empty")
	}
	if m == nil || m.db == nil {
		return apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	var arg any
	if outcome == "" {
		arg = nil
	} else {
		arg = outcome
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := m.db.ExecContext(ctx, `
UPDATE log_generations SET outcome = ?, updated_at = ? WHERE id = ?`, arg, now, id)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to set generation outcome", err)
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return apperr.New(apperr.CodeNotFound, "log generation not found")
	}
	return nil
}

// ListGenerations returns all generation rows ordered by updated_at ASC (oldest first).
func (m *Meta) ListGenerations(ctx context.Context) ([]LogGeneration, error) {
	if m == nil || m.db == nil {
		return nil, apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	rows, err := m.db.QueryContext(ctx, `
SELECT id, profile, job, build, generation, sealed, jenkins_offset, more_data, build_complete, updated_at,
	COALESCE(packed_pack_id, ''), COALESCE(packed_at, ''), COALESCE(outcome, ''),
	COALESCE(l1_released, 0), COALESCE(l1_released_at, '')
FROM log_generations
ORDER BY updated_at ASC, id ASC`)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeCorruptCache, "failed to list generations", err)
	}
	defer rows.Close()
	var out []LogGeneration
	for rows.Next() {
		g, err := scanGeneration(rows)
		if err != nil {
			return nil, apperr.Wrap(apperr.CodeCorruptCache, "failed to scan generation", err)
		}
		out = append(out, *g)
	}
	return out, rows.Err()
}

// GenerationByteUsage is physical (compressed) and logical (uncompressed) L1 sizes.
type GenerationByteUsage struct {
	GenerationID  int64
	PhysicalBytes int64
	LogicalBytes  int64
	ChunkCount    int64
}

// GenerationBytes returns L1 byte totals for one generation from chunk meta.
func (m *Meta) GenerationBytes(ctx context.Context, generationID int64) (GenerationByteUsage, error) {
	var u GenerationByteUsage
	u.GenerationID = generationID
	if m == nil || m.db == nil {
		return u, apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	if generationID <= 0 {
		return u, apperr.New(apperr.CodeInvalidArgument, "generation id is required")
	}
	err := m.db.QueryRowContext(ctx, `
SELECT COALESCE(SUM(compressed_size), 0), COALESCE(SUM(uncompressed_size), 0), COUNT(*)
FROM chunks WHERE generation_id = ?`, generationID).
		Scan(&u.PhysicalBytes, &u.LogicalBytes, &u.ChunkCount)
	if err != nil {
		return u, apperr.Wrap(apperr.CodeCorruptCache, "failed to sum generation bytes", err)
	}
	return u, nil
}

// SumL1Bytes returns profile-wide L1 physical/logical totals from chunk metadata.
func (m *Meta) SumL1Bytes(ctx context.Context) (physical, logical int64, err error) {
	if m == nil || m.db == nil {
		return 0, 0, apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	err = m.db.QueryRowContext(ctx, `
SELECT COALESCE(SUM(compressed_size), 0), COALESCE(SUM(uncompressed_size), 0) FROM chunks`).
		Scan(&physical, &logical)
	if err != nil {
		return 0, 0, apperr.Wrap(apperr.CodeCorruptCache, "failed to sum L1 bytes", err)
	}
	return physical, logical, nil
}

// DeleteGeneration removes a generation row and cascaded chunks/checkpoints.
// Caller is responsible for deleting on-disk frame files (ARC-007 journal-lite).
func (m *Meta) DeleteGeneration(ctx context.Context, id int64) error {
	if id <= 0 {
		return apperr.New(apperr.CodeInvalidArgument, "generation id is required")
	}
	if m == nil || m.db == nil {
		return apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	res, err := m.db.ExecContext(ctx, `DELETE FROM log_generations WHERE id = ?`, id)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to delete generation", err)
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return apperr.New(apperr.CodeNotFound, "log generation not found")
	}
	// Best-effort pin cleanup.
	_, _ = m.db.ExecContext(ctx, `DELETE FROM pins WHERE kind = ? AND target_id = ?`,
		PinKindGeneration, strconv.FormatInt(id, 10))
	return nil
}

// ClearPackedPackID clears packed references for a pack id (after L2 eviction).
func (m *Meta) ClearPackedPackID(ctx context.Context, packID string) error {
	packID = strings.TrimSpace(packID)
	if packID == "" {
		return apperr.New(apperr.CodeInvalidArgument, "pack_id is required")
	}
	if m == nil || m.db == nil {
		return apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	_, err := m.db.ExecContext(ctx, `
UPDATE log_generations SET packed_pack_id = NULL, packed_at = NULL
WHERE packed_pack_id = ?`, packID)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to clear packed pack refs", err)
	}
	return nil
}
