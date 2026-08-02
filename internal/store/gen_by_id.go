package store

import (
	"context"
	"database/sql"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// GetGenerationByID loads a generation row by SQLite id (SEARCH-001 scope).
func (m *Meta) GetGenerationByID(ctx context.Context, id int64) (*LogGeneration, error) {
	if id <= 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument, "generation id is required")
	}
	if m == nil || m.db == nil {
		return nil, apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	row := m.db.QueryRowContext(ctx, `
SELECT id, profile, job, build, generation, sealed, jenkins_offset, more_data, build_complete, updated_at,
	COALESCE(packed_pack_id, ''), COALESCE(packed_at, ''), COALESCE(outcome, ''),
	COALESCE(l1_released, 0), COALESCE(l1_released_at, '')
FROM log_generations
WHERE id = ?`, id)
	g, err := scanGeneration(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeCorruptCache, "failed to load log generation", err)
	}
	return g, nil
}
