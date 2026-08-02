package store

import (
	"context"
	"database/sql"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// MetaStats is a non-secret summary of the L1 metadata store (OPS-001 / ARC-007).
type MetaStats struct {
	SchemaVersion   int   `json:"schemaVersion"`
	Generations     int64 `json:"generations"`
	Chunks          int64 `json:"chunks"`
	L1PhysicalBytes int64 `json:"l1PhysicalBytes,omitempty"`
	L1LogicalBytes  int64 `json:"l1LogicalBytes,omitempty"`
}

// Stats returns row counts, optional L1 byte totals, and schema version.
// Never includes job names or secrets.
func (m *Meta) Stats(ctx context.Context) (MetaStats, error) {
	if m == nil || m.db == nil {
		return MetaStats{}, apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	ver, err := m.SchemaVersion(ctx)
	if err != nil {
		return MetaStats{}, err
	}
	var gens, chunks sql.NullInt64
	if err := m.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM log_generations`).Scan(&gens); err != nil {
		return MetaStats{}, apperr.Wrap(apperr.CodeCorruptCache, "failed to count log generations", err)
	}
	if err := m.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM chunks`).Scan(&chunks); err != nil {
		return MetaStats{}, apperr.Wrap(apperr.CodeCorruptCache, "failed to count chunks", err)
	}
	phys, logical, err := m.SumL1Bytes(ctx)
	if err != nil {
		return MetaStats{}, err
	}
	return MetaStats{
		SchemaVersion:   ver,
		Generations:     gens.Int64,
		Chunks:          chunks.Int64,
		L1PhysicalBytes: phys,
		L1LogicalBytes:  logical,
	}, nil
}
