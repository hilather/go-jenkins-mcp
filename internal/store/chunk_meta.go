package store

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// InsertChunk records a committed frame. Call only after the frame file is durable.
func (m *Meta) InsertChunk(ctx context.Context, c *Chunk, checkpoints []LineCheckpoint) error {
	if m == nil || m.db == nil {
		return apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	if c == nil {
		return apperr.New(apperr.CodeInvalidArgument, "chunk is nil")
	}
	if c.GenerationID <= 0 {
		return apperr.New(apperr.CodeInvalidArgument, "generation_id is required")
	}
	if c.Seq < 0 {
		return apperr.New(apperr.CodeInvalidArgument, "seq must be non-negative")
	}
	if c.RawEnd < c.RawStart {
		return apperr.New(apperr.CodeInvalidArgument, "raw_end must be >= raw_start")
	}
	if c.UncompressedSize != c.RawEnd-c.RawStart {
		return apperr.New(apperr.CodeInvalidArgument, "uncompressed_size must equal raw_end-raw_start")
	}
	if c.ContentSHA256 == "" || c.FrameSHA256 == "" {
		return apperr.New(apperr.CodeInvalidArgument, "content and frame checksums are required")
	}
	if c.RelPath == "" {
		return apperr.New(apperr.CodeInvalidArgument, "rel_path is required")
	}
	if c.Codec == "" {
		c.Codec = CodecZstd
	}
	if c.FormatVersion == 0 {
		c.FormatVersion = FrameFormatVersion
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if c.CreatedAt == "" {
		c.CreatedAt = now
	}

	return m.WithTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
INSERT INTO chunks(
	generation_id, seq, raw_start, raw_end, line_start, line_end,
	uncompressed_size, compressed_size, content_sha256, frame_sha256,
	codec, codec_level, format_version, dict_id, rel_path, created_at,
	enc_alg, enc_key_version
) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			c.GenerationID, c.Seq, c.RawStart, c.RawEnd, c.LineStart, c.LineEnd,
			c.UncompressedSize, c.CompressedSize, c.ContentSHA256, c.FrameSHA256,
			c.Codec, c.CodecLevel, c.FormatVersion, nullIfEmpty(c.DictID), c.RelPath, c.CreatedAt,
			nullIfEmpty(c.EncAlg), c.EncKeyVersion,
		)
		if err != nil {
			return apperr.Wrap(apperr.CodeInternal, "failed to insert chunk", err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			return apperr.Wrap(apperr.CodeInternal, "failed to read chunk id", err)
		}
		c.ID = id
		for _, cp := range checkpoints {
			if _, err := tx.ExecContext(ctx, `
INSERT INTO line_checkpoints(chunk_id, line_no, raw_offset) VALUES(?, ?, ?)`,
				id, cp.LineNo, cp.RawOffset); err != nil {
				return apperr.Wrap(apperr.CodeInternal, "failed to insert line checkpoint", err)
			}
		}
		return nil
	})
}

// ListChunks returns committed frames for a generation ordered by seq.
func (m *Meta) ListChunks(ctx context.Context, generationID int64) ([]Chunk, error) {
	if m == nil || m.db == nil {
		return nil, apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	if generationID <= 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument, "generation_id is required")
	}
	rows, err := m.db.QueryContext(ctx, `
SELECT id, generation_id, seq, raw_start, raw_end, line_start, line_end,
	uncompressed_size, compressed_size, content_sha256, frame_sha256,
	codec, codec_level, format_version, dict_id, rel_path, created_at,
	enc_alg, enc_key_version
FROM chunks
WHERE generation_id = ?
ORDER BY seq ASC`, generationID)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeCorruptCache, "failed to list chunks", err)
	}
	defer rows.Close()
	var out []Chunk
	for rows.Next() {
		c, err := scanChunk(rows)
		if err != nil {
			return nil, apperr.Wrap(apperr.CodeCorruptCache, "failed to scan chunk", err)
		}
		out = append(out, *c)
	}
	if err := rows.Err(); err != nil {
		return nil, apperr.Wrap(apperr.CodeCorruptCache, "failed to iterate chunks", err)
	}
	return out, nil
}

// ChunksIntersectingRaw returns frames whose [raw_start, raw_end) intersects [start, end).
func (m *Meta) ChunksIntersectingRaw(ctx context.Context, generationID, start, end int64) ([]Chunk, error) {
	if end < start {
		return nil, apperr.New(apperr.CodeInvalidArgument, "end must be >= start")
	}
	if start == end {
		return nil, nil
	}
	chunks, err := m.ListChunks(ctx, generationID)
	if err != nil {
		return nil, err
	}
	var out []Chunk
	for _, c := range chunks {
		if c.RawEnd > start && c.RawStart < end {
			out = append(out, c)
		}
	}
	return out, nil
}

// ChunksIntersectingLines returns frames whose [line_start, line_end) intersects [startLine, endLine).
func (m *Meta) ChunksIntersectingLines(ctx context.Context, generationID, startLine, endLine int64) ([]Chunk, error) {
	if endLine < startLine {
		return nil, apperr.New(apperr.CodeInvalidArgument, "endLine must be >= startLine")
	}
	if startLine == endLine {
		return nil, nil
	}
	chunks, err := m.ListChunks(ctx, generationID)
	if err != nil {
		return nil, err
	}
	var out []Chunk
	for _, c := range chunks {
		if c.LineEnd > startLine && c.LineStart < endLine {
			out = append(out, c)
		}
	}
	return out, nil
}

// DurableRawEnd is the exclusive end of the last committed frame (0 if none).
// When L1 has been released, falls back to log_generations.jenkins_offset so
// Tail/State remain correct without chunk rows (ARC-005 residual).
func (m *Meta) DurableRawEnd(ctx context.Context, generationID int64) (int64, error) {
	if m == nil || m.db == nil {
		return 0, apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	var end sql.NullInt64
	err := m.db.QueryRowContext(ctx,
		`SELECT MAX(raw_end) FROM chunks WHERE generation_id = ?`, generationID).Scan(&end)
	if err != nil {
		return 0, apperr.Wrap(apperr.CodeCorruptCache, "failed to read durable raw end", err)
	}
	if end.Valid {
		return end.Int64, nil
	}
	// No chunks: sealed L1-released generations keep size in jenkins_offset.
	g, err := m.GetGenerationByID(ctx, generationID)
	if err != nil {
		return 0, err
	}
	if g != nil && g.L1Released && g.JenkinsOffset > 0 {
		return g.JenkinsOffset, nil
	}
	return 0, nil
}

// NextChunkSeq returns the next free seq for a generation (0 if none).
func (m *Meta) NextChunkSeq(ctx context.Context, generationID int64) (int, error) {
	if m == nil || m.db == nil {
		return 0, apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	var seq sql.NullInt64
	err := m.db.QueryRowContext(ctx,
		`SELECT MAX(seq) FROM chunks WHERE generation_id = ?`, generationID).Scan(&seq)
	if err != nil {
		return 0, apperr.Wrap(apperr.CodeCorruptCache, "failed to read next chunk seq", err)
	}
	if !seq.Valid {
		return 0, nil
	}
	return int(seq.Int64) + 1, nil
}

// LineStateAtDurable returns the exclusive line index after the last durable byte.
// With no chunks, returns 0.
func (m *Meta) LineStateAtDurable(ctx context.Context, generationID int64) (lineEnd int64, err error) {
	if m == nil || m.db == nil {
		return 0, apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	var le sql.NullInt64
	err = m.db.QueryRowContext(ctx, `
SELECT line_end FROM chunks
WHERE generation_id = ?
ORDER BY seq DESC LIMIT 1`, generationID).Scan(&le)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, apperr.Wrap(apperr.CodeCorruptCache, "failed to read line state", err)
	}
	if !le.Valid {
		return 0, nil
	}
	return le.Int64, nil
}

// DeleteChunkRow removes a chunk metadata row (recovery / quarantine helpers).
func (m *Meta) DeleteChunkRow(ctx context.Context, chunkID int64) error {
	if m == nil || m.db == nil {
		return apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	_, err := m.db.ExecContext(ctx, `DELETE FROM chunks WHERE id = ?`, chunkID)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to delete chunk", err)
	}
	return nil
}

// ListAllChunkRelPaths returns all committed frame relative paths (for recovery).
func (m *Meta) ListAllChunkRelPaths(ctx context.Context) (map[string]int64, error) {
	if m == nil || m.db == nil {
		return nil, apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	rows, err := m.db.QueryContext(ctx, `SELECT id, rel_path FROM chunks`)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeCorruptCache, "failed to list chunk paths", err)
	}
	defer rows.Close()
	out := make(map[string]int64)
	for rows.Next() {
		var id int64
		var rel string
		if err := rows.Scan(&id, &rel); err != nil {
			return nil, apperr.Wrap(apperr.CodeCorruptCache, "failed to scan chunk path", err)
		}
		out[filepathToSlash(rel)] = id
	}
	return out, rows.Err()
}

func filepathToSlash(p string) string {
	// Paths are stored with forward slashes (FrameRelPath).
	return strings.ReplaceAll(p, "\\", "/")
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func scanChunk(row scannable) (*Chunk, error) {
	var c Chunk
	var dict sql.NullString
	var encAlg sql.NullString
	var encVer sql.NullInt64
	err := row.Scan(
		&c.ID, &c.GenerationID, &c.Seq, &c.RawStart, &c.RawEnd, &c.LineStart, &c.LineEnd,
		&c.UncompressedSize, &c.CompressedSize, &c.ContentSHA256, &c.FrameSHA256,
		&c.Codec, &c.CodecLevel, &c.FormatVersion, &dict, &c.RelPath, &c.CreatedAt,
		&encAlg, &encVer,
	)
	if err != nil {
		return nil, err
	}
	if dict.Valid {
		c.DictID = dict.String
	}
	if encAlg.Valid {
		c.EncAlg = encAlg.String
	}
	if encVer.Valid {
		c.EncKeyVersion = int(encVer.Int64)
	}
	return &c, nil
}

// DeleteChunksForGeneration removes all chunk and line_checkpoint rows for a
// generation (CASCADE on checkpoints). Does not delete frame files.
func (m *Meta) DeleteChunksForGeneration(ctx context.Context, generationID int64) error {
	if generationID <= 0 {
		return apperr.New(apperr.CodeInvalidArgument, "generation id is required")
	}
	if m == nil || m.db == nil {
		return apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	_, err := m.db.ExecContext(ctx, `DELETE FROM chunks WHERE generation_id = ?`, generationID)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to delete generation chunks", err)
	}
	return nil
}

// MarkGenerationL1Released sets l1_released after L1 frames have been (or are
// about to be) purged following verified L2 pack (ARC-005 residual).
func (m *Meta) MarkGenerationL1Released(ctx context.Context, id int64) error {
	if id <= 0 {
		return apperr.New(apperr.CodeInvalidArgument, "generation id is required")
	}
	if m == nil || m.db == nil {
		return apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	var sealed int
	var packID string
	err := m.db.QueryRowContext(ctx,
		`SELECT sealed, COALESCE(packed_pack_id, '') FROM log_generations WHERE id = ?`, id).
		Scan(&sealed, &packID)
	if err == sql.ErrNoRows {
		return apperr.New(apperr.CodeNotFound, "log generation not found")
	}
	if err != nil {
		return apperr.Wrap(apperr.CodeCorruptCache, "failed to load generation for L1 release", err)
	}
	if sealed == 0 {
		return apperr.New(apperr.CodeInvalidArgument, "cannot release L1 for unsealed generation")
	}
	if strings.TrimSpace(packID) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "cannot release L1 without packed_pack_id")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := m.db.ExecContext(ctx, `
UPDATE log_generations
SET l1_released = 1, l1_released_at = ?, updated_at = ?
WHERE id = ? AND sealed = 1 AND packed_pack_id IS NOT NULL AND packed_pack_id != ''`,
		now, now, id)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to mark L1 released", err)
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return apperr.New(apperr.CodeNotFound, "log generation not found")
	}
	return nil
}
