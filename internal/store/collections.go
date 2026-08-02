package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Member state values for durable collection catalog (LOG-004).
// Secret-free status strings only — never log bodies or credentials.
const (
	CollectionMemberPending  = "pending"
	CollectionMemberSealed   = "sealed"
	CollectionMemberMirrored = "mirrored"
	CollectionMemberError    = "error"
	CollectionMemberSkipped  = "skipped"
)

// LogCollection is non-secret multi-log acquisition membership metadata (schema v6).
// Log bodies are never stored here — only collection identity and seal flag.
type LogCollection struct {
	ID        string
	Profile   string
	CreatedAt time.Time
	UpdatedAt time.Time
	Sealed    bool
}

// LogCollectionMember is one job/build membership row under a collection.
// GenerationID is optional (0 when unknown). State is a non-secret status label.
// Relation is an optional non-secret pack-selection label (e.g. primary).
type LogCollectionMember struct {
	CollectionID string
	Profile      string
	Job          string
	Build        int64
	GenerationID int64 // 0 = unset / unknown
	State        string
	Relation     string
	UpdatedAt    time.Time
}

// Validate checks collection id + profile (secret-free).
func (c LogCollection) Validate() error {
	if strings.TrimSpace(c.ID) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "collection id is required")
	}
	if strings.TrimSpace(c.Profile) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "profile is required")
	}
	return nil
}

// Validate checks member fields (fail closed before write).
func (m LogCollectionMember) Validate() error {
	if strings.TrimSpace(m.CollectionID) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "collection id is required")
	}
	key := LogKey{Profile: m.Profile, Job: m.Job, Build: m.Build}
	if err := key.Validate(); err != nil {
		return err
	}
	if m.GenerationID < 0 {
		return apperr.New(apperr.CodeInvalidArgument, "generation_id must be non-negative")
	}
	return nil
}

// CreateCollection inserts a new durable collection catalog row.
// Fails if id already exists (callers allocate opaque ids).
func (m *Meta) CreateCollection(ctx context.Context, c *LogCollection) error {
	if c == nil {
		return apperr.New(apperr.CodeInvalidArgument, "collection is nil")
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if m == nil || m.db == nil {
		return apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	now := time.Now().UTC()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = now
	}
	_, err := m.db.ExecContext(ctx, `
INSERT INTO log_collections(id, profile, created_at, updated_at, sealed)
VALUES(?, ?, ?, ?, ?)`,
		strings.TrimSpace(c.ID), strings.TrimSpace(c.Profile),
		c.CreatedAt.UTC().Format(time.RFC3339Nano),
		c.UpdatedAt.UTC().Format(time.RFC3339Nano),
		boolToInt(c.Sealed),
	)
	if err != nil {
		// Duplicate id → clear conflict message (no secrets).
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return apperr.New(apperr.CodeInvalidArgument, "collection id already exists")
		}
		return apperr.Wrap(apperr.CodeInternal, "failed to create log collection", err)
	}
	return nil
}

// GetCollection loads a collection by id, enforcing same-profile isolation.
// Returns (nil, nil) when not found. Fail closed on corrupt rows.
func (m *Meta) GetCollection(ctx context.Context, collectionID, profile string) (*LogCollection, error) {
	collectionID = strings.TrimSpace(collectionID)
	profile = strings.TrimSpace(profile)
	if collectionID == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "collection id is required")
	}
	if profile == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "profile is required")
	}
	if m == nil || m.db == nil {
		return nil, apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	row := m.db.QueryRowContext(ctx, `
SELECT id, profile, created_at, updated_at, sealed
FROM log_collections
WHERE id = ? AND profile = ?`, collectionID, profile)
	c, err := scanCollection(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeCorruptCache, "failed to load log collection", err)
	}
	if err := c.Validate(); err != nil {
		return nil, apperr.Wrap(apperr.CodeCorruptCache, "corrupt log collection row", err)
	}
	// Belt-and-suspenders profile isolation (should match WHERE).
	if c.Profile != profile {
		return nil, apperr.New(apperr.CodeInternal, "collection profile mismatch")
	}
	return c, nil
}

// UpsertMember inserts or updates one collection member (membership only).
// Parent collection must exist and match profile (fail closed).
func (m *Meta) UpsertMember(ctx context.Context, mem *LogCollectionMember) error {
	if mem == nil {
		return apperr.New(apperr.CodeInvalidArgument, "collection member is nil")
	}
	if err := mem.Validate(); err != nil {
		return err
	}
	if m == nil || m.db == nil {
		return apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	// Ensure parent exists under same profile (no cross-profile membership).
	var parentProfile string
	err := m.db.QueryRowContext(ctx,
		`SELECT profile FROM log_collections WHERE id = ?`,
		strings.TrimSpace(mem.CollectionID)).Scan(&parentProfile)
	if err == sql.ErrNoRows {
		return apperr.New(apperr.CodeNotFound, "collection not found")
	}
	if err != nil {
		return apperr.Wrap(apperr.CodeCorruptCache, "failed to load collection for member upsert", err)
	}
	if strings.TrimSpace(parentProfile) != strings.TrimSpace(mem.Profile) {
		return apperr.New(apperr.CodeInvalidArgument, "collection member profile mismatch")
	}

	now := time.Now().UTC()
	if mem.UpdatedAt.IsZero() {
		mem.UpdatedAt = now
	}
	state := strings.TrimSpace(mem.State)
	if state == "" {
		state = CollectionMemberPending
	}
	rel := strings.TrimSpace(mem.Relation)
	var gen any
	if mem.GenerationID > 0 {
		gen = mem.GenerationID
	} else {
		gen = nil
	}
	_, err = m.db.ExecContext(ctx, `
INSERT INTO log_collection_members(
	collection_id, profile, job, build, generation_id, state, relation, updated_at
) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(collection_id, profile, job, build) DO UPDATE SET
	generation_id = excluded.generation_id,
	state = excluded.state,
	relation = CASE
		WHEN excluded.relation != '' THEN excluded.relation
		ELSE log_collection_members.relation
	END,
	updated_at = excluded.updated_at`,
		strings.TrimSpace(mem.CollectionID),
		strings.TrimSpace(mem.Profile),
		strings.TrimSpace(mem.Job),
		mem.Build,
		gen,
		state,
		rel,
		mem.UpdatedAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to upsert collection member", err)
	}
	// Touch parent updated_at.
	if _, err := m.db.ExecContext(ctx, `
UPDATE log_collections SET updated_at = ? WHERE id = ? AND profile = ?`,
		now.Format(time.RFC3339Nano), strings.TrimSpace(mem.CollectionID), strings.TrimSpace(mem.Profile)); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to touch collection updated_at", err)
	}
	return nil
}

// ListMembers returns all members for a collection under profile (same-profile only).
// Fail closed: corrupt rows abort the list (do not return partial untrusted data).
func (m *Meta) ListMembers(ctx context.Context, collectionID, profile string) ([]LogCollectionMember, error) {
	collectionID = strings.TrimSpace(collectionID)
	profile = strings.TrimSpace(profile)
	if collectionID == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "collection id is required")
	}
	if profile == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "profile is required")
	}
	if m == nil || m.db == nil {
		return nil, apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	// Confirm collection exists under this profile first (NotFound vs empty members).
	coll, err := m.GetCollection(ctx, collectionID, profile)
	if err != nil {
		return nil, err
	}
	if coll == nil {
		return nil, apperr.New(apperr.CodeNotFound, "collection not found")
	}

	rows, err := m.db.QueryContext(ctx, `
SELECT collection_id, profile, job, build, generation_id, state, relation, updated_at
FROM log_collection_members
WHERE collection_id = ? AND profile = ?
ORDER BY job ASC, build ASC`, collectionID, profile)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeCorruptCache, "failed to list collection members", err)
	}
	defer rows.Close()

	var out []LogCollectionMember
	for rows.Next() {
		mem, err := scanCollectionMember(rows)
		if err != nil {
			return nil, apperr.Wrap(apperr.CodeCorruptCache, "failed to scan collection member", err)
		}
		if err := mem.Validate(); err != nil {
			return nil, apperr.Wrap(apperr.CodeCorruptCache,
				fmt.Sprintf("corrupt collection member row for %s", collectionID), err)
		}
		if mem.Profile != profile || mem.CollectionID != collectionID {
			return nil, apperr.New(apperr.CodeCorruptCache, "collection member isolation violation")
		}
		out = append(out, *mem)
	}
	if err := rows.Err(); err != nil {
		return nil, apperr.Wrap(apperr.CodeCorruptCache, "failed while listing collection members", err)
	}
	return out, nil
}

// GenerationCollection maps a log generation to its durable collection membership
// (Wave 31 / ARC-011 pack affinity). Secret-free: ids and profile only — never
// log bodies or credentials.
type GenerationCollection struct {
	GenerationID int64
	CollectionID string
	Profile      string
	// Relation is an optional non-secret pack-selection label (e.g. primary).
	Relation string
}

// ListGenerationCollections returns generation_id → collection membership for
// members with GenerationID > 0 under the given profile.
//
// When profile is non-empty, only that profile's rows are returned (same-profile
// isolation). When profile is empty, all profiles are included.
//
// Deterministic: if a generation appears in multiple collections, the
// lexicographically smallest collection_id wins. Fail closed: member profile
// must match the parent collection profile and, when a log_generations row
// exists, the generation's profile (mismatch → corrupt_cache). Never returns
// log bodies.
func (m *Meta) ListGenerationCollections(ctx context.Context, profile string) (map[int64]GenerationCollection, error) {
	profile = strings.TrimSpace(profile)
	if m == nil || m.db == nil {
		return nil, apperr.New(apperr.CodeInternal, "metadata store is closed")
	}

	// Join parent collection for profile isolation; left-join generations so
	// orphan gen ids (catalog ahead of gen delete) still map, but mismatch fails.
	const qAll = `
SELECT m.generation_id, m.collection_id, m.profile, m.relation, c.profile, g.profile
FROM log_collection_members m
INNER JOIN log_collections c ON c.id = m.collection_id
LEFT JOIN log_generations g ON g.id = m.generation_id
WHERE m.generation_id IS NOT NULL AND m.generation_id > 0
ORDER BY m.generation_id ASC, m.collection_id ASC`
	const qProfile = `
SELECT m.generation_id, m.collection_id, m.profile, m.relation, c.profile, g.profile
FROM log_collection_members m
INNER JOIN log_collections c ON c.id = m.collection_id
LEFT JOIN log_generations g ON g.id = m.generation_id
WHERE m.generation_id IS NOT NULL AND m.generation_id > 0
  AND m.profile = ?
ORDER BY m.generation_id ASC, m.collection_id ASC`

	var (
		rows *sql.Rows
		err  error
	)
	if profile == "" {
		rows, err = m.db.QueryContext(ctx, qAll)
	} else {
		rows, err = m.db.QueryContext(ctx, qProfile, profile)
	}
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeCorruptCache, "failed to list generation collections", err)
	}
	defer rows.Close()

	out := make(map[int64]GenerationCollection)
	for rows.Next() {
		var genID int64
		var collID, memProfile, relation, parentProfile string
		var genProfile sql.NullString
		if err := rows.Scan(&genID, &collID, &memProfile, &relation, &parentProfile, &genProfile); err != nil {
			return nil, apperr.Wrap(apperr.CodeCorruptCache, "failed to scan generation collection", err)
		}
		collID = strings.TrimSpace(collID)
		memProfile = strings.TrimSpace(memProfile)
		relation = strings.TrimSpace(relation)
		parentProfile = strings.TrimSpace(parentProfile)
		if genID <= 0 || collID == "" || memProfile == "" {
			return nil, apperr.New(apperr.CodeCorruptCache, "corrupt generation collection row")
		}
		// Fail closed: member must match parent collection profile.
		if memProfile != parentProfile {
			return nil, apperr.New(apperr.CodeCorruptCache, "collection member profile mismatch")
		}
		// Fail closed: when generation exists, profiles must match.
		if genProfile.Valid {
			gp := strings.TrimSpace(genProfile.String)
			if gp != "" && gp != memProfile {
				return nil, apperr.New(apperr.CodeCorruptCache, "collection generation profile mismatch")
			}
		}
		if profile != "" && memProfile != profile {
			return nil, apperr.New(apperr.CodeCorruptCache, "collection member isolation violation")
		}
		// First win under ORDER BY collection_id ASC (deterministic multi-membership).
		if _, exists := out[genID]; exists {
			continue
		}
		out[genID] = GenerationCollection{
			GenerationID: genID,
			CollectionID: collID,
			Profile:      memProfile,
			Relation:     relation,
		}
	}
	if err := rows.Err(); err != nil {
		return nil, apperr.Wrap(apperr.CodeCorruptCache, "failed while listing generation collections", err)
	}
	return out, nil
}

// SetCollectionSealed updates the collection seal flag (all members sealed).
func (m *Meta) SetCollectionSealed(ctx context.Context, collectionID, profile string, sealed bool) error {
	collectionID = strings.TrimSpace(collectionID)
	profile = strings.TrimSpace(profile)
	if collectionID == "" {
		return apperr.New(apperr.CodeInvalidArgument, "collection id is required")
	}
	if profile == "" {
		return apperr.New(apperr.CodeInvalidArgument, "profile is required")
	}
	if m == nil || m.db == nil {
		return apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := m.db.ExecContext(ctx, `
UPDATE log_collections
SET sealed = ?, updated_at = ?
WHERE id = ? AND profile = ?`, boolToInt(sealed), now, collectionID, profile)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to update collection sealed", err)
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return apperr.New(apperr.CodeNotFound, "collection not found")
	}
	return nil
}

func scanCollection(row scannable) (*LogCollection, error) {
	var c LogCollection
	var sealed int
	var created, updated string
	if err := row.Scan(&c.ID, &c.Profile, &created, &updated, &sealed); err != nil {
		return nil, err
	}
	c.ID = strings.TrimSpace(c.ID)
	c.Profile = strings.TrimSpace(c.Profile)
	c.Sealed = sealed != 0
	c.CreatedAt = parseRFC3339Flexible(created)
	c.UpdatedAt = parseRFC3339Flexible(updated)
	return &c, nil
}

func scanCollectionMember(row scannable) (*LogCollectionMember, error) {
	var mem LogCollectionMember
	var genID sql.NullInt64
	var updated string
	if err := row.Scan(
		&mem.CollectionID, &mem.Profile, &mem.Job, &mem.Build,
		&genID, &mem.State, &mem.Relation, &updated,
	); err != nil {
		return nil, err
	}
	mem.CollectionID = strings.TrimSpace(mem.CollectionID)
	mem.Profile = strings.TrimSpace(mem.Profile)
	mem.Job = strings.TrimSpace(mem.Job)
	mem.State = strings.TrimSpace(mem.State)
	mem.Relation = strings.TrimSpace(mem.Relation)
	if genID.Valid {
		mem.GenerationID = genID.Int64
	}
	mem.UpdatedAt = parseRFC3339Flexible(updated)
	return &mem, nil
}

func parseRFC3339Flexible(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Time{}
}
