package cachecontrol

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	_ "modernc.org/sqlite"
)

// OverrideStore is a revisioned runtime override database (cache-control.sqlite).
type OverrideStore struct {
	db   *sql.DB
	path string
	mu   sync.Mutex
}

// OpenOverrideStore opens or creates cache-control.sqlite under dir.
func OpenOverrideStore(dir string) (*OverrideStore, error) {
	if dir == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "override store dir required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "mkdir cache-control", err)
	}
	path := filepath.Join(dir, "cache-control.sqlite")
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "open cache-control.sqlite", err)
	}
	db.SetMaxOpenConns(1)
	s := &OverrideStore{db: db, path: path}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *OverrideStore) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS cache_config_revision (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  revision INTEGER NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cache_runtime_override (
  profile_id TEXT NOT NULL,
  type_id TEXT NOT NULL,
  field_path TEXT NOT NULL,
  value_json TEXT NOT NULL,
  actor_id_hash TEXT NOT NULL,
  source TEXT NOT NULL,
  reason TEXT,
  expires_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  revision INTEGER NOT NULL,
  PRIMARY KEY (profile_id, type_id, field_path)
);
CREATE TABLE IF NOT EXISTS cache_type_epoch (
  profile_id TEXT NOT NULL,
  type_id TEXT NOT NULL,
  purge_epoch INTEGER NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (profile_id, type_id)
);
CREATE TABLE IF NOT EXISTS cache_operation (
  plan_id TEXT PRIMARY KEY,
  profile_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  type_id TEXT NOT NULL,
  dump_mode TEXT,
  confirm_token TEXT NOT NULL,
  fingerprint TEXT,
  state TEXT NOT NULL,
  estimated_bytes INTEGER,
  estimated_count INTEGER,
  actor_id_hash TEXT,
  source TEXT,
  reason TEXT,
  notes TEXT,
  expires_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  config_revision INTEGER,
  purge_epoch INTEGER,
  error_code TEXT
);
INSERT OR IGNORE INTO cache_config_revision(singleton, revision, updated_at)
  VALUES (1, 0, datetime('now'));
`)
	return err
}

// Close closes the database.
func (s *OverrideStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Path returns the sqlite path (for tests/doctor; may be redacted in admin).
func (s *OverrideStore) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Revision returns the current config revision.
func (s *OverrideStore) Revision(ctx context.Context) (uint64, error) {
	if s == nil {
		return 0, nil
	}
	var rev int64
	err := s.db.QueryRowContext(ctx, `SELECT revision FROM cache_config_revision WHERE singleton=1`).Scan(&rev)
	if err != nil {
		return 0, apperr.Wrap(apperr.CodeCorruptCache, "read revision", err)
	}
	if rev < 0 {
		return 0, nil
	}
	return uint64(rev), nil
}

// LoadOverrides loads non-expired overrides for a profile as RuntimeOverrides.
func (s *OverrideStore) LoadOverrides(ctx context.Context, profileID string, now time.Time) (*RuntimeOverrides, error) {
	if s == nil {
		return &RuntimeOverrides{Revision: 0, Types: map[TypeID]TypeConfig{}}, nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	rev, err := s.Revision(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT type_id, field_path, value_json, expires_at
FROM cache_runtime_override WHERE profile_id = ?`, profileID)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeCorruptCache, "list overrides", err)
	}
	defer rows.Close()

	out := &RuntimeOverrides{Revision: rev, Types: map[TypeID]TypeConfig{}}
	for rows.Next() {
		var typeID, fieldPath, valueJSON string
		var expires sql.NullString
		if err := rows.Scan(&typeID, &fieldPath, &valueJSON, &expires); err != nil {
			return nil, err
		}
		if expires.Valid && expires.String != "" {
			exp, err := time.Parse(time.RFC3339, expires.String)
			if err != nil {
				// Fail closed: a corrupt expiry must not turn a time-boxed
				// override (e.g. emergency mode=off) into a permanent one.
				return nil, apperr.Wrap(apperr.CodeCorruptCache,
					"override "+typeID+"."+fieldPath+" has malformed expires_at", err)
			}
			if now.After(exp) {
				continue // expired ignored
			}
		}
		tid := TypeID(typeID)
		if !tid.Valid() {
			continue
		}
		tc := out.Types[tid]
		if err := applyFieldPatch(&tc, fieldPath, valueJSON); err != nil {
			return nil, fmt.Errorf("override %s.%s: %w", typeID, fieldPath, err)
		}
		out.Types[tid] = tc
	}
	return out, rows.Err()
}

// PatchRequest is a CAS runtime override mutation.
type PatchRequest struct {
	ProfileID        string
	ExpectedRevision uint64
	Reason           string
	ActorIDHash      string
	Source           string // admin_http | admin_mcp | cli
	ExpiresAt        *time.Time
	// Types maps type → partial TypeConfig (only set fields applied).
	Types map[TypeID]TypeConfig
}

// PatchResult is returned after a successful CAS update.
type PatchResult struct {
	Revision uint64
}

// Patch applies overrides with compare-and-swap on revision.
func (s *OverrideStore) Patch(ctx context.Context, req PatchRequest) (PatchResult, error) {
	if s == nil {
		return PatchResult{}, apperr.New(apperr.CodeInternal, "override store is nil")
	}
	if req.ProfileID == "" {
		return PatchResult{}, apperr.New(apperr.CodeInvalidArgument, "profile_id required")
	}
	if req.ActorIDHash == "" {
		req.ActorIDHash = "unknown"
	}
	if req.Source == "" {
		req.Source = "unknown"
	}
	for id := range req.Types {
		if !id.Valid() {
			return PatchResult{}, fmt.Errorf("%s: %s", ReasonUnknownType, id)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PatchResult{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var cur int64
	if err := tx.QueryRowContext(ctx, `SELECT revision FROM cache_config_revision WHERE singleton=1`).Scan(&cur); err != nil {
		return PatchResult{}, err
	}
	if uint64(cur) != req.ExpectedRevision {
		return PatchResult{}, fmt.Errorf("%s: expected %d current %d", ReasonCASConflict, req.ExpectedRevision, cur)
	}
	next := cur + 1
	now := time.Now().UTC().Format(time.RFC3339)
	var exp any
	if req.ExpiresAt != nil {
		exp = req.ExpiresAt.UTC().Format(time.RFC3339)
	}

	for id, tc := range req.Types {
		fields, err := typeConfigToFields(tc)
		if err != nil {
			return PatchResult{}, err
		}
		for path, valJSON := range fields {
			_, err := tx.ExecContext(ctx, `
INSERT INTO cache_runtime_override(
  profile_id, type_id, field_path, value_json, actor_id_hash, source, reason, expires_at, created_at, updated_at, revision
) VALUES (?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(profile_id, type_id, field_path) DO UPDATE SET
  value_json=excluded.value_json,
  actor_id_hash=excluded.actor_id_hash,
  source=excluded.source,
  reason=excluded.reason,
  expires_at=excluded.expires_at,
  updated_at=excluded.updated_at,
  revision=excluded.revision
`, req.ProfileID, string(id), path, valJSON, req.ActorIDHash, req.Source, req.Reason, exp, now, now, next)
			if err != nil {
				return PatchResult{}, err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE cache_config_revision SET revision=?, updated_at=? WHERE singleton=1`, next, now); err != nil {
		return PatchResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return PatchResult{}, err
	}
	return PatchResult{Revision: uint64(next)}, nil
}

// Reset removes runtime overrides for a type (or all types if typeID empty).
func (s *OverrideStore) Reset(ctx context.Context, profileID string, typeID TypeID, expectedRevision uint64) (PatchResult, error) {
	if s == nil {
		return PatchResult{}, apperr.New(apperr.CodeInternal, "override store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PatchResult{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var cur int64
	if err := tx.QueryRowContext(ctx, `SELECT revision FROM cache_config_revision WHERE singleton=1`).Scan(&cur); err != nil {
		return PatchResult{}, err
	}
	if uint64(cur) != expectedRevision {
		return PatchResult{}, fmt.Errorf("%s: expected %d current %d", ReasonCASConflict, expectedRevision, cur)
	}
	next := cur + 1
	now := time.Now().UTC().Format(time.RFC3339)
	if typeID == "" {
		if _, err := tx.ExecContext(ctx, `DELETE FROM cache_runtime_override WHERE profile_id=?`, profileID); err != nil {
			return PatchResult{}, err
		}
	} else {
		if !typeID.Valid() {
			return PatchResult{}, fmt.Errorf("%s: %s", ReasonUnknownType, typeID)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM cache_runtime_override WHERE profile_id=? AND type_id=?`, profileID, string(typeID)); err != nil {
			return PatchResult{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE cache_config_revision SET revision=?, updated_at=? WHERE singleton=1`, next, now); err != nil {
		return PatchResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return PatchResult{}, err
	}
	return PatchResult{Revision: uint64(next)}, nil
}

// BumpPurgeEpoch increments the purge epoch for a type (late-fill protection).
func (s *OverrideStore) BumpPurgeEpoch(ctx context.Context, profileID string, typeID TypeID) (uint64, error) {
	if s == nil {
		return 0, apperr.New(apperr.CodeInternal, "override store is nil")
	}
	if !typeID.Valid() {
		return 0, fmt.Errorf("%s: %s", ReasonUnknownType, typeID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC().Format(time.RFC3339)
	var cur int64
	err := s.db.QueryRowContext(ctx, `SELECT purge_epoch FROM cache_type_epoch WHERE profile_id=? AND type_id=?`,
		profileID, string(typeID)).Scan(&cur)
	if err == sql.ErrNoRows {
		cur = 0
	} else if err != nil {
		return 0, err
	}
	next := cur + 1
	_, err = s.db.ExecContext(ctx, `
INSERT INTO cache_type_epoch(profile_id, type_id, purge_epoch, updated_at) VALUES (?,?,?,?)
ON CONFLICT(profile_id, type_id) DO UPDATE SET purge_epoch=excluded.purge_epoch, updated_at=excluded.updated_at
`, profileID, string(typeID), next, now)
	if err != nil {
		return 0, err
	}
	return uint64(next), nil
}

// LoadPurgeEpochs returns all purge epochs for a profile.
func (s *OverrideStore) LoadPurgeEpochs(ctx context.Context, profileID string) (map[TypeID]uint64, error) {
	out := map[TypeID]uint64{}
	if s == nil {
		return out, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT type_id, purge_epoch FROM cache_type_epoch WHERE profile_id=?`, profileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var ep int64
		if err := rows.Scan(&id, &ep); err != nil {
			return nil, err
		}
		out[TypeID(id)] = uint64(ep)
	}
	return out, rows.Err()
}

// OperationRecord is a durable plan/execution row (secret-free).
type OperationRecord struct {
	PlanID         string
	ProfileID      string
	Kind           OperationKind
	TypeID         TypeID
	DumpMode       DumpMode
	ConfirmToken   string
	Fingerprint    string
	State          OperationState
	EstimatedBytes int64
	EstimatedCount int64
	ActorIDHash    string
	Source         string
	Reason         string
	Notes          string
	ExpiresAtUnix  int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
	ConfigRevision uint64
	PurgeEpoch     uint64
	ErrorCode      string
}

// SavePlan persists a planned operation (CAS not required; plan_id is unique).
func (s *OverrideStore) SavePlan(ctx context.Context, rec OperationRecord) error {
	if s == nil {
		return apperr.New(apperr.CodeInternal, "override store is nil")
	}
	if rec.PlanID == "" || rec.ConfirmToken == "" {
		return apperr.New(apperr.CodeInvalidArgument, "plan_id and confirm_token required")
	}
	if rec.State == "" {
		rec.State = OpStatePlanned
	}
	now := time.Now().UTC()
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = now
	}
	rec.UpdatedAt = now
	var exp any
	if rec.ExpiresAtUnix > 0 {
		exp = time.Unix(rec.ExpiresAtUnix, 0).UTC().Format(time.RFC3339)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.ExecContext(ctx, `
INSERT INTO cache_operation(
  plan_id, profile_id, kind, type_id, dump_mode, confirm_token, fingerprint, state,
  estimated_bytes, estimated_count, actor_id_hash, source, reason, notes, expires_at,
  created_at, updated_at, config_revision, purge_epoch, error_code
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
`, rec.PlanID, rec.ProfileID, string(rec.Kind), string(rec.TypeID), string(rec.DumpMode),
		rec.ConfirmToken, rec.Fingerprint, string(rec.State), rec.EstimatedBytes, rec.EstimatedCount,
		rec.ActorIDHash, rec.Source, rec.Reason, rec.Notes, exp,
		rec.CreatedAt.UTC().Format(time.RFC3339), rec.UpdatedAt.UTC().Format(time.RFC3339),
		int64(rec.ConfigRevision), int64(rec.PurgeEpoch), rec.ErrorCode)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "save cache operation plan", err)
	}
	return nil
}

// LoadPlan loads a plan by id.
func (s *OverrideStore) LoadPlan(ctx context.Context, planID string) (OperationRecord, error) {
	if s == nil {
		return OperationRecord{}, apperr.New(apperr.CodeInternal, "override store is nil")
	}
	var rec OperationRecord
	var kind, typeID, dumpMode, state, created, updated string
	var exp sql.NullString // nullable: plans saved without an expiry store NULL
	var estB, estC, cfgRev, pe int64
	err := s.db.QueryRowContext(ctx, `
SELECT plan_id, profile_id, kind, type_id, dump_mode, confirm_token, fingerprint, state,
  estimated_bytes, estimated_count, actor_id_hash, source, reason, notes, expires_at,
  created_at, updated_at, config_revision, purge_epoch, error_code
FROM cache_operation WHERE plan_id=?`, planID).Scan(
		&rec.PlanID, &rec.ProfileID, &kind, &typeID, &dumpMode, &rec.ConfirmToken, &rec.Fingerprint, &state,
		&estB, &estC, &rec.ActorIDHash, &rec.Source, &rec.Reason, &rec.Notes, &exp,
		&created, &updated, &cfgRev, &pe, &rec.ErrorCode,
	)
	if err == sql.ErrNoRows {
		return OperationRecord{}, apperr.New(apperr.CodeNotFound, "operation plan not found")
	}
	if err != nil {
		return OperationRecord{}, apperr.Wrap(apperr.CodeCorruptCache, "load operation plan", err)
	}
	rec.Kind = OperationKind(kind)
	rec.TypeID = TypeID(typeID)
	rec.DumpMode = DumpMode(dumpMode)
	rec.State = OperationState(state)
	rec.EstimatedBytes = estB
	rec.EstimatedCount = estC
	rec.ConfigRevision = uint64(cfgRev)
	rec.PurgeEpoch = uint64(pe)
	if exp.Valid && exp.String != "" {
		if t, e := time.Parse(time.RFC3339, exp.String); e == nil {
			rec.ExpiresAtUnix = t.Unix()
		}
	}
	if t, e := time.Parse(time.RFC3339, created); e == nil {
		rec.CreatedAt = t
	}
	if t, e := time.Parse(time.RFC3339, updated); e == nil {
		rec.UpdatedAt = t
	}
	return rec, nil
}

// UpdatePlanState updates state and optional error_code for a plan.
func (s *OverrideStore) UpdatePlanState(ctx context.Context, planID string, state OperationState, errorCode string, purgeEpoch uint64) error {
	if s == nil {
		return apperr.New(apperr.CodeInternal, "override store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx, `
UPDATE cache_operation SET state=?, error_code=?, purge_epoch=?, updated_at=? WHERE plan_id=?`,
		string(state), errorCode, int64(purgeEpoch), now, planID)
	return err
}

func typeConfigToFields(tc TypeConfig) (map[string]string, error) {
	out := map[string]string{}
	if tc.Mode != nil {
		b, _ := json.Marshal(string(*tc.Mode))
		out["mode"] = string(b)
	}
	if tc.TelemetryEnabled != nil {
		b, _ := json.Marshal(*tc.TelemetryEnabled)
		out["telemetryEnabled"] = string(b)
	}
	if tc.FleetShare != nil && tc.FleetShare.Enabled != nil {
		b, _ := json.Marshal(*tc.FleetShare.Enabled)
		out["fleetShare.enabled"] = string(b)
	}
	if tc.Quota != nil {
		if tc.Quota.SoftBytes != nil {
			b, _ := json.Marshal(*tc.Quota.SoftBytes)
			out["quota.softBytes"] = string(b)
		}
		if tc.Quota.HardBytes != nil {
			b, _ := json.Marshal(*tc.Quota.HardBytes)
			out["quota.hardBytes"] = string(b)
		}
	}
	if tc.MaxEntries != nil {
		b, _ := json.Marshal(*tc.MaxEntries)
		out["maxEntries"] = string(b)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: empty patch", ReasonUnknownField)
	}
	return out, nil
}

func applyFieldPatch(tc *TypeConfig, fieldPath, valueJSON string) error {
	switch fieldPath {
	case "mode":
		var s string
		if err := json.Unmarshal([]byte(valueJSON), &s); err != nil {
			return err
		}
		m, err := ParseMode(s)
		if err != nil {
			return err
		}
		tc.Mode = &m
	case "telemetryEnabled":
		var v bool
		if err := json.Unmarshal([]byte(valueJSON), &v); err != nil {
			return err
		}
		tc.TelemetryEnabled = &v
	case "fleetShare.enabled":
		var v bool
		if err := json.Unmarshal([]byte(valueJSON), &v); err != nil {
			return err
		}
		tc.FleetShare = &FleetShareConfig{Enabled: &v}
	case "quota.softBytes":
		var v int64
		if err := json.Unmarshal([]byte(valueJSON), &v); err != nil {
			return err
		}
		if tc.Quota == nil {
			tc.Quota = &QuotaConfig{}
		}
		tc.Quota.SoftBytes = &v
	case "quota.hardBytes":
		var v int64
		if err := json.Unmarshal([]byte(valueJSON), &v); err != nil {
			return err
		}
		if tc.Quota == nil {
			tc.Quota = &QuotaConfig{}
		}
		tc.Quota.HardBytes = &v
	case "maxEntries":
		var v int
		if err := json.Unmarshal([]byte(valueJSON), &v); err != nil {
			return err
		}
		tc.MaxEntries = &v
	default:
		return fmt.Errorf("%s: %s", ReasonUnknownField, fieldPath)
	}
	return nil
}
