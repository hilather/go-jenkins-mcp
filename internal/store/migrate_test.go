package store_test

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/store"
)

// QA-004: upgrade fixtures from every released schema version (1..Current-1 and current).
//
// Survival notes:
//   - log_generations rows survive all steps (v3+ packed_* columns; v4 outcome; v5 l1_released).
//   - v1 stub chunks are dropped at v2 (pilot: no production rows expected).
//   - v2+ full frame chunk + line_checkpoint rows survive to current.
//   - v3 packed_pack_id / packed_at survive.
//   - v4 pins + outcome survive.
//   - v5 l1_released defaults to 0 when upgrading; explicit seed when through>=5.
//   - v6 log_collections / log_collection_members survive; tables appear after upgrade from <6.
//   - v7 survey_summary_cache appears after upgrade from <7; seeded compact rows survive when through>=7.

func TestMigrate_UpgradeFromEveryPriorSchema(t *testing.T) {
	ctx := context.Background()
	// Every released version including current (idempotent open).
	for through := 1; through <= store.CurrentSchemaVersion; through++ {
		through := through
		t.Run("from_v"+strconv.Itoa(through), func(t *testing.T) {
			dir := t.TempDir()
			dataDir := filepath.Join(dir, "profiles", "corp")
			dbPath, err := store.CreateMetaDBAtVersion(dataDir, through)
			if err != nil {
				t.Fatalf("CreateMetaDBAtVersion(%d): %v", through, err)
			}
			seed := seedMetaAtVersion(t, dbPath, through)

			// Open applies remaining migrations transactionally.
			m, err := store.Open(dataDir)
			if err != nil {
				t.Fatalf("Open from v%d: %v", through, err)
			}
			defer m.Close()

			ver, err := m.SchemaVersion(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if ver != store.CurrentSchemaVersion {
				t.Fatalf("schema: got %d want %d", ver, store.CurrentSchemaVersion)
			}

			// Generation identity + progressive fields must survive.
			got, err := m.GetGeneration(ctx, store.LogKey{
				Profile: seed.Profile, Job: seed.Job, Build: seed.Build,
			}, seed.Generation)
			if err != nil || got == nil {
				t.Fatalf("generation after migrate: err=%v got=%+v", err, got)
			}
			if got.JenkinsOffset != seed.JenkinsOffset {
				t.Fatalf("jenkins_offset: got %d want %d", got.JenkinsOffset, seed.JenkinsOffset)
			}
			if got.Sealed != seed.Sealed {
				t.Fatalf("sealed: got %v want %v", got.Sealed, seed.Sealed)
			}

			// packed_* from v3+ fixtures.
			if through >= 3 {
				if got.PackedPackID != seed.PackedPackID {
					t.Fatalf("packed_pack_id: got %q want %q", got.PackedPackID, seed.PackedPackID)
				}
				if seed.PackedPackID != "" && got.PackedAt.IsZero() {
					t.Fatal("packed_at empty after migrate")
				}
			}

			// outcome + pins from v4 fixtures.
			if through >= 4 {
				if got.Outcome != seed.Outcome {
					t.Fatalf("outcome: got %q want %q", got.Outcome, seed.Outcome)
				}
				pinned, err := m.IsPinned(ctx, store.PinKindGeneration, strconv.FormatInt(got.ID, 10))
				if err != nil {
					t.Fatal(err)
				}
				if !pinned {
					t.Fatal("generation pin must survive open at v4")
				}
				packPinned, err := m.IsPinned(ctx, store.PinKindPack, seed.PinPackID)
				if err != nil {
					t.Fatal(err)
				}
				if !packPinned {
					t.Fatal("pack pin must survive open at v4")
				}
			}

			// l1_released from v5 fixtures (default false when upgrading from <5).
			if through >= 5 {
				if got.L1Released != seed.L1Released {
					t.Fatalf("l1_released: got %v want %v", got.L1Released, seed.L1Released)
				}
			} else if got.L1Released {
				t.Fatal("l1_released must default false after upgrade from <v5")
			}

			// v6 collection catalog tables must exist after open.
			var collTables int
			if err := m.DB().QueryRow(`
SELECT COUNT(1) FROM sqlite_master
WHERE type='table' AND name IN ('log_collections','log_collection_members')`).Scan(&collTables); err != nil {
				t.Fatal(err)
			}
			if collTables != 2 {
				t.Fatalf("v6 collection tables missing after migrate: %d", collTables)
			}
			// Collection membership seeded at v6 must survive reopen (through>=6).
			if through >= 6 {
				c, err := m.GetCollection(ctx, seed.CollectionID, seed.Profile)
				if err != nil || c == nil {
					t.Fatalf("collection after migrate: err=%v got=%+v", err, c)
				}
				members, err := m.ListMembers(ctx, seed.CollectionID, seed.Profile)
				if err != nil {
					t.Fatal(err)
				}
				if len(members) != 1 || members[0].Job != seed.Job || members[0].Build != seed.Build {
					t.Fatalf("collection members after migrate: %+v", members)
				}
				if members[0].State != store.CollectionMemberMirrored {
					t.Fatalf("member state: %q", members[0].State)
				}
			} else {
				// Fresh tables after upgrade from <6: empty catalog is usable.
				if err := m.CreateCollection(ctx, &store.LogCollection{
					ID: "post-migrate-coll", Profile: seed.Profile,
				}); err != nil {
					t.Fatalf("CreateCollection after migrate from v%d: %v", through, err)
				}
			}

			// v7 survey compact cache table must exist after open.
			var surveyTables int
			if err := m.DB().QueryRow(`
SELECT COUNT(1) FROM sqlite_master
WHERE type='table' AND name = 'survey_summary_cache'`).Scan(&surveyTables); err != nil {
				t.Fatal(err)
			}
			if surveyTables != 1 {
				t.Fatalf("v7 survey_summary_cache missing after migrate: %d", surveyTables)
			}
			if through >= 7 {
				gotSurvey, err := m.GetSurveySummary(ctx, store.SurveyCacheKey{
					Profile: seed.Profile, Job: seed.Job, Build: seed.Build, MaxLogBytes: seed.SurveyMaxLog,
				})
				if err != nil || gotSurvey == nil {
					t.Fatalf("survey cache after migrate: err=%v got=%+v", err, gotSurvey)
				}
				if gotSurvey.Result != "FAILURE" || len(gotSurvey.Findings) != 1 {
					t.Fatalf("survey entry: %+v", gotSurvey)
				}
				if gotSurvey.Findings[0].Signature != seed.SurveySig {
					t.Fatalf("survey sig: %q want %q", gotSurvey.Findings[0].Signature, seed.SurveySig)
				}
			} else {
				// Fresh table after upgrade from <7 is usable.
				if err := m.PutSurveySummary(ctx, &store.SurveyCacheEntry{
					Key: store.SurveyCacheKey{
						Profile: seed.Profile, Job: seed.Job, Build: seed.Build, MaxLogBytes: 4096,
					},
					Result: "FAILURE",
					Findings: []store.SurveyCacheFinding{{
						Signature: "post-migrate-sig", Pattern: "fatal",
					}},
				}, time.Hour, 32); err != nil {
					t.Fatalf("PutSurveySummary after migrate from v%d: %v", through, err)
				}
			}

			// Frame chunks: v1 stubs are intentionally dropped at v2.
			// v5 seed marks l1_released without deleting the seed chunk (migrate survival only).
			chunks, err := m.ListChunks(ctx, got.ID)
			if err != nil {
				t.Fatal(err)
			}
			if through == 1 {
				if len(chunks) != 0 {
					t.Fatalf("v1 stub chunks must not survive v2 recreate; got %d", len(chunks))
				}
			} else if through >= 2 {
				if len(chunks) != 1 {
					t.Fatalf("chunks: got %d want 1", len(chunks))
				}
				c := chunks[0]
				if c.ContentSHA256 != seed.ContentSHA256 || c.FrameSHA256 != seed.FrameSHA256 {
					t.Fatalf("chunk checksums lost: %+v", c)
				}
				if c.RelPath != seed.RelPath {
					t.Fatalf("rel_path: got %q want %q", c.RelPath, seed.RelPath)
				}
				if c.RawStart != 0 || c.RawEnd != seed.RawEnd {
					t.Fatalf("raw range: %+v", c)
				}
			}

			// New columns usable after upgrade.
			if err := m.SetGenerationOutcome(ctx, got.ID, store.OutcomeFailed); err != nil {
				t.Fatalf("SetGenerationOutcome after migrate: %v", err)
			}
			if err := m.PinPack(ctx, "pack-post-migrate"); err != nil {
				t.Fatalf("PinPack after migrate: %v", err)
			}
		})
	}
}

type migrateSeed struct {
	Profile, Job      string
	Build, Generation int64
	JenkinsOffset     int64
	Sealed            bool
	PackedPackID      string
	Outcome           string
	PinPackID         string
	L1Released        bool
	ContentSHA256     string
	FrameSHA256       string
	RelPath           string
	RawEnd            int64
	CollectionID      string
	// v7 survey compact cache seed.
	SurveyMaxLog int
	SurveySig    string
}

func seedMetaAtVersion(t *testing.T, dbPath string, version int) migrateSeed {
	t.Helper()
	seed := migrateSeed{
		Profile:       "corp",
		Job:           "demo/job",
		Build:         42,
		Generation:    1,
		JenkinsOffset: 1024,
		Sealed:        true,
		PackedPackID:  "pack-abc",
		Outcome:       store.OutcomeSuccess,
		PinPackID:     "pack-pinned",
		ContentSHA256: "aa" + strings.Repeat("0", 62),
		FrameSHA256:   "bb" + strings.Repeat("0", 62),
		RelPath:       "frames/1/0.zst",
		RawEnd:        100,
	}
	db, err := store.OpenRawMetaDB(dbPath)
	if err != nil {
		t.Fatalf("OpenRawMetaDB: %v", err)
	}
	defer db.Close()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	sealed := 0
	if seed.Sealed {
		sealed = 1
	}
	// Base generation columns exist from v1.
	res, err := db.Exec(`
INSERT INTO log_generations(
	profile, job, build, generation, sealed, jenkins_offset, more_data, build_complete, updated_at
) VALUES(?, ?, ?, ?, ?, ?, 0, 1, ?)`,
		seed.Profile, seed.Job, seed.Build, seed.Generation, sealed, seed.JenkinsOffset, now)
	if err != nil {
		t.Fatalf("insert generation: %v", err)
	}
	genID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}

	if version == 1 {
		// Stub chunk shape (v1 only). Dropped at v2.
		if _, err := db.Exec(`
INSERT INTO chunks(generation_id, seq, raw_start, raw_end) VALUES(?, 0, 0, ?)`,
			genID, seed.RawEnd); err != nil {
			t.Fatalf("v1 stub chunk: %v", err)
		}
	}

	if version >= 2 {
		cres, err := db.Exec(`
INSERT INTO chunks(
	generation_id, seq, raw_start, raw_end, line_start, line_end,
	uncompressed_size, compressed_size, content_sha256, frame_sha256,
	codec, codec_level, format_version, dict_id, rel_path, created_at
) VALUES(?, 0, 0, ?, 0, 5, ?, 40, ?, ?, 'zstd', 3, 1, NULL, ?, ?)`,
			genID, seed.RawEnd, seed.RawEnd, seed.ContentSHA256, seed.FrameSHA256, seed.RelPath, now)
		if err != nil {
			t.Fatalf("v2 chunk: %v", err)
		}
		chunkID, err := cres.LastInsertId()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`
INSERT INTO line_checkpoints(chunk_id, line_no, raw_offset) VALUES(?, 0, 0)`, chunkID); err != nil {
			t.Fatalf("checkpoint: %v", err)
		}
	}

	if version >= 3 {
		if _, err := db.Exec(`
UPDATE log_generations SET packed_pack_id = ?, packed_at = ? WHERE id = ?`,
			seed.PackedPackID, now, genID); err != nil {
			t.Fatalf("packed fields: %v", err)
		}
	}

	if version >= 4 {
		if _, err := db.Exec(`UPDATE log_generations SET outcome = ? WHERE id = ?`,
			seed.Outcome, genID); err != nil {
			t.Fatalf("outcome: %v", err)
		}
		if _, err := db.Exec(`
INSERT INTO pins(kind, target_id, pinned_at) VALUES(?, ?, ?)`,
			store.PinKindGeneration, strconv.FormatInt(genID, 10), now); err != nil {
			t.Fatalf("gen pin: %v", err)
		}
		if _, err := db.Exec(`
INSERT INTO pins(kind, target_id, pinned_at) VALUES(?, ?, ?)`,
			store.PinKindPack, seed.PinPackID, now); err != nil {
			t.Fatalf("pack pin: %v", err)
		}
	}

	if version >= 5 {
		// Seed released flag only (chunk row still present for survival of v2+ data).
		seed.L1Released = true
		if _, err := db.Exec(`
UPDATE log_generations SET l1_released = 1, l1_released_at = ? WHERE id = ?`,
			now, genID); err != nil {
			t.Fatalf("l1_released: %v", err)
		}
	}

	if version >= 6 {
		// Durable collection membership (no log bodies).
		seed.CollectionID = "mig6coll00112233445566778899aabb"
		if _, err := db.Exec(`
INSERT INTO log_collections(id, profile, created_at, updated_at, sealed)
VALUES(?, ?, ?, ?, 0)`, seed.CollectionID, seed.Profile, now, now); err != nil {
			t.Fatalf("log_collections seed: %v", err)
		}
		if _, err := db.Exec(`
INSERT INTO log_collection_members(
	collection_id, profile, job, build, generation_id, state, relation, updated_at
) VALUES(?, ?, ?, ?, ?, ?, 'primary', ?)`,
			seed.CollectionID, seed.Profile, seed.Job, seed.Build, genID,
			store.CollectionMemberMirrored, now); err != nil {
			t.Fatalf("log_collection_members seed: %v", err)
		}
	}
	if version >= 7 {
		// Compact survey summary only (signature hash — no log body).
		seed.SurveyMaxLog = 65536
		seed.SurveySig = "mig7sig00112233"
		exp := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
		if _, err := db.Exec(`
INSERT INTO survey_summary_cache(
	profile, job, build, max_log_bytes, result, source, log_bytes, incomplete,
	findings_json, created_at, expires_at
) VALUES(?, ?, ?, ?, 'FAILURE', 'seed', 100, 0, ?, ?, ?)`,
			seed.Profile, seed.Job, seed.Build, seed.SurveyMaxLog,
			`[{"sig":"`+seed.SurveySig+`","pat":"build_failure"}]`, now, exp); err != nil {
			t.Fatalf("survey_summary_cache seed: %v", err)
		}
	}
	return seed
}

// Transactional migrate: uncommitted step must leave schema at prior version;
// reopen completes to CurrentSchemaVersion without corruption.
func TestMigrate_InterruptedStepRollsBackAndResumes(t *testing.T) {
	ctx := context.Background()
	// Start at v2 so remaining steps are v3 and v4 (non-empty SQL with ALTER).
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "profiles", "corp")
	dbPath, err := store.CreateMetaDBAtVersion(dataDir, 2)
	if err != nil {
		t.Fatal(err)
	}
	seed := seedMetaAtVersion(t, dbPath, 2)

	// Simulate crash mid-migration: begin v3 step, apply SQL, do not commit.
	sqlBody, ok := store.MigrationStepSQL(3)
	if !ok {
		t.Fatal("missing migration v3")
	}
	db, err := store.OpenRawMetaDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, sqlBody); err != nil {
		_ = tx.Rollback()
		t.Fatalf("partial v3: %v", err)
	}
	// Crash: close without commit (implicit rollback on connection close for modernc).
	_ = tx.Rollback()
	_ = db.Close()

	// Schema must still be v2 (version row not recorded).
	db2, err := store.OpenRawMetaDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	var ver int
	if err := db2.QueryRow(`SELECT MAX(version) FROM schema_version`).Scan(&ver); err != nil {
		t.Fatal(err)
	}
	if ver != 2 {
		t.Fatalf("after interrupt: schema %d want 2", ver)
	}
	// packed columns must not exist yet (ALTER rolled back).
	var n int
	err = db2.QueryRow(`SELECT COUNT(1) FROM pragma_table_info('log_generations') WHERE name='packed_pack_id'`).Scan(&n)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("packed_pack_id must not exist after rolled-back migration")
	}
	_ = db2.Close()

	// Reopen via store.Open → resume migrations cleanly.
	m, err := store.Open(dataDir)
	if err != nil {
		t.Fatalf("Open after interrupt: %v", err)
	}
	defer m.Close()
	gotVer, err := m.SchemaVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if gotVer != store.CurrentSchemaVersion {
		t.Fatalf("resumed schema: %d", gotVer)
	}
	g, err := m.GetGeneration(ctx, store.LogKey{
		Profile: seed.Profile, Job: seed.Job, Build: seed.Build,
	}, seed.Generation)
	if err != nil || g == nil {
		t.Fatalf("generation: %v %+v", err, g)
	}
	if g.JenkinsOffset != seed.JenkinsOffset {
		t.Fatalf("data corrupted after resume: offset %d", g.JenkinsOffset)
	}
	chunks, err := m.ListChunks(ctx, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 1 || chunks[0].ContentSHA256 != seed.ContentSHA256 {
		t.Fatalf("chunks after resume: %+v", chunks)
	}
}

// Multi-step resume: only v1 applied; Open walks 2→3→4 without stranding.
func TestMigrate_EmptyGapFromV1ResumesFully(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "profiles", "corp")
	if _, err := store.CreateMetaDBAtVersion(dataDir, 1); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dataDir, store.MetaDBFile)
	_ = seedMetaAtVersion(t, dbPath, 1)

	m, err := store.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ver, err := m.SchemaVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ver != store.CurrentSchemaVersion {
		t.Fatalf("schema %d", ver)
	}
	// Ensure v3/v4/v5 tables/columns present.
	var pins int
	if err := m.DB().QueryRow(`SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='pins'`).Scan(&pins); err != nil {
		t.Fatal(err)
	}
	if pins != 1 {
		t.Fatal("pins table missing after full migrate")
	}
	var packedCol int
	if err := m.DB().QueryRow(`SELECT COUNT(1) FROM pragma_table_info('log_generations') WHERE name='packed_pack_id'`).Scan(&packedCol); err != nil {
		t.Fatal(err)
	}
	if packedCol != 1 {
		t.Fatal("packed_pack_id missing after full migrate")
	}
	var releasedCol int
	if err := m.DB().QueryRow(`SELECT COUNT(1) FROM pragma_table_info('log_generations') WHERE name='l1_released'`).Scan(&releasedCol); err != nil {
		t.Fatal(err)
	}
	if releasedCol != 1 {
		t.Fatal("l1_released missing after full migrate")
	}
	var collTables int
	if err := m.DB().QueryRow(`
SELECT COUNT(1) FROM sqlite_master
WHERE type='table' AND name IN ('log_collections','log_collection_members')`).Scan(&collTables); err != nil {
		t.Fatal(err)
	}
	if collTables != 2 {
		t.Fatal("v6 collection tables missing after full migrate")
	}
}

// Unsupported binary downgrade path: future schema fails closed, non-destructive.
// Note: Open may still apply connection pragmas (e.g. WAL) before migrate rejects;
// "non-destructive" means schema rows and user data are not rewritten/downgraded.
func TestMigrate_FutureSchemaFailsClosedNonDestructive(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "profiles", "corp")
	dbPath, err := store.CreateMetaDBAtVersion(dataDir, store.CurrentSchemaVersion)
	if err != nil {
		t.Fatal(err)
	}
	// Mark as a future version while keeping a readable generation for integrity check.
	seed := seedMetaAtVersion(t, dbPath, store.CurrentSchemaVersion)
	db, err := store.OpenRawMetaDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	future := store.CurrentSchemaVersion + 3
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(`INSERT INTO schema_version(version, applied_at) VALUES(?, ?)`, future, now); err != nil {
		t.Fatal(err)
	}
	// Snapshot logical content before failed open.
	var beforeVersions string
	if err := db.QueryRow(`SELECT group_concat(version) FROM (SELECT version FROM schema_version ORDER BY version)`).Scan(&beforeVersions); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	_, err = store.Open(dataDir)
	if err == nil {
		t.Fatal("expected fail-closed open for future schema")
	}
	if !apperr.IsCode(err, apperr.CodeCorruptCache) {
		t.Fatalf("code: got %s want corrupt_cache (%v)", apperr.CodeOf(err), err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "newer than this binary supports") {
		t.Fatalf("message should explain upgrade path: %q", msg)
	}
	if !strings.Contains(msg, "left unchanged") {
		t.Fatalf("message should state non-destructive: %q", msg)
	}
	if !strings.Contains(msg, strconv.Itoa(future)) {
		t.Fatalf("message should include future version: %q", msg)
	}

	// Raw read still sees seed data + future schema row (no downgrade rewrite).
	db2, err := store.OpenRawMetaDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	var afterVersions string
	if err := db2.QueryRow(`SELECT group_concat(version) FROM (SELECT version FROM schema_version ORDER BY version)`).Scan(&afterVersions); err != nil {
		t.Fatal(err)
	}
	if afterVersions != beforeVersions {
		t.Fatalf("schema_version rewritten: before=%q after=%q", beforeVersions, afterVersions)
	}
	var maxVer int
	if err := db2.QueryRow(`SELECT MAX(version) FROM schema_version`).Scan(&maxVer); err != nil {
		t.Fatal(err)
	}
	if maxVer != future {
		t.Fatalf("future version row must remain: got %d", maxVer)
	}
	var job string
	var offset int64
	err = db2.QueryRow(`
SELECT job, jenkins_offset FROM log_generations
WHERE profile = ? AND build = ? AND generation = ?`,
		seed.Profile, seed.Build, seed.Generation).Scan(&job, &offset)
	if err != nil {
		t.Fatal(err)
	}
	if job != seed.Job || offset != seed.JenkinsOffset {
		t.Fatalf("data altered: job=%q offset=%d", job, offset)
	}
	// Pins from v4 seed must still be present.
	var pinCount int
	if err := db2.QueryRow(`SELECT COUNT(1) FROM pins`).Scan(&pinCount); err != nil {
		t.Fatal(err)
	}
	if pinCount < 2 {
		t.Fatalf("pins lost after failed open: %d", pinCount)
	}
}

func TestMigrate_FreshOpenIsCurrent(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "profiles", "fresh")
	m, err := store.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ver, err := m.SchemaVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ver != store.CurrentSchemaVersion {
		t.Fatalf("fresh schema %d", ver)
	}
	// schema_version rows for every step.
	rows, err := m.DB().Query(`SELECT version FROM schema_version ORDER BY version`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var versions []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		versions = append(versions, v)
	}
	if len(versions) != store.CurrentSchemaVersion {
		t.Fatalf("version rows: %v", versions)
	}
	for i, v := range versions {
		if v != i+1 {
			t.Fatalf("versions: %v", versions)
		}
	}
}

// Ensure CreateMetaDBAtVersion rejects out-of-range (fixture helper contract).
func TestCreateMetaDBAtVersion_Bounds(t *testing.T) {
	dir := t.TempDir()
	if _, err := store.CreateMetaDBAtVersion(dir, 0); err == nil {
		t.Fatal("expected reject through=0")
	}
	if _, err := store.CreateMetaDBAtVersion(dir, store.CurrentSchemaVersion+1); err == nil {
		t.Fatal("expected reject past current")
	}
}

// Compile-time reminder: migration list length matches CurrentSchemaVersion.
func TestMigrate_MigrationStepsContiguous(t *testing.T) {
	// Build each step independently via fixture helper.
	for v := 1; v <= store.CurrentSchemaVersion; v++ {
		dir := t.TempDir()
		dataDir := filepath.Join(dir, "d")
		if _, err := store.CreateMetaDBAtVersion(dataDir, v); err != nil {
			t.Fatalf("v%d: %v", v, err)
		}
		db, err := store.OpenRawMetaDB(filepath.Join(dataDir, store.MetaDBFile))
		if err != nil {
			t.Fatal(err)
		}
		var got int
		if err := db.QueryRow(`SELECT MAX(version) FROM schema_version`).Scan(&got); err != nil {
			t.Fatal(err)
		}
		_ = db.Close()
		if got != v {
			t.Fatalf("got %d want %d", got, v)
		}
		sqlBody, ok := store.MigrationStepSQL(v)
		if !ok || strings.TrimSpace(sqlBody) == "" {
			t.Fatalf("empty SQL for v%d", v)
		}
	}
	// No step beyond current.
	if _, ok := store.MigrationStepSQL(store.CurrentSchemaVersion + 1); ok {
		t.Fatal("unexpected step past CurrentSchemaVersion")
	}
}

// Sanity: interrupted mid-tx with open connection also rolls back (explicit).
func TestMigrate_InterruptedOpenTxDoesNotRecordVersion(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "profiles", "corp")
	dbPath, err := store.CreateMetaDBAtVersion(dataDir, 3)
	if err != nil {
		t.Fatal(err)
	}
	sqlBody, ok := store.MigrationStepSQL(4)
	if !ok {
		t.Fatal("missing v4")
	}
	db, err := store.OpenRawMetaDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, sqlBody); err != nil {
		t.Fatal(err)
	}
	// Intentionally do not INSERT schema_version or commit.
	_ = tx.Rollback()
	var ver int
	if err := db.QueryRow(`SELECT MAX(version) FROM schema_version`).Scan(&ver); err != nil {
		t.Fatal(err)
	}
	if ver != 3 {
		t.Fatalf("version %d", ver)
	}
	// pins table must not exist after rollback of CREATE TABLE pins.
	var n int
	err = db.QueryRow(`SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='pins'`).Scan(&n)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("pins leaked after rolled-back v4")
	}
	_ = db.Close()

	m, err := store.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if ver, _ := m.SchemaVersion(ctx); ver != store.CurrentSchemaVersion {
		t.Fatalf("resume: %d", ver)
	}
	// pins usable.
	if err := m.PinPack(ctx, "p1"); err != nil {
		t.Fatal(err)
	}
}
