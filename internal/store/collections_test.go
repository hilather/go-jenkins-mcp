package store_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/store"
)

func TestMeta_CollectionCatalog_CRUD(t *testing.T) {
	m := openTestMeta(t)
	ctx := context.Background()

	coll := &store.LogCollection{
		ID:      "aabbccddeeff00112233445566778899",
		Profile: "corp",
	}
	if err := m.CreateCollection(ctx, coll); err != nil {
		t.Fatalf("CreateCollection: %v", err)
	}
	// Duplicate id fails closed.
	if err := m.CreateCollection(ctx, coll); err == nil {
		t.Fatal("expected duplicate collection id error")
	}

	got, err := m.GetCollection(ctx, coll.ID, "corp")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.ID != coll.ID || got.Profile != "corp" || got.Sealed {
		t.Fatalf("GetCollection: %+v", got)
	}
	// Cross-profile isolation: same id under other profile → not found.
	other, err := m.GetCollection(ctx, coll.ID, "other")
	if err != nil {
		t.Fatal(err)
	}
	if other != nil {
		t.Fatalf("must not leak collection across profiles: %+v", other)
	}

	memA := &store.LogCollectionMember{
		CollectionID: coll.ID,
		Profile:      "corp",
		Job:          "job-a",
		Build:        1,
		State:        store.CollectionMemberPending,
		Relation:     "primary",
	}
	memB := &store.LogCollectionMember{
		CollectionID: coll.ID,
		Profile:      "corp",
		Job:          "job-b",
		Build:        2,
		State:        store.CollectionMemberMirrored,
		Relation:     "related",
		GenerationID: 42,
	}
	if err := m.UpsertMember(ctx, memA); err != nil {
		t.Fatalf("UpsertMember A: %v", err)
	}
	if err := m.UpsertMember(ctx, memB); err != nil {
		t.Fatalf("UpsertMember B: %v", err)
	}
	// Upsert updates state / generation.
	memA.State = store.CollectionMemberSealed
	memA.GenerationID = 7
	if err := m.UpsertMember(ctx, memA); err != nil {
		t.Fatalf("UpsertMember A sealed: %v", err)
	}

	members, err := m.ListMembers(ctx, coll.ID, "corp")
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 2 {
		t.Fatalf("members: got %d want 2", len(members))
	}
	// Deterministic order by job, build.
	if members[0].Job != "job-a" || members[1].Job != "job-b" {
		t.Fatalf("order: %+v", members)
	}
	if members[0].State != store.CollectionMemberSealed || members[0].GenerationID != 7 {
		t.Fatalf("member A: %+v", members[0])
	}
	if members[0].Relation != "primary" {
		t.Fatalf("relation A: %q", members[0].Relation)
	}
	if members[1].GenerationID != 42 || members[1].State != store.CollectionMemberMirrored {
		t.Fatalf("member B: %+v", members[1])
	}

	if err := m.SetCollectionSealed(ctx, coll.ID, "corp", true); err != nil {
		t.Fatal(err)
	}
	got, err = m.GetCollection(ctx, coll.ID, "corp")
	if err != nil || got == nil || !got.Sealed {
		t.Fatalf("sealed: err=%v got=%+v", err, got)
	}
}

// Regression: collection_id lost on restart — persist then reopen Meta and ListMembers.
func TestMeta_CollectionCatalog_SurvivesReopen(t *testing.T) {
	// Regression: jenkins_mirror_logs residual collection_id was in-process only.
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "profiles", "corp")
	ctx := context.Background()

	m1, err := store.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	collID := "11223344556677889900aabbccddeeff"
	if err := m1.CreateCollection(ctx, &store.LogCollection{
		ID: collID, Profile: "corp",
	}); err != nil {
		t.Fatal(err)
	}
	if err := m1.UpsertMember(ctx, &store.LogCollectionMember{
		CollectionID: collID,
		Profile:      "corp",
		Job:          "pipeline/demo",
		Build:        99,
		State:        store.CollectionMemberMirrored,
		Relation:     "primary",
		GenerationID: 3,
	}); err != nil {
		t.Fatal(err)
	}
	if err := m1.Close(); err != nil {
		t.Fatal(err)
	}

	// "Restart": new Meta handle on same files.
	m2, err := store.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer m2.Close()

	got, err := m2.GetCollection(ctx, collID, "corp")
	if err != nil || got == nil {
		t.Fatalf("GetCollection after reopen: err=%v got=%+v", err, got)
	}
	members, err := m2.ListMembers(ctx, collID, "corp")
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 {
		t.Fatalf("members after reopen: %d", len(members))
	}
	if members[0].Job != "pipeline/demo" || members[0].Build != 99 {
		t.Fatalf("member: %+v", members[0])
	}
	if members[0].State != store.CollectionMemberMirrored || members[0].GenerationID != 3 {
		t.Fatalf("member state/gen: %+v", members[0])
	}
	if members[0].Relation != "primary" {
		t.Fatalf("relation: %q", members[0].Relation)
	}
}

func TestMeta_CollectionCatalog_FailClosed(t *testing.T) {
	m := openTestMeta(t)
	ctx := context.Background()

	// Invalid create.
	if err := m.CreateCollection(ctx, &store.LogCollection{ID: "", Profile: "corp"}); err == nil {
		t.Fatal("empty id must fail")
	}
	if err := m.CreateCollection(ctx, &store.LogCollection{ID: "x", Profile: ""}); err == nil {
		t.Fatal("empty profile must fail")
	}

	// Member without parent.
	err := m.UpsertMember(ctx, &store.LogCollectionMember{
		CollectionID: "missing",
		Profile:      "corp",
		Job:          "j",
		Build:        1,
	})
	if err == nil || !apperr.IsCode(err, apperr.CodeNotFound) {
		t.Fatalf("orphan member: %v", err)
	}

	// List unknown collection.
	_, err = m.ListMembers(ctx, "nope", "corp")
	if err == nil || !apperr.IsCode(err, apperr.CodeNotFound) {
		t.Fatalf("list missing: %v", err)
	}

	// Profile mismatch on upsert.
	if err := m.CreateCollection(ctx, &store.LogCollection{ID: "c1", Profile: "corp"}); err != nil {
		t.Fatal(err)
	}
	err = m.UpsertMember(ctx, &store.LogCollectionMember{
		CollectionID: "c1",
		Profile:      "other",
		Job:          "j",
		Build:        1,
	})
	if err == nil {
		t.Fatal("cross-profile member must fail")
	}

	// Bad build.
	err = m.UpsertMember(ctx, &store.LogCollectionMember{
		CollectionID: "c1",
		Profile:      "corp",
		Job:          "j",
		Build:        0,
	})
	if err == nil {
		t.Fatal("build 0 must fail")
	}
}

func TestMeta_CollectionCatalog_CorruptMemberFailsClosed(t *testing.T) {
	m := openTestMeta(t)
	ctx := context.Background()
	if err := m.CreateCollection(ctx, &store.LogCollection{ID: "c-corrupt", Profile: "corp"}); err != nil {
		t.Fatal(err)
	}
	// Insert a corrupt row via raw SQL (empty job).
	_, err := m.DB().ExecContext(ctx, `
INSERT INTO log_collection_members(
	collection_id, profile, job, build, generation_id, state, relation, updated_at
) VALUES('c-corrupt', 'corp', '', 1, NULL, 'pending', '', '2020-01-01T00:00:00Z')`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.ListMembers(ctx, "c-corrupt", "corp")
	if err == nil {
		t.Fatal("expected fail-closed on corrupt member")
	}
	if !apperr.IsCode(err, apperr.CodeCorruptCache) {
		t.Fatalf("code: got %s (%v)", apperr.CodeOf(err), err)
	}
	if !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("message: %v", err)
	}
}

func TestMeta_ListGenerationCollections(t *testing.T) {
	m := openTestMeta(t)
	ctx := context.Background()

	// Two collections; only members with generation_id > 0 appear in the map.
	if err := m.CreateCollection(ctx, &store.LogCollection{ID: "coll-a", Profile: "corp"}); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateCollection(ctx, &store.LogCollection{ID: "coll-b", Profile: "corp"}); err != nil {
		t.Fatal(err)
	}
	// Real generations so profile join succeeds.
	g1 := &store.LogGeneration{Profile: "corp", Job: "job-a", Build: 1, Generation: 1, Sealed: true}
	g2 := &store.LogGeneration{Profile: "corp", Job: "job-b", Build: 2, Generation: 1, Sealed: true}
	g3 := &store.LogGeneration{Profile: "corp", Job: "job-c", Build: 3, Generation: 1, Sealed: true}
	for _, g := range []*store.LogGeneration{g1, g2, g3} {
		if err := m.InsertGeneration(ctx, g); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.UpsertMember(ctx, &store.LogCollectionMember{
		CollectionID: "coll-a", Profile: "corp", Job: "job-a", Build: 1,
		GenerationID: g1.ID, State: store.CollectionMemberSealed, Relation: "primary",
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.UpsertMember(ctx, &store.LogCollectionMember{
		CollectionID: "coll-a", Profile: "corp", Job: "job-b", Build: 2,
		GenerationID: g2.ID, State: store.CollectionMemberSealed, Relation: "related",
	}); err != nil {
		t.Fatal(err)
	}
	// Member without generation_id must not appear.
	if err := m.UpsertMember(ctx, &store.LogCollectionMember{
		CollectionID: "coll-b", Profile: "corp", Job: "job-pending", Build: 1,
		State: store.CollectionMemberPending,
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.UpsertMember(ctx, &store.LogCollectionMember{
		CollectionID: "coll-b", Profile: "corp", Job: "job-c", Build: 3,
		GenerationID: g3.ID, State: store.CollectionMemberSealed,
	}); err != nil {
		t.Fatal(err)
	}

	got, err := m.ListGenerationCollections(ctx, "corp")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("map size %d want 3: %+v", len(got), got)
	}
	if got[g1.ID].CollectionID != "coll-a" || got[g1.ID].Relation != "primary" {
		t.Fatalf("g1: %+v", got[g1.ID])
	}
	if got[g2.ID].CollectionID != "coll-a" {
		t.Fatalf("g2: %+v", got[g2.ID])
	}
	if got[g3.ID].CollectionID != "coll-b" {
		t.Fatalf("g3: %+v", got[g3.ID])
	}

	// Profile filter: empty profile returns all; wrong profile empty.
	all, err := m.ListGenerationCollections(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("all profiles: %d", len(all))
	}
	none, err := m.ListGenerationCollections(ctx, "other")
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Fatalf("other profile leak: %+v", none)
	}
}

func TestMeta_ListGenerationCollections_MultiMembershipDeterministic(t *testing.T) {
	m := openTestMeta(t)
	ctx := context.Background()
	g := &store.LogGeneration{Profile: "corp", Job: "shared", Build: 1, Generation: 1, Sealed: true}
	if err := m.InsertGeneration(ctx, g); err != nil {
		t.Fatal(err)
	}
	// Same gen in two collections — lexicographically smallest collection_id wins.
	for _, id := range []string{"zzz-coll", "aaa-coll"} {
		if err := m.CreateCollection(ctx, &store.LogCollection{ID: id, Profile: "corp"}); err != nil {
			t.Fatal(err)
		}
		if err := m.UpsertMember(ctx, &store.LogCollectionMember{
			CollectionID: id, Profile: "corp", Job: "shared", Build: 1,
			GenerationID: g.ID, State: store.CollectionMemberSealed,
		}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := m.ListGenerationCollections(ctx, "corp")
	if err != nil {
		t.Fatal(err)
	}
	if got[g.ID].CollectionID != "aaa-coll" {
		t.Fatalf("want aaa-coll (lex smallest), got %q", got[g.ID].CollectionID)
	}
}

func TestMeta_ListGenerationCollections_ProfileMismatchFailsClosed(t *testing.T) {
	// Regression: collection catalog profile mismatch must not yield a partial map.
	m := openTestMeta(t)
	ctx := context.Background()
	if err := m.CreateCollection(ctx, &store.LogCollection{ID: "c-mis", Profile: "corp"}); err != nil {
		t.Fatal(err)
	}
	g := &store.LogGeneration{Profile: "corp", Job: "j", Build: 1, Generation: 1, Sealed: true}
	if err := m.InsertGeneration(ctx, g); err != nil {
		t.Fatal(err)
	}
	// Insert valid member then corrupt profile via raw SQL (bypass Upsert checks).
	if err := m.UpsertMember(ctx, &store.LogCollectionMember{
		CollectionID: "c-mis", Profile: "corp", Job: "j", Build: 1,
		GenerationID: g.ID, State: store.CollectionMemberSealed,
	}); err != nil {
		t.Fatal(err)
	}
	// Point generation at another profile while member stays corp.
	_, err := m.DB().ExecContext(ctx, `UPDATE log_generations SET profile = 'other' WHERE id = ?`, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.ListGenerationCollections(ctx, "corp")
	if err == nil {
		t.Fatal("expected fail-closed on generation profile mismatch")
	}
	if !apperr.IsCode(err, apperr.CodeCorruptCache) {
		t.Fatalf("code: %s (%v)", apperr.CodeOf(err), err)
	}
}
