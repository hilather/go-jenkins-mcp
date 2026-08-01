package logmirror_test

import (
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/logmirror"
	"github.com/simonfxr/go-jenkins-mcp/internal/store"
)

func TestAffinityGroupKey_FormatAndNormalize(t *testing.T) {
	got := logmirror.AffinityGroupKey("corp", "folder/job")
	want := "profile=corp|job=folder/job"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	// Profile empty → job-only.
	if g := logmirror.AffinityGroupKey("", "solo"); g != "job=solo" {
		t.Fatalf("job-only: %q", g)
	}
	// Empty job → placeholder.
	if g := logmirror.AffinityGroupKey("p", ""); g != "profile=p|job=_" {
		t.Fatalf("empty job: %q", g)
	}
	// Pipe and controls stripped from parts.
	if g := logmirror.AffinityGroupKey("a|b", "x\ny"); !strings.Contains(g, "profile=a_b") || !strings.Contains(g, "job=x_y") {
		t.Fatalf("normalize: %q", g)
	}
	// Bounded length for huge job names.
	huge := strings.Repeat("j", 400)
	g := logmirror.AffinityGroupKey("p", huge)
	if len(g) > logmirror.MaxAffinityGroupLen {
		t.Fatalf("len %d > max", len(g))
	}
	if !strings.Contains(g, "#") {
		t.Fatalf("expected hash suffix on truncated key: %q", g)
	}
	// Stable across calls.
	if g2 := logmirror.AffinityGroupKey("p", huge); g2 != g {
		t.Fatalf("unstable truncate: %q vs %q", g, g2)
	}
	// No secrets / build numbers in key.
	if strings.Contains(g, "token") {
		t.Fatal("unexpected")
	}
	key := logmirror.AffinityGroupKeyFromLogKey(logmirror.LogKey{Profile: "corp", Job: "demo", Build: 99})
	if strings.Contains(key, "99") {
		t.Fatalf("build must not appear in affinity: %q", key)
	}
}

func TestAffinityGroupFromKeys_SameAndMixed(t *testing.T) {
	same := []logmirror.LogKey{
		{Profile: "corp", Job: "a", Build: 1},
		{Profile: "corp", Job: "a", Build: 2},
	}
	if g := logmirror.AffinityGroupFromKeys(same); g != "profile=corp|job=a" {
		t.Fatalf("same: %q", g)
	}
	mixed := []logmirror.LogKey{
		{Profile: "corp", Job: "a", Build: 1},
		{Profile: "corp", Job: "b", Build: 1},
	}
	if g := logmirror.AffinityGroupFromKeys(mixed); g != logmirror.AffinityGroupMixed {
		t.Fatalf("mixed: %q", g)
	}
	if g := logmirror.AffinityGroupFromKeys(nil); g != "" {
		t.Fatalf("empty: %q", g)
	}
}

func TestSelectAffinityPackBatches_SameJobSharedAffinity(t *testing.T) {
	gens := []store.LogGeneration{
		{ID: 1, Profile: "corp", Job: "job-a", Build: 1},
		{ID: 2, Profile: "corp", Job: "job-a", Build: 2},
		{ID: 3, Profile: "corp", Job: "job-a", Build: 3},
	}
	batches := logmirror.SelectAffinityPackBatches(gens, 8, 2, 4)
	if len(batches) != 1 {
		t.Fatalf("batches %d want 1", len(batches))
	}
	if len(batches[0]) != 3 {
		t.Fatalf("members %d", len(batches[0]))
	}
	if g := logmirror.AffinityGroupFromGenerations(batches[0]); g != "profile=corp|job=job-a" {
		t.Fatalf("affinity %q", g)
	}
}

func TestSelectAffinityPackBatches_DifferentJobsNotForcedTogether(t *testing.T) {
	// Enough candidates per job: must not mix jobs into one pack.
	gens := []store.LogGeneration{
		{ID: 1, Profile: "corp", Job: "job-a", Build: 1},
		{ID: 2, Profile: "corp", Job: "job-a", Build: 2},
		{ID: 3, Profile: "corp", Job: "job-b", Build: 1},
		{ID: 4, Profile: "corp", Job: "job-b", Build: 2},
	}
	batches := logmirror.SelectAffinityPackBatches(gens, 8, 2, 4)
	if len(batches) != 2 {
		t.Fatalf("batches %d want 2 (one per job)", len(batches))
	}
	for i, b := range batches {
		aff := logmirror.AffinityGroupFromGenerations(b)
		if aff == logmirror.AffinityGroupMixed {
			t.Fatalf("batch %d mixed affinity", i)
		}
		if len(b) != 2 {
			t.Fatalf("batch %d members %d", i, len(b))
		}
		// All same job within batch.
		for _, g := range b[1:] {
			if g.Job != b[0].Job {
				t.Fatalf("batch %d mixed jobs %q %q", i, b[0].Job, g.Job)
			}
		}
	}
}

func TestSelectAffinityPackBatches_BelowMinPerAffinityWaits(t *testing.T) {
	// One gen per job, minSize=2 ⇒ no packs (do not force-mix).
	gens := []store.LogGeneration{
		{ID: 1, Profile: "corp", Job: "job-a", Build: 1},
		{ID: 2, Profile: "corp", Job: "job-b", Build: 1},
	}
	batches := logmirror.SelectAffinityPackBatches(gens, 8, 2, 4)
	if len(batches) != 0 {
		t.Fatalf("expected no mixed packs, got %d", len(batches))
	}
	// Force path minSize=1 packs each affinity alone.
	force := logmirror.SelectAffinityPackBatches(gens, 8, 1, 4)
	if len(force) != 2 {
		t.Fatalf("force batches %d", len(force))
	}
}

func TestSelectAffinityPackBatches_MaxMembersAndMaxBatches(t *testing.T) {
	var gens []store.LogGeneration
	for i := 1; i <= 5; i++ {
		gens = append(gens, store.LogGeneration{
			ID: int64(i), Profile: "corp", Job: "same", Build: int64(i),
		})
	}
	batches := logmirror.SelectAffinityPackBatches(gens, 2, 2, 2)
	if len(batches) != 2 {
		t.Fatalf("batches %d", len(batches))
	}
	if len(batches[0]) != 2 || len(batches[1]) != 2 {
		t.Fatalf("sizes %d %d", len(batches[0]), len(batches[1]))
	}
	// Fifth member left for later.
}

func TestSelectAffinityPackBatches_EmptyAffinityStillWorks(t *testing.T) {
	// Empty profile still groups by job; empty job uses placeholder.
	gens := []store.LogGeneration{
		{ID: 1, Profile: "", Job: "solo", Build: 1},
		{ID: 2, Profile: "", Job: "solo", Build: 2},
		{ID: 3, Profile: "", Job: "", Build: 1},
	}
	batches := logmirror.SelectAffinityPackBatches(gens, 8, 1, 4)
	if len(batches) < 2 {
		t.Fatalf("batches %d", len(batches))
	}
	// solo pair or split is fine; ensure empty-job group packs.
	var foundEmpty, foundSolo bool
	for _, b := range batches {
		aff := logmirror.AffinityGroupFromGenerations(b)
		if aff == "job=solo" || strings.HasPrefix(aff, "job=solo") {
			foundSolo = true
		}
		if aff == "job=_" {
			foundEmpty = true
		}
	}
	if !foundSolo || !foundEmpty {
		t.Fatalf("solo=%v empty=%v batches=%v", foundSolo, foundEmpty, batches)
	}
}

func TestCollectionAffinityKey_FormatAndBound(t *testing.T) {
	got := logmirror.CollectionAffinityKey("corp", "aabbccdd")
	want := "profile=corp|collection=aabbccdd"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if g := logmirror.CollectionAffinityKey("", "c1"); g != "collection=c1" {
		t.Fatalf("no profile: %q", g)
	}
	// Pipe stripped; no secrets/build numbers.
	if g := logmirror.CollectionAffinityKey("a|b", "x\ny"); !strings.Contains(g, "profile=a_b") || !strings.Contains(g, "collection=x_y") {
		t.Fatalf("normalize: %q", g)
	}
	huge := strings.Repeat("c", 400)
	g := logmirror.CollectionAffinityKey("p", huge)
	if len(g) > logmirror.MaxAffinityGroupLen {
		t.Fatalf("len %d", len(g))
	}
	if strings.Contains(g, "token") || strings.Contains(g, "password") {
		t.Fatal("unexpected secret-like substring")
	}
	// Empty relation ⇒ same as CollectionAffinityKey.
	if g := logmirror.CollectionAffinityKeyWithRelation("corp", "c1", ""); g != "profile=corp|collection=c1" {
		t.Fatalf("empty relation: %q", g)
	}
	// Wave 32 relation suffix.
	if g := logmirror.CollectionAffinityKeyWithRelation("corp", "c1", "primary"); g != "profile=corp|collection=c1|relation=primary" {
		t.Fatalf("with relation: %q", g)
	}
	if g := logmirror.CollectionAffinityKeyWithRelation("", "c1", "downstream"); g != "collection=c1|relation=downstream" {
		t.Fatalf("no profile + relation: %q", g)
	}
}

func TestAffinityGroupFromGenerationsWithCollections_RelationSuffix(t *testing.T) {
	// Wave 32: shared non-empty relation → |relation= suffix on catalog label.
	gens := []store.LogGeneration{
		{ID: 1, Profile: "corp", Job: "root", Build: 1},
		{ID: 2, Profile: "corp", Job: "child", Build: 2},
	}
	collShared := map[int64]store.GenerationCollection{
		1: {GenerationID: 1, CollectionID: "inv-1", Profile: "corp", Relation: "primary"},
		2: {GenerationID: 2, CollectionID: "inv-1", Profile: "corp", Relation: "primary"},
	}
	got := logmirror.AffinityGroupFromGenerationsWithCollections(gens, collShared)
	want := "profile=corp|collection=inv-1|relation=primary"
	if got != want {
		t.Fatalf("shared relation: got %q want %q", got, want)
	}
	// Selection still groups without relation (co-pack not split by relation).
	batches := logmirror.SelectCollectionAwarePackBatches(gens, collShared, 8, 2, 4)
	if len(batches) != 1 || len(batches[0]) != 2 {
		t.Fatalf("selection batches: %+v", batches)
	}

	// Mixed relations → collection key only (no relation suffix).
	collMixed := map[int64]store.GenerationCollection{
		1: {GenerationID: 1, CollectionID: "inv-1", Profile: "corp", Relation: "primary"},
		2: {GenerationID: 2, CollectionID: "inv-1", Profile: "corp", Relation: "downstream"},
	}
	got = logmirror.AffinityGroupFromGenerationsWithCollections(gens, collMixed)
	if got != "profile=corp|collection=inv-1" {
		t.Fatalf("mixed relations: got %q", got)
	}
	// Still one selection batch under collection.
	if n := len(logmirror.SelectCollectionAwarePackBatches(gens, collMixed, 8, 2, 4)); n != 1 {
		t.Fatalf("mixed still co-packs: %d", n)
	}

	// Empty / whitespace relation → no suffix.
	collEmpty := map[int64]store.GenerationCollection{
		1: {GenerationID: 1, CollectionID: "inv-1", Profile: "corp", Relation: ""},
		2: {GenerationID: 2, CollectionID: "inv-1", Profile: "corp", Relation: "  "},
	}
	got = logmirror.AffinityGroupFromGenerationsWithCollections(gens, collEmpty)
	if got != "profile=corp|collection=inv-1" {
		t.Fatalf("empty relation: got %q", got)
	}

	// One empty + one set ⇒ not shared → no suffix.
	collPartial := map[int64]store.GenerationCollection{
		1: {GenerationID: 1, CollectionID: "inv-1", Profile: "corp", Relation: "primary"},
		2: {GenerationID: 2, CollectionID: "inv-1", Profile: "corp", Relation: ""},
	}
	got = logmirror.AffinityGroupFromGenerationsWithCollections(gens, collPartial)
	if got != "profile=corp|collection=inv-1" {
		t.Fatalf("partial relation: got %q", got)
	}

	// Job-affinity fallback never gets relation suffix even if map has relation
	// with unusable (mismatched) collection profile.
	collMismatch := map[int64]store.GenerationCollection{
		1: {GenerationID: 1, CollectionID: "inv-bad", Profile: "other", Relation: "primary"},
		2: {GenerationID: 2, CollectionID: "inv-bad", Profile: "other", Relation: "primary"},
	}
	gensSameJob := []store.LogGeneration{
		{ID: 1, Profile: "corp", Job: "job-a", Build: 1},
		{ID: 2, Profile: "corp", Job: "job-a", Build: 2},
	}
	got = logmirror.AffinityGroupFromGenerationsWithCollections(gensSameJob, collMismatch)
	if got != "profile=corp|job=job-a" {
		t.Fatalf("job fallback must omit relation: %q", got)
	}
	if strings.Contains(got, "relation=") {
		t.Fatalf("job affinity must not carry relation: %q", got)
	}
}

func TestCollectionAffinityKeyWithRelation_NoSecretsNormalizeAndBound(t *testing.T) {
	// Regression: relation suffix is normalized/bounded; never embeds credentials
	// or raw secret-looking material from construction paths we control.
	g := logmirror.CollectionAffinityKeyWithRelation("corp", "coll-1", "primary")
	if strings.Contains(g, "token") || strings.Contains(g, "password") || strings.Contains(g, "Bearer") {
		t.Fatalf("unexpected secret-like substring: %q", g)
	}
	// Pipe in relation stripped (TrimSpace then '|' → '_').
	g = logmirror.CollectionAffinityKeyWithRelation("corp", "c1", "pri|mary\n")
	if g != "profile=corp|collection=c1|relation=pri_mary" {
		t.Fatalf("normalize relation: %q", g)
	}
	// Overlong relation truncated (part bound); whole key still ≤ MaxAffinityGroupLen.
	hugeRel := strings.Repeat("r", 200)
	g = logmirror.CollectionAffinityKeyWithRelation("corp", "c1", hugeRel)
	if len(g) > logmirror.MaxAffinityGroupLen {
		t.Fatalf("len %d", len(g))
	}
	if !strings.Contains(g, "|relation=") {
		t.Fatalf("expected relation segment: %q", g)
	}
	// Build numbers must not appear from affinity construction (relation is label only).
	if strings.Contains(g, "build=") {
		t.Fatalf("build must not appear: %q", g)
	}
}

func TestSelectCollectionAwarePackBatches_TwoCollectionsSeparate(t *testing.T) {
	// Same jobs across collections must not co-pack.
	gens := []store.LogGeneration{
		{ID: 1, Profile: "corp", Job: "job-a", Build: 1},
		{ID: 2, Profile: "corp", Job: "job-a", Build: 2},
		{ID: 3, Profile: "corp", Job: "job-b", Build: 1},
		{ID: 4, Profile: "corp", Job: "job-b", Build: 2},
	}
	coll := map[int64]store.GenerationCollection{
		1: {GenerationID: 1, CollectionID: "coll-aaa", Profile: "corp"},
		2: {GenerationID: 2, CollectionID: "coll-aaa", Profile: "corp"},
		3: {GenerationID: 3, CollectionID: "coll-bbb", Profile: "corp"},
		4: {GenerationID: 4, CollectionID: "coll-bbb", Profile: "corp"},
	}
	batches := logmirror.SelectCollectionAwarePackBatches(gens, coll, 8, 2, 4)
	if len(batches) != 2 {
		t.Fatalf("batches %d want 2 (one per collection)", len(batches))
	}
	for i, b := range batches {
		aff := logmirror.AffinityGroupFromGenerationsWithCollections(b, coll)
		if aff != "profile=corp|collection=coll-aaa" && aff != "profile=corp|collection=coll-bbb" {
			t.Fatalf("batch %d affinity %q", i, aff)
		}
		if len(b) != 2 {
			t.Fatalf("batch %d size %d", i, len(b))
		}
	}
}

func TestSelectCollectionAwarePackBatches_SameCollectionCoPacksDifferentJobs(t *testing.T) {
	// Investigation collection: root + downstream different jobs co-pack.
	gens := []store.LogGeneration{
		{ID: 10, Profile: "corp", Job: "root-pipeline", Build: 5},
		{ID: 11, Profile: "corp", Job: "child/job", Build: 1},
		{ID: 12, Profile: "corp", Job: "other", Build: 9},
	}
	coll := map[int64]store.GenerationCollection{
		10: {GenerationID: 10, CollectionID: "inv-1", Profile: "corp", Relation: "primary"},
		11: {GenerationID: 11, CollectionID: "inv-1", Profile: "corp", Relation: "downstream"},
		// 12 has no collection → job affinity alone; not co-packed with inv-1.
	}
	batches := logmirror.SelectCollectionAwarePackBatches(gens, coll, 8, 2, 4)
	// inv-1 pair meets minSize=2; "other" alone does not.
	if len(batches) != 1 {
		t.Fatalf("batches %d want 1", len(batches))
	}
	if len(batches[0]) != 2 {
		t.Fatalf("members %d", len(batches[0]))
	}
	jobs := map[string]bool{}
	for _, g := range batches[0] {
		jobs[g.Job] = true
	}
	if !jobs["root-pipeline"] || !jobs["child/job"] {
		t.Fatalf("expected cross-job collection pack: %v", batches[0])
	}
	aff := logmirror.AffinityGroupFromGenerationsWithCollections(batches[0], coll)
	if aff != "profile=corp|collection=inv-1" {
		t.Fatalf("affinity %q", aff)
	}
	// Force-aged path can pack the orphan job alone.
	force := logmirror.SelectCollectionAwarePackBatches(gens, coll, 8, 1, 4)
	if len(force) != 2 {
		t.Fatalf("force batches %d", len(force))
	}
}

func TestSelectCollectionAwarePackBatches_NoCollectionFallsBackToJob(t *testing.T) {
	gens := []store.LogGeneration{
		{ID: 1, Profile: "corp", Job: "job-a", Build: 1},
		{ID: 2, Profile: "corp", Job: "job-a", Build: 2},
		{ID: 3, Profile: "corp", Job: "job-b", Build: 1},
		{ID: 4, Profile: "corp", Job: "job-b", Build: 2},
	}
	// Nil map ≡ SelectAffinityPackBatches.
	batches := logmirror.SelectCollectionAwarePackBatches(gens, nil, 8, 2, 4)
	jobOnly := logmirror.SelectAffinityPackBatches(gens, 8, 2, 4)
	if len(batches) != len(jobOnly) {
		t.Fatalf("nil map batches %d jobOnly %d", len(batches), len(jobOnly))
	}
	for i := range batches {
		if len(batches[i]) != len(jobOnly[i]) {
			t.Fatalf("batch %d size mismatch", i)
		}
		for j := range batches[i] {
			if batches[i][j].ID != jobOnly[i][j].ID {
				t.Fatalf("batch %d member %d id %d vs %d", i, j, batches[i][j].ID, jobOnly[i][j].ID)
			}
		}
	}
}

func TestSelectCollectionAwarePackBatches_ProfileIsolation(t *testing.T) {
	// Same collection id string under different profiles must not co-pack.
	gens := []store.LogGeneration{
		{ID: 1, Profile: "corp", Job: "job-a", Build: 1},
		{ID: 2, Profile: "corp", Job: "job-a", Build: 2},
		{ID: 3, Profile: "other", Job: "job-a", Build: 1},
		{ID: 4, Profile: "other", Job: "job-a", Build: 2},
	}
	coll := map[int64]store.GenerationCollection{
		1: {GenerationID: 1, CollectionID: "shared-id", Profile: "corp"},
		2: {GenerationID: 2, CollectionID: "shared-id", Profile: "corp"},
		3: {GenerationID: 3, CollectionID: "shared-id", Profile: "other"},
		4: {GenerationID: 4, CollectionID: "shared-id", Profile: "other"},
	}
	batches := logmirror.SelectCollectionAwarePackBatches(gens, coll, 8, 2, 4)
	if len(batches) != 2 {
		t.Fatalf("batches %d want 2 (profile isolation)", len(batches))
	}
	for i, b := range batches {
		prof := b[0].Profile
		for _, g := range b {
			if g.Profile != prof {
				t.Fatalf("batch %d mixed profiles", i)
			}
		}
		aff := logmirror.AffinityGroupFromGenerationsWithCollections(b, coll)
		want := "profile=" + prof + "|collection=shared-id"
		if aff != want {
			t.Fatalf("batch %d aff %q want %q", i, aff, want)
		}
	}
}

func TestSelectCollectionAwarePackBatches_MismatchProfileFallsBackToJob(t *testing.T) {
	// Regression: collection profile mismatch must not co-pack under collection key.
	gens := []store.LogGeneration{
		{ID: 1, Profile: "corp", Job: "job-a", Build: 1},
		{ID: 2, Profile: "corp", Job: "job-b", Build: 1},
	}
	// Catalog wrongly labels corp gens with other profile — ignore mapping.
	coll := map[int64]store.GenerationCollection{
		1: {GenerationID: 1, CollectionID: "inv-bad", Profile: "other"},
		2: {GenerationID: 2, CollectionID: "inv-bad", Profile: "other"},
	}
	batches := logmirror.SelectCollectionAwarePackBatches(gens, coll, 8, 2, 4)
	if len(batches) != 0 {
		t.Fatalf("expected no cross-job pack from mismatched collection, got %d", len(batches))
	}
	// Same job still packs via job affinity when mapping ignored.
	gensSameJob := []store.LogGeneration{
		{ID: 1, Profile: "corp", Job: "job-a", Build: 1},
		{ID: 2, Profile: "corp", Job: "job-a", Build: 2},
	}
	ok := logmirror.SelectCollectionAwarePackBatches(gensSameJob, coll, 8, 2, 4)
	if len(ok) != 1 || len(ok[0]) != 2 {
		t.Fatalf("job fallback: %+v", ok)
	}
	aff := logmirror.AffinityGroupFromGenerationsWithCollections(ok[0], coll)
	if aff != "profile=corp|job=job-a" {
		t.Fatalf("want job affinity after mismatch, got %q", aff)
	}
}
