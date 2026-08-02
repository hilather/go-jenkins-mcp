package logmirror_test

import (
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/logmirror"
)

func TestPlanPackBatches_RolloverByMemberCount(t *testing.T) {
	domain := logmirror.AffinityDomain{Profile: "corp", CollectionID: "c1", AffinityGroup: "aff"}
	var cands []logmirror.PackCandidate
	for i := 1; i <= 5; i++ {
		cands = append(cands, logmirror.PackCandidate{
			Key:               logmirror.LogKey{Profile: "corp", Job: "j", Build: int64(i)},
			GenerationID:      int64(i),
			UncompressedBytes: 10,
			FrameCount:        1,
			Domain:            domain,
		})
	}
	batches, err := logmirror.PlanPackBatches(cands, logmirror.PackRolloverBounds{
		MaxMembers:           2,
		MaxUncompressedBytes: 1 << 30,
		MaxFrames:            1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(batches) != 3 {
		t.Fatalf("batches %d want 3", len(batches))
	}
	for i, b := range batches {
		if b.PartIndex != i {
			t.Fatalf("part %d", b.PartIndex)
		}
		if len(b.Members) > 2 {
			t.Fatalf("batch %d has %d members", i, len(b.Members))
		}
		if b.AffinityGroup == "" || b.AffinityGroup == "aff" {
			// multi-part should suffix
			if len(batches) > 1 && b.AffinityGroup == "aff" {
				t.Fatalf("expected part suffix on multi batch: %q", b.AffinityGroup)
			}
		}
	}
}

func TestPlanPackBatches_RolloverByBytesAndFrames(t *testing.T) {
	domain := logmirror.AffinityDomain{Profile: "corp", AffinityGroup: "g"}
	cands := []logmirror.PackCandidate{
		{Key: logmirror.LogKey{Profile: "corp", Job: "a", Build: 1}, UncompressedBytes: 100, FrameCount: 2, Domain: domain},
		{Key: logmirror.LogKey{Profile: "corp", Job: "a", Build: 2}, UncompressedBytes: 100, FrameCount: 2, Domain: domain},
		{Key: logmirror.LogKey{Profile: "corp", Job: "a", Build: 3}, UncompressedBytes: 100, FrameCount: 2, Domain: domain},
	}
	// Byte rollover
	byBytes, err := logmirror.PlanPackBatches(cands, logmirror.PackRolloverBounds{
		MaxMembers: 100, MaxUncompressedBytes: 150, MaxFrames: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(byBytes) != 3 {
		t.Fatalf("byte rollover batches %d", len(byBytes))
	}
	// Frame rollover
	byFrames, err := logmirror.PlanPackBatches(cands, logmirror.PackRolloverBounds{
		MaxMembers: 100, MaxUncompressedBytes: 1 << 30, MaxFrames: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(byFrames) != 3 {
		t.Fatalf("frame rollover batches %d", len(byFrames))
	}
}

func TestPlanPackBatches_IsolationNeverCoPacksProfiles(t *testing.T) {
	cands := []logmirror.PackCandidate{
		{
			Key:               logmirror.LogKey{Profile: "corp", Job: "j", Build: 1},
			Domain:            logmirror.AffinityDomain{Profile: "corp", AffinityGroup: "x"},
			UncompressedBytes: 1, FrameCount: 1,
		},
		{
			Key:               logmirror.LogKey{Profile: "other", Job: "j", Build: 1},
			Domain:            logmirror.AffinityDomain{Profile: "other", AffinityGroup: "x"},
			UncompressedBytes: 1, FrameCount: 1,
		},
	}
	batches, err := logmirror.PlanPackBatches(cands, logmirror.DefaultPackRolloverBounds())
	if err != nil {
		t.Fatal(err)
	}
	if len(batches) != 2 {
		t.Fatalf("want 2 isolation batches, got %d", len(batches))
	}
	// Different retention classes never co-pack.
	cands2 := []logmirror.PackCandidate{
		{
			Key:               logmirror.LogKey{Profile: "corp", Job: "j", Build: 1},
			Domain:            logmirror.AffinityDomain{Profile: "corp", RetentionClass: "short", CollectionID: "c"},
			UncompressedBytes: 1, FrameCount: 1,
		},
		{
			Key:               logmirror.LogKey{Profile: "corp", Job: "j", Build: 2},
			Domain:            logmirror.AffinityDomain{Profile: "corp", RetentionClass: "long", CollectionID: "c"},
			UncompressedBytes: 1, FrameCount: 1,
		},
	}
	batches2, err := logmirror.PlanPackBatches(cands2, logmirror.DefaultPackRolloverBounds())
	if err != nil {
		t.Fatal(err)
	}
	if len(batches2) != 2 {
		t.Fatalf("retention isolation: got %d batches", len(batches2))
	}
}

func TestPlanPackBatches_RejectsProfileMismatch(t *testing.T) {
	_, err := logmirror.PlanPackBatches([]logmirror.PackCandidate{{
		Key:    logmirror.LogKey{Profile: "a", Job: "j", Build: 1},
		Domain: logmirror.AffinityDomain{Profile: "b"},
	}}, logmirror.DefaultPackRolloverBounds())
	if err == nil {
		t.Fatal("expected profile mismatch error")
	}
}

func TestPlanPackBatches_SameCollectionCoLocated(t *testing.T) {
	d := logmirror.AffinityDomain{Profile: "corp", CollectionID: "inv-1", AffinityGroup: "inv-1"}
	cands := []logmirror.PackCandidate{
		{Key: logmirror.LogKey{Profile: "corp", Job: "root", Build: 1}, UncompressedBytes: 5, FrameCount: 1, Domain: d},
		{Key: logmirror.LogKey{Profile: "corp", Job: "down", Build: 2}, UncompressedBytes: 5, FrameCount: 1, Domain: d},
	}
	batches, err := logmirror.PlanPackBatches(cands, logmirror.DefaultPackRolloverBounds())
	if err != nil {
		t.Fatal(err)
	}
	if len(batches) != 1 {
		t.Fatalf("want single affinity pack, got %d", len(batches))
	}
	if len(batches[0].Members) != 2 {
		t.Fatalf("members %d", len(batches[0].Members))
	}
}
