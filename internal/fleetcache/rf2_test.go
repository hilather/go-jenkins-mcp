package fleetcache_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

func TestPlanRF2Replication_SkipVerifiedAndMissing(t *testing.T) {
	t.Parallel()
	wm, frames := makeSealedManifest(t, [][]byte{[]byte("a\n"), []byte("b\n")})
	members := []fleetcache.PlacementMember{
		{ID: "lab-a", CapacityWeight: 100, FailureDomain: "z1"},
		{ID: "lab-b", CapacityWeight: 100, FailureDomain: "z2"},
		{ID: "lab-c", CapacityWeight: 100, FailureDomain: "z3"},
	}
	// No replicas yet.
	plan, err := fleetcache.PlanRF2Replication(wm.LocatorHash, members, wm, nil, fleetcache.PlacementOptions{
		ReplicationFactor: 2, PreferDistinctDomains: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.ReplicationFactor != 2 || len(plan.RequiredOwners) != 2 {
		t.Fatalf("%+v", plan)
	}
	if plan.FramesToTransfer != 2*len(wm.Frames) { // both targets full import
		t.Fatalf("frames transfer %d", plan.FramesToTransfer)
	}
	for _, tgt := range plan.Targets {
		if tgt.Action != fleetcache.ReplicaActionFullImport {
			t.Fatalf("%+v", tgt)
		}
	}

	// Source on first owner, second missing.
	src := plan.RequiredOwners[0]
	dst := plan.RequiredOwners[1]
	replicas := map[string]fleetcache.ReplicaObservation{
		src: {MemberID: src, Digest: wm.ManifestDigest, Status: "committed"},
	}
	plan2, err := fleetcache.PlanRF2Replication(wm.LocatorHash, members, wm, replicas, fleetcache.PlacementOptions{
		ReplicationFactor: 2, PreferDistinctDomains: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan2.SourceMember != src {
		t.Fatalf("source %s want %s", plan2.SourceMember, src)
	}
	var skip, full int
	for _, tgt := range plan2.Targets {
		switch tgt.Action {
		case fleetcache.ReplicaActionSkipVerified:
			skip++
			if tgt.MemberID != src {
				t.Fatal("skip wrong member")
			}
		case fleetcache.ReplicaActionFullImport:
			full++
			if tgt.MemberID != dst {
				t.Fatal("full wrong member")
			}
		}
	}
	if skip != 1 || full != 1 {
		t.Fatalf("skip=%d full=%d plan=%+v", skip, full, plan2)
	}
	if plan2.FramesToTransfer != len(wm.Frames) {
		t.Fatalf("transfer %d", plan2.FramesToTransfer)
	}

	// Staging with one frame present → missing_frames for the other.
	replicas[dst] = fleetcache.ReplicaObservation{
		MemberID: dst, Status: "staging", PresentSeqs: []int{0},
	}
	plan3, err := fleetcache.PlanRF2Replication(wm.LocatorHash, members, wm, replicas, fleetcache.PlacementOptions{
		ReplicationFactor: 2, PreferDistinctDomains: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tgt := range plan3.Targets {
		if tgt.MemberID != dst {
			continue
		}
		if tgt.Action != fleetcache.ReplicaActionMissingFrames {
			t.Fatalf("%+v", tgt)
		}
		if len(tgt.MissingSeqs) != 1 || tgt.MissingSeqs[0] != 1 {
			t.Fatalf("missing %v", tgt.MissingSeqs)
		}
	}
	_ = frames
}

func TestMissingFrameSeqs_AndFilter(t *testing.T) {
	t.Parallel()
	wm, frames := makeSealedManifest(t, [][]byte{[]byte("x\n"), []byte("y\n"), []byte("z\n")})
	miss := fleetcache.MissingFrameSeqs(wm, []int{0, 2})
	if len(miss) != 1 || miss[0] != 1 {
		t.Fatalf("%v", miss)
	}
	filt := fleetcache.FilterImportFrames(frames, miss)
	if len(filt) != 1 || filt[0].Seq != 1 {
		t.Fatalf("%+v", filt)
	}
}

func TestPlanRF2_InsufficientOwners(t *testing.T) {
	t.Parallel()
	wm, _ := makeSealedManifest(t, [][]byte{[]byte("only\n")})
	members := []fleetcache.PlacementMember{{ID: "solo", CapacityWeight: 100}}
	_, err := fleetcache.PlanRF2Replication(wm.LocatorHash, members, wm, nil, fleetcache.PlacementOptions{
		ReplicationFactor: 2,
	})
	if err == nil {
		t.Fatal("expected insufficient owners")
	}
	if apperr.CodeOf(err) != apperr.CodeCapabilityMissing {
		t.Fatalf("code %s", apperr.CodeOf(err))
	}
}

func TestReplicateSealed_IdempotentAndPartial(t *testing.T) {
	t.Parallel()
	wm, frames := makeSealedManifest(t, [][]byte{[]byte("p\n"), []byte("q\n")})
	sink := &memSink{}
	res, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, frames)
	if err != nil || res.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("%+v %v", res, err)
	}
	if res.FramesTransferred != 2 {
		t.Fatalf("xfer %d", res.FramesTransferred)
	}
	// Idempotent.
	res2, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, frames)
	if err != nil || res2.Status != fleetcache.ImportStatusIdempotent {
		t.Fatalf("%+v %v", res2, err)
	}
	if res2.FramesTransferred != 0 {
		t.Fatal("idempotent must not re-transfer")
	}
	// Incomplete frame set rejected (no partial commit).
	_, err = fleetcache.ReplicateSealed(context.Background(), &memSink{}, wm, frames[:1])
	if err == nil {
		t.Fatal("expected incomplete reject")
	}
}

// Regression: post-interrupt resume transfers only missing frames (FLC-043 AC).
func TestReplicateSealed_ResumeTransfersOnlyMissing(t *testing.T) {
	t.Parallel()
	wm, frames := makeSealedManifest(t, [][]byte{[]byte("r0\n"), []byte("r1\n"), []byte("r2\n")})
	sink := &memSink{}

	// Partial: write seq 0 only; leave staging open (no Abort).
	importID, genID, err := sink.Begin(context.Background(), wm)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.WriteFrame(context.Background(), importID, genID, wm.Frames[0], frames[0].PureZstd); err != nil {
		t.Fatal(err)
	}
	// Not committed.
	if _, ok, _ := sink.GetCommitted(context.Background(), wm.LocatorHash); ok {
		t.Fatal("partial must not be committed")
	}

	// Resume with only missing frames (seq 1 and 2) — not the full set.
	missingOnly := fleetcache.FilterImportFrames(frames, []int{1, 2})
	if len(missingOnly) != 2 {
		t.Fatalf("fixture filter %d", len(missingOnly))
	}
	res, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, missingOnly)
	if err != nil || res.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("%+v %v", res, err)
	}
	// Honest transfer count: only missing frames, not 3.
	if res.FramesTransferred != 2 {
		t.Fatalf("Regression: resume must transfer only missing frames; got FramesTransferred=%d want 2", res.FramesTransferred)
	}
	if res.Residual != "resume_missing_frames" {
		t.Fatalf("residual %q", res.Residual)
	}

	// Full set on already-committed → idempotent zero transfer.
	res2, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, frames)
	if err != nil || res2.Status != fleetcache.ImportStatusIdempotent || res2.FramesTransferred != 0 {
		t.Fatalf("%+v %v", res2, err)
	}
}

// ReplicateWave must FilterImportFrames for missing_frames targets (not allFrames).
func TestReplicateWave_MissingFramesOnly(t *testing.T) {
	t.Parallel()
	wm, frames := makeSealedManifest(t, [][]byte{[]byte("w0\n"), []byte("w1\n")})
	members := []fleetcache.PlacementMember{
		{ID: "a", CapacityWeight: 100, FailureDomain: "z1"},
		{ID: "b", CapacityWeight: 100, FailureDomain: "z2"},
	}
	// Seed A committed; B staging with seq 0 only.
	sinkA := &memSink{}
	if _, err := fleetcache.ReplicateSealed(context.Background(), sinkA, wm, frames); err != nil {
		t.Fatal(err)
	}
	sinkB := &memSink{}
	id, gen, err := sinkB.Begin(context.Background(), wm)
	if err != nil {
		t.Fatal(err)
	}
	if err := sinkB.WriteFrame(context.Background(), id, gen, wm.Frames[0], frames[0].PureZstd); err != nil {
		t.Fatal(err)
	}
	obs := map[string]fleetcache.ReplicaObservation{
		"a": {MemberID: "a", Digest: wm.ManifestDigest, Status: "committed"},
		"b": {MemberID: "b", Status: "staging", PresentSeqs: []int{0}},
	}
	plan, err := fleetcache.PlanRF2Replication(wm.LocatorHash, members, wm, obs, fleetcache.PlacementOptions{
		ReplicationFactor: 2, PreferDistinctDomains: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var bTarget fleetcache.ReplicateTarget
	for _, tgt := range plan.Targets {
		if tgt.MemberID == "b" {
			bTarget = tgt
		}
	}
	if bTarget.Action != fleetcache.ReplicaActionMissingFrames || len(bTarget.MissingSeqs) != 1 || bTarget.MissingSeqs[0] != 1 {
		t.Fatalf("plan target %+v", bTarget)
	}
	results, err := fleetcache.ReplicateWave(context.Background(), plan, wm, frames, map[string]fleetcache.ImportSink{
		"a": sinkA, "b": sinkB,
	})
	if err != nil {
		t.Fatal(err)
	}
	rb := results["b"]
	if rb.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("b %+v", rb)
	}
	if rb.FramesTransferred != 1 {
		t.Fatalf("Regression: wave missing_frames must transfer 1 frame; got %d", rb.FramesTransferred)
	}
}

func TestReplicateWave_SkipAndImport(t *testing.T) {
	t.Parallel()
	wm, frames := makeSealedManifest(t, [][]byte{[]byte("w\n")})
	members := []fleetcache.PlacementMember{
		{ID: "a", CapacityWeight: 100, FailureDomain: "z1"},
		{ID: "b", CapacityWeight: 100, FailureDomain: "z2"},
	}
	// Pre-commit on a.
	sinkA := &memSink{}
	if _, err := fleetcache.ReplicateSealed(context.Background(), sinkA, wm, frames); err != nil {
		t.Fatal(err)
	}
	obs := map[string]fleetcache.ReplicaObservation{
		"a": {MemberID: "a", Digest: wm.ManifestDigest, Status: "committed"},
	}
	// Force owners a,b by using members as-is
	plan, err := fleetcache.PlanRF2Replication(wm.LocatorHash, members, wm, obs, fleetcache.PlacementOptions{
		ReplicationFactor: 2, PreferDistinctDomains: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	sinkB := &memSink{}
	// Map sinks by actual required owner IDs
	sinks := map[string]fleetcache.ImportSink{}
	for _, o := range plan.RequiredOwners {
		if o == plan.SourceMember || (obs[o].Status == "committed") {
			sinks[o] = sinkA
		} else {
			sinks[o] = sinkB
		}
	}
	// Ensure both owners have sinks
	for _, o := range plan.RequiredOwners {
		if sinks[o] == nil {
			sinks[o] = sinkB
		}
	}
	results, err := fleetcache.ReplicateWave(context.Background(), plan, wm, frames, sinks)
	if err != nil {
		t.Fatal(err)
	}
	var skipped, committed int
	for _, r := range results {
		switch r.Status {
		case "skipped", fleetcache.ImportStatusIdempotent:
			skipped++
		case fleetcache.ImportStatusCommitted:
			committed++
		}
	}
	if skipped < 1 || committed < 1 {
		t.Fatalf("results %+v plan=%+v", results, plan)
	}
	_ = strings.TrimSpace
}
