package store_test

// FLC-071 store-side chaos qualification: dual-dir / real PeerImportSink recovery.
// Offline only — Docker multi-host chaos lab remains residual.

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
	"github.com/hilather/go-jenkins-mcp/internal/store"
)

// TestChaosQual_PartialInvisibleRecoverFleetImports: Begin + one frame, process
// restart → RecoverFleetImports aborts staging; no committed mapping; full re-import OK.
func TestChaosQual_PartialInvisibleRecoverFleetImports(t *testing.T) {
	parts := [][]byte{[]byte("chaos-store-0\n"), []byte("chaos-store-1\n")}
	wm, frames, full := buildImportFixture(t, parts)
	dir := filepath.Join(t.TempDir(), "profiles", "chaos-partial")
	meta, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	fr, err := store.NewFrames(meta, dir)
	if err != nil {
		t.Fatal(err)
	}
	sink := store.NewPeerImportSink(meta, fr)
	importID, genID, err := sink.Begin(context.Background(), wm)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.WriteFrame(context.Background(), importID, genID, wm.Frames[0], frames[0].PureZstd); err != nil {
		t.Fatal(err)
	}
	// AC4: staging invisible as committed before recovery.
	if _, ok, err := meta.GetCommittedFleetMapping(context.Background(), wm.LocatorHash); err != nil || ok {
		t.Fatalf("staging must not be committed hit ok=%v err=%v", ok, err)
	}
	_ = fr.Close()
	_ = meta.Close()

	// Restart + RecoverFleetImports via Frames.Recover.
	meta2, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = meta2.Close() })
	fr2, err := store.NewFrames(meta2, dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fr2.Close() })
	rec, err := fr2.Recover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rec.Fleet.StagingAborted < 1 {
		t.Fatalf("expected staging abort: %+v", rec.Fleet)
	}
	if _, ok, err := meta2.GetCommittedFleetMapping(context.Background(), wm.LocatorHash); err != nil || ok {
		t.Fatalf("after recover still no committed ok=%v err=%v", ok, err)
	}
	j, err := meta2.GetFleetImport(context.Background(), importID)
	if err != nil || j.Status != store.FleetImportAborted {
		t.Fatalf("journal aborted: %+v %v", j, err)
	}
	// Full re-import succeeds (no partial bytes served).
	sink2 := store.NewPeerImportSink(meta2, fr2)
	res, err := fleetcache.RunImport(context.Background(), sink2, wm, frames)
	if err != nil || res.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("re-import %+v %v", res, err)
	}
	reader, err := fr2.Reader()
	if err != nil {
		t.Fatal(err)
	}
	rr, err := reader.ReadRange(context.Background(), res.GenerationID, 0, int64(len(full)))
	if err != nil {
		t.Fatal(err)
	}
	if string(rr.Data) != string(full) {
		t.Fatalf("parity len got=%d want=%d", len(rr.Data), len(full))
	}
	// Residuals secret-free.
	for _, r := range rec.Fleet.Residuals {
		if containsSecretShape(r) {
			t.Fatalf("secret residual: %q", r)
		}
	}
}

// TestChaosQual_DualDirMemberLossRFRestore: two real profile dirs — A committed,
// B empty (lost peer), ReplicateSealed pure-zstd export A→B restores second replica;
// second replicate idempotent.
func TestChaosQual_DualDirMemberLossRFRestore(t *testing.T) {
	parts := [][]byte{[]byte("dual-loss-0\n"), []byte("dual-loss-1\n")}
	wm, frames, full := buildImportFixture(t, parts)

	dirA := filepath.Join(t.TempDir(), "profiles", "member-loss-a")
	metaA, err := store.Open(dirA)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = metaA.Close() })
	frA, err := store.NewFrames(metaA, dirA)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = frA.Close() })
	sinkA := store.NewPeerImportSink(metaA, frA)
	resA, err := fleetcache.ReplicateSealed(context.Background(), sinkA, wm, frames)
	if err != nil || resA.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("A commit: %+v %v", resA, err)
	}
	wire := exportAllPure(t, metaA, frA, resA.GenerationID, nil)

	// Member B was "lost" (empty dir) — restore RF by peer pure-zstd import.
	dirB := filepath.Join(t.TempDir(), "profiles", "member-loss-b")
	metaB, err := store.Open(dirB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = metaB.Close() })
	frB, err := store.NewFrames(metaB, dirB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = frB.Close() })
	sinkB := store.NewPeerImportSink(metaB, frB)

	// PlanRepair over two members with only A observed committed.
	members := []fleetcache.PlacementMember{
		{ID: "lab-a", CapacityWeight: 100, FailureDomain: "z1"},
		{ID: "lab-b", CapacityWeight: 100, FailureDomain: "z2"},
	}
	replicas := map[string]fleetcache.ReplicaObservation{
		"lab-a": {MemberID: "lab-a", Digest: wm.ManifestDigest, Status: "committed"},
	}
	plan, err := fleetcache.PlanRepair(wm.LocatorHash, members, wm, replicas, fleetcache.RepairOptions{
		MaxConcurrentCopies: 2,
		Placement: fleetcache.PlacementOptions{
			ReplicationFactor: 2, PreferDistinctDomains: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.TransferCount < 1 {
		t.Fatalf("expected transfer to restore RF: %+v", plan)
	}
	sinks := map[string]fleetcache.ImportSink{"lab-a": sinkA, "lab-b": sinkB}
	// Ensure sinks map covers required owners (IDs may be lab-a/lab-b in any order).
	for _, o := range plan.RequiredOwners {
		if _, ok := sinks[o]; !ok {
			// Placement may pick only these two members — always lab-a/lab-b.
			if o == "lab-a" {
				sinks[o] = sinkA
			} else {
				sinks[o] = sinkB
			}
		}
	}
	run, err := fleetcache.RunRepair(context.Background(), plan, wm, wire, sinks)
	if err != nil {
		t.Fatal(err)
	}
	if !run.HealthyRF {
		t.Fatalf("AC2 dual-dir RF not healthy: %+v plan=%+v", run, plan)
	}
	// B has committed mapping + LogReader parity.
	cmB, ok, err := metaB.GetCommittedFleetMapping(context.Background(), wm.LocatorHash)
	if err != nil || !ok {
		t.Fatalf("B committed ok=%v err=%v", ok, err)
	}
	if !strings.EqualFold(cmB.ManifestDigest, wm.ManifestDigest) {
		t.Fatalf("digest mismatch B=%s want %s", cmB.ManifestDigest, wm.ManifestDigest)
	}
	readerB, err := frB.Reader()
	if err != nil {
		t.Fatal(err)
	}
	rr, err := readerB.ReadRange(context.Background(), cmB.GenerationID, 0, int64(len(full)))
	if err != nil {
		t.Fatal(err)
	}
	if string(rr.Data) != string(full) {
		t.Fatalf("B parity got=%d want=%d", len(rr.Data), len(full))
	}

	// Second RunRepair idempotent (zero frames).
	replicas2 := map[string]fleetcache.ReplicaObservation{}
	for _, o := range plan.RequiredOwners {
		replicas2[o] = fleetcache.ReplicaObservation{
			MemberID: o, Digest: wm.ManifestDigest, Status: "committed",
		}
	}
	plan2, err := fleetcache.PlanRepair(wm.LocatorHash, members, wm, replicas2, fleetcache.RepairOptions{
		MaxConcurrentCopies: 2,
		Placement: fleetcache.PlacementOptions{
			ReplicationFactor: 2, PreferDistinctDomains: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	run2, err := fleetcache.RunRepair(context.Background(), plan2, wm, wire, sinks)
	if err != nil {
		t.Fatal(err)
	}
	if run2.FramesTransferred != 0 {
		t.Fatalf("idempotent second repair FramesTransferred=%d", run2.FramesTransferred)
	}
	if !run2.HealthyRF {
		t.Fatal("still healthy")
	}
}

// TestChaosQual_CorruptFrameNoCommit: bad pure-zstd hash on dual-dir import fails
// closed; no committed fleet mapping.
func TestChaosQual_CorruptFrameNoCommit(t *testing.T) {
	parts := [][]byte{[]byte("c0\n"), []byte("c1\n")}
	wm, frames, _ := buildImportFixture(t, parts)
	bad := append([]fleetcache.ImportFrameBytes{}, frames...)
	bad[0].PureZstd = append([]byte{}, bad[0].PureZstd...)
	bad[0].PureZstd[len(bad[0].PureZstd)/2] ^= 0xff

	meta, fr, _ := openImportStore(t)
	sink := store.NewPeerImportSink(meta, fr)
	res, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, bad)
	if err == nil {
		t.Fatal("corrupt must fail")
	}
	if res.Status == fleetcache.ImportStatusCommitted {
		t.Fatal("must not commit")
	}
	if _, ok, _ := meta.GetCommittedFleetMapping(context.Background(), wm.LocatorHash); ok {
		t.Fatal("AC1: no committed mapping after corrupt import")
	}
}
