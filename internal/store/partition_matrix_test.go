package store_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
	"github.com/hilather/go-jenkins-mcp/internal/store"
	storecrypto "github.com/hilather/go-jenkins-mcp/internal/store/crypto"
)

// FLC-045 store-level partition matrix: same/different digest via PeerImportSink + LogReader.

func openPartitionStore(t *testing.T) (*store.Meta, *store.Frames, *store.PeerImportSink) {
	t.Helper()
	meta, fr, _ := openImportStore(t)
	env := &storecrypto.Envelope{Enabled: true, Write: testKey(t, 3)}
	fc, err := store.NewFrameCrypto(env)
	if err != nil {
		t.Fatal(err)
	}
	fr.SetCrypto(fc)
	return meta, fr, store.NewPeerImportSink(meta, fr)
}

func TestPartition_Store_SameDigestDualImport(t *testing.T) {
	parts := [][]byte{[]byte("store-dual-0\n"), []byte("store-dual-1\n")}
	wm, frames, full := buildImportFixture(t, parts)
	meta, fr, sink := openPartitionStore(t)

	res, err := fleetcache.RunImport(context.Background(), sink, wm, frames)
	if err != nil || res.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("first %+v %v", res, err)
	}
	gen1 := res.GenerationID

	// Same digest via ReplicateSealed — idempotent, no extra mapping.
	res2, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, frames)
	if err != nil || res2.Status != fleetcache.ImportStatusIdempotent {
		t.Fatalf("second %+v %v", res2, err)
	}
	if res2.FramesTransferred != 0 {
		t.Fatalf("FramesTransferred=%d", res2.FramesTransferred)
	}
	if res2.Residual != fleetcache.PartitionResidualDuplicateConverged {
		t.Fatalf("residual %q", res2.Residual)
	}

	m, ok, err := meta.GetCommittedFleetMapping(context.Background(), wm.LocatorHash)
	if err != nil || !ok {
		t.Fatalf("mapping ok=%v err=%v", ok, err)
	}
	if m.ManifestDigest != wm.ManifestDigest || m.GenerationID != gen1 {
		t.Fatalf("mapping drift %+v gen1=%d", m, gen1)
	}

	// LogReader body equals original — no mixed content.
	assertPartitionLogBody(t, fr, m.GenerationID, full)
}

func TestPartition_Store_DifferentDigestConflict(t *testing.T) {
	partsA := [][]byte{[]byte("store-A0\n"), []byte("store-A1\n")}
	partsB := [][]byte{[]byte("store-B0-DIFF\n"), []byte("store-B1-DIFF\n")}
	wmA, framesA, fullA := buildImportFixture(t, partsA)
	wmB, framesB, _ := buildImportFixture(t, partsB)
	if wmA.LocatorHash != wmB.LocatorHash {
		t.Fatalf("locator %s vs %s", wmA.LocatorHash, wmB.LocatorHash)
	}
	if wmA.ManifestDigest == wmB.ManifestDigest {
		t.Fatal("need different digests")
	}

	meta, fr, sink := openPartitionStore(t)

	if _, err := fleetcache.RunImport(context.Background(), sink, wmA, framesA); err != nil {
		t.Fatal(err)
	}

	// Conflict via RunImport.
	resC, err := fleetcache.RunImport(context.Background(), sink, wmB, framesB)
	if err == nil || resC.Status != fleetcache.ImportStatusRejected {
		t.Fatalf("want conflict reject %+v %v", resC, err)
	}
	if resC.Residual != fleetcache.PartitionResidualConflictDigest {
		t.Fatalf("residual %q", resC.Residual)
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code %s", apperr.CodeOf(err))
	}

	// Conflict via ReplicateSealed (must not overwrite).
	resR, err := fleetcache.ReplicateSealed(context.Background(), sink, wmB, framesB)
	if err == nil || resR.Status != fleetcache.ImportStatusRejected {
		t.Fatalf("replicate want reject %+v %v", resR, err)
	}
	if resR.Residual != fleetcache.PartitionResidualConflictDigest {
		t.Fatalf("residual %q", resR.Residual)
	}

	m, ok, _ := meta.GetCommittedFleetMapping(context.Background(), wmA.LocatorHash)
	if !ok || m.ManifestDigest != wmA.ManifestDigest {
		t.Fatalf("must keep A %+v", m)
	}
	assertPartitionLogBody(t, fr, m.GenerationID, fullA)
}

// No mixed content under conflict: A frames only after rejected B.
func TestPartition_Store_NoMixedContentAfterConflict(t *testing.T) {
	partsA := [][]byte{[]byte("AAA-frame0\n"), []byte("AAA-frame1\n")}
	partsB := [][]byte{[]byte("BBB-frame0\n"), []byte("BBB-frame1\n")}
	wmA, framesA, fullA := buildImportFixture(t, partsA)
	wmB, framesB, fullB := buildImportFixture(t, partsB)
	if bytes.Equal(fullA, fullB) {
		t.Fatal("fixtures must differ")
	}

	meta, fr, sink := openPartitionStore(t)
	if _, err := fleetcache.RunImport(context.Background(), sink, wmA, framesA); err != nil {
		t.Fatal(err)
	}
	if _, err := fleetcache.ReplicateSealed(context.Background(), sink, wmB, framesB); err == nil {
		t.Fatal("expected conflict")
	}

	m, ok, _ := meta.GetCommittedFleetMapping(context.Background(), wmA.LocatorHash)
	if !ok {
		t.Fatal("missing mapping")
	}
	body := assertPartitionLogBody(t, fr, m.GenerationID, fullA)
	if strings.Contains(string(body), "BBB") {
		t.Fatalf("mixed B content into A body: %q", body)
	}
	// Pure evaluator residual for conflict.
	out := fleetcache.EvaluateManifestConflict(&fleetcache.CommittedMapping{
		LocatorHash: m.LocatorHash, ManifestDigest: m.ManifestDigest, Status: "committed",
	}, wmB)
	if out.Action != fleetcache.PartitionActionConflict {
		t.Fatalf("%+v", out)
	}
}

func assertPartitionLogBody(t *testing.T, fr *store.Frames, generationID int64, want []byte) []byte {
	t.Helper()
	reader, err := fr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	rr, err := reader.ReadRange(context.Background(), generationID, 0, int64(len(want)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rr.Data, want) {
		t.Fatalf("LogReader mismatch got %q want %q", rr.Data, want)
	}
	return rr.Data
}
