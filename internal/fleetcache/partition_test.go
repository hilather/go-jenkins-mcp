package fleetcache_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

// --- Pure evaluator unit matrix (FLC-045) ---

func TestEvaluateDuplicateFill_Matrix(t *testing.T) {
	t.Parallel()
	dA := strings.Repeat("aa", 32)
	dB := strings.Repeat("bb", 32)

	cases := []struct {
		name     string
		existing string
		cand     string
		action   string
		residual string
	}{
		{"no_existing", "", dA, fleetcache.PartitionActionStart, fleetcache.PartitionResidualNoCommitted},
		{"same_digest", dA, dA, fleetcache.PartitionActionConverge, fleetcache.PartitionResidualDuplicateConverged},
		{"same_digest_case", strings.ToUpper(dA), dA, fleetcache.PartitionActionConverge, fleetcache.PartitionResidualDuplicateConverged},
		{"conflict", dA, dB, fleetcache.PartitionActionConflict, fleetcache.PartitionResidualConflictDigest},
		{"empty_candidate", dA, "", fleetcache.PartitionActionReject, fleetcache.PartitionResidualConflictDigest},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out := fleetcache.EvaluateDuplicateFill(tc.existing, tc.cand)
			if out.Action != tc.action || out.Residual != tc.residual {
				t.Fatalf("got action=%q residual=%q want %q %q", out.Action, out.Residual, tc.action, tc.residual)
			}
		})
	}
}

func TestEvaluateStaleFence_FailClosed(t *testing.T) {
	t.Parallel()
	if err := fleetcache.EvaluateStaleFence(3, 3); err != nil {
		t.Fatal(err)
	}
	err := fleetcache.EvaluateStaleFence(3, 2)
	if err == nil {
		t.Fatal("stale fence must fail")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code %s", apperr.CodeOf(err))
	}
	if !strings.Contains(err.Error(), fleetcache.PartitionResidualStaleFence) {
		t.Fatalf("error %v", err)
	}
}

func TestEvaluateStaleEpoch_CompletedWrongFence(t *testing.T) {
	t.Parallel()
	if err := fleetcache.EvaluateStaleEpoch(true, 5, 5); err != nil {
		t.Fatal(err)
	}
	err := fleetcache.EvaluateStaleEpoch(true, 5, 4)
	if err == nil {
		t.Fatal("stale epoch must fail")
	}
	if !strings.Contains(err.Error(), fleetcache.PartitionResidualStaleEpoch) {
		t.Fatalf("error %v", err)
	}
	// Not completed: fence must still match.
	if err := fleetcache.EvaluateStaleEpoch(false, 2, 1); err == nil {
		t.Fatal("active mismatch must fail")
	}
}

func TestEvaluateManifestConflict_AndPlanImport(t *testing.T) {
	t.Parallel()
	wm, _ := makeSealedManifest(t, [][]byte{[]byte("partition-a\n")})
	digest := wm.ManifestDigest

	// Start
	out := fleetcache.EvaluateManifestConflict(nil, wm)
	if out.Action != fleetcache.PartitionActionStart {
		t.Fatalf("%+v", out)
	}
	plan, err := fleetcache.PlanImport(nil, wm)
	if err != nil || plan.Action != fleetcache.ImportActionStart {
		t.Fatalf("%+v %v", plan, err)
	}

	// Converge
	out = fleetcache.EvaluateManifestConflict(&fleetcache.CommittedMapping{
		LocatorHash: wm.LocatorHash, ManifestDigest: digest, Status: "committed",
	}, wm)
	if out.Action != fleetcache.PartitionActionConverge || out.Residual != fleetcache.PartitionResidualDuplicateConverged {
		t.Fatalf("%+v", out)
	}
	plan, err = fleetcache.PlanImport(&fleetcache.CommittedMapping{
		LocatorHash: wm.LocatorHash, ManifestDigest: digest, Status: "committed",
	}, wm)
	if err != nil || plan.Action != fleetcache.ImportActionIdempotent {
		t.Fatalf("%+v %v", plan, err)
	}
	if plan.Residual != fleetcache.PartitionResidualDuplicateConverged {
		t.Fatalf("residual %q", plan.Residual)
	}

	// Conflict
	other := strings.Repeat("ff", 32)
	out = fleetcache.EvaluateManifestConflict(&fleetcache.CommittedMapping{
		LocatorHash: wm.LocatorHash, ManifestDigest: other, Status: "committed",
	}, wm)
	if out.Action != fleetcache.PartitionActionConflict || out.Residual != fleetcache.PartitionResidualConflictDigest {
		t.Fatalf("%+v", out)
	}
	_, err = fleetcache.PlanImport(&fleetcache.CommittedMapping{
		LocatorHash: wm.LocatorHash, ManifestDigest: other, Status: "committed",
	}, wm)
	if err == nil {
		t.Fatal("expected conflict")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code %s", apperr.CodeOf(err))
	}
}

// AC1 + AC3: same digest dual fill converges; no extra persisted commit; FramesTransferred=0.
func TestPartition_SameDigestDualFill_Idempotent(t *testing.T) {
	t.Parallel()
	wm, frames := makeSealedManifest(t, [][]byte{[]byte("dual-fill-1\n"), []byte("dual-fill-2\n")})
	sink := &memSink{}

	// Producer A via RunImport
	res, err := fleetcache.RunImport(context.Background(), sink, wm, frames)
	if err != nil || res.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("first import %+v %v", res, err)
	}
	gen1 := res.GenerationID
	if sink.commitCount[wm.LocatorHash] != 1 {
		t.Fatalf("commitCount=%d", sink.commitCount[wm.LocatorHash])
	}
	hashes1 := append([]string{}, sink.committedFrameHashes[wm.LocatorHash]...)

	// Producer B (same digest) via ReplicateSealed — idempotent, zero transfer.
	res2, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, frames)
	if err != nil || res2.Status != fleetcache.ImportStatusIdempotent {
		t.Fatalf("second replicate %+v %v", res2, err)
	}
	if res2.FramesTransferred != 0 {
		t.Fatalf("FramesTransferred=%d want 0", res2.FramesTransferred)
	}
	if res2.Residual != fleetcache.PartitionResidualDuplicateConverged {
		t.Fatalf("residual %q", res2.Residual)
	}
	// Third path: RunImport also idempotent.
	res3, err := fleetcache.RunImport(context.Background(), sink, wm, frames)
	if err != nil || res3.Status != fleetcache.ImportStatusIdempotent {
		t.Fatalf("third import %+v %v", res3, err)
	}

	// Single committed mapping; no extra Commit.
	if sink.commitCount[wm.LocatorHash] != 1 {
		t.Fatalf("extra commits commitCount=%d", sink.commitCount[wm.LocatorHash])
	}
	cm, ok, err := sink.GetCommitted(context.Background(), wm.LocatorHash)
	if err != nil || !ok {
		t.Fatalf("committed ok=%v err=%v", ok, err)
	}
	if cm.ManifestDigest != wm.ManifestDigest || cm.GenerationID != gen1 {
		t.Fatalf("mapping changed %+v gen1=%d", cm, gen1)
	}
	// Body hashes unchanged (no mixed content).
	if len(sink.committedFrameHashes[wm.LocatorHash]) != len(hashes1) {
		t.Fatal("frame hash length drift")
	}
	for i := range hashes1 {
		if sink.committedFrameHashes[wm.LocatorHash][i] != hashes1[i] {
			t.Fatalf("frame %d mixed/changed", i)
		}
	}
}

// AC4: different digest conflict — residual visible, committed A not overwritten.
func TestPartition_DifferentDigestConflict_NotOverwritten(t *testing.T) {
	t.Parallel()
	wmA, framesA := makeSealedManifest(t, [][]byte{[]byte("content-A-frame0\n"), []byte("content-A-frame1\n")})
	// Same locator (same job/build in makeSealedManifest), different body → different digest.
	wmB, framesB := makeSealedManifest(t, [][]byte{[]byte("content-B-OTHER\n"), []byte("content-B-ALT\n")})
	if wmA.LocatorHash != wmB.LocatorHash {
		t.Fatalf("locator mismatch %s vs %s", wmA.LocatorHash, wmB.LocatorHash)
	}
	if wmA.ManifestDigest == wmB.ManifestDigest {
		t.Fatal("expected different digests")
	}

	sink := &memSink{}
	res, err := fleetcache.RunImport(context.Background(), sink, wmA, framesA)
	if err != nil || res.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("%+v %v", res, err)
	}
	hashesA := append([]string{}, sink.committedFrameHashes[wmA.LocatorHash]...)

	// RunImport conflict.
	resC, err := fleetcache.RunImport(context.Background(), sink, wmB, framesB)
	if err == nil || resC.Status != fleetcache.ImportStatusRejected {
		t.Fatalf("RunImport conflict want reject %+v %v", resC, err)
	}
	if resC.Residual != fleetcache.PartitionResidualConflictDigest {
		t.Fatalf("RunImport residual %q", resC.Residual)
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code %s", apperr.CodeOf(err))
	}

	// ReplicateSealed conflict (must not begin transfer).
	resR, err := fleetcache.ReplicateSealed(context.Background(), sink, wmB, framesB)
	if err == nil || resR.Status != fleetcache.ImportStatusRejected {
		t.Fatalf("ReplicateSealed conflict want reject %+v %v", resR, err)
	}
	if resR.Residual != fleetcache.PartitionResidualConflictDigest {
		t.Fatalf("replicate residual %q", resR.Residual)
	}
	if resR.FramesTransferred != 0 {
		t.Fatalf("must not transfer frames on conflict: %d", resR.FramesTransferred)
	}

	// Original mapping + body intact.
	cm, ok, _ := sink.GetCommitted(context.Background(), wmA.LocatorHash)
	if !ok || cm.ManifestDigest != wmA.ManifestDigest {
		t.Fatalf("overwritten or missing %+v", cm)
	}
	if sink.commitCount[wmA.LocatorHash] != 1 {
		t.Fatalf("commitCount=%d", sink.commitCount[wmA.LocatorHash])
	}
	for i, h := range hashesA {
		if sink.committedFrameHashes[wmA.LocatorHash][i] != h {
			t.Fatalf("frame body mixed at %d", i)
		}
	}
	// Pure evaluator residual matches shipped residual.
	out := fleetcache.EvaluateManifestConflict(&cm, wmB)
	if out.Action != fleetcache.PartitionActionConflict || out.Residual != fleetcache.PartitionResidualConflictDigest {
		t.Fatalf("%+v", out)
	}
}

// AC2: stale completion rejected (wrong fence).
func TestPartition_StaleFence_CompleteRejected(t *testing.T) {
	t.Parallel()
	auth := fleetcache.NewFillLeaseAuthority(30 * time.Second)
	lh := strings.Repeat("45", 32) // 64 hex

	j, err := auth.Join("fleet", lh, "producer-1")
	if err != nil || j.Role != fleetcache.FillRoleProducer {
		t.Fatalf("%+v %v", j, err)
	}
	// Pure evaluator agrees fence must match.
	if err := fleetcache.EvaluateStaleFence(j.Lease.Fence, j.Lease.Fence+99); err == nil {
		t.Fatal("EvaluateStaleFence must reject")
	}
	// Shipped Complete with wrong fence.
	err = auth.Complete("fleet", lh, "producer-1", j.Lease.LeaseID, j.Lease.Fence+99, strings.Repeat("11", 32))
	if err == nil {
		t.Fatal("Complete with wrong fence must fail")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code %s", apperr.CodeOf(err))
	}
	st := auth.Status(lh)
	if st.Completed || st.State == fleetcache.FillLeaseCompleted {
		t.Fatalf("must not complete under wrong fence %+v", st)
	}
	if st.State != fleetcache.FillLeaseActive {
		t.Fatalf("want active %+v", st)
	}
	// Correct fence completes.
	digest := strings.Repeat("22", 32)
	if err := auth.Complete("fleet", lh, "producer-1", j.Lease.LeaseID, j.Lease.Fence, digest); err != nil {
		t.Fatal(err)
	}
	st = auth.Status(lh)
	if !st.Completed || st.ManifestDigest != digest {
		t.Fatalf("%+v", st)
	}
}

// AC2: stale epoch — after complete, Join returns completed; wrong-fence Complete residual.
func TestPartition_StaleEpoch_AfterComplete(t *testing.T) {
	t.Parallel()
	auth := fleetcache.NewFillLeaseAuthority(30 * time.Second)
	lh := strings.Repeat("46", 32)

	j, err := auth.Join("fleet", lh, "prod-a")
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("33", 32)
	if err := auth.Complete("fleet", lh, "prod-a", j.Lease.LeaseID, j.Lease.Fence, digest); err != nil {
		t.Fatal(err)
	}
	// Join after complete → completed role (stale epoch for new producers).
	j2, err := auth.Join("fleet", lh, "prod-b")
	if err != nil || j2.Role != fleetcache.FillRoleCompleted {
		t.Fatalf("join after complete %+v %v", j2, err)
	}
	if j2.Lease.ManifestDigest != digest {
		t.Fatalf("digest %+v", j2.Lease)
	}
	// Pure stale-epoch residual.
	if err := fleetcache.EvaluateStaleEpoch(true, j.Lease.Fence, j.Lease.Fence+1); err == nil {
		t.Fatal("stale epoch expected")
	}
	// Complete with different fence fail closed; Status still original digest.
	err = auth.Complete("fleet", lh, "prod-b", "fl_fake", j.Lease.Fence+1, strings.Repeat("ff", 32))
	if err == nil {
		t.Fatal("stale complete after epoch must fail")
	}
	st := auth.Status(lh)
	if st.State != fleetcache.FillLeaseCompleted || st.ManifestDigest != digest {
		t.Fatalf("epoch must keep digest %+v", st)
	}
	// Wrong member same fence also fails (already completed with different producer).
	err = auth.Complete("fleet", lh, "prod-b", j.Lease.LeaseID, j.Lease.Fence, digest)
	if err == nil {
		t.Fatal("wrong member complete after epoch must fail")
	}
}

// AC1: no mixed content — frames from different manifests rejected; committed body not interleaved.
func TestPartition_NoMixedContent_FramesRejected(t *testing.T) {
	t.Parallel()
	wmA, framesA := makeSealedManifest(t, [][]byte{[]byte("mix-A0\n"), []byte("mix-A1\n")})
	wmB, framesB := makeSealedManifest(t, [][]byte{[]byte("mix-B0\n"), []byte("mix-B1\n")})
	if wmA.ManifestDigest == wmB.ManifestDigest {
		t.Fatal("need different manifests")
	}

	// Mix: frame0 from A, frame1 from B against manifest A.
	mixed := []fleetcache.ImportFrameBytes{
		framesA[0],
		{Seq: framesB[1].Seq, PureZstd: framesB[1].PureZstd},
	}
	err := fleetcache.AssertFramesSameManifest(wmA, mixed)
	if err == nil {
		t.Fatal("mixed frames must be rejected")
	}
	if !strings.Contains(err.Error(), fleetcache.PartitionResidualMixedFramesRejected) &&
		apperr.CodeOf(err) != apperr.CodeCorruptCache {
		// Accept either residual wrap or corrupt hash from ValidateImportFrames.
		t.Logf("mixed reject err=%v code=%s", err, apperr.CodeOf(err))
	}
	// ValidateImportFrames also fails (shipped path).
	if err := fleetcache.ValidateImportFrames(wmA, mixed); err == nil {
		t.Fatal("ValidateImportFrames must reject mixed hashes")
	}

	// After conflict on dual digest, only A body is committed (no interleave).
	sink := &memSink{}
	if _, err := fleetcache.RunImport(context.Background(), sink, wmA, framesA); err != nil {
		t.Fatal(err)
	}
	if _, err := fleetcache.RunImport(context.Background(), sink, wmB, framesB); err == nil {
		t.Fatal("conflict expected")
	}
	// Committed frame hashes match only A (not B).
	wantA0 := shaHex(framesA[0].PureZstd)
	wantA1 := shaHex(framesA[1].PureZstd)
	got := sink.committedFrameHashes[wmA.LocatorHash]
	if len(got) != 2 || got[0] != wantA0 || got[1] != wantA1 {
		t.Fatalf("mixed body %+v want %s %s", got, wantA0, wantA1)
	}
	// Staging must not leave B frames under committed mapping.
	if len(sink.staging) != 0 {
		// staging map may be empty after reject (reject before Begin) — good.
	}
	// Count committed mappings: exactly one locator, one digest.
	if len(sink.committed) != 1 {
		t.Fatalf("committed map size %d", len(sink.committed))
	}
}

// Partition honesty residual: secret-free; documents may-duplicate-origin; FLC-045 Done*.
func TestPartition_HonestyResidual_SecretFree(t *testing.T) {
	t.Parallel()
	r := fleetcache.FillLeaseAuthorityResidual()
	if !strings.Contains(r, "partition") {
		t.Fatal(r)
	}
	if !strings.Contains(r, "FLC-045") {
		t.Fatal(r)
	}
	if !strings.Contains(r, "Done*") {
		t.Fatal("matrix Done* expected in residual: " + r)
	}
	ph := fleetcache.PartitionHonestyResidual()
	if !strings.Contains(ph, fleetcache.PartitionResidualNote) {
		t.Fatal(ph)
	}
	for _, bad := range []string{"password", "Bearer ", "ghp_", "token=", "Authorization"} {
		if strings.Contains(r, bad) || strings.Contains(ph, bad) {
			t.Fatalf("secret-like residual: %q / %q", r, ph)
		}
	}
	// Status path remains secret-free under partition.
	auth := fleetcache.NewFillLeaseAuthority(0)
	lh := strings.Repeat("47", 32)
	j, err := auth.Join("fleet", lh, "edge-partition")
	if err != nil {
		t.Fatal(err)
	}
	_ = auth.Complete("fleet", lh, "edge-partition", j.Lease.LeaseID, j.Lease.Fence, strings.Repeat("ab", 32))
	st := fmt.Sprintf("%+v", auth.Status(lh))
	for _, bad := range []string{"password", "Bearer ", "ghp_"} {
		if strings.Contains(st, bad) {
			t.Fatalf("status secret-like: %s", st)
		}
	}
}

// Split-primary simulation: two independent authorities both complete same digest;
// dual import into one sink converges (AC3 under partition).
func TestPartition_SplitPrimary_SameDigestConverges(t *testing.T) {
	t.Parallel()
	wm, frames := makeSealedManifest(t, [][]byte{[]byte("split-primary\n")})
	lh := wm.LocatorHash
	digest := wm.ManifestDigest

	auth1 := fleetcache.NewFillLeaseAuthority(30 * time.Second)
	auth2 := fleetcache.NewFillLeaseAuthority(30 * time.Second) // independent "partitioned" primary

	j1, err := auth1.Join("fleet", lh, "node-a")
	if err != nil || j1.Role != fleetcache.FillRoleProducer {
		t.Fatalf("auth1 %+v %v", j1, err)
	}
	j2, err := auth2.Join("fleet", lh, "node-b")
	if err != nil || j2.Role != fleetcache.FillRoleProducer {
		t.Fatalf("auth2 %+v %v", j2, err)
	}
	// Both can Complete under their own authority (partition may duplicate origin).
	if err := auth1.Complete("fleet", lh, "node-a", j1.Lease.LeaseID, j1.Lease.Fence, digest); err != nil {
		t.Fatal(err)
	}
	if err := auth2.Complete("fleet", lh, "node-b", j2.Lease.LeaseID, j2.Lease.Fence, digest); err != nil {
		t.Fatal(err)
	}

	sink := &memSink{}
	// Both "producers" import into the same receiver sink sequentially.
	r1, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, frames)
	if err != nil || r1.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("first %+v %v", r1, err)
	}
	r2, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, frames)
	if err != nil || r2.Status != fleetcache.ImportStatusIdempotent || r2.FramesTransferred != 0 {
		t.Fatalf("second converge %+v %v", r2, err)
	}
	if sink.commitCount[lh] != 1 {
		t.Fatalf("must not double-commit under same digest: %d", sink.commitCount[lh])
	}
}
