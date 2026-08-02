package fleetcache_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

func finalizeLocator(t *testing.T) fleetcache.Locator {
	t.Helper()
	loc, err := fleetcache.NewConsoleLogLocator("fleet", "pool", "ctrl", "job/a", 7)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func TestPlanFinalizeFromDurable_NoRecompressPlan(t *testing.T) {
	t.Parallel()
	wm, frames := makeSealedManifest(t, [][]byte{[]byte("fin-a\n"), []byte("fin-b\n")})
	loc := finalizeLocator(t)

	// Wire frames from the published manifest (already-known pure digests).
	wire := append([]fleetcache.WireFrame(nil), wm.Frames...)
	plan, out, err := fleetcache.PlanFinalizeFromDurable(loc, wire, frames)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Residual != fleetcache.ResidualFinalizeFramesReused {
		t.Fatalf("residual %q", plan.Residual)
	}
	if len(plan.FrameSeqs) != 2 || plan.FrameSeqs[0] != 0 || plan.FrameSeqs[1] != 1 {
		t.Fatalf("seqs %v", plan.FrameSeqs)
	}
	if plan.LocatorHash != wm.LocatorHash || plan.ManifestDigest != wm.ManifestDigest {
		t.Fatalf("plan identity: %+v vs %+v", plan, wm)
	}
	if out.ManifestDigest != wm.ManifestDigest {
		t.Fatalf("manifest digest changed (recompress?): %s vs %s", out.ManifestDigest, wm.ManifestDigest)
	}
	// Digest-stable replan (idempotent plan).
	plan2, out2, err := fleetcache.PlanFinalizeFromDurable(loc, wire, frames)
	if err != nil {
		t.Fatal(err)
	}
	if plan2.ManifestDigest != plan.ManifestDigest || out2.ManifestDigest != out.ManifestDigest {
		t.Fatal("plan not idempotent")
	}
	// Digest-only path (no pure bytes) still builds the same sealed digest.
	plan3, out3, err := fleetcache.PlanFinalizeFromDurable(loc, wire, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan3.ManifestDigest != plan.ManifestDigest || out3.ManifestDigest != out.ManifestDigest {
		t.Fatal("digest-only plan must match pure proof plan")
	}
}

func TestPlanFinalizeFromDurable_RejectEmptyAndMismatch(t *testing.T) {
	t.Parallel()
	loc := finalizeLocator(t)
	_, _, err := fleetcache.PlanFinalizeFromDurable(loc, nil, nil)
	if err == nil {
		t.Fatal("empty frames")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code %s", apperr.CodeOf(err))
	}

	wm, frames := makeSealedManifest(t, [][]byte{[]byte("x\n"), []byte("y\n")})
	// Corrupt pure digests.
	bad := append([]fleetcache.ImportFrameBytes{}, frames...)
	bad[0].PureZstd = append([]byte{}, bad[0].PureZstd...)
	bad[0].PureZstd[len(bad[0].PureZstd)-1] ^= 0xff
	_, _, err = fleetcache.PlanFinalizeFromDurable(loc, wm.Frames, bad)
	if err == nil {
		t.Fatal("expected digest mismatch")
	}
	// Gap in progressive ranges.
	gap := []fleetcache.WireFrame{
		{Seq: 0, RawStart: 0, RawEnd: 5, DecodedSize: 5,
			DecodedSHA256: strings.Repeat("ab", 32), ZstdSize: 4, ZstdSHA256: strings.Repeat("cd", 32)},
		{Seq: 1, RawStart: 9, RawEnd: 12, DecodedSize: 3,
			DecodedSHA256: strings.Repeat("ef", 32), ZstdSize: 4, ZstdSHA256: strings.Repeat("01", 32)},
	}
	_, _, err = fleetcache.PlanFinalizeFromDurable(loc, gap, nil)
	if err == nil {
		t.Fatal("expected gap reject")
	}
	// Missing wire identity.
	missing := []fleetcache.WireFrame{
		{Seq: 0, RawStart: 0, RawEnd: 2, DecodedSize: 2, DecodedSHA256: strings.Repeat("11", 32)},
	}
	_, _, err = fleetcache.PlanFinalizeFromDurable(loc, missing, nil)
	if err == nil {
		t.Fatal("missing zstd identity")
	}
}

func TestFinalizeSealed_CommitIdempotentFramesReused(t *testing.T) {
	t.Parallel()
	wm, frames := makeSealedManifest(t, [][]byte{[]byte("line1\n"), []byte("line2\n")})
	sink := &memSink{}

	res, err := fleetcache.FinalizeSealed(context.Background(), sink, wm, frames)
	if err != nil || res.Status != fleetcache.FinalizeStatusCommitted {
		t.Fatalf("%+v %v", res, err)
	}
	if res.FramesReused != len(frames) {
		t.Fatalf("FramesReused %d want %d (no recompress)", res.FramesReused, len(frames))
	}
	if res.Residual != fleetcache.ResidualFinalizeFramesReused {
		t.Fatalf("residual %q", res.Residual)
	}
	if _, ok, _ := sink.GetCommitted(context.Background(), wm.LocatorHash); !ok {
		t.Fatal("must be committed")
	}
	// Exactly one preferred version: second finalize idempotent, same digest, full reuse count.
	res2, err := fleetcache.FinalizeSealed(context.Background(), sink, wm, frames)
	if err != nil || res2.Status != fleetcache.FinalizeStatusIdempotent {
		t.Fatalf("%+v %v", res2, err)
	}
	if res2.FramesReused != len(frames) {
		t.Fatalf("idempotent FramesReused %d", res2.FramesReused)
	}
	if res2.ManifestDigest != res.ManifestDigest {
		t.Fatal("digest drift on second finalize")
	}
	if res2.Residual != fleetcache.ResidualFinalizeIdempotent {
		t.Fatalf("residual %q", res2.Residual)
	}
	// Commit count must not bump on idempotent path (single preferred version).
	sink.mu.Lock()
	n := sink.commitCount[wm.LocatorHash]
	sink.mu.Unlock()
	if n != 1 {
		t.Fatalf("commitCount %d want 1", n)
	}
}

func TestFinalizeSealed_PartialAbortInvisible(t *testing.T) {
	t.Parallel()
	wm, frames := makeSealedManifest(t, [][]byte{[]byte("p0\n"), []byte("p1\n")})
	sink := &memSink{}

	// Manual partial: Begin + one frame + Abort → not committed.
	importID, genID, err := sink.Begin(context.Background(), wm)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.WriteFrame(context.Background(), importID, genID, wm.Frames[0], frames[0].PureZstd); err != nil {
		t.Fatal(err)
	}
	if err := sink.Abort(context.Background(), importID); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := sink.GetCommitted(context.Background(), wm.LocatorHash); err != nil || ok {
		t.Fatalf("partial must not be GetCommitted: ok=%v err=%v", ok, err)
	}

	// Full FinalizeSealed → committed once; FramesReused == len.
	res, err := fleetcache.FinalizeSealed(context.Background(), sink, wm, frames)
	if err != nil || res.Status != fleetcache.FinalizeStatusCommitted {
		t.Fatalf("%+v %v", res, err)
	}
	if res.FramesReused != len(frames) {
		t.Fatalf("FramesReused %d", res.FramesReused)
	}
	// Second call FramesReused + idempotent.
	res2, err := fleetcache.FinalizeSealed(context.Background(), sink, wm, frames)
	if err != nil || res2.Status != fleetcache.FinalizeStatusIdempotent {
		t.Fatalf("%+v %v", res2, err)
	}
	if res2.FramesReused != len(frames) {
		t.Fatalf("idempotent FramesReused %d", res2.FramesReused)
	}
}

func TestFinalizeSealed_WriteFailAbortNoCommit(t *testing.T) {
	t.Parallel()
	wm, frames := makeSealedManifest(t, [][]byte{[]byte("a\n"), []byte("b\n")})
	sink := &memSink{failAt: 1}
	res, err := fleetcache.FinalizeSealed(context.Background(), sink, wm, frames)
	if err == nil || res.Status != fleetcache.FinalizeStatusAborted {
		t.Fatalf("expected abort %+v %v", res, err)
	}
	if res.FramesReused != 0 {
		t.Fatalf("aborted must not claim full reuse: %d", res.FramesReused)
	}
	if _, ok, _ := sink.GetCommitted(context.Background(), wm.LocatorHash); ok {
		t.Fatal("fail mid-finalize must not leave preferred mapping")
	}
	// Resume/complete is idempotent: full finalize after abort succeeds once.
	sink2 := &memSink{}
	// Use clean sink (aborted staging deleted); full finalize.
	res2, err := fleetcache.FinalizeSealed(context.Background(), sink2, wm, frames)
	if err != nil || res2.Status != fleetcache.FinalizeStatusCommitted {
		t.Fatalf("%+v %v", res2, err)
	}
	res3, err := fleetcache.FinalizeSealed(context.Background(), sink2, wm, frames)
	if err != nil || res3.Status != fleetcache.FinalizeStatusIdempotent {
		t.Fatalf("%+v %v", res3, err)
	}
}

func TestFinalizeFence_SingleWriter(t *testing.T) {
	t.Parallel()
	wm, _ := makeSealedManifest(t, [][]byte{[]byte("fence\n")})
	auth := fleetcache.NewFinalizeFenceAuthority()
	f1, err := auth.AcquireFinalizeFence(wm.LocatorHash)
	if err != nil || f1 == 0 {
		t.Fatalf("%v fence=%d", err, f1)
	}
	if !auth.IsFinalizeFenceHeld(wm.LocatorHash) {
		t.Fatal("must be held")
	}
	_, err = auth.AcquireFinalizeFence(wm.LocatorHash)
	if err == nil {
		t.Fatal("second acquire must fail")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code %s", apperr.CodeOf(err))
	}
	// Stale complete fail-closed.
	if err := auth.CompleteFinalizeFence(wm.LocatorHash, wm.ManifestDigest, f1+99); err == nil {
		t.Fatal("stale fence")
	}
	if err := auth.CompleteFinalizeFence(wm.LocatorHash, wm.ManifestDigest, f1); err != nil {
		t.Fatal(err)
	}
	if auth.IsFinalizeFenceHeld(wm.LocatorHash) {
		t.Fatal("released after complete")
	}
	// Release is idempotent for non-held.
	auth.ReleaseFinalizeFence(wm.LocatorHash, f1)
	// Re-acquire after complete.
	f2, err := auth.AcquireFinalizeFence(wm.LocatorHash)
	if err != nil || f2 == 0 {
		t.Fatal(err)
	}
	auth.ReleaseFinalizeFence(wm.LocatorHash, f2)
	if auth.IsFinalizeFenceHeld(wm.LocatorHash) {
		t.Fatal("released")
	}
}

func TestFinalize_SecretFreeResiduals(t *testing.T) {
	t.Parallel()
	// All residual tokens must be secret-free (no paths, tokens, credentials).
	banned := []string{"token", "password", "authorization", "/home/", "bearer ", "secret"}
	for _, s := range []string{
		fleetcache.ResidualFinalizeFramesReused,
		fleetcache.ResidualFinalizeIdempotent,
		fleetcache.ResidualFinalizePartialAborted,
		fleetcache.ResidualFinalizeNoFrames,
		fleetcache.ResidualFinalizeDigestMismatch,
		fleetcache.ResidualFinalizeFenceHeld,
		fleetcache.ResidualFinalizeFenceStale,
		fleetcache.FinalizeHonestyResidual,
	} {
		low := strings.ToLower(s)
		for _, b := range banned {
			if strings.Contains(low, b) {
				t.Fatalf("residual must be secret-free: %q contains %q", s, b)
			}
		}
	}
	// End-to-end residual on happy path.
	wm, frames := makeSealedManifest(t, [][]byte{[]byte("sec\n")})
	res, err := fleetcache.FinalizeSealed(context.Background(), &memSink{}, wm, frames)
	if err != nil {
		t.Fatal(err)
	}
	low := strings.ToLower(res.Residual)
	for _, b := range banned {
		if strings.Contains(low, b) {
			t.Fatalf("result residual secret leak: %q", res.Residual)
		}
	}
}
