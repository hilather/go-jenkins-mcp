package fleetcache_test

import (
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

func TestValidateProgressiveRanges_ContiguousOK(t *testing.T) {
	t.Parallel()
	frames := []fleetcache.WireFrame{
		{Seq: 0, RawStart: 0, RawEnd: 10, DecodedSize: 10},
		{Seq: 1, RawStart: 10, RawEnd: 25, DecodedSize: 15},
		{Seq: 2, RawStart: 25, RawEnd: 30, DecodedSize: 5},
	}
	if err := fleetcache.ValidateProgressiveRanges(frames); err != nil {
		t.Fatal(err)
	}
	if err := fleetcache.ValidateProgressiveRanges(nil); err != nil {
		t.Fatal(err)
	}
}

func TestValidateProgressiveRanges_GapOverlapSeq(t *testing.T) {
	t.Parallel()
	// Gap.
	if err := fleetcache.ValidateProgressiveRanges([]fleetcache.WireFrame{
		{Seq: 0, RawStart: 0, RawEnd: 10},
		{Seq: 1, RawStart: 12, RawEnd: 20}, // gap at 10..12
	}); err == nil {
		t.Fatal("expected gap error")
	}
	// Overlap.
	if err := fleetcache.ValidateProgressiveRanges([]fleetcache.WireFrame{
		{Seq: 0, RawStart: 0, RawEnd: 10},
		{Seq: 1, RawStart: 8, RawEnd: 20},
	}); err == nil {
		t.Fatal("expected overlap error")
	}
	// Seq hole.
	if err := fleetcache.ValidateProgressiveRanges([]fleetcache.WireFrame{
		{Seq: 0, RawStart: 0, RawEnd: 5},
		{Seq: 2, RawStart: 5, RawEnd: 10},
	}); err == nil {
		t.Fatal("expected seq error")
	}
	// raw_end < raw_start
	if err := fleetcache.ValidateProgressiveRanges([]fleetcache.WireFrame{
		{Seq: 0, RawStart: 5, RawEnd: 3},
	}); err == nil {
		t.Fatal("expected raw_end < raw_start")
	}
	// decoded_size mismatch
	if err := fleetcache.ValidateProgressiveRanges([]fleetcache.WireFrame{
		{Seq: 0, RawStart: 0, RawEnd: 10, DecodedSize: 9},
	}); err == nil {
		t.Fatal("expected decoded_size mismatch")
	}
}

func TestOffsetRegressionNeedsNewGeneration(t *testing.T) {
	t.Parallel()
	cases := []struct {
		prior, neu int64
		want       bool
	}{
		{100, 50, true},
		{100, 100, false},
		{100, 101, false},
		{0, 0, false},
		{10, -1, false}, // unknown next size
		{0, -1, false},
		{5, 0, true}, // rewrite to empty/shorter
	}
	for _, tc := range cases {
		got := fleetcache.OffsetRegressionNeedsNewGeneration(tc.prior, tc.neu)
		if got != tc.want {
			t.Fatalf("prior=%d new=%d got %v want %v", tc.prior, tc.neu, got, tc.want)
		}
	}
}

func TestPlanRunningDurablePrefix_OnlyDurable(t *testing.T) {
	t.Parallel()
	// Empty → no durable frames residual.
	plan, err := fleetcache.PlanRunningDurablePrefix(42, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.SealedSeqEnd != -1 || plan.FrameCount != 0 || plan.Residual != "no_durable_frames" {
		t.Fatalf("%+v", plan)
	}
	if plan.GenerationID != 42 {
		t.Fatalf("generation local residual: %d", plan.GenerationID)
	}
	if plan.ExportSeqs() != nil {
		t.Fatal("export seqs must be nil when empty")
	}

	durable := []fleetcache.WireFrame{
		{Seq: 0, RawStart: 0, RawEnd: 8, DecodedSize: 8},
		{Seq: 1, RawStart: 8, RawEnd: 16, DecodedSize: 8},
	}
	plan, err = fleetcache.PlanRunningDurablePrefix(7, durable)
	if err != nil {
		t.Fatal(err)
	}
	if plan.SealedSeqEnd != 1 || plan.FrameCount != 2 || plan.Residual != "durable_prefix_only" {
		t.Fatalf("%+v", plan)
	}
	seqs := plan.ExportSeqs()
	if len(seqs) != 2 || seqs[0] != 0 || seqs[1] != 1 {
		t.Fatalf("seqs %v", seqs)
	}
	selected := fleetcache.SelectRunningExportFrames(durable, plan)
	if len(selected) != 2 {
		t.Fatalf("selected %d", len(selected))
	}
	// Plan must not invent a third (buffered) frame.
	if plan.SealedSeqEnd >= len(durable) {
		t.Fatal("plan must not exceed durable")
	}

	// Invalid ranges fail closed.
	_, err = fleetcache.PlanRunningDurablePrefix(1, []fleetcache.WireFrame{
		{Seq: 0, RawStart: 0, RawEnd: 5},
		{Seq: 1, RawStart: 9, RawEnd: 12},
	})
	if err == nil {
		t.Fatal("expected invalid_ranges")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code %v", err)
	}
}

func TestProgressiveWireFrames_FromChunks(t *testing.T) {
	t.Parallel()
	chunks := []fleetcache.ProgressiveChunk{
		{Seq: 0, RawStart: 0, RawEnd: 4, LineStart: 0, LineEnd: 1},
		{Seq: 1, RawStart: 4, RawEnd: 10, LineStart: 1, LineEnd: 3, DecodedSize: 6},
	}
	wf := fleetcache.ProgressiveWireFrames(chunks)
	if err := fleetcache.ValidateProgressiveRanges(wf); err != nil {
		t.Fatal(err)
	}
	if wf[0].DecodedSize != 4 {
		t.Fatalf("derived decoded size: %d", wf[0].DecodedSize)
	}
}

func TestRunningFramePlan_SecretFreeResidual(t *testing.T) {
	t.Parallel()
	// Residuals must never look like paths, tokens, or credentials.
	plan, _ := fleetcache.PlanRunningDurablePrefix(1, []fleetcache.WireFrame{
		{Seq: 0, RawStart: 0, RawEnd: 1, DecodedSize: 1},
	})
	for _, s := range []string{plan.Residual} {
		low := strings.ToLower(s)
		for _, banned := range []string{"token", "password", "authorization", "/home/", "bearer "} {
			if strings.Contains(low, banned) {
				t.Fatalf("residual must be secret-free: %q", s)
			}
		}
	}
}
