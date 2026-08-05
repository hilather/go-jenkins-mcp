package cachecontrol

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestOverrideStore_CASAndExpiry(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenOverrideStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ctx := context.Background()
	rev, err := st.Revision(ctx)
	if err != nil || rev != 0 {
		t.Fatalf("rev %d %v", rev, err)
	}

	ro := ModeReadOnly
	res, err := st.Patch(ctx, PatchRequest{
		ProfileID:        "p1",
		ExpectedRevision: 0,
		Reason:           "disk pressure",
		ActorIDHash:      "actor1",
		Source:           "admin_mcp",
		Types:            map[TypeID]TypeConfig{TypeArtifactBlob: {Mode: &ro}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Revision != 1 {
		t.Fatalf("rev %d", res.Revision)
	}

	// CAS conflict
	_, err = st.Patch(ctx, PatchRequest{
		ProfileID:        "p1",
		ExpectedRevision: 0,
		Types:            map[TypeID]TypeConfig{TypeArtifactBlob: {Mode: &ro}},
		ActorIDHash:      "x",
		Source:           "cli",
	})
	if err == nil {
		t.Fatal("expected CAS conflict")
	}

	ov, err := st.LoadOverrides(ctx, "p1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if ov.Revision != 1 {
		t.Fatal(ov.Revision)
	}
	if ov.Types[TypeArtifactBlob].Mode == nil || *ov.Types[TypeArtifactBlob].Mode != ModeReadOnly {
		t.Fatalf("%+v", ov.Types[TypeArtifactBlob])
	}

	// Expiry
	exp := time.Now().UTC().Add(-time.Minute)
	off := ModeOff
	_, err = st.Patch(ctx, PatchRequest{
		ProfileID:        "p1",
		ExpectedRevision: 1,
		ExpiresAt:        &exp,
		ActorIDHash:      "a",
		Source:           "cli",
		Types:            map[TypeID]TypeConfig{TypeStageLog: {Mode: &off}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ov, err = st.LoadOverrides(ctx, "p1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ov.Types[TypeStageLog]; ok {
		t.Fatal("expired override should be ignored")
	}

	// Reset type
	_, err = st.Reset(ctx, "p1", TypeArtifactBlob, ov.Revision)
	if err != nil {
		t.Fatal(err)
	}
	ov, err = st.LoadOverrides(ctx, "p1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ov.Types[TypeArtifactBlob]; ok {
		t.Fatal("reset should remove override")
	}

	// Purge epoch
	ep, err := st.BumpPurgeEpoch(ctx, "p1", TypeArtifactBlob)
	if err != nil || ep != 1 {
		t.Fatalf("epoch %d %v", ep, err)
	}
	ep, err = st.BumpPurgeEpoch(ctx, "p1", TypeArtifactBlob)
	if err != nil || ep != 2 {
		t.Fatalf("epoch %d %v", ep, err)
	}
	epochs, err := st.LoadPurgeEpochs(ctx, "p1")
	if err != nil || epochs[TypeArtifactBlob] != 2 {
		t.Fatalf("%v %v", epochs, err)
	}

	if filepath.Base(st.Path()) != "cache-control.sqlite" {
		t.Fatal(st.Path())
	}
}

func TestService_InventoryAndPatch(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenOverrideStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	svc, err := NewService(ServiceConfig{
		Registry:      DefaultRegistry(),
		OverrideStore: st,
		ProfileID:     "corp",
	})
	if err != nil {
		t.Fatal(err)
	}
	inv := svc.Inventory(context.Background())
	if len(inv) != 12 {
		t.Fatalf("inventory %d", len(inv))
	}
	// Default modes
	for _, item := range inv {
		if item.Descriptor.TypeID == TypeRatarmountIndex {
			if item.Mode != ModeOff {
				t.Fatal("ratarmount")
			}
			continue
		}
		if item.Mode != ModeReadWrite {
			t.Fatalf("%s mode %s", item.Descriptor.TypeID, item.Mode)
		}
	}

	// Patch artifact_blob off
	off := ModeOff
	res, err := svc.Patch(context.Background(), PatchRequest{
		ExpectedRevision: 0,
		Reason:           "test disable",
		ActorIDHash:      "h",
		Source:           "admin_mcp",
		Types:            map[TypeID]TypeConfig{TypeArtifactBlob: {Mode: &off}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Revision != 1 {
		t.Fatal(res.Revision)
	}
	if svc.Effective().TypeMode(TypeArtifactBlob) != ModeOff {
		t.Fatal("mode not applied")
	}
	if svc.AllowLookup("artifact_blob") || svc.AllowFill("artifact_blob") {
		t.Fatal("off must block lookup/fill")
	}
	// Other types unchanged
	if !svc.AllowLookup("test_report") {
		t.Fatal("test_report still on")
	}

	// Reject ratarmount enable
	rw := ModeReadWrite
	_, err = svc.Patch(context.Background(), PatchRequest{
		ExpectedRevision: res.Revision,
		ActorIDHash:      "h",
		Source:           "cli",
		Types:            map[TypeID]TypeConfig{TypeRatarmountIndex: {Mode: &rw}},
	})
	if err == nil {
		t.Fatal("expected unqualified rejection")
	}

	// Plan dump requires confirm; raw blocked
	_, err = svc.PlanOperation(context.Background(), OperationRequest{
		Kind: OpDump, TypeID: TypeArtifactBlob, DumpMode: DumpRaw,
	})
	if err == nil {
		t.Fatal("raw dump should be blocked")
	}
	plan, err := svc.PlanOperation(context.Background(), OperationRequest{
		Kind: OpPurge, TypeID: TypeArtifactBlob,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.ConfirmToken != "PURGE" {
		t.Fatal(plan.ConfirmToken)
	}
	// Execute without confirm
	if err := svc.ExecuteOperation(context.Background(), plan, "", "h", "admin_mcp"); err == nil {
		t.Fatal("confirm required")
	}
	// Static adapter execute fails even with confirm (unsupported until real adapter)
	epBefore := svc.Effective().Types[TypeArtifactBlob].PurgeEpoch
	if err := svc.ExecuteOperation(context.Background(), plan, "PURGE", "h", "admin_mcp"); err == nil {
		t.Fatal("static execute should fail")
	}
	// Purge epoch must NOT bump on failed execute (regression: theater epoch)
	if svc.Effective().Types[TypeArtifactBlob].PurgeEpoch != epBefore {
		t.Fatalf("purge epoch advanced on failed execute: before=%d after=%d",
			epBefore, svc.Effective().Types[TypeArtifactBlob].PurgeEpoch)
	}
	// Plan should be durable and marked failed
	rec, err := st.LoadPlan(context.Background(), plan.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != OpStateFailed {
		t.Fatalf("plan state %s want failed", rec.State)
	}
}

func TestService_RuntimeMutationsDisabled(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenOverrideStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	svc, err := NewService(ServiceConfig{
		OverrideStore: st,
		ProfileID:     "p",
		Startup:       StartupConstraints{DisableRuntimeMutations: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	off := ModeOff
	_, err = svc.Patch(context.Background(), PatchRequest{
		ExpectedRevision: 0,
		ActorIDHash:      "h",
		Source:           "cli",
		Types:            map[TypeID]TypeConfig{TypeConsoleLog: {Mode: &off}},
	})
	if err == nil {
		t.Fatal("expected mutations disabled")
	}
}

func TestTelemetry_LowCardinality(t *testing.T) {
	r := NewTelemetryRecorder()
	r.Record(TelemetryEvent{TypeID: TypeArtifactBlob, Layer: LayerDisk, Outcome: OutcomeHit, Bytes: 100})
	r.Record(TelemetryEvent{TypeID: TypeArtifactBlob, Layer: LayerDisk, Outcome: OutcomeHit, Bytes: 50})
	r.Record(TelemetryEvent{TypeID: TypeArtifactBlob, Layer: LayerNone, Outcome: OutcomeMiss})
	snap := r.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("rows %d", len(snap))
	}
	var hitCount, hitBytes int64
	for _, row := range snap {
		if row.Outcome == OutcomeHit {
			hitCount = row.Count
			hitBytes = row.Bytes
		}
		// Canary: no path-like fields
		if len(row.Reason) > 64 {
			t.Fatal("reason too long")
		}
	}
	if hitCount != 2 || hitBytes != 150 {
		t.Fatalf("hit %d bytes %d", hitCount, hitBytes)
	}
}
