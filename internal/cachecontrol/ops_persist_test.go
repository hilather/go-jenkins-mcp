package cachecontrol

import (
	"context"
	"path/filepath"
	"testing"
)

// succeedingAdapter executes purge successfully (for epoch-on-success tests).
type succeedingAdapter struct {
	staticAdapter
	executed int
}

func (a *succeedingAdapter) Execute(context.Context, OperationContext, OperationPlan) error {
	a.executed++
	return nil
}

func TestPlanExecute_PersistentAndEpochOnSuccessOnly(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenOverrideStore(filepath.Join(dir, "cc"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Registry with succeeding purge adapter for artifact_blob
	b := NewBuilder()
	for _, d := range defaultDescriptors() {
		if d.TypeID == TypeArtifactBlob {
			ad := &succeedingAdapter{staticAdapter: staticAdapter{d: d}}
			if err := b.Register(ad); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := b.Register(&staticAdapter{d: d}); err != nil {
			t.Fatal(err)
		}
	}
	reg, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(ServiceConfig{
		Registry: reg, OverrideStore: st, ProfileID: "p",
	})
	if err != nil {
		t.Fatal(err)
	}

	plan, err := svc.PlanOperation(context.Background(), OperationRequest{
		Kind: OpPurge, TypeID: TypeArtifactBlob, Reason: "test purge",
	})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := st.LoadPlan(context.Background(), plan.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != OpStatePlanned || rec.ConfirmToken != "PURGE" {
		t.Fatalf("%+v", rec)
	}

	if err := svc.ExecuteOperation(context.Background(), plan, "PURGE", "actor", "admin_mcp"); err != nil {
		t.Fatal(err)
	}
	rec2, err := st.LoadPlan(context.Background(), plan.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	if rec2.State != OpStateSucceeded {
		t.Fatalf("state %s", rec2.State)
	}
	if svc.PurgeEpoch(TypeArtifactBlob) < 1 {
		t.Fatal("epoch must bump after successful purge execute")
	}
}
