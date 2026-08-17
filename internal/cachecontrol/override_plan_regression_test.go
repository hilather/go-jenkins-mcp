package cachecontrol

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Regression: SavePlan with zero expiry wrote NULL expires_at, which LoadPlan
// then failed to scan into a non-nullable string — a plan saved without an
// expiry was unreadable (corrupt_cache on every LoadPlan/ExecuteOperation).
func TestPlanStore_ZeroExpiryRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenOverrideStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()

	rec := OperationRecord{
		PlanID:       "plan-noexpiry",
		ProfileID:    "lab",
		Kind:         OpPurge,
		TypeID:       TypeArtifactBlob,
		ConfirmToken: "tok",
		State:        OpStatePlanned,
		// ExpiresAtUnix deliberately zero (no expiry).
	}
	if err := st.SavePlan(ctx, rec); err != nil {
		t.Fatal(err)
	}
	got, err := st.LoadPlan(ctx, "plan-noexpiry")
	if err != nil {
		t.Fatalf("LoadPlan of zero-expiry plan: %v", err)
	}
	if got.PlanID != rec.PlanID || got.State != OpStatePlanned || got.ExpiresAtUnix != 0 {
		t.Fatalf("round trip: %+v", got)
	}
}

// Regression: LoadOverrides failed open on a malformed expires_at — the expiry
// filter skipped a row only when time.Parse SUCCEEDED and the time was past,
// so a corrupt/unparseable expires_at made a time-boxed override (e.g. an
// emergency mode=off) apply forever. Malformed expiry now fails closed
// (corrupt_cache), consistent with the rest of the package.
func TestLoadOverrides_MalformedExpiryFailsClosed(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenOverrideStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()

	ro := ModeReadOnly
	if _, err := st.Patch(ctx, PatchRequest{
		ProfileID: "p1",
		Reason:    "seed",
		Types:     map[TypeID]TypeConfig{TypeArtifactBlob: {Mode: &ro}},
	}); err != nil {
		t.Fatal(err)
	}
	// Corrupt the expires_at column directly.
	if _, err := st.db.ExecContext(ctx,
		`UPDATE cache_runtime_override SET expires_at = 'not-a-timestamp' WHERE profile_id = 'p1'`); err != nil {
		t.Fatal(err)
	}
	_, err = st.LoadOverrides(ctx, "p1", time.Now().UTC())
	if err == nil {
		t.Fatal("malformed expires_at must fail closed, not apply forever")
	}
}

// failingAdapter fails Execute with an operational (non-unsupported) error.
type failingAdapter struct {
	staticAdapter
}

func (a *failingAdapter) Execute(context.Context, OperationContext, OperationPlan) error {
	return apperr.New(apperr.CodeInternal, "disk write failed mid-purge")
}

// Regression: ExecuteOperation recorded ReasonUnsupportedOp as the error code
// for ANY adapter execution failure (IO error, cancellation, partial purge),
// misdirecting operators reading the durable plan record. The adapter failure
// now records a generic execution-failure code instead.
func TestExecuteOperation_AdapterFailureErrorCode(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenOverrideStore(filepath.Join(dir, "cc"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	b := NewBuilder()
	for _, d := range defaultDescriptors() {
		if d.TypeID == TypeArtifactBlob {
			if err := b.Register(&failingAdapter{staticAdapter{d: d}}); err != nil {
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
	svc, err := NewService(ServiceConfig{Registry: reg, OverrideStore: st, ProfileID: "lab"})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	plan, err := svc.PlanOperation(ctx, OperationRequest{
		Kind: OpPurge, TypeID: TypeArtifactBlob, Reason: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	err = svc.ExecuteOperation(ctx, plan, plan.ConfirmToken, "actor", "test")
	if err == nil {
		t.Fatal("failing adapter must fail the execution")
	}
	rec, lerr := st.LoadPlan(ctx, plan.PlanID)
	if lerr != nil {
		t.Fatal(lerr)
	}
	if rec.State != OpStateFailed {
		t.Fatalf("state=%s want failed", rec.State)
	}
	if rec.ErrorCode == ReasonUnsupportedOp {
		t.Fatalf("adapter execution failure misrecorded as %q", rec.ErrorCode)
	}
	if rec.ErrorCode == "" {
		t.Fatal("error_code must be recorded")
	}
}
