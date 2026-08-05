package cachecontrol

import (
	"context"
	"sync"
	"testing"
)

func TestDefaultRegistry_InventoryComplete(t *testing.T) {
	reg := DefaultRegistry()
	if reg.Len() != len(AllTypeIDs()) {
		t.Fatalf("registry len %d want %d", reg.Len(), len(AllTypeIDs()))
	}
	inv := reg.Inventory()
	if len(inv) != reg.Len() {
		t.Fatalf("inventory len mismatch")
	}
	// Deterministic order by type id
	for i := 1; i < len(inv); i++ {
		if inv[i-1].TypeID >= inv[i].TypeID {
			t.Fatalf("inventory not sorted: %s >= %s", inv[i-1].TypeID, inv[i].TypeID)
		}
	}
	for _, id := range AllTypeIDs() {
		d, ok := reg.Descriptor(id)
		if !ok {
			t.Fatalf("missing %s", id)
		}
		if d.TypeID != id {
			t.Fatalf("descriptor type mismatch")
		}
	}
	// ratarmount unqualified and only off
	d, _ := reg.Descriptor(TypeRatarmountIndex)
	if d.Availability != AvailabilityUnqualified {
		t.Fatalf("ratarmount availability %s", d.Availability)
	}
	if d.EnablementAllowed() {
		t.Fatal("ratarmount must not allow enablement")
	}
	if !d.SupportsMode(ModeOff) || d.SupportsMode(ModeReadWrite) {
		t.Fatal("ratarmount modes")
	}
}

func TestBuilder_DuplicateRejected(t *testing.T) {
	b := NewBuilder()
	d := defaultDescriptors()[0]
	if err := b.Register(&staticAdapter{d: d}); err != nil {
		t.Fatal(err)
	}
	if err := b.Register(&staticAdapter{d: d}); err == nil {
		t.Fatal("expected duplicate error")
	}
}

func TestBuilder_InvalidDescriptor(t *testing.T) {
	b := NewBuilder()
	err := b.Register(&staticAdapter{d: Descriptor{
		TypeID: "not_a_type", DisplayName: "x", StorageClass: ClassStreamLog,
		Availability: AvailabilityAvailable, SupportedModes: []Mode{ModeOff},
	}})
	if err == nil {
		t.Fatal("expected invalid type id")
	}
}

func TestRegistry_ConcurrentReads(t *testing.T) {
	reg := DefaultRegistry()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = reg.Inventory()
			_, _ = reg.Get(TypeArtifactBlob)
			_, _ = reg.Descriptor(TypeConsoleLog)
		}()
	}
	wg.Wait()
}

func TestStaticAdapter_UnsupportedOp(t *testing.T) {
	reg := DefaultRegistry()
	a, ok := reg.Get(TypeDiagnosticFetch)
	if !ok {
		t.Fatal("missing diagnostic")
	}
	_, err := a.ListEntries(context.Background(), EntryQuery{TypeID: TypeDiagnosticFetch})
	if err == nil {
		t.Fatal("list should be unsupported")
	}
	_, err = a.Plan(context.Background(), OperationRequest{
		Kind: OpDump, TypeID: TypeDiagnosticFetch, DumpMode: DumpRaw,
	})
	if err == nil {
		t.Fatal("raw dump should be unsupported for diagnostic")
	}
}
