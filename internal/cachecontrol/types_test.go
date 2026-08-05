package cachecontrol

import (
	"testing"
)

func TestTypeIDs_ClosedSet(t *testing.T) {
	ids := AllTypeIDs()
	if len(ids) != 12 {
		t.Fatalf("expected 12 type IDs, got %d", len(ids))
	}
	seen := map[TypeID]bool{}
	for _, id := range ids {
		if !id.Valid() {
			t.Fatalf("invalid id in AllTypeIDs: %s", id)
		}
		if seen[id] {
			t.Fatalf("duplicate %s", id)
		}
		seen[id] = true
	}
	if TypeID("nope").Valid() {
		t.Fatal("unknown type should be invalid")
	}
}

func TestMode_ParseAndSemantics(t *testing.T) {
	for _, m := range AllModes() {
		if !m.Valid() {
			t.Fatalf("invalid mode %s", m)
		}
		p, err := ParseMode(string(m))
		if err != nil || p != m {
			t.Fatalf("ParseMode %s: %v %v", m, p, err)
		}
	}
	if _, err := ParseMode("rw"); err == nil {
		t.Fatal("expected error for unknown mode")
	}
	if ModeOff.AllowsRead() || ModeOff.AllowsWrite() {
		t.Fatal("off must not read or write")
	}
	if !ModeReadOnly.AllowsRead() || ModeReadOnly.AllowsWrite() {
		t.Fatal("read_only semantics")
	}
	if ModeWriteOnly.AllowsRead() || !ModeWriteOnly.AllowsWrite() {
		t.Fatal("write_only semantics")
	}
	if !ModeReadWrite.AllowsRead() || !ModeReadWrite.AllowsWrite() {
		t.Fatal("read_write semantics")
	}
}

func TestDecide(t *testing.T) {
	cases := []struct {
		enabled bool
		mode    Mode
		want    Decision
	}{
		{true, ModeOff, DecisionBypassOrigin},
		{false, ModeReadWrite, DecisionBypassOrigin},
		{true, ModeReadOnly, DecisionLookupOnly},
		{true, ModeWriteOnly, DecisionFillOnly},
		{true, ModeReadWrite, DecisionCacheAside},
	}
	for _, tc := range cases {
		if got := Decide(tc.enabled, tc.mode); got != tc.want {
			t.Fatalf("Decide(%v,%s)=%s want %s", tc.enabled, tc.mode, got, tc.want)
		}
	}
}
