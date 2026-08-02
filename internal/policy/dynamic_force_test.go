package policy_test

import (
	"sync"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

func TestDynamicForceSetMidLife_ForceTrueToFalse(t *testing.T) {
	t.Parallel()
	dyn := policy.NewDynamicForce(true, true)
	gate := policy.NewReadOnlyGate(policy.Inputs{
		AllowMutations: true,
		Force:          dyn,
	})
	if !gate.Effective() {
		t.Fatal("force=true must make Effective true")
	}
	if gate.AllowMutationRegistration() {
		t.Fatal("force=true must block write-enabled registration flag")
	}
	// Wave 30: opt-in still wants tools attached under force RO.
	if !gate.ShouldRegisterMutations() {
		t.Fatal("ShouldRegisterMutations true under allow-mutations + force")
	}
	if !contains(gate.Sources(), policy.SourceEnterpriseForce) {
		t.Fatalf("sources=%v want enterprise_force", gate.Sources())
	}

	// Wave 25: clear force mid-life (allow-mutations still set; no other RO sources).
	dyn.Set(false, true)
	if gate.Effective() {
		t.Fatal("force true→false must clear Effective when only enterprise force contributed RO")
	}
	if !gate.AllowMutationRegistration() {
		t.Fatal("AllowMutationRegistration must become true after force clears")
	}
	if !gate.ShouldRegisterMutations() {
		t.Fatal("ShouldRegisterMutations stays true after force clears")
	}
	if contains(gate.Sources(), policy.SourceEnterpriseForce) {
		t.Fatalf("sources must drop enterprise_force: %v", gate.Sources())
	}
}

func TestDynamicForceSetMidLife_ForceFalseToTrue(t *testing.T) {
	t.Parallel()
	dyn := policy.NewDynamicForce(false, true)
	gate := policy.NewReadOnlyGate(policy.Inputs{
		AllowMutations: true,
		Force:          dyn,
	})
	if gate.Effective() {
		t.Fatal("force=false present must not force RO alone")
	}
	if !gate.AllowMutationRegistration() {
		t.Fatal("want mutation registration allowed")
	}

	dyn.Set(true, true)
	if !gate.Effective() {
		t.Fatal("force false→true must make Effective true mid-life")
	}
	if gate.AllowMutationRegistration() {
		t.Fatal("AllowMutationRegistration must become false after force flips on")
	}
	if err := gate.DenyMutation(policy.ToolStartJob); err == nil {
		t.Fatal("DenyMutation must fail closed after force flips on")
	}
}

func TestDynamicForcePresentFalseIgnored(t *testing.T) {
	t.Parallel()
	dyn := policy.NewDynamicForce(true, false)
	gate := policy.NewReadOnlyGate(policy.Inputs{
		AllowMutations: true,
		Force:          dyn,
	})
	if gate.Effective() {
		t.Fatal("present=false must ignore force")
	}
	dyn.Set(true, false)
	if gate.Effective() {
		t.Fatal("still ignored after Set present=false")
	}
	// Raise present with force=true.
	dyn.Set(true, true)
	if !gate.Effective() {
		t.Fatal("present=true force=true must apply")
	}
}

func TestNewDynamicForceFromOverlay(t *testing.T) {
	t.Parallel()
	if f := policy.NewDynamicForceFromOverlay(nil); f == nil {
		t.Fatal("nil overlay still returns holder")
	} else if force, ok := f.ForceReadOnly(); ok || force {
		t.Fatalf("nil overlay: force=%v ok=%v", force, ok)
	}

	o := &policy.Overlay{Version: 1, ForceReadOnly: true}
	f := policy.NewDynamicForceFromOverlay(o)
	force, ok := f.ForceReadOnly()
	if !ok || !force {
		t.Fatalf("overlay force: force=%v ok=%v", force, ok)
	}
	f.SetFromOverlay(&policy.Overlay{Version: 1, ForceReadOnly: false})
	force, ok = f.ForceReadOnly()
	if !ok || force {
		t.Fatalf("after SetFromOverlay false: force=%v ok=%v", force, ok)
	}
}

func TestDynamicForceConcurrentSetAndRead(t *testing.T) {
	t.Parallel()
	dyn := policy.NewDynamicForce(false, true)
	gate := policy.NewReadOnlyGate(policy.Inputs{
		AllowMutations: true,
		Force:          dyn,
	})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				dyn.Set(j%2 == 0, true)
				_ = gate.Effective()
				_ = gate.AllowMutationRegistration()
				_ = gate.Sources()
			}
		}(i)
	}
	wg.Wait()
	// Final deterministic state.
	dyn.Set(true, true)
	if !gate.Effective() {
		t.Fatal("final force=true must be effective")
	}
}

// Regression: force true→false while flag RO remains keeps Effective true.
func TestDynamicForceClearDoesNotDefeatFlag(t *testing.T) {
	t.Parallel()
	dyn := policy.NewDynamicForce(true, true)
	gate := policy.NewReadOnlyGate(policy.Inputs{
		AllowMutations: true,
		FlagReadOnly:   true,
		Force:          dyn,
	})
	if !gate.Effective() {
		t.Fatal("want RO")
	}
	dyn.Set(false, true)
	if !gate.Effective() {
		t.Fatal("clearing enterprise force must not defeat --read-only")
	}
	if !contains(gate.Sources(), policy.SourceCLIFlag) {
		t.Fatalf("sources=%v", gate.Sources())
	}
}
