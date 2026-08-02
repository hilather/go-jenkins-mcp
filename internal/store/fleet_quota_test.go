package store_test

import (
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
	"github.com/hilather/go-jenkins-mcp/internal/store"
)

func TestFleetAwareQuotaActive_ModeOff(t *testing.T) {
	t.Parallel()
	if store.FleetAwareQuotaActive(fleetcache.ModeOff) {
		t.Fatal("mode off must not enable fleet-aware quota")
	}
	if store.FleetAwareQuotaActive("") {
		t.Fatal("empty mode = off")
	}
	if store.FleetAwareQuotaActive(fleetcache.ModeShadow) {
		t.Fatal("shadow must not reorder local reclaim")
	}
	if !store.FleetAwareQuotaActive(fleetcache.ModeRead) {
		t.Fatal("read enables fleet-aware quota planning")
	}
	if !store.FleetAwareQuotaActive(fleetcache.ModeFull) {
		t.Fatal("full enables fleet-aware quota planning")
	}
}

func TestFleetQuotaRoleFromMapping(t *testing.T) {
	t.Parallel()
	if store.FleetQuotaRoleFromMapping(store.FleetImportStaging) != fleetcache.CopyRoleIncomplete {
		t.Fatal("staging → incomplete")
	}
	if store.FleetQuotaRoleFromMapping(store.FleetMappingCommitted) != fleetcache.CopyRoleUnknown {
		t.Fatal("committed → unknown (store hook partial)")
	}
	if store.FleetQuotaRoleFromMapping(store.FleetMappingQuarantined) != fleetcache.CopyRoleIncomplete {
		t.Fatal("quarantined → incomplete")
	}
}

func TestOrderFleetEvictCandidates_ModeOffUnchanged(t *testing.T) {
	t.Parallel()
	cands := []fleetcache.EvictCandidate{
		{GenerationID: 1, CopyRole: fleetcache.CopyRoleRequired},
		{GenerationID: 2, CopyRole: fleetcache.CopyRoleNear},
	}
	got := store.OrderFleetEvictCandidates(cands, false)
	if got[0].GenerationID != 1 || got[1].GenerationID != 2 {
		t.Fatalf("mode off order preserved: %+v", got)
	}
	gotAware := store.OrderFleetEvictCandidates(cands, true)
	if gotAware[0].GenerationID != 2 || gotAware[1].GenerationID != 1 {
		t.Fatalf("fleet aware near before required: %+v", gotAware)
	}
}

func TestOwnerRemovalFleetResidual(t *testing.T) {
	t.Parallel()
	if store.OwnerRemovalFleetResidual(true) != fleetcache.ResidualUnderReplicatedEnqueueRepair {
		t.Fatal("required removal residual")
	}
	if store.ShouldSkipFleetL1Release(fleetcache.CopyRoleRequired, true) != true {
		t.Fatal("skip L1 required")
	}
	if store.ShouldSkipFleetL1Release(fleetcache.CopyRoleRequired, false) {
		t.Fatal("mode off no skip")
	}
}
