package fleetcache_test

import (
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

func enabledNearPolicy() fleetcache.NearCachePolicy {
	p := fleetcache.DefaultNearCachePolicy()
	p.Enabled = true
	return p
}

func TestDefaultNearCachePolicy_Disabled(t *testing.T) {
	t.Parallel()
	p := fleetcache.DefaultNearCachePolicy()
	if p.Enabled {
		t.Fatal("product default must keep near promotion disabled")
	}
	if p.MaxObjectBytes != fleetcache.DefaultNearMaxObjectBytes {
		t.Fatalf("MaxObjectBytes=%d", p.MaxObjectBytes)
	}
	if p.MinRepeatAccess != fleetcache.DefaultNearMinRepeatAccess {
		t.Fatalf("MinRepeatAccess=%d", p.MinRepeatAccess)
	}
	if p.NoStore {
		t.Fatal("NoStore default false")
	}
}

func TestAdmitNearCache_Disabled(t *testing.T) {
	t.Parallel()
	res := fleetcache.AdmitNearCache(fleetcache.NearAdmitRequest{
		LocatorHash:      "abc",
		TotalRawBytes:    1024,
		PriorAccessCount: 10,
		AuthzAllowed:     true,
		ManifestVerified: true,
		Policy:           fleetcache.DefaultNearCachePolicy(), // Enabled=false
	})
	if res.Admit || res.CopyRole != "" {
		t.Fatalf("disabled must deny: %+v", res)
	}
	if res.Residual != fleetcache.NearResidualDisabled {
		t.Fatalf("residual=%q want near_disabled", res.Residual)
	}
}

func TestAdmitNearCache_NoStore(t *testing.T) {
	t.Parallel()
	pol := enabledNearPolicy()
	pol.NoStore = true
	res := fleetcache.AdmitNearCache(fleetcache.NearAdmitRequest{
		TotalRawBytes:    100,
		PriorAccessCount: 5,
		AuthzAllowed:     true,
		ManifestVerified: true,
		Policy:           pol,
	})
	if res.Admit || res.Residual != fleetcache.NearResidualNoStore {
		t.Fatalf("%+v", res)
	}
}

func TestAdmitNearCache_AuthzDeny(t *testing.T) {
	t.Parallel()
	res := fleetcache.AdmitNearCache(fleetcache.NearAdmitRequest{
		TotalRawBytes:    100,
		PriorAccessCount: 5,
		AuthzAllowed:     false,
		ManifestVerified: true,
		Policy:           enabledNearPolicy(),
	})
	if res.Admit || res.Residual != fleetcache.NearResidualAuthzDeny {
		t.Fatalf("%+v", res)
	}
}

func TestAdmitNearCache_ManifestUnverified(t *testing.T) {
	t.Parallel()
	res := fleetcache.AdmitNearCache(fleetcache.NearAdmitRequest{
		TotalRawBytes:    100,
		PriorAccessCount: 5,
		AuthzAllowed:     true,
		ManifestVerified: false,
		Policy:           enabledNearPolicy(),
	})
	if res.Admit || res.Residual != fleetcache.NearResidualManifestUnverified {
		t.Fatalf("%+v", res)
	}
}

func TestAdmitNearCache_HugeSingleUse(t *testing.T) {
	t.Parallel()
	// Huge log: exceed MaxObjectBytes even with many prior accesses.
	pol := enabledNearPolicy()
	pol.MaxObjectBytes = 1024
	res := fleetcache.AdmitNearCache(fleetcache.NearAdmitRequest{
		TotalRawBytes:    1024 + 1,
		PriorAccessCount: 100,
		AuthzAllowed:     true,
		ManifestVerified: true,
		Policy:           pol,
	})
	if res.Admit || res.Residual != fleetcache.NearResidualTooLarge {
		t.Fatalf("huge: %+v", res)
	}

	// Single-use: small object but insufficient prior hits (do not auto-promote).
	res2 := fleetcache.AdmitNearCache(fleetcache.NearAdmitRequest{
		TotalRawBytes:    512,
		PriorAccessCount: 0, // first evidence read
		AuthzAllowed:     true,
		ManifestVerified: true,
		Policy:           pol,
	})
	if res2.Admit || res2.Residual != fleetcache.NearResidualSingleUse {
		t.Fatalf("single-use: %+v", res2)
	}
	// One prior hit with MinRepeatAccess=2 still single-use.
	res3 := fleetcache.AdmitNearCache(fleetcache.NearAdmitRequest{
		TotalRawBytes:    512,
		PriorAccessCount: 1,
		AuthzAllowed:     true,
		ManifestVerified: true,
		Policy:           pol,
	})
	if res3.Admit || res3.Residual != fleetcache.NearResidualSingleUse {
		t.Fatalf("still single-use: %+v", res3)
	}
}

func TestAdmitNearCache_SmallWithRepeatsAdmitted(t *testing.T) {
	t.Parallel()
	pol := enabledNearPolicy()
	res := fleetcache.AdmitNearCache(fleetcache.NearAdmitRequest{
		LocatorHash:      "deadbeef",
		TotalRawBytes:    64 << 10, // 64 KiB << 8 MiB default
		PriorAccessCount: fleetcache.DefaultNearMinRepeatAccess,
		AuthzAllowed:     true,
		ManifestVerified: true,
		Policy:           pol,
	})
	if !res.Admit {
		t.Fatalf("expected admit: %+v", res)
	}
	if res.CopyRole != fleetcache.CopyRoleNear {
		t.Fatalf("CopyRole=%q want %q", res.CopyRole, fleetcache.CopyRoleNear)
	}
	if res.Residual != fleetcache.NearResidualAdmitted {
		t.Fatalf("residual=%q", res.Residual)
	}
}

func TestAdmitNearCache_LowSpace(t *testing.T) {
	t.Parallel()
	pol := enabledNearPolicy()
	pol.FreeSpaceMinBytes = 10 << 20
	// Unknown free space (0) skips check → admit.
	resUnknown := fleetcache.AdmitNearCache(fleetcache.NearAdmitRequest{
		TotalRawBytes:    100,
		PriorAccessCount: 5,
		FreeSpaceBytes:   0,
		AuthzAllowed:     true,
		ManifestVerified: true,
		Policy:           pol,
	})
	if !resUnknown.Admit {
		t.Fatalf("unknown free space should not deny: %+v", resUnknown)
	}
	// Known free space below min → deny.
	resLow := fleetcache.AdmitNearCache(fleetcache.NearAdmitRequest{
		TotalRawBytes:    100,
		PriorAccessCount: 5,
		FreeSpaceBytes:   1 << 20,
		AuthzAllowed:     true,
		ManifestVerified: true,
		Policy:           pol,
	})
	if resLow.Admit || resLow.Residual != fleetcache.NearResidualLowSpace {
		t.Fatalf("%+v", resLow)
	}
}

func TestAdmitNearCache_BoundaryEqualMaxAdmitted(t *testing.T) {
	t.Parallel()
	pol := enabledNearPolicy()
	pol.MaxObjectBytes = 1000
	res := fleetcache.AdmitNearCache(fleetcache.NearAdmitRequest{
		TotalRawBytes:    1000, // not > max
		PriorAccessCount: 2,
		AuthzAllowed:     true,
		ManifestVerified: true,
		Policy:           pol,
	})
	if !res.Admit {
		t.Fatalf("%+v", res)
	}
}

func TestFilterRFObservations_NearExcluded(t *testing.T) {
	t.Parallel()
	obs := map[string]fleetcache.ReplicaObservation{
		"owner-a": {MemberID: "owner-a", Status: "committed", Digest: "aa"},
		"owner-b": {MemberID: "owner-b", Status: "missing"},
		"near-x":  {MemberID: "near-x", Status: "committed", Digest: "aa"},
	}
	near := map[string]bool{"near-x": true}
	filt := fleetcache.FilterRFObservations(obs, near)
	if _, ok := filt["near-x"]; ok {
		t.Fatal("near member must be filtered out of RF observations")
	}
	if len(filt) != 2 {
		t.Fatalf("len=%d want 2: %+v", len(filt), filt)
	}
	// Input map not mutated.
	if _, ok := obs["near-x"]; !ok {
		t.Fatal("FilterRFObservations must not mutate input")
	}
	// nil nearMembers → copy all
	all := fleetcache.FilterRFObservations(obs, nil)
	if len(all) != 3 {
		t.Fatalf("nil near: %+v", all)
	}
	if fleetcache.FilterRFObservations(nil, near) != nil {
		t.Fatal("nil obs → nil")
	}
}

func TestPlanRF2_NearOnlyCommittedStillUnderReplicated(t *testing.T) {
	t.Parallel()
	// AC: promotion never changes owner placement or RF health — near-only committed
	// must not satisfy RF2; PlanRF2 still needs owner transfers.
	wm, _ := makeSealedManifest(t, [][]byte{[]byte("near-rf\n"), []byte("line2\n")})
	members := []fleetcache.PlacementMember{
		{ID: "lab-a", CapacityWeight: 100, FailureDomain: "z1"},
		{ID: "lab-b", CapacityWeight: 100, FailureDomain: "z2"},
		{ID: "lab-c", CapacityWeight: 100, FailureDomain: "z3"},
	}
	// Non-owner near member holds a committed copy; RF owners do not.
	nearMember := "lab-c"
	obsRaw := map[string]fleetcache.ReplicaObservation{
		nearMember: {
			MemberID: nearMember,
			Status:   "committed",
			Digest:   wm.ManifestDigest,
		},
	}
	nearSet := map[string]bool{nearMember: true}
	obs := fleetcache.FilterRFObservations(obsRaw, nearSet)

	plan, err := fleetcache.PlanRF2Replication(wm.LocatorHash, members, wm, obs, fleetcache.PlacementOptions{
		ReplicationFactor: 2, PreferDistinctDomains: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.RequiredOwners) != 2 {
		t.Fatalf("owners=%v", plan.RequiredOwners)
	}
	// Near member must not be a required owner solely because of near promotion
	// (placement is hash-based; lab-c might still be an owner — assert near role
	// observation did not create a healthy RF skip for owners without copies).
	for _, id := range plan.RequiredOwners {
		if id == nearMember {
			// If placement selected nearMember as owner, filtered obs means no committed
			// → full_import, not skip_verified.
			for _, tgt := range plan.Targets {
				if tgt.MemberID == nearMember && tgt.Action == fleetcache.ReplicaActionSkipVerified {
					t.Fatal("near-only committed must not count as verified RF owner")
				}
			}
		}
	}
	// With near filtered out, no source from near-only map → source_missing residual OK.
	// Both required owners need transfer (not skip).
	healthy := fleetcache.CountHealthyRFFromObservations(plan.RequiredOwners, wm.ManifestDigest, obs)
	if healthy != 0 {
		t.Fatalf("healthy RF from near-filtered obs=%d want 0", healthy)
	}
	if plan.FramesToTransfer == 0 {
		t.Fatalf("under-replicated: expected frame transfers; plan=%+v", plan)
	}
	for _, tgt := range plan.Targets {
		if tgt.Action == fleetcache.ReplicaActionSkipVerified {
			t.Fatalf("no owner should skip with only near filtered obs: %+v", tgt)
		}
	}

	// Without FilterRFObservations, if nearMember is NOT a required owner, PlanRF2
	// also ignores it (only inspects required owners). Assert placement stability:
	// RequiredOwners unchanged whether near obs present or not.
	plan2, err := fleetcache.PlanRF2Replication(wm.LocatorHash, members, wm, obsRaw, fleetcache.PlacementOptions{
		ReplicationFactor: 2, PreferDistinctDomains: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan2.RequiredOwners) != len(plan.RequiredOwners) {
		t.Fatalf("near obs must not change owner count: %v vs %v", plan.RequiredOwners, plan2.RequiredOwners)
	}
	for i := range plan.RequiredOwners {
		if plan.RequiredOwners[i] != plan2.RequiredOwners[i] {
			t.Fatalf("near obs must not change placement: %v vs %v", plan.RequiredOwners, plan2.RequiredOwners)
		}
	}
}

func TestPlanRepair_NearDoesNotCountAsRF(t *testing.T) {
	t.Parallel()
	wm, _ := makeSealedManifest(t, [][]byte{[]byte("repair-near\n")})
	members := []fleetcache.PlacementMember{
		{ID: "m1", CapacityWeight: 100, FailureDomain: "a"},
		{ID: "m2", CapacityWeight: 100, FailureDomain: "b"},
		{ID: "m3", CapacityWeight: 100, FailureDomain: "c"},
	}
	// Near-only committed filtered out — RF still under-replicated.
	obs := fleetcache.FilterRFObservations(map[string]fleetcache.ReplicaObservation{
		"m3": {MemberID: "m3", Status: "committed", Digest: wm.ManifestDigest},
	}, map[string]bool{"m3": true})

	plan, err := fleetcache.PlanRepair(wm.LocatorHash, members, wm, obs, fleetcache.RepairOptions{
		MaxConcurrentCopies: 2,
		Placement:           fleetcache.PlacementOptions{ReplicationFactor: 2, PreferDistinctDomains: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Residual == "rf_healthy" {
		t.Fatalf("near-only must not yield rf_healthy residual: %+v", plan)
	}
	healthy := fleetcache.CountHealthyRFFromObservations(plan.RequiredOwners, wm.ManifestDigest, obs)
	if healthy != 0 {
		t.Fatalf("near-filtered healthy=%d want 0", healthy)
	}
	if plan.FramesToTransfer == 0 && plan.TransferCount == 0 && len(plan.DeferredOwners) == 0 {
		t.Fatalf("expected under-replicated repair work; plan=%+v", plan)
	}
}

func TestRecordNearAdmit_Metrics(t *testing.T) {
	// Not parallel: package Metrics.
	fleetcache.ResetForTest()
	deny := fleetcache.AdmitNearCache(fleetcache.NearAdmitRequest{
		Policy: fleetcache.DefaultNearCachePolicy(),
	})
	fleetcache.RecordNearAdmit(deny)
	admit := fleetcache.AdmitNearCache(fleetcache.NearAdmitRequest{
		TotalRawBytes:    10,
		PriorAccessCount: 5,
		AuthzAllowed:     true,
		ManifestVerified: true,
		Policy:           enabledNearPolicy(),
	})
	fleetcache.RecordNearAdmit(admit)
	snap := fleetcache.Metrics.Snapshot()
	if snap[fleetcache.MetricNearDeny] != 1 {
		t.Fatalf("near_deny=%d", snap[fleetcache.MetricNearDeny])
	}
	if snap[fleetcache.MetricNearAdmit] != 1 {
		t.Fatalf("near_admit=%d", snap[fleetcache.MetricNearAdmit])
	}
}

func TestAdmitNearCache_SecretFreeCanary(t *testing.T) {
	t.Parallel()
	// Residuals must never embed caller secrets even if LocatorHash is secret-shaped.
	// (LocatorHash is not echoed into Residual by design.)
	pol := enabledNearPolicy()
	cases := []fleetcache.NearAdmitRequest{
		{Policy: fleetcache.DefaultNearCachePolicy(), LocatorHash: "token=sekrit"},
		{Policy: pol, AuthzAllowed: false, LocatorHash: "Bearer xyz"},
		{Policy: pol, AuthzAllowed: true, ManifestVerified: false},
		{Policy: pol, AuthzAllowed: true, ManifestVerified: true, TotalRawBytes: 1 << 40, PriorAccessCount: 99},
		{Policy: func() fleetcache.NearCachePolicy { p := pol; p.NoStore = true; return p }(), AuthzAllowed: true, ManifestVerified: true, PriorAccessCount: 5},
		{Policy: pol, AuthzAllowed: true, ManifestVerified: true, TotalRawBytes: 1, PriorAccessCount: 5},
	}
	for i, req := range cases {
		res := fleetcache.AdmitNearCache(req)
		canarySecretFree(t, res.Residual)
		canarySecretFree(t, res.CopyRole)
		for _, bad := range []string{"password", "Bearer ", "ghp_", "token=", "Authorization", "sekrit"} {
			if strings.Contains(res.Residual, bad) {
				t.Fatalf("case %d residual leaked %q: %q", i, bad, res.Residual)
			}
		}
		// Known residual vocabulary only.
		switch res.Residual {
		case fleetcache.NearResidualDisabled, fleetcache.NearResidualNoStore,
			fleetcache.NearResidualTooLarge, fleetcache.NearResidualSingleUse,
			fleetcache.NearResidualAuthzDeny, fleetcache.NearResidualManifestUnverified,
			fleetcache.NearResidualLowSpace, fleetcache.NearResidualAdmitted:
			// ok
		default:
			t.Fatalf("case %d unknown residual %q", i, res.Residual)
		}
	}
}

func TestCopyRoleNear_QuotaEvictsBeforeRequired(t *testing.T) {
	t.Parallel()
	// AC interaction: near reclaimed before required (FLC-050 already; sanity for FLC-033).
	ordered := fleetcache.OrderEvictCandidates([]fleetcache.EvictCandidate{
		{GenerationID: 1, CopyRole: fleetcache.CopyRoleRequired, Bytes: 10},
		{GenerationID: 2, CopyRole: fleetcache.CopyRoleNear, Bytes: 10},
	}, true)
	if ordered[0].CopyRole != fleetcache.CopyRoleNear {
		t.Fatalf("near before required: %+v", ordered)
	}
	if fleetcache.ShouldSkipL1Release(fleetcache.CopyRoleNear, true) {
		t.Fatal("near must not skip L1 release")
	}
}
