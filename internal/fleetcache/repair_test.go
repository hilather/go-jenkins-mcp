package fleetcache_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

func TestDrainAllowsPrimary(t *testing.T) {
	t.Parallel()
	if !fleetcache.DrainAllowsPrimary("a", nil) {
		t.Fatal("nil drain set allows")
	}
	if fleetcache.DrainAllowsPrimary("", map[string]struct{}{"a": {}}) {
		t.Fatal("empty id never allowed")
	}
	drain := map[string]struct{}{"b": {}}
	if !fleetcache.DrainAllowsPrimary("a", drain) {
		t.Fatal("a not draining")
	}
	if fleetcache.DrainAllowsPrimary("b", drain) {
		t.Fatal("b is draining")
	}
}

// Node loss: 3 members RF2, source on A committed, B gone from roster → plan targets C;
// RunRepair commits C; second RunRepair FramesTransferred total 0 (idempotent / skip).
func TestPlanRepair_MemberLossRestoresRF(t *testing.T) {
	t.Parallel()
	wm, frames := makeSealedManifest(t, [][]byte{[]byte("loss0\n"), []byte("loss1\n")})
	// Full roster was A,B,C; B lost — remaining A,C must restore RF without origin.
	members := []fleetcache.PlacementMember{
		{ID: "lab-a", CapacityWeight: 100, FailureDomain: "z1"},
		{ID: "lab-c", CapacityWeight: 100, FailureDomain: "z3"},
	}
	// Source committed on A (peer pure-zstd exporter); C missing.
	replicas := map[string]fleetcache.ReplicaObservation{
		"lab-a": {MemberID: "lab-a", Digest: wm.ManifestDigest, Status: "committed"},
	}
	opts := fleetcache.RepairOptions{
		MaxConcurrentCopies: 2,
		PreviousOwnerGrace:  false,
		Placement: fleetcache.PlacementOptions{
			ReplicationFactor: 2, PreferDistinctDomains: true,
		},
		MembershipEpoch: 7,
	}
	plan, err := fleetcache.PlanRepair(wm.LocatorHash, members, wm, replicas, opts)
	if err != nil {
		t.Fatal(err)
	}
	if plan.ReplicationFactor != 2 || len(plan.RequiredOwners) != 2 {
		t.Fatalf("owners %+v", plan)
	}
	if plan.MembershipEpoch != 7 {
		t.Fatalf("epoch %d", plan.MembershipEpoch)
	}
	// Required owners must be subset of remaining roster (no lab-b).
	for _, o := range plan.RequiredOwners {
		if o == "lab-b" {
			t.Fatal("lost member must not be required owner")
		}
	}
	if plan.SourceMember != "lab-a" {
		// A may or may not be required; if A is required it is source; if not, residual source_missing
		// unless A is still among required (with 2 members both are required).
		if containsStr(plan.RequiredOwners, "lab-a") {
			t.Fatalf("source %q want lab-a when A is required; plan=%+v", plan.SourceMember, plan)
		}
	}

	sinks := map[string]fleetcache.ImportSink{}
	// Pre-seed A if it is a required owner.
	sinkA := &memSink{}
	if _, err := fleetcache.ReplicateSealed(context.Background(), sinkA, wm, frames); err != nil {
		t.Fatal(err)
	}
	for _, o := range plan.RequiredOwners {
		if o == "lab-a" {
			sinks[o] = sinkA
		} else {
			sinks[o] = &memSink{}
		}
	}

	// Expect at least one transfer target (under-replicated peer).
	var transferTargets int
	for _, tgt := range plan.Targets {
		if tgt.Action == fleetcache.RepairActionReplicateTo || tgt.Action == fleetcache.RepairActionDrainHandoff {
			if tgt.Residual != "budget_deferred" {
				transferTargets++
			}
		}
	}
	if transferTargets < 1 {
		t.Fatalf("expected under-replicated target; plan=%+v", plan)
	}

	res, err := fleetcache.RunRepair(context.Background(), plan, wm, frames, sinks)
	if err != nil {
		t.Fatal(err)
	}
	if res.FramesTransferred < 1 {
		t.Fatalf("expected peer pure-zstd transfer; res=%+v", res)
	}
	if !res.HealthyRF {
		t.Fatalf("RF not restored: %+v plan=%+v", res, plan)
	}
	// Verify every required owner committed matching digest (no Jenkins origin).
	for _, o := range plan.RequiredOwners {
		cm, ok, err := sinks[o].GetCommitted(context.Background(), wm.LocatorHash)
		if err != nil || !ok || !strings.EqualFold(cm.ManifestDigest, wm.ManifestDigest) {
			t.Fatalf("owner %s not healthy: ok=%v cm=%+v err=%v", o, ok, cm, err)
		}
	}

	// Second repair: plan all skip_healthy; RunRepair FramesTransferred 0.
	replicas2 := map[string]fleetcache.ReplicaObservation{}
	for _, o := range plan.RequiredOwners {
		replicas2[o] = fleetcache.ReplicaObservation{
			MemberID: o, Digest: wm.ManifestDigest, Status: "committed",
		}
	}
	plan2, err := fleetcache.PlanRepair(wm.LocatorHash, members, wm, replicas2, opts)
	if err != nil {
		t.Fatal(err)
	}
	if plan2.Residual != "rf_healthy" && plan2.TransferCount != 0 {
		t.Fatalf("second plan should be healthy: %+v", plan2)
	}
	for _, tgt := range plan2.Targets {
		if tgt.Action == fleetcache.RepairActionReplicateTo && tgt.Residual != "budget_deferred" {
			t.Fatalf("second plan must not schedule transfer: %+v", tgt)
		}
	}
	res2, err := fleetcache.RunRepair(context.Background(), plan2, wm, frames, sinks)
	if err != nil {
		t.Fatal(err)
	}
	if res2.FramesTransferred != 0 {
		t.Fatalf("Regression: second repair must be no-op; FramesTransferred=%d", res2.FramesTransferred)
	}
	if !res2.HealthyRF {
		t.Fatal("still healthy")
	}
}

// Drain: B draining — not a new required owner; refuse_new_primary if candidate;
// handoff from B (source) to remaining healthy owners under MaxConcurrentCopies=1.
func TestPlanRepair_DrainRefuseAndHandoff(t *testing.T) {
	t.Parallel()
	wm, frames := makeSealedManifest(t, [][]byte{[]byte("drain0\n"), []byte("drain1\n")})
	members := []fleetcache.PlacementMember{
		{ID: "node-a", CapacityWeight: 100, FailureDomain: "z1"},
		{ID: "node-b", CapacityWeight: 100, FailureDomain: "z2"},
		{ID: "node-c", CapacityWeight: 100, FailureDomain: "z3"},
	}
	// Force a case where B would be an unconstrained owner: seed replicas only on B
	// and check refuse when B is in drain set. Placement is HRW-based — if B is not
	// unconstrained owner, still assert B is never in RequiredOwners under drain.
	drain := map[string]struct{}{"node-b": {}}
	replicas := map[string]fleetcache.ReplicaObservation{
		"node-b": {MemberID: "node-b", Digest: wm.ManifestDigest, Status: "committed"},
	}
	opts := fleetcache.RepairOptions{
		MaxConcurrentCopies: 1,
		PreviousOwnerGrace:  true, // B may be grace source if not required
		DrainMemberIDs:      drain,
		Placement: fleetcache.PlacementOptions{
			ReplicationFactor: 2, PreferDistinctDomains: true,
		},
	}
	plan, err := fleetcache.PlanRepair(wm.LocatorHash, members, wm, replicas, opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range plan.RequiredOwners {
		if o == "node-b" {
			t.Fatalf("drain member must not be required owner: %+v", plan)
		}
		if !fleetcache.DrainAllowsPrimary(o, drain) {
			t.Fatalf("required owner %s still draining", o)
		}
	}
	// B never accepts new primary.
	if fleetcache.DrainAllowsPrimary("node-b", drain) {
		t.Fatal("DrainAllowsPrimary")
	}

	// If unconstrained placement would have picked B, residual refuse_new_primary.
	unconstrained, err := fleetcache.SelectPrimaryOwners(wm.LocatorHash, members, fleetcache.PlacementOptions{
		ReplicationFactor: 2, PreferDistinctDomains: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	bWasCandidate := containsStr(unconstrained, "node-b")
	var refuse bool
	for _, tgt := range plan.Targets {
		if tgt.Action == fleetcache.RepairActionRefuseNewPrimary && tgt.MemberID == "node-b" {
			refuse = true
		}
	}
	if bWasCandidate && !refuse {
		t.Fatalf("expected refuse_new_primary for candidate B; unconstrained=%v plan=%+v", unconstrained, plan)
	}
	if !bWasCandidate && refuse {
		// Still OK to refuse if we emitted it only for candidates — should not happen.
		t.Fatalf("unexpected refuse when B not candidate: %+v", plan)
	}

	// Source for handoff should be B (only committed replica) when grace or drain pick.
	if plan.SourceMember != "node-b" {
		t.Fatalf("expected drain/grace source node-b, got %q plan=%+v", plan.SourceMember, plan)
	}
	// Budget: at most 1 transfer this wave.
	if plan.TransferCount > 1 {
		t.Fatalf("MaxConcurrentCopies=1 but TransferCount=%d", plan.TransferCount)
	}
	var handoffOrCopy int
	for _, tgt := range plan.Targets {
		switch tgt.Action {
		case fleetcache.RepairActionDrainHandoff, fleetcache.RepairActionReplicateTo:
			if tgt.Residual != "budget_deferred" {
				handoffOrCopy++
				if tgt.Action != fleetcache.RepairActionDrainHandoff {
					// Source is draining → action should be drain_handoff for non-drain targets.
					t.Fatalf("want drain_handoff when source draining: %+v", tgt)
				}
			}
		}
	}
	if handoffOrCopy != 1 {
		t.Fatalf("want exactly 1 budgeted handoff; got %d plan=%+v", handoffOrCopy, plan)
	}

	// Run handoff under budget: one target commits from B's frames.
	sinks := map[string]fleetcache.ImportSink{}
	for _, o := range plan.RequiredOwners {
		sinks[o] = &memSink{}
	}
	// Optional: B sink not required for RunRepair (frames supplied by caller from B export).
	res, err := fleetcache.RunRepair(context.Background(), plan, wm, frames, sinks)
	if err != nil {
		t.Fatal(err)
	}
	if res.CopiesRun != 1 {
		t.Fatalf("copies %d res=%+v", res.CopiesRun, res)
	}
	if res.FramesTransferred < 1 {
		t.Fatalf("handoff must transfer pure-zstd frames: %+v", res)
	}
	// With RF2 and budget 1, one owner may still be deferred — HealthyRF may be false.
	if len(plan.DeferredOwners) > 0 && res.HealthyRF {
		t.Fatal("cannot be fully healthy with deferred owners unless they were already committed")
	}
	// Complete second wave to finish handoff under budget.
	// Refresh observations from sinks + still-draining B source.
	replicas2 := map[string]fleetcache.ReplicaObservation{
		"node-b": {MemberID: "node-b", Digest: wm.ManifestDigest, Status: "committed"},
	}
	for _, o := range plan.RequiredOwners {
		if cm, ok, _ := sinks[o].GetCommitted(context.Background(), wm.LocatorHash); ok {
			replicas2[o] = fleetcache.ReplicaObservation{
				MemberID: o, Digest: cm.ManifestDigest, Status: "committed",
			}
		}
	}
	plan2, err := fleetcache.PlanRepair(wm.LocatorHash, members, wm, replicas2, opts)
	if err != nil {
		t.Fatal(err)
	}
	res2, err := fleetcache.RunRepair(context.Background(), plan2, wm, frames, sinks)
	if err != nil {
		t.Fatal(err)
	}
	// After up to two waves with MaxConcurrentCopies=1, RF should be healthy.
	// (wave1 + wave2 cover RF2 under-replicated pair)
	replicas3 := map[string]fleetcache.ReplicaObservation{
		"node-b": {MemberID: "node-b", Digest: wm.ManifestDigest, Status: "committed"},
	}
	for _, o := range plan.RequiredOwners {
		cm, ok, err := sinks[o].GetCommitted(context.Background(), wm.LocatorHash)
		if err != nil || !ok {
			// May need plan2's required owners if placement same.
			_ = res2
			t.Fatalf("owner %s missing after drain handoff waves: plan2=%+v res2=%+v", o, plan2, res2)
		}
		replicas3[o] = fleetcache.ReplicaObservation{
			MemberID: o, Digest: cm.ManifestDigest, Status: "committed",
		}
	}
	plan3, err := fleetcache.PlanRepair(wm.LocatorHash, members, wm, replicas3, opts)
	if err != nil {
		t.Fatal(err)
	}
	if plan3.TransferCount != 0 {
		t.Fatalf("drain handoff complete should be healthy: %+v", plan3)
	}
	for _, o := range plan3.RequiredOwners {
		if o == "node-b" {
			t.Fatal("B still primary after drain")
		}
	}
}

// Budget: MaxConcurrentCopies=1 with 2 under-replicated targets → only 1 transfer this wave.
func TestPlanRepair_BoundedConcurrentCopies(t *testing.T) {
	t.Parallel()
	wm, frames := makeSealedManifest(t, [][]byte{[]byte("bud0\n"), []byte("bud1\n")})
	members := []fleetcache.PlacementMember{
		{ID: "m1", CapacityWeight: 100, FailureDomain: "z1"},
		{ID: "m2", CapacityWeight: 100, FailureDomain: "z2"},
		{ID: "m3", CapacityWeight: 100, FailureDomain: "z3"},
	}
	// No replicas among members — both RF owners need full import; frames are local.
	opts := fleetcache.RepairOptions{
		MaxConcurrentCopies: 1,
		Placement: fleetcache.PlacementOptions{
			ReplicationFactor: 2, PreferDistinctDomains: true,
		},
	}
	plan, err := fleetcache.PlanRepair(wm.LocatorHash, members, wm, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	if plan.TransferCount != 1 {
		t.Fatalf("TransferCount=%d want 1; plan=%+v", plan.TransferCount, plan)
	}
	if len(plan.DeferredOwners) != 1 {
		t.Fatalf("DeferredOwners=%v want 1 deferred", plan.DeferredOwners)
	}
	if plan.Residual != "budget_capped" && plan.Residual != "source_missing" {
		// source_missing may win when no replicas; still budget capped via DeferredOwners.
		if len(plan.DeferredOwners) == 0 {
			t.Fatalf("residual %q plan=%+v", plan.Residual, plan)
		}
	}

	sinks := map[string]fleetcache.ImportSink{}
	for _, o := range plan.RequiredOwners {
		sinks[o] = &memSink{}
	}
	res, err := fleetcache.RunRepair(context.Background(), plan, wm, frames, sinks)
	if err != nil {
		t.Fatal(err)
	}
	if res.CopiesRun != 1 {
		t.Fatalf("Regression: unbounded copies; CopiesRun=%d res=%+v", res.CopiesRun, res)
	}
	// Exactly one owner committed after wave.
	committed := 0
	for _, o := range plan.RequiredOwners {
		if _, ok, _ := sinks[o].GetCommitted(context.Background(), wm.LocatorHash); ok {
			committed++
		}
	}
	if committed != 1 {
		t.Fatalf("committed=%d want 1 after budgeted wave", committed)
	}
	_ = frames
}

// Secret-free residual canary: residuals must not contain token=/Bearer material.
func TestPlanRepair_SecretFreeResiduals(t *testing.T) {
	t.Parallel()
	wm, _ := makeSealedManifest(t, [][]byte{[]byte("sec\n")})
	members := []fleetcache.PlacementMember{
		{ID: "s1", CapacityWeight: 100, FailureDomain: "z1"},
		{ID: "s2", CapacityWeight: 100, FailureDomain: "z2"},
	}
	// Poison-shaped observation fields must never appear in residuals.
	replicas := map[string]fleetcache.ReplicaObservation{
		"s1": {
			MemberID: "s1", Digest: wm.ManifestDigest, Status: "committed",
		},
	}
	opts := fleetcache.RepairOptions{
		MaxConcurrentCopies: 1,
		DrainMemberIDs:      map[string]struct{}{"s2": {}},
		PreviousOwnerGrace:  true,
		Placement:           fleetcache.PlacementOptions{ReplicationFactor: 2},
	}
	// With only 2 members and s2 draining, may fail insufficient owners — still check residual strings.
	plan, err := fleetcache.PlanRepair(wm.LocatorHash, members, wm, replicas, opts)
	if err != nil {
		// insufficient is OK for this canary — check error string
		canarySecretFree(t, err.Error())
	}
	canarySecretFree(t, plan.Residual)
	canarySecretFree(t, plan.SourceMember)
	canarySecretFree(t, plan.LocatorHash)
	canarySecretFree(t, plan.ManifestDigest)
	for _, tgt := range plan.Targets {
		canarySecretFree(t, tgt.Residual)
		canarySecretFree(t, tgt.Action)
		canarySecretFree(t, tgt.MemberID)
	}
	for _, id := range plan.RequiredOwners {
		canarySecretFree(t, id)
	}
	for _, id := range plan.GraceSources {
		canarySecretFree(t, id)
	}
	for _, id := range plan.DeferredOwners {
		canarySecretFree(t, id)
	}
}

// Restart-survival / idempotent second repair when RF already healthy.
func TestRunRepair_IdempotentWhenRFHealthy(t *testing.T) {
	t.Parallel()
	wm, frames := makeSealedManifest(t, [][]byte{[]byte("id0\n")})
	members := []fleetcache.PlacementMember{
		{ID: "p1", CapacityWeight: 100, FailureDomain: "z1"},
		{ID: "p2", CapacityWeight: 100, FailureDomain: "z2"},
	}
	// Seed both sinks as if post-repair restart.
	sink1, sink2 := &memSink{}, &memSink{}
	if _, err := fleetcache.ReplicateSealed(context.Background(), sink1, wm, frames); err != nil {
		t.Fatal(err)
	}
	if _, err := fleetcache.ReplicateSealed(context.Background(), sink2, wm, frames); err != nil {
		t.Fatal(err)
	}
	replicas := map[string]fleetcache.ReplicaObservation{
		"p1": {MemberID: "p1", Digest: wm.ManifestDigest, Status: "committed"},
		"p2": {MemberID: "p2", Digest: wm.ManifestDigest, Status: "committed"},
	}
	opts := fleetcache.RepairOptions{
		MaxConcurrentCopies: 2,
		Placement:           fleetcache.PlacementOptions{ReplicationFactor: 2},
	}
	plan, err := fleetcache.PlanRepair(wm.LocatorHash, members, wm, replicas, opts)
	if err != nil {
		t.Fatal(err)
	}
	if plan.TransferCount != 0 {
		t.Fatalf("healthy plan must not transfer: %+v", plan)
	}
	sinks := map[string]fleetcache.ImportSink{"p1": sink1, "p2": sink2}
	res, err := fleetcache.RunRepair(context.Background(), plan, wm, frames, sinks)
	if err != nil {
		t.Fatal(err)
	}
	if res.FramesTransferred != 0 || res.CopiesRun != 0 {
		t.Fatalf("idempotent no-op want 0: %+v", res)
	}
	if !res.HealthyRF {
		t.Fatal("HealthyRF")
	}
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func canarySecretFree(t *testing.T, s string) {
	t.Helper()
	low := strings.ToLower(s)
	if strings.Contains(low, "bearer ") || strings.Contains(s, "token=") || strings.Contains(low, "authorization:") {
		t.Fatalf("secret-shaped residual: %q", s)
	}
}
