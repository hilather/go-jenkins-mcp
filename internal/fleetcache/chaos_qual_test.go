package fleetcache_test

// FLC-071 offline multi-node chaos / race qualification matrix.
//
// Scope: dual-dir / multi-sink pure-Go library tests driving PlanRepair, RunRepair,
// ReplicateSealed, IsolationCheck, RunImport, CoordinateOriginFill, and metrics
// fallback_origin. Does **not** require Docker for Done*.
//
// Residual (documented in backlog + fleet docs):
//   - live multi-host Docker chaos lab / process kill under real HTTP
//   - long soak with goroutine / FD growth thresholds under load
//
// AC map:
//  1. No unverified/cross-boundary bytes served → Isolation + corrupt digest reject
//  2. Healthy RF restored after member loss → PlanRepair/RunRepair + ReplicateSealed
//  3. Cache failure → origin fallback honesty (CoordinateOriginFill + fallback_origin)
//  4. Recovery leaves no visible partial objects → Abort / no GetCommitted
//  5. Secret-free canaries on residuals / plans / results

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

// TestChaosQual_MemberLossRFRestore: 3-member placement, A committed, B gone from
// roster → PlanRepair/RunRepair to remaining owners → RF healthy; second run idempotent.
func TestChaosQual_MemberLossRFRestore(t *testing.T) {
	t.Parallel()
	wm, frames := makeSealedManifest(t, [][]byte{[]byte("chaos-loss-0\n"), []byte("chaos-loss-1\n")})
	// Full roster was A,B,C; B lost — remaining A,C restore RF without origin.
	members := []fleetcache.PlacementMember{
		{ID: "chaos-a", CapacityWeight: 100, FailureDomain: "z1"},
		{ID: "chaos-c", CapacityWeight: 100, FailureDomain: "z3"},
	}
	replicas := map[string]fleetcache.ReplicaObservation{
		"chaos-a": {MemberID: "chaos-a", Digest: wm.ManifestDigest, Status: "committed"},
	}
	opts := fleetcache.RepairOptions{
		MaxConcurrentCopies: 2,
		PreviousOwnerGrace:  false,
		Placement: fleetcache.PlacementOptions{
			ReplicationFactor: 2, PreferDistinctDomains: true,
		},
		MembershipEpoch: 11,
	}
	plan, err := fleetcache.PlanRepair(wm.LocatorHash, members, wm, replicas, opts)
	if err != nil {
		t.Fatal(err)
	}
	if plan.ReplicationFactor != 2 || len(plan.RequiredOwners) != 2 {
		t.Fatalf("owners %+v", plan)
	}
	for _, o := range plan.RequiredOwners {
		if o == "chaos-b" {
			t.Fatal("lost member must not be required owner")
		}
	}
	var transferTargets int
	for _, tgt := range plan.Targets {
		if (tgt.Action == fleetcache.RepairActionReplicateTo || tgt.Action == fleetcache.RepairActionDrainHandoff) &&
			tgt.Residual != "budget_deferred" {
			transferTargets++
		}
	}
	if transferTargets < 1 {
		t.Fatalf("expected under-replicated target; plan=%+v", plan)
	}

	sinkA := &memSink{}
	if _, err := fleetcache.ReplicateSealed(context.Background(), sinkA, wm, frames); err != nil {
		t.Fatal(err)
	}
	sinks := map[string]fleetcache.ImportSink{}
	for _, o := range plan.RequiredOwners {
		if o == "chaos-a" {
			sinks[o] = sinkA
		} else {
			sinks[o] = &memSink{}
		}
	}
	res, err := fleetcache.RunRepair(context.Background(), plan, wm, frames, sinks)
	if err != nil {
		t.Fatal(err)
	}
	if res.FramesTransferred < 1 {
		t.Fatalf("expected peer pure-zstd transfer; res=%+v", res)
	}
	if !res.HealthyRF {
		t.Fatalf("AC2: RF not restored: %+v plan=%+v", res, plan)
	}
	for _, o := range plan.RequiredOwners {
		cm, ok, err := sinks[o].GetCommitted(context.Background(), wm.LocatorHash)
		if err != nil || !ok || !strings.EqualFold(cm.ManifestDigest, wm.ManifestDigest) {
			t.Fatalf("owner %s not healthy: ok=%v cm=%+v err=%v", o, ok, cm, err)
		}
	}

	// Second repair: healthy / idempotent zero transfer.
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
	if plan2.TransferCount != 0 {
		t.Fatalf("second plan must be healthy no-op: %+v", plan2)
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
	chaosCanarySecretFree(t, plan.Residual, plan2.Residual, res.Residual, res2.Residual)
}

// TestChaosQual_PartialInterruptInvisible: Begin + one frame, no commit → GetCommitted
// false; Abort leaves no committed mapping (AC4).
func TestChaosQual_PartialInterruptInvisible(t *testing.T) {
	t.Parallel()
	wm, frames := makeSealedManifest(t, [][]byte{[]byte("partial-0\n"), []byte("partial-1\n")})
	sink := &memSink{}

	importID, genID, err := sink.Begin(context.Background(), wm)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.WriteFrame(context.Background(), importID, genID, wm.Frames[0], frames[0].PureZstd); err != nil {
		t.Fatal(err)
	}
	// AC4: staging must not be lookup-visible as committed.
	if _, ok, _ := sink.GetCommitted(context.Background(), wm.LocatorHash); ok {
		t.Fatal("AC4: partial interrupt must not expose committed object")
	}
	// Incomplete ReplicateSealed rejects (no partial commit).
	_, err = fleetcache.ReplicateSealed(context.Background(), &memSink{}, wm, frames[:1])
	if err == nil {
		t.Fatal("incomplete frame set must fail closed")
	}
	if _, ok, _ := sink.GetCommitted(context.Background(), wm.LocatorHash); ok {
		t.Fatal("partial still invisible after failed full import attempt on other sink")
	}
	// Abort staging → still invisible.
	if err := sink.Abort(context.Background(), importID); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := sink.GetCommitted(context.Background(), wm.LocatorHash); ok {
		t.Fatal("after Abort still no committed")
	}
	// Full import after abort succeeds.
	res, err := fleetcache.RunImport(context.Background(), sink, wm, frames)
	if err != nil || res.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("full import after abort: %+v %v", res, err)
	}
	chaosCanarySecretFree(t, res.Status, res.Residual)
}

// TestChaosQual_IsolationFailClosed: physical bytes under A do not authorize B after
// ReplicateSealed (AC1).
func TestChaosQual_IsolationFailClosed(t *testing.T) {
	t.Parallel()
	const (
		subjectA = "subj_hash_chaos_alice"
		subjectB = "subj_hash_chaos_bob"
		ctrl     = "ctrl-chaos"
		job      = "folder/chaos"
		build    = int64(71)
	)
	wm, frames := makeSealedManifestAt(t, "fleet-chaos", "pool-logs", ctrl, job, build, [][]byte{
		[]byte("shared-physical-bytes\n"),
	})
	sink := &memSink{}
	res, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, frames)
	if err != nil || res.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("populate: %+v %v", res, err)
	}
	if _, ok, _ := sink.GetCommitted(context.Background(), wm.LocatorHash); !ok {
		t.Fatal("expected committed mapping")
	}

	gate := fleetcache.NewFreshnessGate(30*time.Second, func(ctx context.Context, k fleetcache.AuthzKey) (bool, string, error) {
		if k.SubjectKeyHash == subjectA && k.ControllerID == ctrl && k.JobFullName == job {
			return true, fleetcache.ReasonAuthzOK, nil
		}
		return false, fleetcache.ReasonAuthzPolicyDeny, nil
	})
	loc, err := fleetcache.NewConsoleLogLocator("fleet-chaos", "pool-logs", ctrl, job, build)
	if err != nil {
		t.Fatal(err)
	}

	decA, err := gate.Allow(context.Background(), fleetcache.AuthzKey{
		SubjectKeyHash: subjectA, ControllerID: ctrl, JobFullName: job,
	})
	if err != nil || !decA.Allowed {
		t.Fatalf("A authz: %+v %v", decA, err)
	}
	isoA := fleetcache.IsolationCheck(fleetcache.IsolationRequest{
		Locator: loc, ExpectedFleetID: "fleet-chaos", ExpectedCachePool: "pool-logs",
		ExpectedControllerID: ctrl, RequestLocatorHash: wm.LocatorHash, AuthzAllowed: decA.Allowed,
	})
	if !isoA.Allowed || isoA.Residual != fleetcache.IsolationResidualOK {
		t.Fatalf("A isolation: %+v", isoA)
	}

	decB, err := gate.Allow(context.Background(), fleetcache.AuthzKey{
		SubjectKeyHash: subjectB, ControllerID: ctrl, JobFullName: job,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decB.Allowed {
		t.Fatal("B must not be authorized by cache presence")
	}
	isoB := fleetcache.IsolationCheck(fleetcache.IsolationRequest{
		Locator: loc, ExpectedFleetID: "fleet-chaos", ExpectedCachePool: "pool-logs",
		ExpectedControllerID: ctrl, RequestLocatorHash: wm.LocatorHash, AuthzAllowed: decB.Allowed,
	})
	if isoB.Allowed {
		t.Fatal("AC1: IsolationCheck must fail closed for unauthorized subject")
	}
	if isoB.Residual != fleetcache.IsolationResidualAuthzDeny {
		t.Fatalf("want isolation_authz_deny got %q", isoB.Residual)
	}
	// Cross-fleet scope also fail closed even if authz true.
	isoCross := fleetcache.IsolationCheck(fleetcache.IsolationRequest{
		Locator: loc, ExpectedFleetID: "other-fleet", ExpectedCachePool: "pool-logs",
		ExpectedControllerID: ctrl, RequestLocatorHash: wm.LocatorHash, AuthzAllowed: true,
	})
	if isoCross.Allowed || isoCross.Residual != fleetcache.IsolationResidualFleetMismatch {
		t.Fatalf("cross-fleet: %+v", isoCross)
	}
	chaosCanarySecretFree(t, isoA.Residual, isoB.Residual, isoCross.Residual)
}

// TestChaosQual_CorruptDigestReject: ReplicateSealed with bad frame hash fails;
// no committed mapping (AC1).
func TestChaosQual_CorruptDigestReject(t *testing.T) {
	t.Parallel()
	wm, frames := makeSealedManifest(t, [][]byte{[]byte("good-0\n"), []byte("good-1\n")})
	bad := append([]fleetcache.ImportFrameBytes{}, frames...)
	bad[0].PureZstd = append([]byte{}, bad[0].PureZstd...)
	bad[0].PureZstd[len(bad[0].PureZstd)-1] ^= 0xff

	sink := &memSink{}
	res, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, bad)
	if err == nil {
		t.Fatal("corrupt zstd hash must fail")
	}
	if res.Status == fleetcache.ImportStatusCommitted {
		t.Fatal("must not commit corrupt frames")
	}
	if _, ok, _ := sink.GetCommitted(context.Background(), wm.LocatorHash); ok {
		t.Fatal("AC1: corrupt import must leave no committed mapping")
	}
	// AEAD magic on wire rejected.
	aead := append([]byte("JME1"), frames[0].PureZstd...)
	sink2 := &memSink{}
	_, err = fleetcache.ReplicateSealed(context.Background(), sink2, wm, []fleetcache.ImportFrameBytes{
		{Seq: frames[0].Seq, PureZstd: aead},
		frames[1],
	})
	if err == nil {
		t.Fatal("AEAD envelope on wire must reject")
	}
	if _, ok, _ := sink2.GetCommitted(context.Background(), wm.LocatorHash); ok {
		t.Fatal("AEAD reject must leave no committed")
	}
	// Honest path still works on a clean sink.
	okRes, err := fleetcache.ReplicateSealed(context.Background(), &memSink{}, wm, frames)
	if err != nil || okRes.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("clean path: %+v %v", okRes, err)
	}
	chaosCanarySecretFree(t, res.Residual, okRes.Residual)
	if err != nil {
		chaosCanarySecretFree(t, err.Error())
	}
}

// TestChaosQual_TombstoneBlocksResurrection: ActiveTombstones block PlanRepair /
// ReplicateSealed after purge (chaos path).
func TestChaosQual_TombstoneBlocksResurrection(t *testing.T) {
	// Mutates package-level ActiveTombstones — not parallel.
	prev := fleetcache.ActiveTombstones
	t.Cleanup(func() { fleetcache.ActiveTombstones = prev })

	wm, frames := makeSealedManifest(t, [][]byte{[]byte("tomb-chaos-0\n")})
	sink := &memSink{}
	if _, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, frames); err != nil {
		t.Fatal(err)
	}
	ts := fleetcache.NewMemoryTombstoneStore()
	fleetcache.ActiveTombstones = ts
	req := fleetcache.PurgeRequest{
		LocatorHash:    wm.LocatorHash,
		ManifestDigest: wm.ManifestDigest,
		OperatorRole:   fleetcache.PurgeRoleOperator,
		Confirm:        fleetcache.PurgeConfirmToken,
	}
	now := time.Now().UTC()
	pres, err := fleetcache.ApplyPurgeLocal(context.Background(), sink, req, ts, now)
	if err != nil || pres.Status != fleetcache.PurgeStatusPurged {
		t.Fatalf("purge %+v %v", pres, err)
	}
	if _, ok, _ := sink.GetCommitted(context.Background(), wm.LocatorHash); ok {
		t.Fatal("purged must delete committed")
	}

	rep, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, frames)
	if err == nil || rep.Status != fleetcache.ImportStatusRejected {
		t.Fatalf("replicate tombstone: %+v %v", rep, err)
	}
	if rep.Residual != fleetcache.PurgeResidualTombstoneBlocked {
		t.Fatalf("residual %q", rep.Residual)
	}

	members := []fleetcache.PlacementMember{
		{ID: "t1", CapacityWeight: 100, FailureDomain: "z1"},
		{ID: "t2", CapacityWeight: 100, FailureDomain: "z2"},
	}
	_, err = fleetcache.PlanRepair(wm.LocatorHash, members, wm, nil, fleetcache.RepairOptions{
		MaxConcurrentCopies: 2,
		Placement:           fleetcache.PlacementOptions{ReplicationFactor: 2},
	})
	if err == nil {
		t.Fatal("PlanRepair must refuse tombstoned object")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code %s", apperr.CodeOf(err))
	}
	chaosCanarySecretFree(t, rep.Residual, err.Error())
}

// TestChaosQual_PartitionConflict: different digest conflict residual; committed
// object not overwritten (partition chaos path).
func TestChaosQual_PartitionConflict(t *testing.T) {
	t.Parallel()
	// Same locator identity (fleet/pool/ctrl/job/build) with different frame content → different digests.
	wmA, framesA := makeSealedManifestAt(t, "fleet", "pool", "ctrl", "job/conflict", 99, [][]byte{[]byte("digest-aaa\n")})
	wmB, framesB := makeSealedManifestAt(t, "fleet", "pool", "ctrl", "job/conflict", 99, [][]byte{[]byte("digest-bbb-different\n")})
	if wmA.LocatorHash != wmB.LocatorHash {
		t.Fatalf("same locator required: %s vs %s", wmA.LocatorHash, wmB.LocatorHash)
	}
	if strings.EqualFold(wmA.ManifestDigest, wmB.ManifestDigest) {
		t.Fatal("fixture must produce different digests")
	}

	sink := &memSink{}
	resA, err := fleetcache.ReplicateSealed(context.Background(), sink, wmA, framesA)
	if err != nil || resA.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("A: %+v %v", resA, err)
	}
	cm, ok, _ := sink.GetCommitted(context.Background(), wmA.LocatorHash)
	if !ok || !strings.EqualFold(cm.ManifestDigest, wmA.ManifestDigest) {
		t.Fatalf("committed A: %+v", cm)
	}

	resB, err := fleetcache.ReplicateSealed(context.Background(), sink, wmB, framesB)
	if err == nil || resB.Status != fleetcache.ImportStatusRejected {
		t.Fatalf("B conflict: %+v %v", resB, err)
	}
	if resB.Residual != fleetcache.PartitionResidualConflictDigest {
		t.Fatalf("residual %q", resB.Residual)
	}
	// Original digest preserved — no overwrite.
	cm2, ok, _ := sink.GetCommitted(context.Background(), wmA.LocatorHash)
	if !ok || !strings.EqualFold(cm2.ManifestDigest, wmA.ManifestDigest) {
		t.Fatalf("AC: conflict must not overwrite: %+v", cm2)
	}
	// Same-digest converge remains idempotent.
	resConv, err := fleetcache.ReplicateSealed(context.Background(), sink, wmA, framesA)
	if err != nil || resConv.Status != fleetcache.ImportStatusIdempotent {
		t.Fatalf("converge: %+v %v", resConv, err)
	}
	if resConv.FramesTransferred != 0 {
		t.Fatal("converge must not re-transfer")
	}
	chaosCanarySecretFree(t, resB.Residual, resConv.Residual)
}

// TestChaosQual_DrainRefuseNewPrimary: PlanRepair with DrainMemberIDs refuses new
// primary on draining member (AC2 drain path).
func TestChaosQual_DrainRefuseNewPrimary(t *testing.T) {
	t.Parallel()
	wm, frames := makeSealedManifest(t, [][]byte{[]byte("drain-chaos-0\n"), []byte("drain-chaos-1\n")})
	members := []fleetcache.PlacementMember{
		{ID: "d-a", CapacityWeight: 100, FailureDomain: "z1"},
		{ID: "d-b", CapacityWeight: 100, FailureDomain: "z2"},
		{ID: "d-c", CapacityWeight: 100, FailureDomain: "z3"},
	}
	drain := map[string]struct{}{"d-b": {}}
	replicas := map[string]fleetcache.ReplicaObservation{
		"d-b": {MemberID: "d-b", Digest: wm.ManifestDigest, Status: "committed"},
	}
	opts := fleetcache.RepairOptions{
		MaxConcurrentCopies: 1,
		PreviousOwnerGrace:  true,
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
		if o == "d-b" {
			t.Fatalf("drain member must not be required owner: %+v", plan)
		}
		if !fleetcache.DrainAllowsPrimary(o, drain) {
			t.Fatalf("required owner %s still draining", o)
		}
	}
	if fleetcache.DrainAllowsPrimary("d-b", drain) {
		t.Fatal("DrainAllowsPrimary must refuse d-b")
	}
	// Unconstrained candidate check → refuse_new_primary when B was candidate.
	unconstrained, err := fleetcache.SelectPrimaryOwners(wm.LocatorHash, members, fleetcache.PlacementOptions{
		ReplicationFactor: 2, PreferDistinctDomains: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	bWasCandidate := containsStr(unconstrained, "d-b")
	var refuse bool
	for _, tgt := range plan.Targets {
		if tgt.Action == fleetcache.RepairActionRefuseNewPrimary && tgt.MemberID == "d-b" {
			refuse = true
		}
	}
	if bWasCandidate && !refuse {
		t.Fatalf("expected refuse_new_primary for candidate B; unconstrained=%v plan=%+v", unconstrained, plan)
	}

	// Handoff under budget to non-draining owners.
	sinks := map[string]fleetcache.ImportSink{}
	for _, o := range plan.RequiredOwners {
		sinks[o] = &memSink{}
	}
	res, err := fleetcache.RunRepair(context.Background(), plan, wm, frames, sinks)
	if err != nil {
		t.Fatal(err)
	}
	if res.FramesTransferred < 1 && plan.TransferCount > 0 {
		t.Fatalf("expected handoff transfer when plan has transfers: plan=%+v res=%+v", plan, res)
	}
	// Completing waves until RF healthy on non-drain owners.
	replicasN := map[string]fleetcache.ReplicaObservation{
		"d-b": {MemberID: "d-b", Digest: wm.ManifestDigest, Status: "committed"},
	}
	for wave := 0; wave < 4; wave++ {
		for _, o := range plan.RequiredOwners {
			if cm, ok, _ := sinks[o].GetCommitted(context.Background(), wm.LocatorHash); ok {
				replicasN[o] = fleetcache.ReplicaObservation{
					MemberID: o, Digest: cm.ManifestDigest, Status: "committed",
				}
			}
		}
		p, err := fleetcache.PlanRepair(wm.LocatorHash, members, wm, replicasN, opts)
		if err != nil {
			t.Fatal(err)
		}
		if p.TransferCount == 0 {
			for _, o := range p.RequiredOwners {
				if o == "d-b" {
					t.Fatal("B still primary after drain complete")
				}
				if _, ok, _ := sinks[o].GetCommitted(context.Background(), wm.LocatorHash); !ok {
					t.Fatalf("owner %s missing after drain", o)
				}
			}
			chaosCanarySecretFree(t, p.Residual, res.Residual)
			return
		}
		if _, err := fleetcache.RunRepair(context.Background(), p, wm, frames, sinks); err != nil {
			t.Fatal(err)
		}
		plan = p
	}
	t.Fatalf("drain handoff did not complete RF in budgeted waves; last plan=%+v", plan)
}

// TestChaosQual_FallbackOriginHonesty: cache miss / origin path records fallback_origin
// and CoordinateOriginFill invokes Origin only on producer (AC3 residual honesty).
// Full logmirror bridge residual: documented; this proves library + metrics contract.
func TestChaosQual_FallbackOriginHonesty(t *testing.T) {
	// Package Metrics registry — not parallel.
	fleetcache.ResetForTest()

	// Metrics contract: operators see fallback_origin when peer/cache path falls back.
	fleetcache.Metrics.RecordFallbackOrigin("peer_unavailable")
	fleetcache.Metrics.RecordFallbackOrigin("rf_under_replicated")
	snap := fleetcache.Metrics.Snapshot()
	if snap[fleetcache.MetricFallbackOrigin] != 2 {
		t.Fatalf("fallback_origin=%d want 2", snap[fleetcache.MetricFallbackOrigin])
	}
	// Origin path still callable under mode off (no lease) — conceptual origin fill residual.
	var originCalls int
	res, err := fleetcache.CoordinateOriginFill(context.Background(), nil, fleetcache.FillCoordRequest{
		FleetID: "fleet", MemberID: "edge", LocatorHash: strings.Repeat("ab", 32),
		Mode: fleetcache.ModeOff,
	}, func(ctx context.Context) error {
		originCalls++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OriginCalled || originCalls != 1 {
		t.Fatalf("mode off origin: %+v calls=%d", res, originCalls)
	}
	if res.Residual != "mode_off_or_no_auth" {
		t.Fatalf("residual %q", res.Residual)
	}

	// Mode read: single producer origin; second concurrent join while origin runs must
	// not double-fetch (waiter role). Uses bounded origin duration (no deadlock).
	auth := fleetcache.NewFillLeaseAuthority(30 * time.Second)
	lh := fleetcache.FillLocatorHash("fleet-chaos", "profile", "job/x", 5)
	var mu sync.Mutex
	var originCallers []string
	var originStarted sync.WaitGroup
	originStarted.Add(1)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = fleetcache.CoordinateOriginFill(context.Background(), auth, fleetcache.FillCoordRequest{
			FleetID: "fleet-chaos", MemberID: "prod", LocatorHash: lh, Mode: fleetcache.ModeRead,
			Heartbeat: 50 * time.Millisecond,
		}, func(ctx context.Context) error {
			mu.Lock()
			originCallers = append(originCallers, "prod")
			mu.Unlock()
			originStarted.Done()
			// Long enough for waiter to join under active lease; short enough for test.
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(200 * time.Millisecond):
				return nil
			}
		})
	}()
	originStarted.Wait()

	wres, werr := fleetcache.CoordinateOriginFill(context.Background(), auth, fleetcache.FillCoordRequest{
		FleetID: "fleet-chaos", MemberID: "wait", LocatorHash: lh, Mode: fleetcache.ModeRead,
		WaiterPoll: 10 * time.Millisecond, WaiterMax: 40, Heartbeat: 50 * time.Millisecond,
	}, func(ctx context.Context) error {
		mu.Lock()
		originCallers = append(originCallers, "wait")
		mu.Unlock()
		return nil
	})
	if werr != nil {
		t.Fatalf("waiter: %v", werr)
	}
	wg.Wait()
	if wres.OriginCalled {
		t.Fatalf("AC3: waiter must not origin-fill under active producer: %+v", wres)
	}
	mu.Lock()
	callers := append([]string(nil), originCallers...)
	mu.Unlock()
	if len(callers) != 1 || callers[0] != "prod" {
		t.Fatalf("only producer may origin-fill: %v", callers)
	}

	// Origin error releases lease (honest residual — not cache poison).
	boom := errors.New("jenkins_unavailable")
	eres, eerr := fleetcache.CoordinateOriginFill(context.Background(), auth, fleetcache.FillCoordRequest{
		FleetID: "fleet-chaos", MemberID: "edge2",
		LocatorHash: fleetcache.FillLocatorHash("fleet-chaos", "profile", "job/y", 1),
		Mode:        fleetcache.ModeRead,
	}, func(ctx context.Context) error { return boom })
	if eerr == nil || !eres.OriginCalled {
		t.Fatalf("origin error: %+v %v", eres, eerr)
	}
	if eres.Residual != "origin_error_released" {
		t.Fatalf("residual %q", eres.Residual)
	}
	// Security ring for fallback must be secret-free.
	for _, ev := range fleetcache.Metrics.RecentSecurity(20) {
		chaosCanarySecretFree(t, ev.Type, ev.ReasonCode, ev.Residual)
	}
	chaosCanarySecretFree(t, res.Residual, eres.Residual, wres.Residual)
}

// TestChaosQual_ConcurrentMemberLossRace: concurrent dual-sink repair under -race
// restores RF without double-commit corruption (soak-lite).
func TestChaosQual_ConcurrentMemberLossRace(t *testing.T) {
	t.Parallel()
	wm, frames := makeSealedManifest(t, [][]byte{[]byte("race-0\n"), []byte("race-1\n")})
	members := []fleetcache.PlacementMember{
		{ID: "r-a", CapacityWeight: 100, FailureDomain: "z1"},
		{ID: "r-b", CapacityWeight: 100, FailureDomain: "z2"},
		{ID: "r-c", CapacityWeight: 100, FailureDomain: "z3"},
	}
	// Source only on r-a.
	sinkA := &memSink{}
	if _, err := fleetcache.ReplicateSealed(context.Background(), sinkA, wm, frames); err != nil {
		t.Fatal(err)
	}
	replicas := map[string]fleetcache.ReplicaObservation{
		"r-a": {MemberID: "r-a", Digest: wm.ManifestDigest, Status: "committed"},
	}
	opts := fleetcache.RepairOptions{
		MaxConcurrentCopies: 2,
		Placement: fleetcache.PlacementOptions{
			ReplicationFactor: 2, PreferDistinctDomains: true,
		},
	}
	plan, err := fleetcache.PlanRepair(wm.LocatorHash, members, wm, replicas, opts)
	if err != nil {
		t.Fatal(err)
	}
	sinks := map[string]fleetcache.ImportSink{}
	for _, o := range plan.RequiredOwners {
		if o == "r-a" {
			sinks[o] = sinkA
		} else {
			sinks[o] = &memSink{}
		}
	}
	// Two concurrent RunRepair waves (second should be mostly no-op / idempotent).
	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := fleetcache.RunRepair(context.Background(), plan, wm, frames, sinks)
			errCh <- e
		}()
	}
	wg.Wait()
	close(errCh)
	for e := range errCh {
		if e != nil {
			t.Fatal(e)
		}
	}
	for _, o := range plan.RequiredOwners {
		cm, ok, err := sinks[o].GetCommitted(context.Background(), wm.LocatorHash)
		if err != nil || !ok || !strings.EqualFold(cm.ManifestDigest, wm.ManifestDigest) {
			t.Fatalf("race RF owner %s: ok=%v cm=%+v err=%v", o, ok, cm, err)
		}
	}
}

// TestChaosQual_SecretFreeCanaries: residuals from a mixed chaos plan must not carry
// token/Bearer shapes (AC5).
func TestChaosQual_SecretFreeCanaries(t *testing.T) {
	t.Parallel()
	wm, frames := makeSealedManifest(t, [][]byte{[]byte("sec-chaos\n")})
	members := []fleetcache.PlacementMember{
		{ID: "s-a", CapacityWeight: 100, FailureDomain: "z1"},
		{ID: "s-b", CapacityWeight: 100, FailureDomain: "z2"},
	}
	drain := map[string]struct{}{"s-b": {}}
	plan, err := fleetcache.PlanRepair(wm.LocatorHash, members, wm, map[string]fleetcache.ReplicaObservation{
		"s-a": {MemberID: "s-a", Digest: wm.ManifestDigest, Status: "committed"},
	}, fleetcache.RepairOptions{
		MaxConcurrentCopies: 1,
		DrainMemberIDs:      drain,
		PreviousOwnerGrace:  true,
		Placement:           fleetcache.PlacementOptions{ReplicationFactor: 2},
	})
	// May fail insufficient owners when only one non-drain member — still canary strings.
	if err != nil {
		chaosCanarySecretFree(t, err.Error())
	}
	chaosCanarySecretFree(t, plan.Residual, plan.SourceMember, plan.LocatorHash, plan.ManifestDigest)
	for _, tgt := range plan.Targets {
		chaosCanarySecretFree(t, tgt.Residual, tgt.Action, tgt.MemberID)
	}
	// Bad import error paths also secret-free.
	bad := append([]fleetcache.ImportFrameBytes{}, frames...)
	if len(bad) > 0 {
		bad[0].PureZstd = append([]byte{}, bad[0].PureZstd...)
		if len(bad[0].PureZstd) > 0 {
			bad[0].PureZstd[0] ^= 0x55
		}
	}
	_, err = fleetcache.ReplicateSealed(context.Background(), &memSink{}, wm, bad)
	if err != nil {
		chaosCanarySecretFree(t, err.Error())
	}
}

func chaosCanarySecretFree(t *testing.T, ss ...string) {
	t.Helper()
	for _, s := range ss {
		if s == "" {
			continue
		}
		low := strings.ToLower(s)
		for _, bad := range []string{"token=", "bearer ", "password", "authorization:", "ghp_", "hunter2", "sk-live", "cookie"} {
			if strings.Contains(low, bad) || strings.Contains(s, bad) {
				t.Fatalf("secret canary %q in %q", bad, s)
			}
		}
	}
}
