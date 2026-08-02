package fleetcache_test

import (
	"context"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

func authorizedPurgeReq(lh, digest string) fleetcache.PurgeRequest {
	return fleetcache.PurgeRequest{
		LocatorHash:    lh,
		ManifestDigest: digest,
		OperatorRole:   fleetcache.PurgeRoleOperator,
		Confirm:        fleetcache.PurgeConfirmToken,
		MaxOwners:      8,
		Reason:         "incident_response",
	}
}

// Regression: unauthorized role / wrong confirm must deny (AC1 pure gate).
func TestPlanPurge_UnauthorizedRoleAndConfirm(t *testing.T) {
	t.Parallel()
	owners := []string{"m1", "m2"}
	base := fleetcache.PurgeRequest{
		LocatorHash:  strings.Repeat("ab", 32),
		OperatorRole: "viewer",
		Confirm:      fleetcache.PurgeConfirmToken,
	}
	plan, err := fleetcache.PlanPurge(base, owners)
	if err == nil || plan.Action != fleetcache.PurgeActionDeny {
		t.Fatalf("viewer must deny: %+v %v", plan, err)
	}
	if plan.Residual != fleetcache.PurgeResidualUnauthorizedRole {
		t.Fatalf("residual %q", plan.Residual)
	}
	if apperr.CodeOf(err) != apperr.CodeAuthorization {
		t.Fatalf("code %s", apperr.CodeOf(err))
	}

	base.OperatorRole = fleetcache.PurgeRoleOperator
	base.Confirm = "EVICT"
	plan, err = fleetcache.PlanPurge(base, owners)
	if err == nil || plan.Action != fleetcache.PurgeActionDeny {
		t.Fatalf("wrong confirm must deny: %+v %v", plan, err)
	}
	if plan.Residual != fleetcache.PurgeResidualConfirmRequired {
		t.Fatalf("residual %q", plan.Residual)
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code %s", apperr.CodeOf(err))
	}

	// Empty confirm
	base.Confirm = ""
	if _, err := fleetcache.PlanPurge(base, owners); err == nil {
		t.Fatal("empty confirm must fail")
	}

	// policy_admin is allowed
	base.OperatorRole = fleetcache.PurgeRolePolicyAdmin
	base.Confirm = fleetcache.PurgeConfirmToken
	plan, err = fleetcache.PlanPurge(base, owners)
	if err != nil || plan.Action != fleetcache.PurgeActionPurge {
		t.Fatalf("policy_admin should purge: %+v %v", plan, err)
	}
	if len(plan.Targets) != 2 {
		t.Fatalf("targets %+v", plan.Targets)
	}
}

func TestPlanPurge_MaxOwnersBounds(t *testing.T) {
	t.Parallel()
	owners := []string{"a", "b", "c", "d", "e"}
	req := authorizedPurgeReq(strings.Repeat("cd", 32), "")
	req.MaxOwners = 2
	plan, err := fleetcache.PlanPurge(req, owners)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Truncated || len(plan.Targets) != 2 {
		t.Fatalf("want max 2 truncated: %+v", plan)
	}
	if plan.Residual != fleetcache.PurgeResidualMaxOwners {
		t.Fatalf("residual %q", plan.Residual)
	}
	// TargetMemberIDs intersect
	req.MaxOwners = 8
	req.TargetMemberIDs = []string{"c", "missing", "e"}
	plan, err = fleetcache.PlanPurge(req, owners)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Targets) != 2 || plan.Targets[0] != "c" || plan.Targets[1] != "e" {
		t.Fatalf("intersect %+v", plan.Targets)
	}
}

// AC2: purge reaches planned owners; unreachable reported as residuals (not silent success).
func TestApplyPurge_UnreachableResiduals(t *testing.T) {
	t.Parallel()
	wm, frames := makeSealedManifest(t, [][]byte{[]byte("purge-u0\n"), []byte("purge-u1\n")})
	sinkA := &memSink{}
	if _, err := fleetcache.ReplicateSealed(context.Background(), sinkA, wm, frames); err != nil {
		t.Fatal(err)
	}
	sinkB := &memSink{}
	if _, err := fleetcache.ReplicateSealed(context.Background(), sinkB, wm, frames); err != nil {
		t.Fatal(err)
	}

	req := authorizedPurgeReq(wm.LocatorHash, wm.ManifestDigest)
	owners := []string{"m-a", "m-b", "m-unreachable"}
	plan, err := fleetcache.PlanPurge(req, owners)
	if err != nil {
		t.Fatal(err)
	}
	ts := fleetcache.NewMemoryTombstoneStore()
	// Only A and B reachable — m-unreachable missing from sinks map.
	res, err := fleetcache.ApplyPurge(context.Background(), plan, req, map[string]fleetcache.PurgeSink{
		"m-a": sinkA,
		"m-b": sinkB,
	}, ts, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != fleetcache.PurgeStatusPartial {
		t.Fatalf("status %+v", res)
	}
	if len(res.ResidualMembers) != 1 || res.ResidualMembers[0] != "m-unreachable" {
		t.Fatalf("residuals %+v", res.ResidualMembers)
	}
	if len(res.PurgedMembers) != 2 {
		t.Fatalf("purged %+v", res.PurgedMembers)
	}
	if !res.TombstonePut {
		t.Fatal("tombstone must still be put on partial")
	}
	// Deleted locally
	if _, ok, _ := sinkA.GetCommitted(context.Background(), wm.LocatorHash); ok {
		t.Fatal("A must be purged")
	}
	if _, ok, _ := sinkB.GetCommitted(context.Background(), wm.LocatorHash); ok {
		t.Fatal("B must be purged")
	}
}

// AC3/AC4: authorized purge puts tombstone; second purge idempotent; blocks resurrection.
func TestPurge_TombstoneBlocksResurrection(t *testing.T) {
	// Mutates package-level ActiveTombstones — not parallel.
	prev := fleetcache.ActiveTombstones
	t.Cleanup(func() { fleetcache.ActiveTombstones = prev })

	wm, frames := makeSealedManifest(t, [][]byte{[]byte("tomb0\n"), []byte("tomb1\n")})
	sink := &memSink{}
	if _, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, frames); err != nil {
		t.Fatal(err)
	}

	ts := fleetcache.NewMemoryTombstoneStore()
	fleetcache.ActiveTombstones = ts
	req := authorizedPurgeReq(wm.LocatorHash, wm.ManifestDigest)
	now := time.Now().UTC()

	res, err := fleetcache.ApplyPurgeLocal(context.Background(), sink, req, ts, now)
	if err != nil || res.Status != fleetcache.PurgeStatusPurged {
		t.Fatalf("purge1 %+v %v", res, err)
	}
	if !res.TombstonePut {
		t.Fatal("tombstone put")
	}
	if _, ok, _ := sink.GetCommitted(context.Background(), wm.LocatorHash); ok {
		t.Fatal("must delete committed")
	}

	// Second purge idempotent.
	res2, err := fleetcache.ApplyPurgeLocal(context.Background(), sink, req, ts, now)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Status != fleetcache.PurgeStatusPurged && res2.Status != fleetcache.PurgeStatusNoop {
		// purged with residual purge_idempotent is OK
		t.Fatalf("idempotent status %+v", res2)
	}
	if !res2.TombstonePut {
		t.Fatal("second put still refreshes tombstone")
	}

	// PlanImport / ReplicateSealed reject same digest.
	plan, err := fleetcache.PlanImport(nil, wm)
	if err == nil || plan.Action != fleetcache.ImportActionRejectStale {
		t.Fatalf("import must reject tombstoned: %+v %v", plan, err)
	}
	if plan.Residual != fleetcache.PurgeResidualTombstoneBlocked {
		t.Fatalf("residual %q", plan.Residual)
	}

	rep, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, frames)
	if err == nil || rep.Status != fleetcache.ImportStatusRejected {
		t.Fatalf("replicate must reject: %+v %v", rep, err)
	}
	if rep.Residual != fleetcache.PurgeResidualTombstoneBlocked {
		t.Fatalf("rep residual %q", rep.Residual)
	}

	// RunImport path also blocked via PlanImport.
	run, err := fleetcache.RunImport(context.Background(), sink, wm, frames)
	if err == nil || run.Status != fleetcache.ImportStatusRejected {
		t.Fatalf("runimport %+v %v", run, err)
	}

	// PlanRepair refuses resurrection.
	members := []fleetcache.PlacementMember{
		{ID: "r1", CapacityWeight: 100, FailureDomain: "z1"},
		{ID: "r2", CapacityWeight: 100, FailureDomain: "z2"},
	}
	replicas := map[string]fleetcache.ReplicaObservation{
		"r1": {MemberID: "r1", Digest: wm.ManifestDigest, Status: "committed"},
	}
	rplan, err := fleetcache.PlanRepair(wm.LocatorHash, members, wm, replicas, fleetcache.RepairOptions{
		MaxConcurrentCopies: 2,
		Placement:           fleetcache.PlacementOptions{ReplicationFactor: 2, PreferDistinctDomains: true},
	})
	if err == nil {
		t.Fatalf("repair must refuse tombstone: %+v", rplan)
	}
	if rplan.Residual != fleetcache.PurgeResidualTombstoneBlocked {
		t.Fatalf("repair residual %q", rplan.Residual)
	}
	// No transfer targets planned.
	for _, tgt := range rplan.Targets {
		if tgt.Action == fleetcache.RepairActionReplicateTo || tgt.Action == fleetcache.RepairActionDrainHandoff {
			t.Fatalf("must not plan transfer %+v", tgt)
		}
	}

	// RunRepair with a forged plan still hits ReplicateSealed tombstone.
	forged := fleetcache.RepairPlan{
		LocatorHash: wm.LocatorHash, ManifestDigest: wm.ManifestDigest,
		RequiredOwners: []string{"r2"},
		Targets: []fleetcache.RepairTarget{
			{MemberID: "r2", Action: fleetcache.RepairActionReplicateTo, Residual: "force"},
		},
	}
	rr, _ := fleetcache.RunRepair(context.Background(), forged, wm, frames, map[string]fleetcache.ImportSink{
		"r2": &memSink{},
	})
	if rr.Results["r2"].Status != fleetcache.ImportStatusRejected {
		t.Fatalf("runrepair resurrect %+v", rr.Results["r2"])
	}
}

func TestTombstone_DigestScopeAndExpiry(t *testing.T) {
	t.Parallel()
	ts := fleetcache.NewMemoryTombstoneStore()
	lh := strings.Repeat("ef", 32)
	d1 := strings.Repeat("11", 32)
	d2 := strings.Repeat("22", 32)
	now := time.Now().UTC()

	if err := ts.Put(context.Background(), fleetcache.Tombstone{
		LocatorHash: lh, ManifestDigest: d1, ExpiresAt: now.Add(time.Hour), Reason: "v1",
	}); err != nil {
		t.Fatal(err)
	}
	blocked, res := fleetcache.TombstoneBlocks(ts, lh, d1, now)
	if !blocked || res != fleetcache.PurgeResidualTombstoneBlocked {
		t.Fatalf("d1 blocked? %v %q", blocked, res)
	}
	blocked, _ = fleetcache.TombstoneBlocks(ts, lh, d2, now)
	if blocked {
		t.Fatal("d2 must not be blocked by d1-scoped tombstone")
	}

	// Empty digest tombstone blocks all versions.
	if err := ts.Put(context.Background(), fleetcache.Tombstone{
		LocatorHash: lh, ManifestDigest: "", ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if blocked, _ := fleetcache.TombstoneBlocks(ts, lh, d2, now); !blocked {
		t.Fatal("all-version tombstone must block d2")
	}

	// Expiry.
	if err := ts.Put(context.Background(), fleetcache.Tombstone{
		LocatorHash: strings.Repeat("aa", 32), ManifestDigest: d1,
		ExpiresAt: now.Add(-time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	if blocked, _ := fleetcache.TombstoneBlocks(ts, strings.Repeat("aa", 32), d1, now); blocked {
		t.Fatal("expired must not block")
	}

	// Nil store
	if blocked, _ := fleetcache.TombstoneBlocks(nil, lh, d1, now); blocked {
		t.Fatal("nil store never blocks")
	}
}

// AC5: secret-free canaries on residuals/results.
func TestPurge_SecretFreeCanary(t *testing.T) {
	t.Parallel()
	// Attempt to smuggle secrets into Reason — scrubbed.
	req := authorizedPurgeReq(strings.Repeat("99", 32), "")
	req.Reason = "token=supersecret Bearer sk-live hunter2"
	owners := []string{"m1"}
	plan, err := fleetcache.PlanPurge(req, owners)
	if err != nil {
		t.Fatal(err)
	}
	canarySecretFree(t, plan.Residual)
	canarySecretFree(t, plan.Action)
	for _, id := range plan.Targets {
		canarySecretFree(t, id)
	}

	ts := fleetcache.NewMemoryTombstoneStore()
	res, err := fleetcache.ApplyPurge(context.Background(), plan, req, map[string]fleetcache.PurgeSink{
		"m1": &memSink{},
	}, ts, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	canarySecretFree(t, res.Status)
	canarySecretFree(t, res.Residual)
	canarySecretFree(t, res.LocatorHash)
	canarySecretFree(t, res.ManifestDigest)
	for _, id := range res.PurgedMembers {
		canarySecretFree(t, id)
	}
	// Stored reason must be scrubbed.
	list, err := ts.Get(context.Background(), req.LocatorHash)
	if err != nil || len(list) == 0 {
		t.Fatalf("tombstones %v %v", list, err)
	}
	canarySecretFree(t, list[0].Reason)
	if list[0].Reason != "scrubbed" && strings.Contains(strings.ToLower(list[0].Reason), "token=") {
		t.Fatalf("reason not scrubbed: %q", list[0].Reason)
	}
}

// AC: origin Jenkins untouched — no jenkins client imports in fleetcache package.
func TestPurge_NoJenkinsImportsInPackage(t *testing.T) {
	t.Parallel()
	dir := "."
	// Resolve package dir from this test file location when run via go test.
	if wd, err := os.Getwd(); err == nil {
		dir = wd
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		// Skip tests for production-import rule; still check non-_test.go
		if strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			// Forbid Jenkins HTTP client package; allow go-jenkins-mcp/internal/* helpers.
			if strings.Contains(p, "/internal/jenkins") || strings.HasSuffix(p, "/jenkins") && !strings.Contains(p, "go-jenkins-mcp") {
				t.Fatalf("%s imports jenkins client %s", e.Name(), p)
			}
			if strings.Contains(p, "github.com/boundless-io") || strings.Contains(p, "bndw/jenkins") {
				t.Fatalf("%s imports external jenkins %s", e.Name(), p)
			}
			// Hard fail any import path containing "jenkins/client" style.
			if strings.Contains(p, "internal/jenkins/") {
				t.Fatalf("%s must not import %s (origin Jenkins untouched)", e.Name(), p)
			}
		}
	}
}

func TestApplyPurgeLocal_DeniedDoesNotDelete(t *testing.T) {
	t.Parallel()
	wm, frames := makeSealedManifest(t, [][]byte{[]byte("deny0\n")})
	sink := &memSink{}
	if _, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, frames); err != nil {
		t.Fatal(err)
	}
	req := fleetcache.PurgeRequest{
		LocatorHash:  wm.LocatorHash,
		OperatorRole: "viewer",
		Confirm:      fleetcache.PurgeConfirmToken,
	}
	ts := fleetcache.NewMemoryTombstoneStore()
	res, err := fleetcache.ApplyPurgeLocal(context.Background(), sink, req, ts, time.Now().UTC())
	if err == nil || res.Status != fleetcache.PurgeStatusDenied {
		t.Fatalf("%+v %v", res, err)
	}
	if _, ok, _ := sink.GetCommitted(context.Background(), wm.LocatorHash); !ok {
		t.Fatal("denied purge must not delete")
	}
	if res.TombstonePut {
		t.Fatal("denied must not tombstone")
	}
}
