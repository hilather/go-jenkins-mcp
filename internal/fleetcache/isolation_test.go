package fleetcache_test

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

// secretCanaryTokens are patterns that must never appear in residuals / decisions / results.
var secretCanaryTokens = []string{
	"token=",
	"Bearer ",
	"bearer ",
	"password",
	"cookie",
	"Authorization:",
	"ghp_",
	"hunter2",
	"sk-live",
}

func assertSecretFree(t *testing.T, label string, ss ...string) {
	t.Helper()
	for _, s := range ss {
		low := strings.ToLower(s)
		for _, bad := range secretCanaryTokens {
			if strings.Contains(s, bad) || strings.Contains(low, strings.ToLower(bad)) {
				t.Fatalf("%s: secret canary %q in %q", label, bad, s)
			}
		}
	}
}

// makeSealedManifestAt publishes a sealed wire manifest at a specific fleet/pool/controller/job/build.
func makeSealedManifestAt(t *testing.T, fleet, pool, controller, job string, build int64, parts [][]byte) (fleetcache.WireManifest, []fleetcache.ImportFrameBytes) {
	t.Helper()
	loc, err := fleetcache.NewConsoleLogLocator(fleet, pool, controller, job, build)
	if err != nil {
		t.Fatal(err)
	}
	lh, err := loc.Hash()
	if err != nil {
		t.Fatal(err)
	}
	var frames []fleetcache.FrameDescriptor
	var importFrames []fleetcache.ImportFrameBytes
	var rawOff, lineOff int64
	for i, raw := range parts {
		z := zstdFrame(t, raw)
		lines := int64(0)
		for _, b := range raw {
			if b == '\n' {
				lines++
			}
		}
		if len(raw) > 0 && raw[len(raw)-1] != '\n' {
			lines++
		}
		fd := fleetcache.FrameDescriptor{
			Seq: i, RawStart: rawOff, RawEnd: rawOff + int64(len(raw)),
			LineStart: lineOff, LineEnd: lineOff + lines,
			DecodedSize: int64(len(raw)), DecodedSHA256: shaHex(raw),
			ZstdSize: int64(len(z)), ZstdSHA256: shaHex(z),
		}
		frames = append(frames, fd)
		importFrames = append(importFrames, fleetcache.ImportFrameBytes{Seq: i, PureZstd: z})
		rawOff += int64(len(raw))
		lineOff += lines
	}
	wm, err := fleetcache.PublishSealed(fleetcache.SealedPublishInput{
		FleetID: fleet, CachePool: pool, ControllerID: controller,
		JobFullName: job, BuildNumber: build, Sealed: true, Frames: frames,
	})
	if err != nil {
		t.Fatalf("PublishSealed: %v", err)
	}
	if wm.LocatorHash == "" {
		wm.LocatorHash = lh
	}
	return wm, importFrames
}

// TestIsolation_CrossUser: physical bytes populated under subject A do not authorize subject B.
// FreshnessGate allows only A's subject hash; IsolationCheck + gate deny B with policy_deny.
func TestIsolation_CrossUser(t *testing.T) {
	t.Parallel()
	const (
		subjectA = "subj_hash_alice_a1b2c3"
		subjectB = "subj_hash_bob_d4e5f6"
		ctrl     = "ctrl-prod"
		job      = "folder/demo"
		build    = int64(11)
	)
	wm, frames := makeSealedManifestAt(t, "fleet-corp", "pool-logs", ctrl, job, build, [][]byte{
		[]byte("user-a-secret-content\n"), // body is log content, not credentials
	})
	sink := &memSink{}
	res, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, frames)
	if err != nil || res.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("populate A: %+v %v", res, err)
	}
	// Physical bytes present for this locator.
	if _, ok, _ := sink.GetCommitted(context.Background(), wm.LocatorHash); !ok {
		t.Fatal("expected committed mapping for A population")
	}

	// Probe: only subject A allowed for this controller+job (independent current authorization).
	gate := fleetcache.NewFreshnessGate(30*time.Second, func(ctx context.Context, k fleetcache.AuthzKey) (bool, string, error) {
		if k.SubjectKeyHash == subjectA && k.ControllerID == ctrl && k.JobFullName == job {
			return true, fleetcache.ReasonAuthzOK, nil
		}
		return false, fleetcache.ReasonAuthzPolicyDeny, nil
	})

	loc, err := fleetcache.NewConsoleLogLocator("fleet-corp", "pool-logs", ctrl, job, build)
	if err != nil {
		t.Fatal(err)
	}

	// Subject A: gate allows + IsolationCheck OK.
	decA, err := gate.Allow(context.Background(), fleetcache.AuthzKey{
		SubjectKeyHash: subjectA, ControllerID: ctrl, JobFullName: job,
	})
	if err != nil || !decA.Allowed || decA.ReasonCode != fleetcache.ReasonAuthzOK {
		t.Fatalf("A authz: %+v %v", decA, err)
	}
	if decA.CacheHitElevation {
		t.Fatal("cache must never elevate")
	}
	isoA := fleetcache.IsolationCheck(fleetcache.IsolationRequest{
		Locator: loc, ExpectedFleetID: "fleet-corp", ExpectedCachePool: "pool-logs",
		ExpectedControllerID: ctrl, RequestLocatorHash: wm.LocatorHash, AuthzAllowed: decA.Allowed,
	})
	if !isoA.Allowed || isoA.Residual != fleetcache.IsolationResidualOK {
		t.Fatalf("A isolation: %+v", isoA)
	}

	// Subject B: same locator / physical bytes; gate denies; IsolationCheck fails closed.
	decB, err := gate.Allow(context.Background(), fleetcache.AuthzKey{
		SubjectKeyHash: subjectB, ControllerID: ctrl, JobFullName: job,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decB.Allowed {
		t.Fatalf("B must not be Allowed: %+v", decB)
	}
	if decB.ReasonCode != fleetcache.ReasonAuthzPolicyDeny {
		t.Fatalf("B reason want policy_deny got %q", decB.ReasonCode)
	}
	if decB.CacheHitElevation {
		t.Fatal("B elevation residual honesty")
	}
	isoB := fleetcache.IsolationCheck(fleetcache.IsolationRequest{
		Locator: loc, ExpectedFleetID: "fleet-corp", ExpectedCachePool: "pool-logs",
		ExpectedControllerID: ctrl, RequestLocatorHash: wm.LocatorHash, AuthzAllowed: decB.Allowed,
	})
	if isoB.Allowed || isoB.Residual != fleetcache.IsolationResidualAuthzDeny {
		t.Fatalf("B isolation: %+v", isoB)
	}

	// Physical presence still does not change B's IsolationCheck if we flip AuthzAllowed by mistake?
	// Re-assert: with AuthzAllowed=false always deny even if committed.
	isoB2 := fleetcache.IsolationCheck(fleetcache.IsolationRequest{
		Locator: loc, ExpectedFleetID: "fleet-corp", ExpectedCachePool: "pool-logs",
		ExpectedControllerID: ctrl, AuthzAllowed: false,
	})
	if isoB2.Allowed || isoB2.Residual != fleetcache.IsolationResidualAuthzDeny {
		t.Fatalf("physical bytes must not elevate B: %+v", isoB2)
	}

	assertSecretFree(t, "isoA", isoA.Residual)
	assertSecretFree(t, "isoB", isoB.Residual, decB.ReasonCode)
	assertSecretFree(t, "import", res.Status, res.Residual)
}

// TestIsolation_CrossController: same job/build names on c1 vs c2 never collide on locator hash;
// import for c1 does not commit c2's locator key on memSink.
func TestIsolation_CrossController(t *testing.T) {
	t.Parallel()
	const (
		fleet = "fleet-corp"
		pool  = "pool-logs"
		job   = "shared/name"
		build = int64(99)
	)
	locC1, err := fleetcache.NewConsoleLogLocator(fleet, pool, "c1", job, build)
	if err != nil {
		t.Fatal(err)
	}
	locC2, err := fleetcache.NewConsoleLogLocator(fleet, pool, "c2", job, build)
	if err != nil {
		t.Fatal(err)
	}
	h1, err := locC1.Hash()
	if err != nil {
		t.Fatal(err)
	}
	h2, err := locC2.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h2 {
		t.Fatal("same job/build on different controllers must produce different locator hashes")
	}

	wmC1, frames := makeSealedManifestAt(t, fleet, pool, "c1", job, build, [][]byte{[]byte("c1-body\n")})
	if wmC1.LocatorHash != h1 {
		t.Fatalf("c1 manifest locator %s want %s", wmC1.LocatorHash, h1)
	}
	sink := &memSink{}
	res, err := fleetcache.ReplicateSealed(context.Background(), sink, wmC1, frames)
	if err != nil || res.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("import c1: %+v %v", res, err)
	}
	if _, ok, _ := sink.GetCommitted(context.Background(), h1); !ok {
		t.Fatal("c1 locator must be committed")
	}
	if _, ok, _ := sink.GetCommitted(context.Background(), h2); ok {
		t.Fatal("c2 locator must not be committed by c1 import")
	}

	// IsolationCheck: expected controller c1 with c2 locator → mismatch residual.
	isoWrong := fleetcache.IsolationCheck(fleetcache.IsolationRequest{
		Locator: locC2, ExpectedFleetID: fleet, ExpectedCachePool: pool,
		ExpectedControllerID: "c1", AuthzAllowed: true,
	})
	if isoWrong.Allowed || isoWrong.Residual != fleetcache.IsolationResidualControllerMismatch {
		t.Fatalf("controller mismatch: %+v", isoWrong)
	}
	// Correct scope for c2 with authz → ok (no bytes required for pure check).
	isoOK := fleetcache.IsolationCheck(fleetcache.IsolationRequest{
		Locator: locC2, ExpectedFleetID: fleet, ExpectedCachePool: pool,
		ExpectedControllerID: "c2", AuthzAllowed: true,
	})
	if !isoOK.Allowed || isoOK.Residual != fleetcache.IsolationResidualOK {
		t.Fatalf("c2 isolation: %+v", isoOK)
	}
	// Request locator hash bind: c1 request hash with c2 locator fails closed.
	isoHash := fleetcache.IsolationCheck(fleetcache.IsolationRequest{
		Locator: locC2, ExpectedFleetID: fleet, ExpectedCachePool: pool,
		ExpectedControllerID: "c2", RequestLocatorHash: h1, AuthzAllowed: true,
	})
	if isoHash.Allowed || isoHash.Residual != fleetcache.IsolationResidualLocatorHashMismatch {
		t.Fatalf("hash bind: %+v", isoHash)
	}

	assertSecretFree(t, "cross-ctrl", isoWrong.Residual, isoOK.Residual, isoHash.Residual, res.Residual)
}

// TestIsolation_WrongFleetPool: different fleet/pool IDs produce different hashes;
// IsolationCheck fails closed on mismatched expected scope.
func TestIsolation_WrongFleetPool(t *testing.T) {
	t.Parallel()
	base, err := fleetcache.NewConsoleLogLocator("fleet-a", "pool-a", "ctrl", "job", 1)
	if err != nil {
		t.Fatal(err)
	}
	otherFleet, err := fleetcache.NewConsoleLogLocator("fleet-b", "pool-a", "ctrl", "job", 1)
	if err != nil {
		t.Fatal(err)
	}
	otherPool, err := fleetcache.NewConsoleLogLocator("fleet-a", "pool-b", "ctrl", "job", 1)
	if err != nil {
		t.Fatal(err)
	}
	hBase, _ := base.Hash()
	hFleet, _ := otherFleet.Hash()
	hPool, _ := otherPool.Hash()
	if hBase == hFleet || hBase == hPool || hFleet == hPool {
		t.Fatalf("fleet/pool must change locator hash: %s %s %s", hBase, hFleet, hPool)
	}

	// Wrong fleet expected.
	isoF := fleetcache.IsolationCheck(fleetcache.IsolationRequest{
		Locator: base, ExpectedFleetID: "fleet-b", ExpectedCachePool: "pool-a",
		ExpectedControllerID: "ctrl", AuthzAllowed: true,
	})
	if isoF.Allowed || isoF.Residual != fleetcache.IsolationResidualFleetMismatch {
		t.Fatalf("fleet: %+v", isoF)
	}
	// Wrong pool expected.
	isoP := fleetcache.IsolationCheck(fleetcache.IsolationRequest{
		Locator: base, ExpectedFleetID: "fleet-a", ExpectedCachePool: "pool-b",
		ExpectedControllerID: "ctrl", AuthzAllowed: true,
	})
	if isoP.Allowed || isoP.Residual != fleetcache.IsolationResidualPoolMismatch {
		t.Fatalf("pool: %+v", isoP)
	}
	// Wrong fleet wins before pool when both wrong (documented order: fleet → pool → controller → authz).
	isoBoth := fleetcache.IsolationCheck(fleetcache.IsolationRequest{
		Locator: base, ExpectedFleetID: "wrong-fleet", ExpectedCachePool: "wrong-pool",
		ExpectedControllerID: "ctrl", AuthzAllowed: true,
	})
	if isoBoth.Allowed || isoBoth.Residual != fleetcache.IsolationResidualFleetMismatch {
		t.Fatalf("both wrong fleet first: %+v", isoBoth)
	}

	// PlanImport / Replicate: object from fleet-b is a different locator key — no collision with fleet-a commit.
	wmA, framesA := makeSealedManifestAt(t, "fleet-a", "pool-a", "ctrl", "job", 1, [][]byte{[]byte("a\n")})
	wmB, framesB := makeSealedManifestAt(t, "fleet-b", "pool-a", "ctrl", "job", 1, [][]byte{[]byte("a\n")})
	if wmA.LocatorHash == wmB.LocatorHash {
		t.Fatal("cross-fleet manifests must not share locator_hash")
	}
	sink := &memSink{}
	if _, err := fleetcache.ReplicateSealed(context.Background(), sink, wmA, framesA); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := sink.GetCommitted(context.Background(), wmB.LocatorHash); ok {
		t.Fatal("fleet-b locator must not be committed by fleet-a import")
	}
	// Import B independently succeeds under its own key.
	if res, err := fleetcache.ReplicateSealed(context.Background(), sink, wmB, framesB); err != nil || res.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("fleet-b import: %+v %v", res, err)
	}

	// Assertion Verify with wrong fleet expected fails closed (shipped FLC-017).
	key := testKey(t)
	now := time.Now().UTC()
	a, err := fleetcache.IssueAssertion(key, fleetcache.AssertionClaims{
		FleetID: "fleet-a", RequestingMemberID: "m1", LocatorHash: hBase,
		Operation: fleetcache.OpRead, MaxDecodedBytes: 64 << 10,
		SubjectKeyHash: "opaque_subj_1", IssuedAt: now, ExpiresAt: now.Add(20 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := fleetcache.VerifyAssertion(key, a, now, fleetcache.Expected{FleetID: "fleet-b"}, fleetcache.NewMemoryNonceStore()); err == nil {
		t.Fatal("assertion wrong fleet must fail closed")
	}

	assertSecretFree(t, "wrong-fleet", isoF.Residual, isoP.Residual, isoBoth.Residual)
}

// TestIsolation_CrossProfileResidualHonesty: locator never embeds profile ID.
// Structural: Locator fields are only fleet/pool/controller/object_kind/job/build/schema.
func TestIsolation_CrossProfileResidualHonesty(t *testing.T) {
	t.Parallel()
	loc, err := fleetcache.NewConsoleLogLocator("fleet", "pool", "ctrl", "folder/job", 3)
	if err != nil {
		t.Fatal(err)
	}
	// reflect: only the documented identity fields exist on Locator.
	rt := reflect.TypeOf(loc)
	allowed := map[string]struct{}{
		"FleetID": {}, "CachePool": {}, "ControllerID": {}, "ObjectKind": {},
		"JobFullNameNormalized": {}, "BuildNumber": {}, "LocatorSchemaVersion": {},
	}
	for i := 0; i < rt.NumField(); i++ {
		name := rt.Field(i).Name
		if _, ok := allowed[name]; !ok {
			t.Fatalf("unexpected Locator field %q (profile/user must not appear)", name)
		}
		low := strings.ToLower(name)
		for _, banned := range []string{"profile", "user", "subject", "generation", "sqlite"} {
			if strings.Contains(low, banned) {
				t.Fatalf("Locator field %q looks like local/profile identity", name)
			}
		}
	}
	// Canonical bytes must not contain profile markers.
	raw, err := loc.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	cs := string(raw)
	for _, banned := range []string{"profile", "profile_id", "user_id", "subject", "generation"} {
		if strings.Contains(strings.ToLower(cs), banned) {
			t.Fatalf("canonical contains %q: %s", banned, cs)
		}
	}
	// Store-key shaped job (profile|job|build) is rejected by constructor.
	if _, err := fleetcache.NewConsoleLogLocator("fleet", "pool", "ctrl", "myprofile|folder/job|3", 3); err == nil {
		t.Fatal("profile|job|build store key must be rejected")
	}
	// Honesty residual is secret-free and names FLC-052.
	note := fleetcache.IsolationHonestyResidual()
	if !strings.Contains(note, "FLC-052") {
		t.Fatalf("honesty residual: %s", note)
	}
	assertSecretFree(t, "honesty", note, cs)
}

// TestIsolation_SecretFreeCanary: scan IsolationResult, AuthzDecision, Import/Replicate residuals.
func TestIsolation_SecretFreeCanary(t *testing.T) {
	t.Parallel()
	// Isolation residuals are fixed constants — none are secret-shaped.
	for _, code := range []string{
		fleetcache.IsolationResidualOK,
		fleetcache.IsolationResidualAuthzDeny,
		fleetcache.IsolationResidualControllerMismatch,
		fleetcache.IsolationResidualFleetMismatch,
		fleetcache.IsolationResidualPoolMismatch,
		fleetcache.IsolationResidualLocatorInvalid,
		fleetcache.IsolationResidualLocatorHashMismatch,
	} {
		assertSecretFree(t, "isolation code", code)
	}

	// AuthzDecision residual path with deny.
	gate := fleetcache.NewFreshnessGate(time.Second, func(ctx context.Context, k fleetcache.AuthzKey) (bool, string, error) {
		return false, fleetcache.ReasonAuthzPolicyDeny, nil
	})
	dec, err := gate.Allow(context.Background(), fleetcache.AuthzKey{
		SubjectKeyHash: "opaque_hash_xyz", ControllerID: "c", JobFullName: "j",
	})
	if err != nil {
		t.Fatal(err)
	}
	assertSecretFree(t, "authz", dec.ReasonCode, fmt.Sprintf("%+v", dec))

	// Import/replicate residual on committed path.
	wm, frames := makeSealedManifestAt(t, "fleet", "pool", "ctrl", "canary-job", 1, [][]byte{[]byte("ok\n")})
	sink := &memSink{}
	res, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, frames)
	if err != nil {
		t.Fatal(err)
	}
	assertSecretFree(t, "replicate", res.Status, res.Residual, res.LocatorHash, res.ManifestDigest)

	// IsolationCheck on invalid locator fails closed without leaking secrets.
	iso := fleetcache.IsolationCheck(fleetcache.IsolationRequest{
		Locator:      fleetcache.Locator{}, // empty → invalid
		AuthzAllowed: true,
	})
	if iso.Allowed || iso.Residual != fleetcache.IsolationResidualLocatorInvalid {
		t.Fatalf("%+v", iso)
	}
	assertSecretFree(t, "invalid loc", iso.Residual)

	// Authz OK path residual.
	isoOK := fleetcache.IsolationCheck(fleetcache.IsolationRequest{
		Locator:         mustLoc(t, "f", "p", "c", "job", 1),
		ExpectedFleetID: "f", ExpectedCachePool: "p", ExpectedControllerID: "c",
		AuthzAllowed: true,
	})
	assertSecretFree(t, "ok", isoOK.Residual)
}

func mustLoc(t *testing.T, fleet, pool, ctrl, job string, build int64) fleetcache.Locator {
	t.Helper()
	loc, err := fleetcache.NewConsoleLogLocator(fleet, pool, ctrl, job, build)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

// TestIsolation_DecodedReadRequestBind: ValidateDecodedReadRequest accepts only 64-hex locator;
// wrong-fleet request hash remains a different identity (no elevation via read form alone).
func TestIsolation_DecodedReadValidateBind(t *testing.T) {
	t.Parallel()
	locA, _ := fleetcache.NewConsoleLogLocator("fleet-a", "pool", "ctrl", "job", 1)
	locB, _ := fleetcache.NewConsoleLogLocator("fleet-b", "pool", "ctrl", "job", 1)
	hA, _ := locA.Hash()
	hB, _ := locB.Hash()
	if err := fleetcache.ValidateDecodedReadRequest(fleetcache.DecodedReadRequest{
		LocatorHash: hA, Kind: fleetcache.ReadKindByteRange, Start: 0, Length: 16,
	}); err != nil {
		t.Fatal(err)
	}
	// Cross-fleet: IsolationCheck with request hash for B against locator A fails.
	iso := fleetcache.IsolationCheck(fleetcache.IsolationRequest{
		Locator: locA, ExpectedFleetID: "fleet-a", ExpectedCachePool: "pool",
		ExpectedControllerID: "ctrl", RequestLocatorHash: hB, AuthzAllowed: true,
	})
	if iso.Allowed || iso.Residual != fleetcache.IsolationResidualLocatorHashMismatch {
		t.Fatalf("%+v", iso)
	}
	// Authz deny still wins when hash matches but probe denies (compose order: after scope).
	isoAuthz := fleetcache.IsolationCheck(fleetcache.IsolationRequest{
		Locator: locA, ExpectedFleetID: "fleet-a", ExpectedCachePool: "pool",
		ExpectedControllerID: "ctrl", RequestLocatorHash: hA, AuthzAllowed: false,
	})
	if isoAuthz.Allowed || isoAuthz.Residual != fleetcache.IsolationResidualAuthzDeny {
		t.Fatalf("%+v", isoAuthz)
	}
	assertSecretFree(t, "decoded bind", iso.Residual, isoAuthz.Residual, hA, hB)
}
