package fleetcache_test

import (
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

func TestPlanOwnerContacts_BoundedNotBroadcast(t *testing.T) {
	t.Parallel()
	// Only placement-selected owners, not full roster.
	owners := []string{"lab-b", "lab-a"} // RF2
	urls := map[string]string{
		"lab-a": "https://a.example",
		"lab-b": "https://b.example",
		"lab-c": "https://c.example", // not selected
	}
	c := fleetcache.PlanOwnerContacts(owners, urls)
	if len(c) != 2 {
		t.Fatalf("%+v", c)
	}
	if c[0].MemberID != "lab-b" || c[1].MemberID != "lab-a" {
		t.Fatalf("order: %+v", c)
	}
	for _, x := range c {
		if x.MemberID == "lab-c" {
			t.Fatal("broadcasted to non-owner")
		}
	}
}

func TestMergeOwnerManifestResults_HitMissWrongFleet(t *testing.T) {
	t.Parallel()
	in := sealedPublishFixture(t)
	wm, err := fleetcache.PublishSealed(in)
	if err != nil {
		t.Fatal(err)
	}
	tried := []fleetcache.OwnerContact{{MemberID: "a"}, {MemberID: "b"}}
	// Hit on second owner.
	res, err := fleetcache.MergeOwnerManifestResults(wm.LocatorHash, "fleet", tried, []fleetcache.PeerManifestResult{
		{MemberID: "a", OK: true, Hit: false},
		{MemberID: "b", OK: true, Hit: true, Manifest: &wm},
	}, true)
	if err != nil || res.Status != fleetcache.LookupHit || res.Manifest == nil {
		t.Fatalf("%+v %v", res, err)
	}
	// Wrong fleet rejected.
	bad := wm
	bad.FleetID = "other"
	res2, err := fleetcache.MergeOwnerManifestResults(wm.LocatorHash, "fleet", tried, []fleetcache.PeerManifestResult{
		{MemberID: "a", OK: true, Hit: true, Manifest: &bad},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Status == fleetcache.LookupHit {
		t.Fatal("wrong fleet must not hit")
	}
	// Miss.
	res3, err := fleetcache.MergeOwnerManifestResults(wm.LocatorHash, "fleet", tried, []fleetcache.PeerManifestResult{
		{MemberID: "a", OK: true, Hit: false},
		{MemberID: "b", OK: true, Hit: false},
	}, true)
	if err != nil || res3.Status != fleetcache.LookupMiss || !res3.OriginFallbackRecommended {
		t.Fatalf("%+v", res3)
	}
	// Partial timeout.
	res4, err := fleetcache.MergeOwnerManifestResults(wm.LocatorHash, "fleet", tried, []fleetcache.PeerManifestResult{
		{MemberID: "a", OK: false, ErrorCode: "timeout", Residual: "peer timeout"},
		{MemberID: "b", OK: true, Hit: false},
	}, true)
	if err != nil || res4.Status != fleetcache.LookupPartial {
		t.Fatalf("%+v", res4)
	}
	if strings.Contains(res4.Residual, "token") {
		t.Fatal(res4.Residual)
	}
}
