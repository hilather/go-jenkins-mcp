package fleetcache_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
	"github.com/hilather/go-jenkins-mcp/internal/fleetmcp"
)

// Golden owner order for hrw-sha256-weight-v1 with:
// locator 0123…def (64 hex), members lab-a/b/c weights 100/100/50.
// Update only when PlacementAlgorithmID or scoring formula changes.
const placementGoldenOrder = "lab-b,lab-c,lab-a"

func TestOwnerOrder_GoldenStable(t *testing.T) {
	t.Parallel()
	const loc = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	members := []fleetcache.PlacementMember{
		{ID: "lab-a", CapacityWeight: 100, FailureDomain: "zone-a"},
		{ID: "lab-b", CapacityWeight: 100, FailureDomain: "zone-b"},
		{ID: "lab-c", CapacityWeight: 50, FailureDomain: "zone-c"},
	}
	o1, err := fleetcache.OwnerOrder(loc, members)
	if err != nil {
		t.Fatal(err)
	}
	o2, err := fleetcache.OwnerOrder(loc, members)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(o1, ",")
	if got != strings.Join(o2, ",") {
		t.Fatalf("non-deterministic: %v vs %v", o1, o2)
	}
	if got != placementGoldenOrder {
		t.Fatalf("placement golden changed: got %s want %s", got, placementGoldenOrder)
	}
}

func TestSelectPrimaryOwners_ExcludesDraining(t *testing.T) {
	t.Parallel()
	const loc = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	members := []fleetcache.PlacementMember{
		{ID: "a", CapacityWeight: 100, FailureDomain: "z1"},
		{ID: "b", CapacityWeight: 100, FailureDomain: "z1", Draining: true},
		{ID: "c", CapacityWeight: 100, FailureDomain: "z2"},
		{ID: "d", CapacityWeight: 100, FailureDomain: "z3"},
	}
	owners, err := fleetcache.SelectPrimaryOwners(loc, members, fleetcache.PlacementOptions{
		ReplicationFactor:     2,
		PreferDistinctDomains: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) != 2 {
		t.Fatalf("%v", owners)
	}
	for _, id := range owners {
		if id == "b" {
			t.Fatal("draining member must not be primary owner")
		}
	}
}

func TestOwnerOrder_WeightBias(t *testing.T) {
	t.Parallel()
	light := fleetcache.PlacementMember{ID: "light", CapacityWeight: 1}
	heavy := fleetcache.PlacementMember{ID: "heavy", CapacityWeight: 100}
	members := []fleetcache.PlacementMember{light, heavy}
	heavyFirst := 0
	const n = 64
	for i := 0; i < n; i++ {
		loc := fmt.Sprintf("%064x", i) // 64 hex chars from small integers padded
		// fmt %064x of i is not 64 chars for small i — pad:
		loc = strings.Repeat("0", 64)
		// unique per i:
		hex := fmt.Sprintf("%x", i)
		loc = hex + strings.Repeat("0", 64-len(hex))
		if len(loc) != 64 {
			loc = (loc + strings.Repeat("0", 64))[:64]
		}
		order, err := fleetcache.OwnerOrder(loc, members)
		if err != nil {
			t.Fatal(err)
		}
		if order[0] == "heavy" {
			heavyFirst++
		}
	}
	if heavyFirst < n/2 {
		t.Fatalf("expected heavy to win majority of keys; heavyFirst=%d/%d", heavyFirst, n)
	}
}

func TestOwnersForEligibleRoster_CrossControllerEmpty(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
	  "schema_version": 1,
	  "fleet_id": "corp",
	  "members": [
	    {"id":"a","peer_url":"https://a",
	      "cache":{"enabled":true,"controller_id":"c1","pool":"p1","protocols":["fleet-cache/1"]}},
	    {"id":"b","peer_url":"https://b",
	      "cache":{"enabled":true,"controller_id":"c2","pool":"p1","protocols":["fleet-cache/1"]}}
	  ]
	}`)
	r, err := fleetmcp.ParseRoster(raw)
	if err != nil {
		t.Fatal(err)
	}
	loc := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	owners, err := fleetcache.OwnersForEligibleRoster(r, "c1", "p1", loc, fleetcache.PlacementOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) != 1 || owners[0] != "a" {
		t.Fatalf("%v", owners)
	}
	owners2, err := fleetcache.OwnersForEligibleRoster(r, "c1", "nope", loc, fleetcache.PlacementOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(owners2) != 0 {
		t.Fatalf("cross pool: %v", owners2)
	}
}

func TestOwnerOrder_RejectsBadHash(t *testing.T) {
	t.Parallel()
	_, err := fleetcache.OwnerOrder("short", []fleetcache.PlacementMember{{ID: "a", CapacityWeight: 1}})
	if err == nil {
		t.Fatal("expected error")
	}
}
