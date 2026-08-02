package fleetcache_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
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

// TestSelectPrimaryOwners_PreferDistinctDomains forces a case where plain HRW
// top-2 share a domain, but domain preference must pick a different domain for RF=2.
// Fails if PreferDistinctDomains is a no-op (would keep two z1 members).
func TestSelectPrimaryOwners_PreferDistinctDomains(t *testing.T) {
	t.Parallel()
	// Craft members so HRW order puts both z1 members first when PreferDistinctDomains=false.
	// Use many probes: find a locator where plain RF=2 both have domain z1.
	members := []fleetcache.PlacementMember{
		{ID: "z1-alpha", CapacityWeight: 100, FailureDomain: "z1"},
		{ID: "z1-beta", CapacityWeight: 100, FailureDomain: "z1"},
		{ID: "z2-only", CapacityWeight: 100, FailureDomain: "z2"},
	}
	var foundLoc string
	var plain []string
	for i := 0; i < 4096; i++ {
		loc := fmt.Sprintf("%064x", i)
		order, err := fleetcache.OwnerOrder(loc, members)
		if err != nil {
			t.Fatal(err)
		}
		if len(order) < 2 {
			continue
		}
		// Map id -> domain
		dom := map[string]string{
			"z1-alpha": "z1", "z1-beta": "z1", "z2-only": "z2",
		}
		if dom[order[0]] == "z1" && dom[order[1]] == "z1" {
			foundLoc = loc
			plain = append([]string(nil), order[:2]...)
			break
		}
	}
	if foundLoc == "" {
		t.Fatal("could not find locator where HRW top-2 share domain z1 (test setup)")
	}
	// Without domain preference: top 2 both z1.
	noPref, err := fleetcache.SelectPrimaryOwners(foundLoc, members, fleetcache.PlacementOptions{
		ReplicationFactor:     2,
		PreferDistinctDomains: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(noPref) != 2 || !(noPref[0] == plain[0] && noPref[1] == plain[1]) {
		// still require both z1
		dom := map[string]string{"z1-alpha": "z1", "z1-beta": "z1", "z2-only": "z2"}
		if dom[noPref[0]] != "z1" || dom[noPref[1]] != "z1" {
			t.Fatalf("setup broken: noPref=%v plain=%v", noPref, plain)
		}
	}
	// With preference: must include z2-only (or otherwise two distinct domains).
	withPref, err := fleetcache.SelectPrimaryOwners(foundLoc, members, fleetcache.PlacementOptions{
		ReplicationFactor:     2,
		PreferDistinctDomains: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(withPref) != 2 {
		t.Fatalf("%v", withPref)
	}
	dom := map[string]string{"z1-alpha": "z1", "z1-beta": "z1", "z2-only": "z2"}
	if dom[withPref[0]] == dom[withPref[1]] {
		t.Fatalf("PreferDistinctDomains is a no-op: owners %v both domain %s (loc=%s plain HRW top2=%v)",
			withPref, dom[withPref[0]], foundLoc, plain)
	}
	// And z2-only should be selected when available.
	hasZ2 := withPref[0] == "z2-only" || withPref[1] == "z2-only"
	if !hasZ2 {
		t.Fatalf("expected z2-only in domain-aware pick: %v", withPref)
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
		hex := fmt.Sprintf("%x", i)
		loc := hex + strings.Repeat("0", 64-len(hex))
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

func TestOwnerOrder_RejectsBadHash(t *testing.T) {
	t.Parallel()
	_, err := fleetcache.OwnerOrder("short", []fleetcache.PlacementMember{{ID: "a", CapacityWeight: 1}})
	if err == nil {
		t.Fatal("expected error")
	}
}
