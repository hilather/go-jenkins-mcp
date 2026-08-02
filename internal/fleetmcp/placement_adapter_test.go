package fleetmcp_test

import (
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
	"github.com/hilather/go-jenkins-mcp/internal/fleetmcp"
)

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
	owners, err := fleetmcp.OwnersForEligibleRoster(r, "c1", "p1", loc, fleetcache.PlacementOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) != 1 || owners[0] != "a" {
		t.Fatalf("%v", owners)
	}
	owners2, err := fleetmcp.OwnersForEligibleRoster(r, "c1", "nope", loc, fleetcache.PlacementOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(owners2) != 0 {
		t.Fatalf("cross pool: %v", owners2)
	}
}

func TestPlacementMembersFromEligible(t *testing.T) {
	t.Parallel()
	members := []fleetmcp.RosterMember{
		{ID: "x", Cache: &fleetmcp.MemberCache{Enabled: true, CapacityWeight: 50, FailureDomain: "z", Draining: true}},
		{ID: "y"}, // no cache block
	}
	pm := fleetmcp.PlacementMembersFromEligible(members)
	if len(pm) != 2 {
		t.Fatalf("%+v", pm)
	}
	if pm[0].CapacityWeight != 50 || pm[0].FailureDomain != "z" || !pm[0].Draining {
		t.Fatalf("%+v", pm[0])
	}
	if pm[1].CapacityWeight != fleetcache.DefaultPlacementWeight {
		t.Fatalf("default weight: %+v", pm[1])
	}
}
