package fleetmcp

import (
	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

// PlacementMembersFromEligible converts CacheEligibleMembers results into pure
// fleetcache.PlacementMember values. Lives in fleetmcp so fleetcache never
// imports this package (avoids an import cycle when peer-read routes land).
func PlacementMembersFromEligible(members []RosterMember) []fleetcache.PlacementMember {
	out := make([]fleetcache.PlacementMember, 0, len(members))
	for _, m := range members {
		w := fleetcache.DefaultPlacementWeight
		domain := ""
		draining := false
		if m.Cache != nil {
			if m.Cache.CapacityWeight > 0 {
				w = m.Cache.CapacityWeight
			}
			domain = m.Cache.FailureDomain
			draining = m.Cache.Draining
		}
		out = append(out, fleetcache.PlacementMember{
			ID:             m.ID,
			CapacityWeight: w,
			FailureDomain:  domain,
			Draining:       draining,
		})
	}
	return out
}

// OwnersForEligibleRoster filters the roster by controller/pool/protocol then
// runs pure fleetcache placement.
func OwnersForEligibleRoster(r *Roster, controllerID, pool, locatorHash string, opts fleetcache.PlacementOptions) ([]string, error) {
	if r == nil {
		return nil, apperr.New(apperr.CodeInvalidArgument, "roster is nil")
	}
	elig := r.CacheEligibleMembers(controllerID, pool, CacheEligibleOptions{
		Protocol:        fleetcache.ProtocolV1,
		IncludeDraining: true, // full ranking; SelectPrimaryOwners drops drain
	})
	members := PlacementMembersFromEligible(elig)
	if opts.ReplicationFactor > 0 {
		return fleetcache.SelectPrimaryOwners(locatorHash, members, opts)
	}
	return fleetcache.OwnerOrder(locatorHash, members)
}
