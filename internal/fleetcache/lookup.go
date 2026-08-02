package fleetcache

import (
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// LookupStatus is the outcome of an owner-directed manifest lookup (FLC-030).
type LookupStatus string

const (
	LookupHit            LookupStatus = "hit"
	LookupMiss           LookupStatus = "miss"
	LookupPartial        LookupStatus = "partial" // some owners failed; no verified hit
	LookupModeOff        LookupStatus = "mode_off"
	LookupAuthzDenied    LookupStatus = "authz_denied"
	LookupInvalidLocator LookupStatus = "invalid_locator"
)

// OwnerContact is one placement-selected peer to query (not full roster broadcast).
type OwnerContact struct {
	MemberID string
	PeerURL  string
}

// PeerManifestResult is one owner's response (secret-free residual codes).
type PeerManifestResult struct {
	MemberID  string
	OK        bool
	Hit       bool
	Manifest  *WireManifest
	ErrorCode string // timeout, auth_failed, wrong_fleet, protocol, etc.
	Residual  string // secret-free human residual
}

// LookupResult aggregates owner-directed lookup (never claims fill/RF2 Done).
type LookupResult struct {
	Status      LookupStatus
	Manifest    *WireManifest
	OwnersTried []string
	PeerResults []PeerManifestResult
	// OriginFallbackRecommended is true when miss/partial and origin fallback policy applies.
	OriginFallbackRecommended bool
	Residual                  string
}

// PlanOwnerContacts builds the bounded owner contact list from placement order.
// contactsByID maps member id → peer URL; missing URLs are skipped with residual later.
func PlanOwnerContacts(ownerIDs []string, contactsByID map[string]string) []OwnerContact {
	out := make([]OwnerContact, 0, len(ownerIDs))
	for _, id := range ownerIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		url := ""
		if contactsByID != nil {
			url = strings.TrimSpace(contactsByID[id])
		}
		out = append(out, OwnerContact{MemberID: id, PeerURL: url})
	}
	return out
}

// MergeOwnerManifestResults reduces peer responses into a single LookupResult.
// First verified hit matching expected fleet/locator wins; wrong fleet is rejected.
func MergeOwnerManifestResults(locatorHash, fleetID string, tried []OwnerContact, peers []PeerManifestResult, originFallback bool) (LookupResult, error) {
	locatorHash = strings.ToLower(strings.TrimSpace(locatorHash))
	if len(locatorHash) != 64 || !isHex(locatorHash) {
		return LookupResult{Status: LookupInvalidLocator, Residual: "invalid locator_hash"},
			apperr.New(apperr.CodeInvalidArgument, "lookup locator_hash invalid")
	}
	out := LookupResult{
		OwnersTried:               make([]string, 0, len(tried)),
		PeerResults:               peers,
		OriginFallbackRecommended: originFallback,
	}
	for _, t := range tried {
		out.OwnersTried = append(out.OwnersTried, t.MemberID)
	}
	var anyFail bool
	for i := range peers {
		p := &peers[i]
		if !p.OK {
			anyFail = true
			continue
		}
		if !p.Hit || p.Manifest == nil {
			continue
		}
		m := p.Manifest
		if err := ValidateWireManifest(*m); err != nil {
			anyFail = true
			p.OK = false
			p.Hit = false
			p.ErrorCode = "protocol"
			p.Residual = "invalid peer manifest"
			p.Manifest = nil
			continue
		}
		if fleetID != "" && m.FleetID != fleetID {
			anyFail = true
			p.OK = false
			p.Hit = false
			p.ErrorCode = "wrong_fleet"
			p.Residual = "peer fleet mismatch"
			p.Manifest = nil
			continue
		}
		if !strings.EqualFold(m.LocatorHash, locatorHash) {
			anyFail = true
			p.OK = false
			p.Hit = false
			p.ErrorCode = "wrong_locator"
			p.Residual = "peer locator mismatch"
			p.Manifest = nil
			continue
		}
		// Verified hit.
		cp := *m
		out.Status = LookupHit
		out.Manifest = &cp
		out.Residual = ""
		return out, nil
	}
	if anyFail {
		out.Status = LookupPartial
		out.Residual = "owner lookup incomplete; origin fallback recommended"
		out.OriginFallbackRecommended = true
		return out, nil
	}
	out.Status = LookupMiss
	out.Residual = "no owner hit"
	out.OriginFallbackRecommended = originFallback
	return out, nil
}
