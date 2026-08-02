package fleetcache

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// PlacementAlgorithmID is the versioned placement function name (golden vectors).
const PlacementAlgorithmID = "hrw-sha256-weight-v1"

// Capacity weight bounds for placement (aligned with roster cache validation).
// Defined here so fleetcache stays free of fleetmcp imports (no import cycle).
const (
	DefaultPlacementWeight = 100
	MaxPlacementWeight     = 10000
)

// PlacementMember is a cache-eligible owner candidate (pure; no roster type).
type PlacementMember struct {
	ID             string
	CapacityWeight int
	FailureDomain  string
	Draining       bool
}

// PlacementOptions controls owner ordering.
type PlacementOptions struct {
	// ReplicationFactor is used only by SelectPrimaryOwners (domain-aware pick).
	// OwnerOrder always returns the full deterministic ranking.
	ReplicationFactor int
	// PreferDistinctDomains prefers different failure_domain values among the first RF owners.
	PreferDistinctDomains bool
}

// OwnerOrder returns all candidates ordered by weighted rendezvous score (highest first).
// Ties break by member ID ascending for stability. Empty locatorHash or members → error/empty.
// Draining members may still appear in the full order (readable grace) but SelectPrimaryOwners
// excludes them from new primary ownership by default.
func OwnerOrder(locatorHash string, members []PlacementMember) ([]string, error) {
	locatorHash = strings.ToLower(strings.TrimSpace(locatorHash))
	if len(locatorHash) != 64 || !isHex(locatorHash) {
		return nil, apperr.New(apperr.CodeInvalidArgument, "placement requires 64-hex locator_hash")
	}
	if len(members) == 0 {
		return nil, nil
	}
	type scored struct {
		id    string
		score uint64
	}
	items := make([]scored, 0, len(members))
	seen := make(map[string]struct{}, len(members))
	for _, m := range members {
		id := strings.TrimSpace(m.ID)
		if id == "" {
			return nil, apperr.New(apperr.CodeInvalidArgument, "placement member id is required")
		}
		if _, ok := seen[id]; ok {
			return nil, apperr.New(apperr.CodeInvalidArgument, "duplicate placement member id")
		}
		seen[id] = struct{}{}
		w := m.CapacityWeight
		if w <= 0 {
			w = DefaultPlacementWeight
		}
		if w > MaxPlacementWeight {
			return nil, apperr.New(apperr.CodeInvalidArgument, "placement capacity_weight exceeds maximum")
		}
		items = append(items, scored{id: id, score: hrwScore(locatorHash, id, w)})
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].score != items[j].score {
			return items[i].score > items[j].score
		}
		return items[i].id < items[j].id
	})
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.id
	}
	return out, nil
}

// SelectPrimaryOwners returns up to RF member IDs for new ownership.
// Draining members are excluded. When PreferDistinctDomains is true, the selection
// prefers candidates whose failure_domain is not already represented (still HRW-ordered).
func SelectPrimaryOwners(locatorHash string, members []PlacementMember, opts PlacementOptions) ([]string, error) {
	rf := opts.ReplicationFactor
	if rf <= 0 {
		rf = 2
	}
	// Exclude draining for new primary ownership.
	active := make([]PlacementMember, 0, len(members))
	byID := make(map[string]PlacementMember, len(members))
	for _, m := range members {
		byID[m.ID] = m
		if m.Draining {
			continue
		}
		active = append(active, m)
	}
	order, err := OwnerOrder(locatorHash, active)
	if err != nil {
		return nil, err
	}
	if !opts.PreferDistinctDomains || rf <= 1 {
		if len(order) > rf {
			order = order[:rf]
		}
		return order, nil
	}
	// Domain-aware: walk HRW order, pick first of each domain until RF, then fill.
	picked := make([]string, 0, rf)
	usedDomain := make(map[string]struct{})
	var rest []string
	for _, id := range order {
		if len(picked) >= rf {
			break
		}
		m := byID[id]
		dom := strings.TrimSpace(m.FailureDomain)
		if dom == "" {
			rest = append(rest, id)
			continue
		}
		if _, ok := usedDomain[dom]; ok {
			rest = append(rest, id)
			continue
		}
		usedDomain[dom] = struct{}{}
		picked = append(picked, id)
	}
	for _, id := range rest {
		if len(picked) >= rf {
			break
		}
		picked = append(picked, id)
	}
	// If still short (few domains), continue with remaining order.
	if len(picked) < rf {
		have := make(map[string]struct{}, len(picked))
		for _, id := range picked {
			have[id] = struct{}{}
		}
		for _, id := range order {
			if len(picked) >= rf {
				break
			}
			if _, ok := have[id]; ok {
				continue
			}
			picked = append(picked, id)
		}
	}
	return picked, nil
}

// hrwScore implements weighted highest-random-weight:
// score = hash64(locator||member) as uint64, then bias by weight via
// multi-probe HRW (deterministic; no process RNG).
func hrwScore(locatorHash, memberID string, weight int) uint64 {
	h := sha256.Sum256([]byte(PlacementAlgorithmID + "\n" + locatorHash + "\n" + memberID + "\n"))
	base := binary.BigEndian.Uint64(h[0:8])
	if weight <= 1 {
		return base
	}
	best := base
	for i := 1; i < weight; i++ {
		payload := fmt.Sprintf("%s\n%s\n%s\n%d\n", PlacementAlgorithmID, locatorHash, memberID, i)
		hi := sha256.Sum256([]byte(payload))
		v := binary.BigEndian.Uint64(hi[0:8])
		if v > best {
			best = v
		}
	}
	return best
}

// PlacementDebugHash exposes a stable hex of the placement algorithm id + inputs for docs/tests.
func PlacementDebugHash(locatorHash string, memberIDs []string) string {
	var b strings.Builder
	b.WriteString(PlacementAlgorithmID)
	b.WriteByte('\n')
	b.WriteString(locatorHash)
	b.WriteByte('\n')
	for _, id := range memberIDs {
		b.WriteString(id)
		b.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}
