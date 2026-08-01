package logmirror

import (
	"fmt"
	"sort"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// PackRolloverBounds limits how large one affinity pack may grow (ARC-011).
// Zero fields use DefaultPackRolloverBounds.
type PackRolloverBounds struct {
	// MaxMembers is the max TAR members per pack (default 64).
	MaxMembers int
	// MaxUncompressedBytes caps sum of member bodies (default 256 MiB for MVP).
	// Architecture targets 4–16 GiB physical; this is a conservative pilot default.
	MaxUncompressedBytes int64
	// MaxFrames caps estimated independent frames across members (default 4096).
	MaxFrames int
}

// DefaultPackRolloverBounds returns pilot-safe pack size limits.
func DefaultPackRolloverBounds() PackRolloverBounds {
	return PackRolloverBounds{
		MaxMembers:           64,
		MaxUncompressedBytes: 256 << 20, // 256 MiB
		MaxFrames:            4096,
	}
}

// Normalize fills zero fields with defaults.
func (b PackRolloverBounds) Normalize() PackRolloverBounds {
	d := DefaultPackRolloverBounds()
	if b.MaxMembers <= 0 {
		b.MaxMembers = d.MaxMembers
	}
	if b.MaxUncompressedBytes <= 0 {
		b.MaxUncompressedBytes = d.MaxUncompressedBytes
	}
	if b.MaxFrames <= 0 {
		b.MaxFrames = d.MaxFrames
	}
	return b
}

// AffinityDomain is the isolation + co-location key for packing (ARC-011).
//
// Never mix profiles (or any set isolation dimension). Optional retention /
// sensitivity / policy classes must match when non-empty on both sides.
type AffinityDomain struct {
	// Profile is required isolation (user/controller data plane).
	Profile string
	// RetentionClass optional (e.g. "success-30d"); empty matches only empty.
	RetentionClass string
	// Sensitivity optional (e.g. "standard", "restricted").
	Sensitivity string
	// PolicyClass optional MCP/policy overlay id.
	PolicyClass string
	// CollectionID groups related logs from one investigation/acquire session.
	CollectionID string
	// AffinityGroup is the catalog label written on packs (defaults from collection).
	AffinityGroup string
}

// IsolationKey returns the hard isolation tuple (never co-pack across these).
func (d AffinityDomain) IsolationKey() string {
	return strings.Join([]string{
		strings.TrimSpace(d.Profile),
		strings.TrimSpace(d.RetentionClass),
		strings.TrimSpace(d.Sensitivity),
		strings.TrimSpace(d.PolicyClass),
	}, "\x1f")
}

// Validate requires a non-empty profile.
func (d AffinityDomain) Validate() error {
	if strings.TrimSpace(d.Profile) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "affinity domain profile is required")
	}
	return nil
}

// PackCandidate is one sealed log considered for packing.
type PackCandidate struct {
	Key               LogKey
	GenerationID      int64
	UncompressedBytes int64
	// FrameCount is the L1 independent frame count (or 1 if unknown/repack).
	FrameCount int
	Domain     AffinityDomain
}

// PackBatch is one rollover-bounded set of candidates sharing an isolation domain.
type PackBatch struct {
	// Domain is the isolation domain (profile + optional classes).
	Domain AffinityDomain
	// AffinityGroup is the catalog label for PutPack.
	AffinityGroup string
	// Members are ordered deterministically (job, build).
	Members []PackCandidate
	// TotalUncompressed / TotalFrames are pre-rollover sums for the batch.
	TotalUncompressed int64
	TotalFrames       int
	// PartIndex is 0-based within the same isolation+collection split sequence.
	PartIndex int
	// CollectionID is copied for continuation metadata.
	CollectionID string
}

// PlanPackBatches groups candidates by isolation domain (never mixing profiles
// or incompatible retention/sensitivity/policy), prefers co-locating the same
// collection/affinity group, and splits when rollover bounds are exceeded.
//
// Deterministic: stable sort within each domain, then greedy fill.
func PlanPackBatches(candidates []PackCandidate, bounds PackRolloverBounds) ([]PackBatch, error) {
	bounds = bounds.Normalize()
	if len(candidates) == 0 {
		return nil, nil
	}

	// Validate + group by isolation key, then by collection preference.
	type groupKey struct {
		iso  string
		coll string
	}
	groups := make(map[groupKey][]PackCandidate)
	isoDomain := make(map[string]AffinityDomain)
	for i, c := range candidates {
		if err := c.Key.Validate(); err != nil {
			return nil, err
		}
		if err := c.Domain.Validate(); err != nil {
			return nil, err
		}
		// Isolation belt: candidate key profile must match domain profile.
		if c.Key.Profile != c.Domain.Profile {
			return nil, apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("candidate %d profile mismatch key=%q domain=%q", i, c.Key.Profile, c.Domain.Profile))
		}
		if c.UncompressedBytes < 0 {
			return nil, apperr.New(apperr.CodeInvalidArgument, "uncompressed bytes must be non-negative")
		}
		fc := c.FrameCount
		if fc <= 0 {
			fc = 1
			c.FrameCount = 1
		}
		// Single member exceeding bound still forms its own batch (split residual).
		iso := c.Domain.IsolationKey()
		isoDomain[iso] = c.Domain
		coll := strings.TrimSpace(c.Domain.CollectionID)
		if coll == "" {
			coll = strings.TrimSpace(c.Domain.AffinityGroup)
		}
		gk := groupKey{iso: iso, coll: coll}
		groups[gk] = append(groups[gk], c)
	}

	// Stable order of groups for deterministic packs.
	var keys []groupKey
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].iso != keys[j].iso {
			return keys[i].iso < keys[j].iso
		}
		return keys[i].coll < keys[j].coll
	})

	var out []PackBatch
	for _, gk := range keys {
		members := groups[gk]
		sort.Slice(members, func(i, j int) bool {
			if members[i].Key.Job != members[j].Key.Job {
				return members[i].Key.Job < members[j].Key.Job
			}
			return members[i].Key.Build < members[j].Key.Build
		})
		domain := isoDomain[gk.iso]
		// Prefer collection affinity label.
		aff := strings.TrimSpace(domain.AffinityGroup)
		if aff == "" {
			aff = strings.TrimSpace(domain.CollectionID)
		}
		if aff == "" {
			aff = "profile:" + domain.Profile
		}

		// Pre-split into rollover batches, then label with #partN when split.
		var rawBatches [][]PackCandidate
		var rawBytes []int64
		var rawFrames []int
		var cur []PackCandidate
		var bytes int64
		var frames int
		for _, m := range members {
			fc := m.FrameCount
			if fc <= 0 {
				fc = 1
			}
			if len(cur) > 0 {
				if len(cur)+1 > bounds.MaxMembers ||
					bytes+m.UncompressedBytes > bounds.MaxUncompressedBytes ||
					frames+fc > bounds.MaxFrames {
					rawBatches = append(rawBatches, cur)
					rawBytes = append(rawBytes, bytes)
					rawFrames = append(rawFrames, frames)
					cur = nil
					bytes = 0
					frames = 0
				}
			}
			cur = append(cur, m)
			bytes += m.UncompressedBytes
			frames += fc
		}
		if len(cur) > 0 {
			rawBatches = append(rawBatches, cur)
			rawBytes = append(rawBytes, bytes)
			rawFrames = append(rawFrames, frames)
		}
		multi := len(rawBatches) > 1
		for part, batch := range rawBatches {
			label := aff
			if multi {
				label = fmt.Sprintf("%s#part%d", aff, part)
			}
			out = append(out, PackBatch{
				Domain:            domain,
				AffinityGroup:     label,
				Members:           append([]PackCandidate(nil), batch...),
				TotalUncompressed: rawBytes[part],
				TotalFrames:       rawFrames[part],
				PartIndex:         part,
				CollectionID:      domain.CollectionID,
			})
		}
	}
	return out, nil
}

// DomainFromSession builds an AffinityDomain for a collection session (same profile).
func DomainFromSession(profile, collectionID, affinityGroup, retention, sensitivity, policy string) AffinityDomain {
	return AffinityDomain{
		Profile:        profile,
		CollectionID:   collectionID,
		AffinityGroup:  affinityGroup,
		RetentionClass: retention,
		Sensitivity:    sensitivity,
		PolicyClass:    policy,
	}
}
