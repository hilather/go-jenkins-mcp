package logmirror

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/hilather/go-jenkins-mcp/internal/store"
)

// MaxAffinityGroupLen bounds catalog AffinityGroup labels (no secrets, stable).
// Long job fullNames are truncated with a short content hash suffix for uniqueness.
const MaxAffinityGroupLen = 256

// MaxAffinityRelationLen bounds optional |relation=<label> suffixes on
// collection AffinityGroup labels (Wave 32). Relations are non-secret catalog
// tags (e.g. primary, downstream); oversize parts are truncated before the
// whole key is length-bounded.
const MaxAffinityRelationLen = 64

// AffinityGroupMixed is the catalog label when a pack intentionally contains
// members from more than one job affinity (discouraged; selection prefers not to).
const AffinityGroupMixed = "mixed"

// AffinityGroupKey derives a stable pack affinity label from profile + job fullName.
//
// Format:
//
//	profile=<id>|job=<fullName>   when profile is non-empty
//	job=<fullName>                when profile is empty
//
// Normalization: trim space, strip controls, replace '|' and newlines that would
// break the key, bound length. Never includes credentials, tokens, build numbers,
// or log body. Empty job becomes "job=_".
func AffinityGroupKey(profile, job string) string {
	p := normalizeAffinityPart(profile)
	j := normalizeAffinityPart(job)
	if j == "" {
		j = "_"
	}
	var out string
	if p == "" {
		out = "job=" + j
	} else {
		out = "profile=" + p + "|job=" + j
	}
	return boundAffinityGroup(out)
}

// AffinityGroupKeyFromLogKey is AffinityGroupKey(key.Profile, key.Job).
func AffinityGroupKeyFromLogKey(key LogKey) string {
	return AffinityGroupKey(key.Profile, key.Job)
}

// AffinityGroupKeyFromGeneration is AffinityGroupKey(gen.Profile, gen.Job).
func AffinityGroupKeyFromGeneration(g store.LogGeneration) string {
	return AffinityGroupKey(g.Profile, g.Job)
}

// CollectionAffinityKey derives a stable pack affinity label from profile +
// durable collection id (Wave 31 / ARC-011). Equivalent to
// CollectionAffinityKeyWithRelation with an empty relation.
//
// Format:
//
//	profile=<id>|collection=<collectionID>   when profile is non-empty
//	collection=<collectionID>                when profile is empty
//
// Same normalization and length bounds as AffinityGroupKey. Never includes
// credentials, tokens, build numbers, or log body. Empty collection becomes
// "collection=_".
func CollectionAffinityKey(profile, collectionID string) string {
	return CollectionAffinityKeyWithRelation(profile, collectionID, "")
}

// CollectionAffinityKeyWithRelation is CollectionAffinityKey plus an optional
// Wave 32 relation suffix when relation is non-empty after normalization.
//
// Format (relation present):
//
//	profile=<id>|collection=<collectionID>|relation=<label>
//	collection=<collectionID>|relation=<label>
//
// Selection keys (PackSelectionKey / packSelectionKeyForGen) never include
// relation so mixed relations still co-pack under one collection. Catalog
// AffinityGroup labels use the suffix only when a pack batch shares one
// non-empty relation (see AffinityGroupFromGenerationsWithCollections).
func CollectionAffinityKeyWithRelation(profile, collectionID, relation string) string {
	p := normalizeAffinityPart(profile)
	c := normalizeAffinityPart(collectionID)
	if c == "" {
		c = "_"
	}
	var out string
	if p == "" {
		out = "collection=" + c
	} else {
		out = "profile=" + p + "|collection=" + c
	}
	if r := normalizeAffinityRelation(relation); r != "" {
		out = out + "|relation=" + r
	}
	return boundAffinityGroup(out)
}

// PackSelectionKey returns the affinity group key used when selecting packs for
// one generation. When collectionID is non-empty (after trim), prefers
// CollectionAffinityKey (no relation suffix); otherwise job affinity. Profile
// always comes from the generation (never from an untrusted external profile alone).
func PackSelectionKey(g store.LogGeneration, collectionID string) string {
	coll := strings.TrimSpace(collectionID)
	if coll != "" {
		return CollectionAffinityKey(g.Profile, coll)
	}
	return AffinityGroupKeyFromGeneration(g)
}

// AffinityGroupFromKeys returns the shared affinity when all keys share the same
// profile+job affinity; AffinityGroupMixed when they differ; empty when no keys.
func AffinityGroupFromKeys(keys []LogKey) string {
	if len(keys) == 0 {
		return ""
	}
	first := AffinityGroupKeyFromLogKey(keys[0])
	for i := 1; i < len(keys); i++ {
		if AffinityGroupKeyFromLogKey(keys[i]) != first {
			return AffinityGroupMixed
		}
	}
	return first
}

// AffinityGroupFromGenerations is AffinityGroupFromKeys over generation identity fields.
func AffinityGroupFromGenerations(gens []store.LogGeneration) string {
	if len(gens) == 0 {
		return ""
	}
	keys := make([]LogKey, len(gens))
	for i, g := range gens {
		keys[i] = LogKey{Profile: g.Profile, Job: g.Job, Build: g.Build}
	}
	return AffinityGroupFromKeys(keys)
}

// AffinityGroupFromGenerationsWithCollections returns the shared catalog
// AffinityGroup label when all gens share the same PackSelectionKey (collection
// or job). Mixed when they differ; empty when no gens. genToColl may be nil
// (job-only).
//
// Wave 32: when the shared key is a collection affinity and every member has
// the same non-empty relation label, the returned label includes
// |relation=<label> (normalized, length-bounded). Differing or empty relations
// omit the suffix (collection key only). Job-affinity batches never get a
// relation suffix.
//
// Fail closed on profile mismatch: if genToColl[g.ID].Profile is non-empty and
// differs from g.Profile, that mapping is ignored (job affinity fallback) so a
// bad catalog never co-packs across profiles.
func AffinityGroupFromGenerationsWithCollections(gens []store.LogGeneration, genToColl map[int64]store.GenerationCollection) string {
	if len(gens) == 0 {
		return ""
	}
	first := packSelectionKeyForGen(gens[0], genToColl)
	for i := 1; i < len(gens); i++ {
		if packSelectionKeyForGen(gens[i], genToColl) != first {
			return AffinityGroupMixed
		}
	}
	// Optional relation suffix on collection packs only (not selection key).
	if rel, collID, ok := sharedCollectionRelation(gens, genToColl); ok {
		return CollectionAffinityKeyWithRelation(gens[0].Profile, collID, rel)
	}
	return first
}

// sharedCollectionRelation returns the shared non-empty relation and collection
// id when every generation resolves to the same usable collection membership
// with the same normalized relation. Otherwise ok is false (omit suffix).
func sharedCollectionRelation(gens []store.LogGeneration, genToColl map[int64]store.GenerationCollection) (relation, collectionID string, ok bool) {
	if genToColl == nil || len(gens) == 0 {
		return "", "", false
	}
	ref0, ok0 := usableCollectionRef(gens[0], genToColl)
	if !ok0 {
		return "", "", false
	}
	rel0 := normalizeAffinityRelation(ref0.Relation)
	if rel0 == "" {
		return "", "", false
	}
	coll0 := strings.TrimSpace(ref0.CollectionID)
	for _, g := range gens[1:] {
		ref, ok := usableCollectionRef(g, genToColl)
		if !ok {
			return "", "", false
		}
		if strings.TrimSpace(ref.CollectionID) != coll0 {
			return "", "", false
		}
		if normalizeAffinityRelation(ref.Relation) != rel0 {
			return "", "", false
		}
	}
	return rel0, coll0, true
}

// usableCollectionRef returns the catalog mapping when pack selection would
// prefer collection affinity for g (same fail-closed profile rules as
// packSelectionKeyForGen).
func usableCollectionRef(g store.LogGeneration, genToColl map[int64]store.GenerationCollection) (store.GenerationCollection, bool) {
	if genToColl == nil {
		return store.GenerationCollection{}, false
	}
	ref, ok := genToColl[g.ID]
	if !ok {
		return store.GenerationCollection{}, false
	}
	if strings.TrimSpace(ref.CollectionID) == "" {
		return store.GenerationCollection{}, false
	}
	refProfile := strings.TrimSpace(ref.Profile)
	genProfile := strings.TrimSpace(g.Profile)
	if refProfile != "" && genProfile != "" && refProfile != genProfile {
		return store.GenerationCollection{}, false
	}
	return ref, true
}

// SelectAffinityPackBatches groups sealed generations by job affinity, then
// fills packs of at most maxMembers within each affinity (ARC-011 lite).
//
// Equivalent to SelectCollectionAwarePackBatches with a nil collection map.
// See that function for grouping / bounds semantics.
func SelectAffinityPackBatches(gens []store.LogGeneration, maxMembers, minSize, maxBatches int) [][]store.LogGeneration {
	return SelectCollectionAwarePackBatches(gens, nil, maxMembers, minSize, maxBatches)
}

// SelectCollectionAwarePackBatches groups sealed generations preferring durable
// collection co-packing (Wave 31 / ARC-011), then job affinity as fallback.
//
// Primary group key: when gen has a collection mapping with matching profile,
// use profile=<p>|collection=<id>. Generations without a usable collection fall
// back to profile=<p>|job=<fullName>. Different profiles never share a group
// (profile is part of every key). Collection map entries whose Profile is set
// and mismatches the generation are ignored (fail closed → job affinity).
//
// Groups are processed in sorted affinity-key order; members within a group are
// ordered by job, build, then generation id. Chunks respect maxMembers /
// minSize / maxBatches (force-aged path uses minSize=1).
//
// Empty input or non-positive bounds ⇒ nil. genToColl may be nil.
func SelectCollectionAwarePackBatches(
	gens []store.LogGeneration,
	genToColl map[int64]store.GenerationCollection,
	maxMembers, minSize, maxBatches int,
) [][]store.LogGeneration {
	if maxMembers <= 0 || minSize <= 0 || maxBatches <= 0 || len(gens) == 0 {
		return nil
	}
	if minSize > maxMembers {
		minSize = maxMembers
	}

	groups := make(map[string][]store.LogGeneration, len(gens))
	for _, g := range gens {
		k := packSelectionKeyForGen(g, genToColl)
		groups[k] = append(groups[k], g)
	}

	affKeys := make([]string, 0, len(groups))
	for k := range groups {
		affKeys = append(affKeys, k)
	}
	sort.Strings(affKeys)

	var out [][]store.LogGeneration
	for _, ak := range affKeys {
		if len(out) >= maxBatches {
			break
		}
		members := groups[ak]
		sort.SliceStable(members, func(i, j int) bool {
			if members[i].Job != members[j].Job {
				return members[i].Job < members[j].Job
			}
			if members[i].Build != members[j].Build {
				return members[i].Build < members[j].Build
			}
			return members[i].ID < members[j].ID
		})
		// Chunk within this affinity only — never mix collections/jobs across groups.
		for len(members) >= minSize && len(out) < maxBatches {
			n := maxMembers
			if n > len(members) {
				n = len(members)
			}
			if n < minSize {
				break
			}
			batch := make([]store.LogGeneration, n)
			copy(batch, members[:n])
			out = append(out, batch)
			members = members[n:]
		}
	}
	return out
}

// packSelectionKeyForGen resolves collection vs job affinity with fail-closed
// profile checks against store.GenerationCollection.Profile. Selection keys
// never include |relation= (Wave 32 labels only).
func packSelectionKeyForGen(g store.LogGeneration, genToColl map[int64]store.GenerationCollection) string {
	if ref, ok := usableCollectionRef(g, genToColl); ok {
		return CollectionAffinityKey(g.Profile, ref.CollectionID)
	}
	return AffinityGroupKeyFromGeneration(g)
}

func normalizeAffinityPart(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '|' || r == '\n' || r == '\r' || r == '\t':
			// Keep key parseable; job fullNames may contain path separators which we keep.
			b.WriteByte('_')
		case r < 32 || r == 127 || !unicode.IsPrint(r):
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// normalizeAffinityRelation normalizes a catalog relation label for optional
// |relation= suffixes. Empty after normalize ⇒ omit suffix. Length-bounded so
// a hostile/long relation cannot dominate the AffinityGroup key.
func normalizeAffinityRelation(s string) string {
	r := normalizeAffinityPart(s)
	if r == "" {
		return ""
	}
	if len(r) <= MaxAffinityRelationLen {
		return r
	}
	return truncateUTF8(r, MaxAffinityRelationLen)
}

func boundAffinityGroup(s string) string {
	if len(s) <= MaxAffinityGroupLen {
		return s
	}
	// Stable truncation: keep head (UTF-8 safe), append short hash of full string.
	sum := sha256.Sum256([]byte(s))
	suffix := "#" + hex.EncodeToString(sum[:4]) // 9 chars
	keep := MaxAffinityGroupLen - len(suffix)
	if keep < 16 {
		// Extremely small max — still return something bounded on a rune edge.
		return truncateUTF8(s, MaxAffinityGroupLen)
	}
	return truncateUTF8(s, keep) + suffix
}

func truncateUTF8(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	// Back up from maxBytes to a rune boundary (never split multi-byte UTF-8).
	for maxBytes > 0 && !utf8.ValidString(s[:maxBytes]) {
		maxBytes--
	}
	return s[:maxBytes]
}
