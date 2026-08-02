package fleetcache

import (
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// DefaultReplicationFactor is RF2 for sealed console-log objects (FLC-043).
// Near-cache copies never count toward this factor (FLC-033 Done*; use
// FilterRFObservations so near members are not passed as committed RF owners).
const DefaultReplicationFactor = 2

// AbsoluteMaxReplicationFactor hard-caps RF (placement already bounds owners).
const AbsoluteMaxReplicationFactor = 3

// ReplicaAction is the per-target plan for RF2 replication (secret-free).
const (
	ReplicaActionSkipVerified  = "skip_verified"
	ReplicaActionFullImport    = "full_import"
	ReplicaActionMissingFrames = "missing_frames"
	ReplicaActionQuarantined   = "quarantined_replace"
)

// ReplicaObservation is a member's known state for a locator (no credentials).
type ReplicaObservation struct {
	MemberID string
	// Digest is committed manifest digest when Status is committed (64 hex).
	Digest string
	// Status: committed | missing | quarantined | staging
	Status string
	// PresentSeqs lists frame sequences already durable on a staging/partial replica
	// (for resume); nil means unknown/none.
	PresentSeqs []int
}

// ReplicateTarget is one required owner action for a replication wave.
type ReplicateTarget struct {
	MemberID string
	Action   string
	// MissingSeqs is set for missing_frames / full_import (all seqs for full).
	MissingSeqs []int
	// Residual is secret-free.
	Residual string
}

// ReplicatePlan is a pure RF2 plan: required owners, source, per-target actions.
// Near-cache members are never included (only placement SelectPrimaryOwners).
type ReplicatePlan struct {
	LocatorHash       string
	ManifestDigest    string
	ReplicationFactor int
	RequiredOwners    []string
	// SourceMember is preferred exporter (first required owner with matching committed digest).
	SourceMember string
	Targets      []ReplicateTarget
	// FramesToTransfer is total missing frames across targets (for metrics/tests).
	FramesToTransfer int
	// Residual secret-free (e.g. source_missing).
	Residual string
}

// PlanRF2Replication selects RF owners and decides skip vs transfer per target.
// replicas is keyed by member ID. Near copies must not be passed as committed RF
// owners — call FilterRFObservations first when near members are known (FLC-033).
// Placement SelectPrimaryOwners is independent of near promotion.
//
// Fail closed if manifest invalid or RF cannot be satisfied (insufficient members).
func PlanRF2Replication(
	locatorHash string,
	members []PlacementMember,
	manifest WireManifest,
	replicas map[string]ReplicaObservation,
	opts PlacementOptions,
) (ReplicatePlan, error) {
	locatorHash = strings.ToLower(strings.TrimSpace(locatorHash))
	if err := ValidateWireManifest(manifest); err != nil {
		return ReplicatePlan{}, err
	}
	if !strings.EqualFold(manifest.LocatorHash, locatorHash) && locatorHash != "" {
		return ReplicatePlan{}, apperr.New(apperr.CodeInvalidArgument, "rf2 locator mismatch")
	}
	locatorHash = strings.ToLower(strings.TrimSpace(manifest.LocatorHash))
	digest := manifest.ManifestDigest
	if digest == "" {
		d, err := DigestWireManifest(manifest)
		if err != nil {
			return ReplicatePlan{}, err
		}
		digest = d
	}
	digest = strings.ToLower(digest)

	rf := opts.ReplicationFactor
	if rf <= 0 {
		rf = DefaultReplicationFactor
	}
	if rf > AbsoluteMaxReplicationFactor {
		return ReplicatePlan{}, apperr.New(apperr.CodeInvalidArgument, "rf2 replication factor exceeds max")
	}
	opts.ReplicationFactor = rf
	if opts.PreferDistinctDomains == false && rf >= 2 {
		// Default prefer distinct domains for RF2 when not explicitly disabled via zero-value:
		// PlacementOptions zero has PreferDistinctDomains false — enable for RF>=2 product default.
		opts.PreferDistinctDomains = true
	}

	owners, err := SelectPrimaryOwners(locatorHash, members, opts)
	if err != nil {
		return ReplicatePlan{}, err
	}
	if len(owners) < rf {
		return ReplicatePlan{
			LocatorHash: locatorHash, ManifestDigest: digest, ReplicationFactor: rf,
			RequiredOwners: owners, Residual: "insufficient_eligible_owners",
		}, apperr.New(apperr.CodeCapabilityMissing, "rf2 insufficient eligible owners")
	}
	// Cap to RF.
	if len(owners) > rf {
		owners = owners[:rf]
	}

	plan := ReplicatePlan{
		LocatorHash:       locatorHash,
		ManifestDigest:    digest,
		ReplicationFactor: rf,
		RequiredOwners:    append([]string(nil), owners...),
	}

	// Source: first required owner with matching committed digest.
	for _, id := range owners {
		obs, ok := replicas[id]
		if !ok {
			continue
		}
		if obs.Status == "committed" && strings.EqualFold(obs.Digest, digest) {
			plan.SourceMember = id
			break
		}
	}
	if plan.SourceMember == "" {
		plan.Residual = "source_missing"
		// Still plan targets; caller may use local frames as source.
	}

	allSeqs := make([]int, len(manifest.Frames))
	for i, f := range manifest.Frames {
		allSeqs[i] = f.Seq
	}

	for _, id := range owners {
		obs := replicas[id]
		t := ReplicateTarget{MemberID: id}
		switch {
		case obs.Status == "committed" && strings.EqualFold(obs.Digest, digest):
			t.Action = ReplicaActionSkipVerified
			t.Residual = "already_verified"
			t.MissingSeqs = nil
		case obs.Status == "quarantined":
			t.Action = ReplicaActionQuarantined
			t.MissingSeqs = append([]int(nil), allSeqs...)
			t.Residual = "replace_quarantined"
			plan.FramesToTransfer += len(allSeqs)
		case obs.Status == "staging" && len(obs.PresentSeqs) > 0:
			missing := MissingFrameSeqs(manifest, obs.PresentSeqs)
			if len(missing) == 0 {
				// Staging claims all frames but not committed — still need commit path (full verify import).
				t.Action = ReplicaActionFullImport
				t.MissingSeqs = append([]int(nil), allSeqs...)
				t.Residual = "staging_needs_commit"
				plan.FramesToTransfer += len(allSeqs)
			} else {
				t.Action = ReplicaActionMissingFrames
				t.MissingSeqs = missing
				t.Residual = "resume_missing_frames"
				plan.FramesToTransfer += len(missing)
			}
		default:
			t.Action = ReplicaActionFullImport
			t.MissingSeqs = append([]int(nil), allSeqs...)
			plan.FramesToTransfer += len(allSeqs)
		}
		plan.Targets = append(plan.Targets, t)
	}
	return plan, nil
}

// MissingFrameSeqs returns manifest sequences not present in have (resume helper).
// Order follows manifest frame order. Secret-free pure function.
func MissingFrameSeqs(manifest WireManifest, have []int) []int {
	set := make(map[int]struct{}, len(have))
	for _, s := range have {
		set[s] = struct{}{}
	}
	var missing []int
	for _, f := range manifest.Frames {
		if _, ok := set[f.Seq]; !ok {
			missing = append(missing, f.Seq)
		}
	}
	return missing
}

// FilterImportFrames returns only the requested sequences (pure zstd transfer subset).
func FilterImportFrames(frames []ImportFrameBytes, seqs []int) []ImportFrameBytes {
	if len(seqs) == 0 {
		return nil
	}
	want := make(map[int]struct{}, len(seqs))
	for _, s := range seqs {
		want[s] = struct{}{}
	}
	out := make([]ImportFrameBytes, 0, len(seqs))
	for _, f := range frames {
		if _, ok := want[f.Seq]; ok {
			out = append(out, f)
		}
	}
	return out
}
