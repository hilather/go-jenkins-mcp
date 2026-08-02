package fleetcache

import (
	"context"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Repair action kinds for PlanRepair / RunRepair (FLC-044; secret-free).
const (
	RepairActionReplicateTo      = "replicate_to"
	RepairActionSkipHealthy      = "skip_healthy"
	RepairActionDrainHandoff     = "drain_handoff"
	RepairActionRefuseNewPrimary = "refuse_new_primary"
	RepairActionGraceSource      = "grace_source"
)

// Default repair budget bounds (lazy RF restore; no storm).
const (
	DefaultMaxConcurrentCopies = 1
	DefaultMaxObjectsPerRun    = 1
)

// RepairOptions controls a single-object lazy repair wave (pure planning).
//
// PreviousOwnerGrace, when true, allows previous owners (committed matching digest
// outside the desired RF set) to export pure-zstd frames for repair only — they
// do not count toward RF health.
//
// DrainMemberIDs members must not be selected as new primary destinations
// (refuse_new_primary residual when they would have been unconstrained owners).
type RepairOptions struct {
	MaxConcurrentCopies int
	// MaxObjectsPerRun is reserved for multi-object scanners; PlanRepair is one locator.
	MaxObjectsPerRun int
	// PreviousOwnerGrace enables grace_source exporters outside the desired RF set.
	PreviousOwnerGrace bool
	// DrainMemberIDs is the set of members in drain (no new primary ownership).
	DrainMemberIDs map[string]struct{}
	// Placement selects RF owners (defaults RF2 + prefer distinct domains).
	Placement PlacementOptions
	// MembershipEpoch is observation-only (secret-free residual / audit).
	MembershipEpoch int64
}

// RepairTarget is one planned action for repair/drain (secret-free).
type RepairTarget struct {
	MemberID string
	Action   string
	// MissingSeqs is set for transfer actions (full set or resume subset).
	MissingSeqs []int
	// Residual is secret-free (e.g. already_verified, budget_deferred, refuse_new_primary).
	Residual string
}

// RepairPlan is a pure, bounded RF repair/drain plan for one locator.
// Near-cache members never appear as required owners (placement only).
type RepairPlan struct {
	LocatorHash       string
	ManifestDigest    string
	MembershipEpoch   int64
	ReplicationFactor int
	RequiredOwners    []string
	// SourceMember is the preferred pure-zstd exporter for this wave.
	SourceMember string
	// GraceSources are previous owners allowed to export during grace (not RF).
	GraceSources []string
	// Targets includes this wave's decisions: skip, budgeted transfer, refuse, grace.
	Targets []RepairTarget
	// TransferCount is the number of copy actions this wave (≤ MaxConcurrentCopies).
	TransferCount int
	// FramesToTransfer sums missing frames across budgeted transfer targets.
	FramesToTransfer int
	// DeferredOwners are under-replicated required owners deferred by copy budget.
	DeferredOwners []string
	// Residual aggregate secret-free note (e.g. source_missing, rf_healthy).
	Residual string
}

// RepairRunResult is the secret-free outcome of RunRepair.
type RepairRunResult struct {
	LocatorHash       string
	ManifestDigest    string
	Results           map[string]ReplicateResult
	FramesTransferred int
	CopiesRun         int
	// HealthyRF is true when all RequiredOwners are committed with matching digest
	// after this run (from sink GetCommitted when available, else from plan skips).
	HealthyRF bool
	Residual  string
}

// DrainAllowsPrimary reports whether memberID may become a new primary owner.
// Drain set nil/empty allows all; empty memberID is never allowed.
func DrainAllowsPrimary(memberID string, drainSet map[string]struct{}) bool {
	id := strings.TrimSpace(memberID)
	if id == "" {
		return false
	}
	if len(drainSet) == 0 {
		return true
	}
	_, draining := drainSet[id]
	return !draining
}

// PlanRepair builds a bounded lazy-repair plan for one sealed object.
//
// Desired owners = SelectPrimaryOwners with RF (default 2), excluding DrainMemberIDs
// and PlacementMember.Draining. Under-replicated required owners get transfer actions
// capped by MaxConcurrentCopies. Previous owners with matching committed digest may
// be grace sources when PreviousOwnerGrace is set. No Jenkins origin fetch is planned —
// pure peer zstd path only (caller supplies frames from SourceMember / local).
// Near-cache members must not appear as committed RF owners — FilterRFObservations
// first (FLC-033); near never counts toward RF health.
func PlanRepair(
	locatorHash string,
	members []PlacementMember,
	manifest WireManifest,
	replicas map[string]ReplicaObservation,
	opts RepairOptions,
) (RepairPlan, error) {
	locatorHash = strings.ToLower(strings.TrimSpace(locatorHash))
	if err := ValidateWireManifest(manifest); err != nil {
		return RepairPlan{}, err
	}
	if !strings.EqualFold(manifest.LocatorHash, locatorHash) && locatorHash != "" {
		return RepairPlan{}, apperr.New(apperr.CodeInvalidArgument, "repair locator mismatch")
	}
	locatorHash = strings.ToLower(strings.TrimSpace(manifest.LocatorHash))
	digest := manifest.ManifestDigest
	if digest == "" {
		d, err := DigestWireManifest(manifest)
		if err != nil {
			return RepairPlan{}, err
		}
		digest = d
	}
	digest = strings.ToLower(digest)

	// FLC-051: do not plan repair that would resurrect a tombstoned locator+digest.
	if blocked, res := purgeImportTombstoneCheck(locatorHash, digest); blocked {
		return RepairPlan{
			LocatorHash: locatorHash, ManifestDigest: digest,
			MembershipEpoch: opts.MembershipEpoch, Residual: res,
		}, apperr.New(apperr.CodePolicyDenial, "tombstoned fleet object")
	}

	maxCopy := opts.MaxConcurrentCopies
	if maxCopy <= 0 {
		maxCopy = DefaultMaxConcurrentCopies
	}
	// MaxObjectsPerRun reserved (single-object plan always 1).
	_ = opts.MaxObjectsPerRun

	place := opts.Placement
	rf := place.ReplicationFactor
	if rf <= 0 {
		rf = DefaultReplicationFactor
	}
	if rf > AbsoluteMaxReplicationFactor {
		return RepairPlan{}, apperr.New(apperr.CodeInvalidArgument, "repair replication factor exceeds max")
	}
	place.ReplicationFactor = rf
	if !place.PreferDistinctDomains && rf >= 2 {
		place.PreferDistinctDomains = true
	}

	drainSet := opts.DrainMemberIDs
	// Effective membership: force Draining for DrainMemberIDs (no new primary).
	effective := applyDrainToMembers(members, drainSet)

	owners, err := SelectPrimaryOwners(locatorHash, effective, place)
	if err != nil {
		return RepairPlan{}, err
	}
	if len(owners) < rf {
		return RepairPlan{
			LocatorHash: locatorHash, ManifestDigest: digest, MembershipEpoch: opts.MembershipEpoch,
			ReplicationFactor: rf, RequiredOwners: owners, Residual: "insufficient_eligible_owners",
		}, apperr.New(apperr.CodeCapabilityMissing, "repair insufficient eligible owners")
	}
	if len(owners) > rf {
		owners = owners[:rf]
	}

	plan := RepairPlan{
		LocatorHash:       locatorHash,
		ManifestDigest:    digest,
		MembershipEpoch:   opts.MembershipEpoch,
		ReplicationFactor: rf,
		RequiredOwners:    append([]string(nil), owners...),
	}

	// refuse_new_primary: drain-set members that would have been unconstrained RF owners.
	unconstrained, uerr := SelectPrimaryOwners(locatorHash, membersWithoutDrainSet(members, drainSet), place)
	if uerr == nil {
		for _, id := range unconstrained {
			if !DrainAllowsPrimary(id, drainSet) {
				plan.Targets = append(plan.Targets, RepairTarget{
					MemberID: id,
					Action:   RepairActionRefuseNewPrimary,
					Residual: "refuse_new_primary",
				})
			}
		}
	}

	allSeqs := make([]int, len(manifest.Frames))
	for i, f := range manifest.Frames {
		allSeqs[i] = f.Seq
	}

	requiredSet := make(map[string]struct{}, len(owners))
	for _, id := range owners {
		requiredSet[id] = struct{}{}
	}

	// Classify grace sources: committed matching digest, outside required set.
	if opts.PreviousOwnerGrace && replicas != nil {
		for id, obs := range replicas {
			if _, req := requiredSet[id]; req {
				continue
			}
			if obs.Status == "committed" && strings.EqualFold(obs.Digest, digest) {
				plan.GraceSources = append(plan.GraceSources, id)
				plan.Targets = append(plan.Targets, RepairTarget{
					MemberID: id,
					Action:   RepairActionGraceSource,
					Residual: "previous_owner_grace",
				})
			}
		}
	}

	// Source: preferred pure-zstd exporter (required committed → grace → any committed).
	plan.SourceMember = pickRepairSource(owners, plan.GraceSources, replicas, digest, drainSet)

	// Per required owner: healthy skip vs needs transfer.
	type needCopy struct {
		t RepairTarget
	}
	var needs []needCopy
	healthy := 0
	for _, id := range owners {
		obs := ReplicaObservation{}
		if replicas != nil {
			obs = replicas[id]
		}
		t := RepairTarget{MemberID: id}
		switch {
		case obs.Status == "committed" && strings.EqualFold(obs.Digest, digest):
			t.Action = RepairActionSkipHealthy
			t.Residual = "already_verified"
			healthy++
			plan.Targets = append(plan.Targets, t)
		case obs.Status == "quarantined":
			t.Action = repairTransferAction(id, plan.SourceMember, drainSet)
			t.MissingSeqs = append([]int(nil), allSeqs...)
			t.Residual = "replace_quarantined"
			needs = append(needs, needCopy{t: t})
		case obs.Status == "staging" && len(obs.PresentSeqs) > 0:
			missing := MissingFrameSeqs(manifest, obs.PresentSeqs)
			if len(missing) == 0 {
				t.Action = repairTransferAction(id, plan.SourceMember, drainSet)
				t.MissingSeqs = append([]int(nil), allSeqs...)
				t.Residual = "staging_needs_commit"
				needs = append(needs, needCopy{t: t})
			} else {
				t.Action = repairTransferAction(id, plan.SourceMember, drainSet)
				t.MissingSeqs = missing
				t.Residual = "resume_missing_frames"
				needs = append(needs, needCopy{t: t})
			}
		default:
			t.Action = repairTransferAction(id, plan.SourceMember, drainSet)
			t.MissingSeqs = append([]int(nil), allSeqs...)
			if t.Action == RepairActionDrainHandoff {
				t.Residual = "drain_handoff"
			}
			needs = append(needs, needCopy{t: t})
		}
	}

	if plan.SourceMember == "" && len(needs) > 0 {
		plan.Residual = "source_missing"
		// Still plan transfers; caller may supply local frames as source.
	}

	// Bound simultaneous copies.
	for _, n := range needs {
		if plan.TransferCount >= maxCopy {
			plan.DeferredOwners = append(plan.DeferredOwners, n.t.MemberID)
			// Observation residual only — not executed this wave.
			deferred := n.t
			deferred.Residual = "budget_deferred"
			// Keep action kind for honesty but RunRepair ignores budget_deferred.
			plan.Targets = append(plan.Targets, deferred)
			continue
		}
		plan.Targets = append(plan.Targets, n.t)
		plan.TransferCount++
		plan.FramesToTransfer += len(n.t.MissingSeqs)
	}

	if len(needs) == 0 && healthy >= rf {
		if plan.Residual == "" {
			plan.Residual = "rf_healthy"
		}
	} else if len(plan.DeferredOwners) > 0 && plan.Residual == "" {
		plan.Residual = "budget_capped"
	}

	return plan, nil
}

// RunRepair applies a RepairPlan's budgeted transfer targets via pure-zstd import.
// Skip/refuse/grace/deferred targets do not transfer. Idempotent when required owners
// already commit matching digest (FramesTransferred total 0).
//
// sinks maps member ID → ImportSink. Source frames are supplied by the caller (peer export
// or local); no Jenkins origin path.
func RunRepair(
	ctx context.Context,
	plan RepairPlan,
	manifest WireManifest,
	frames []ImportFrameBytes,
	sinks map[string]ImportSink,
) (RepairRunResult, error) {
	out := RepairRunResult{
		LocatorHash:    plan.LocatorHash,
		ManifestDigest: plan.ManifestDigest,
		Results:        make(map[string]ReplicateResult),
	}
	if plan.LocatorHash == "" {
		return out, apperr.New(apperr.CodeInvalidArgument, "repair plan empty")
	}
	if err := ValidateWireManifest(manifest); err != nil {
		out.Residual = "invalid manifest"
		return out, err
	}

	for _, t := range plan.Targets {
		if err := ctx.Err(); err != nil {
			out.Residual = "cancelled"
			return out, err
		}
		switch t.Action {
		case RepairActionSkipHealthy:
			out.Results[t.MemberID] = ReplicateResult{
				Status: "skipped", LocatorHash: plan.LocatorHash,
				ManifestDigest: plan.ManifestDigest, FramesTransferred: 0,
				Residual: t.Residual,
			}
			continue
		case RepairActionRefuseNewPrimary, RepairActionGraceSource:
			out.Results[t.MemberID] = ReplicateResult{
				Status: "skipped", LocatorHash: plan.LocatorHash,
				ManifestDigest: plan.ManifestDigest, FramesTransferred: 0,
				Residual: t.Residual,
			}
			continue
		case RepairActionReplicateTo, RepairActionDrainHandoff:
			if t.Residual == "budget_deferred" {
				out.Results[t.MemberID] = ReplicateResult{
					Status: "skipped", LocatorHash: plan.LocatorHash,
					ManifestDigest: plan.ManifestDigest, FramesTransferred: 0,
					Residual: "budget_deferred",
				}
				continue
			}
		default:
			out.Results[t.MemberID] = ReplicateResult{
				Status: "skipped", Residual: "unknown_action",
				LocatorHash: plan.LocatorHash, ManifestDigest: plan.ManifestDigest,
			}
			continue
		}

		sink := sinks[t.MemberID]
		if sink == nil {
			out.Results[t.MemberID] = ReplicateResult{
				Status: ImportStatusRejected, Residual: "sink_missing",
				LocatorHash: plan.LocatorHash, ManifestDigest: plan.ManifestDigest,
			}
			continue
		}
		transfer := frames
		if len(t.MissingSeqs) > 0 && t.Residual == "resume_missing_frames" {
			transfer = FilterImportFrames(frames, t.MissingSeqs)
		} else if len(t.MissingSeqs) > 0 && len(t.MissingSeqs) < len(manifest.Frames) {
			transfer = FilterImportFrames(frames, t.MissingSeqs)
		}
		res, err := ReplicateSealed(ctx, sink, manifest, transfer)
		out.Results[t.MemberID] = res
		out.CopiesRun++
		out.FramesTransferred += res.FramesTransferred
		if err != nil && res.Status != ImportStatusIdempotent {
			// Continue other budgeted targets; caller aggregates.
			continue
		}
	}

	// HealthyRF: every required owner committed matching digest (sink or skip).
	out.HealthyRF = repairRFHealthy(ctx, plan, sinks)
	if out.HealthyRF && out.FramesTransferred == 0 && out.CopiesRun == 0 {
		out.Residual = "rf_healthy_noop"
	} else if out.HealthyRF {
		out.Residual = "rf_restored"
	} else if len(plan.DeferredOwners) > 0 {
		out.Residual = "budget_capped"
	}
	return out, nil
}

func applyDrainToMembers(members []PlacementMember, drainSet map[string]struct{}) []PlacementMember {
	if len(members) == 0 {
		return nil
	}
	out := make([]PlacementMember, len(members))
	copy(out, members)
	for i := range out {
		if !DrainAllowsPrimary(out[i].ID, drainSet) {
			out[i].Draining = true
		}
	}
	return out
}

// membersWithoutDrainSet returns a copy where only PlacementMember.Draining is
// respected — DrainMemberIDs is not applied — so refuse_new_primary can be detected.
func membersWithoutDrainSet(members []PlacementMember, drainSet map[string]struct{}) []PlacementMember {
	if len(drainSet) == 0 {
		return members
	}
	// Clear Draining only for members that are draining solely due to DrainMemberIDs
	// is not expressible if callers also set Draining on the member. Treat member.Draining
	// as sticky; only un-force IDs that appear in drainSet for unconstrained comparison
	// by cloning with Draining=false for drain-set-only members that were not already draining.
	out := make([]PlacementMember, len(members))
	copy(out, members)
	// Unconstrained view: ignore DrainMemberIDs; keep explicit PlacementMember.Draining.
	// (DrainMemberIDs is the ops drain set applied in applyDrainToMembers.)
	return out
}

func repairTransferAction(targetID, sourceMember string, drainSet map[string]struct{}) string {
	// Drain handoff when source is a draining member exporting toward a non-drain target.
	if sourceMember != "" && !DrainAllowsPrimary(sourceMember, drainSet) && DrainAllowsPrimary(targetID, drainSet) {
		return RepairActionDrainHandoff
	}
	return RepairActionReplicateTo
}

func pickRepairSource(
	required []string,
	grace []string,
	replicas map[string]ReplicaObservation,
	digest string,
	drainSet map[string]struct{},
) string {
	if replicas == nil {
		return ""
	}
	for _, id := range required {
		obs, ok := replicas[id]
		if !ok {
			continue
		}
		if obs.Status == "committed" && strings.EqualFold(obs.Digest, digest) {
			return id
		}
	}
	for _, id := range grace {
		obs, ok := replicas[id]
		if !ok {
			continue
		}
		if obs.Status == "committed" && strings.EqualFold(obs.Digest, digest) {
			return id
		}
	}
	// Any committed matching digest (including draining previous owners for handoff).
	// Prefer draining sources only after required/grace so RF owners win when healthy.
	var drainSrc string
	for id, obs := range replicas {
		if obs.Status != "committed" || !strings.EqualFold(obs.Digest, digest) {
			continue
		}
		if !DrainAllowsPrimary(id, drainSet) {
			if drainSrc == "" {
				drainSrc = id
			}
			continue
		}
		return id
	}
	return drainSrc
}

func repairRFHealthy(ctx context.Context, plan RepairPlan, sinks map[string]ImportSink) bool {
	if len(plan.RequiredOwners) == 0 {
		return false
	}
	digest := strings.ToLower(plan.ManifestDigest)
	for _, id := range plan.RequiredOwners {
		// Prefer live sink state after transfers.
		if sink := sinks[id]; sink != nil {
			cm, ok, err := sink.GetCommitted(ctx, plan.LocatorHash)
			if err != nil || !ok || !strings.EqualFold(cm.ManifestDigest, digest) {
				return false
			}
			continue
		}
		// No sink: trust plan skip only.
		foundSkip := false
		for _, t := range plan.Targets {
			if t.MemberID == id && t.Action == RepairActionSkipHealthy {
				foundSkip = true
				break
			}
		}
		if !foundSkip {
			return false
		}
	}
	return true
}
