package fleetcache_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

func TestOrderEvictCandidates_FleetAware_IncompleteNearBeforeRequired(t *testing.T) {
	t.Parallel()
	cands := []fleetcache.EvictCandidate{
		{GenerationID: 1, CopyRole: fleetcache.CopyRoleRequired, Bytes: 100},
		{GenerationID: 2, CopyRole: fleetcache.CopyRoleNear, Bytes: 50},
		{GenerationID: 3, CopyRole: fleetcache.CopyRoleIncomplete, Bytes: 10},
		{GenerationID: 4, CopyRole: fleetcache.CopyRoleObsolete, Bytes: 20},
	}
	got := fleetcache.OrderEvictCandidates(cands, true)
	if len(got) != 4 {
		t.Fatalf("len=%d", len(got))
	}
	// incomplete < near < obsolete < required
	wantIDs := []int64{3, 2, 4, 1}
	for i, id := range wantIDs {
		if got[i].GenerationID != id {
			t.Fatalf("pos %d: gen=%d want %d (order=%v)", i, got[i].GenerationID, id, genIDs(got))
		}
	}
}

func TestOrderEvictCandidates_HardSafetyRequiredFirst(t *testing.T) {
	t.Parallel()
	// Hard disk threshold wins over fleet role preference: a required hard-safety
	// candidate is selected before non-hard incomplete/near under pressure.
	cands := []fleetcache.EvictCandidate{
		{GenerationID: 10, CopyRole: fleetcache.CopyRoleIncomplete, Bytes: 1},
		{GenerationID: 11, CopyRole: fleetcache.CopyRoleNear, Bytes: 1},
		{GenerationID: 12, CopyRole: fleetcache.CopyRoleRequired, Bytes: 99, IsHardSafety: true},
		{GenerationID: 13, CopyRole: fleetcache.CopyRoleRequired, Bytes: 50},
	}
	got := fleetcache.OrderEvictCandidates(cands, true)
	if got[0].GenerationID != 12 || !got[0].IsHardSafety {
		t.Fatalf("hard-safety required must be first: got gen=%d hard=%v order=%v",
			got[0].GenerationID, got[0].IsHardSafety, genIDs(got))
	}
	// Soft required remains last among non-pinned.
	if got[len(got)-1].GenerationID != 13 {
		t.Fatalf("soft required should be last: order=%v", genIDs(got))
	}
	// After hard required: incomplete then near (role order among soft).
	if got[1].GenerationID != 10 || got[2].GenerationID != 11 {
		t.Fatalf("soft role order after hard: order=%v", genIDs(got))
	}
}

func TestOrderEvictCandidates_PinnedNeverFirst(t *testing.T) {
	t.Parallel()
	cands := []fleetcache.EvictCandidate{
		{GenerationID: 1, CopyRole: fleetcache.CopyRoleIncomplete, Bytes: 1, Pinned: true, IsHardSafety: true},
		{GenerationID: 2, CopyRole: fleetcache.CopyRoleRequired, Bytes: 1},
		{GenerationID: 3, CopyRole: fleetcache.CopyRoleNear, Bytes: 1},
	}
	got := fleetcache.OrderEvictCandidates(cands, true)
	if got[0].Pinned {
		t.Fatalf("pinned must not be first: order=%v pinned=%v", genIDs(got), got[0].Pinned)
	}
	// Near before required; pinned last.
	if got[0].GenerationID != 3 || got[1].GenerationID != 2 || got[2].GenerationID != 1 {
		t.Fatalf("want near, required, pinned: order=%v", genIDs(got))
	}
	if r := fleetcache.PinSkipResidual(got[2].Pinned); r != fleetcache.ResidualPinSkip {
		t.Fatalf("pin residual %q", r)
	}
}

func TestOrderEvictCandidates_FleetAwareFalse_RoleIgnoredStable(t *testing.T) {
	t.Parallel()
	// Mode off: preserve input order even if roles would reverse under fleetAware.
	cands := []fleetcache.EvictCandidate{
		{GenerationID: 1, CopyRole: fleetcache.CopyRoleRequired, Bytes: 100},
		{GenerationID: 2, CopyRole: fleetcache.CopyRoleIncomplete, Bytes: 10},
		{GenerationID: 3, CopyRole: fleetcache.CopyRoleNear, Bytes: 50, IsHardSafety: true},
		{GenerationID: 4, CopyRole: fleetcache.CopyRoleObsolete, Bytes: 20, Pinned: true},
	}
	got := fleetcache.OrderEvictCandidates(cands, false)
	if len(got) != 4 {
		t.Fatalf("len=%d", len(got))
	}
	for i := range cands {
		if got[i].GenerationID != cands[i].GenerationID {
			t.Fatalf("mode-off must preserve input order: pos %d got %d want %d order=%v",
				i, got[i].GenerationID, cands[i].GenerationID, genIDs(got))
		}
	}
	// CopyRole must not affect order — prove required stayed first despite incomplete later.
	if got[0].CopyRole != fleetcache.CopyRoleRequired {
		t.Fatal("expected required first in input-stable order")
	}
}

func TestOrderEvictCandidates_EmptyAndStableTies(t *testing.T) {
	t.Parallel()
	if got := fleetcache.OrderEvictCandidates(nil, true); got != nil {
		t.Fatalf("nil input → nil, got %#v", got)
	}
	if got := fleetcache.OrderEvictCandidates([]fleetcache.EvictCandidate{}, true); got != nil {
		t.Fatalf("empty → nil, got %#v", got)
	}
	// Same role + same hard/pin: stable by input index.
	cands := []fleetcache.EvictCandidate{
		{GenerationID: 5, CopyRole: fleetcache.CopyRoleNear},
		{GenerationID: 6, CopyRole: fleetcache.CopyRoleNear},
		{GenerationID: 7, CopyRole: fleetcache.CopyRoleNear},
	}
	got := fleetcache.OrderEvictCandidates(cands, true)
	if genIDs(got) != "5,6,7" {
		t.Fatalf("stable ties: %s", genIDs(got))
	}
}

func TestShouldSkipL1Release_RequiredVsNear(t *testing.T) {
	t.Parallel()
	if !fleetcache.ShouldSkipL1Release(fleetcache.CopyRoleRequired, true) {
		t.Fatal("required + fleetAware must skip L1 release")
	}
	if fleetcache.ShouldSkipL1Release(fleetcache.CopyRoleNear, true) {
		t.Fatal("near must not skip L1 release")
	}
	if fleetcache.ShouldSkipL1Release(fleetcache.CopyRoleIncomplete, true) {
		t.Fatal("incomplete must not skip L1 release")
	}
	if fleetcache.ShouldSkipL1Release(fleetcache.CopyRoleObsolete, true) {
		t.Fatal("obsolete must not skip L1 release")
	}
	// Mode off: never skip based on role (non-fleet L1 release unchanged).
	if fleetcache.ShouldSkipL1Release(fleetcache.CopyRoleRequired, false) {
		t.Fatal("mode off must not skip L1 for required")
	}
	if !fleetcache.ShouldSkipL1Release("REQUIRED", true) {
		t.Fatal("case-insensitive required")
	}
}

func TestOwnerRemovalResidual_UnderReplicated(t *testing.T) {
	t.Parallel()
	r := fleetcache.OwnerRemovalResidual(true)
	if r != fleetcache.ResidualUnderReplicatedEnqueueRepair {
		t.Fatalf("got %q", r)
	}
	if r != "under_replicated_enqueue_repair" {
		t.Fatalf("stable residual string %q", r)
	}
	if fleetcache.OwnerRemovalResidual(false) != "" {
		t.Fatal("non-required removal has empty residual")
	}
	// Owner removal residual must force repair signal — not "healthy".
	if strings.Contains(r, "healthy") {
		t.Fatalf("must not claim healthy: %q", r)
	}
}

func TestQuotaRole_SecretFreeResiduals(t *testing.T) {
	t.Parallel()
	poison := []string{
		"token=abc", "Bearer xyz", "password=secret",
		"Authorization: Bearer", "api_key=k",
	}
	check := func(s string) {
		t.Helper()
		canarySecretFree(t, s)
		for _, p := range poison {
			if strings.Contains(s, p) {
				t.Fatalf("residual contains poison %q: %q", p, s)
			}
		}
	}
	check(fleetcache.ResidualPinSkip)
	check(fleetcache.ResidualUnderReplicatedEnqueueRepair)
	check(fleetcache.OwnerRemovalResidual(true))
	check(fleetcache.PinSkipResidual(true))
	check(fleetcache.CopyRoleRequired)
	check(fleetcache.CopyRoleNear)
	check(fleetcache.CopyRoleIncomplete)
	check(fleetcache.CopyRoleObsolete)
	check(fleetcache.CopyRoleUnknown)
	// Order output fields never inject secrets (generation ids / roles only).
	got := fleetcache.OrderEvictCandidates([]fleetcache.EvictCandidate{
		{GenerationID: 1, LocatorHash: strings.Repeat("ab", 32), CopyRole: fleetcache.CopyRoleRequired, Pinned: true},
		{GenerationID: 2, CopyRole: fleetcache.CopyRoleNear, IsHardSafety: true},
	}, true)
	for _, c := range got {
		check(c.CopyRole)
		check(c.LocatorHash)
		check(fleetcache.PinSkipResidual(c.Pinned))
		if c.CopyRole == fleetcache.CopyRoleRequired {
			check(fleetcache.OwnerRemovalResidual(true))
		}
	}
}

func TestInferCopyRoleFromMappingStatus(t *testing.T) {
	t.Parallel()
	cases := []struct {
		status string
		want   string
	}{
		{"committed", fleetcache.CopyRoleUnknown},
		{"staging", fleetcache.CopyRoleIncomplete},
		{"quarantined", fleetcache.CopyRoleIncomplete},
		{"aborted", fleetcache.CopyRoleObsolete},
		{"near", fleetcache.CopyRoleNear},
		{"required", fleetcache.CopyRoleRequired},
		{"", fleetcache.CopyRoleUnknown},
		{"STAGING", fleetcache.CopyRoleIncomplete},
	}
	for _, tc := range cases {
		if got := fleetcache.InferCopyRoleFromMappingStatus(tc.status); got != tc.want {
			t.Fatalf("status %q: got %q want %q", tc.status, got, tc.want)
		}
	}
}

func TestNormalizeCopyRole(t *testing.T) {
	t.Parallel()
	if fleetcache.NormalizeCopyRole("  Required ") != fleetcache.CopyRoleRequired {
		t.Fatal("normalize required")
	}
	if fleetcache.NormalizeCopyRole("garbage") != fleetcache.CopyRoleUnknown {
		t.Fatal("garbage → unknown")
	}
}

func genIDs(cands []fleetcache.EvictCandidate) string {
	parts := make([]string, len(cands))
	for i, c := range cands {
		parts[i] = fmt.Sprintf("%d", c.GenerationID)
	}
	return strings.Join(parts, ",")
}
