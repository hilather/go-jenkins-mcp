package policy_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

// Wave 42 / POL-005 policy-layer canaries:
//   - Hard: deny-only Document surfaces still present (Wave 35–41 list privacy source)
//   - Soft residual note: Wave 42 feature tracks live in tools/diagnostics (no new policy symbols)

// TestWave42_DenyListSurfacesStillOnDocument hard-asserts Document still carries
// all deny list fields used by tools-layer fingerprints/filters (Wave 41 Done*
// cache path + list_jobs collect still read these via Deny*FromEvaluator).
func TestWave42_DenyListSurfacesStillOnDocument(t *testing.T) {
	t.Parallel()

	pt := reflect.TypeOf(policy.Document{})
	for _, name := range []string{
		"DenyJobPrefixes",
		"DenyBranchNames",
		"DenyArtifactPaths",
		"DenyNodeNames",
		"DenyViewNames",
	} {
		if _, ok := pt.FieldByName(name); !ok {
			t.Fatalf("Document.%s missing (list privacy / fingerprint source)", name)
		}
	}

	// Deny-only: no elevation fields.
	for i := 0; i < pt.NumField(); i++ {
		name := pt.Field(i).Name
		lower := strings.ToLower(name)
		if strings.Contains(lower, "allow_tool") ||
			strings.Contains(lower, "grant") ||
			strings.HasPrefix(lower, "allowjob") {
			t.Fatalf("Document must not grow elevation fields: %s", name)
		}
	}

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:              policy.ModePilot,
		DenyArtifactPaths: []string{"secrets/**"},
		DenyJobPrefixes:   []string{"secret-folder"},
	})
	if got := policy.DenyArtifactPathsFromEvaluator(ev); len(got) != 1 || got[0] != "secrets/**" {
		t.Fatalf("DenyArtifactPathsFromEvaluator: %v", got)
	}
	if got := policy.DenyJobPrefixesFromEvaluator(ev); len(got) != 1 || got[0] != "secret-folder" {
		t.Fatalf("DenyJobPrefixesFromEvaluator: %v", got)
	}
}

// TestWave42_SoftResidual_PolicyLayerNote records that Wave 42 residual tracks
// (artifacts hard-cap resolve, nodes/views collect max pages, multi-sig self-check)
// are tools/cmd/diagnostics concerns — policy Document has no new symbols for them.
// Soft residual only; never fails for absence.
func TestWave42_SoftResidual_PolicyLayerNote(t *testing.T) {
	t.Parallel()
	// Multi-sig lite already exists (MinSignatures on verifier); full t-of-n residual.
	if policy.EnvPolicyMinSignatures == "" {
		t.Fatal("EnvPolicyMinSignatures must remain a public contract name")
	}
	t.Logf("Wave 42 soft residual (policy): EnvPolicyMinSignatures=%q present; dedicated self-check canary is diagnostics residual",
		policy.EnvPolicyMinSignatures)
}
