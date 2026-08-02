package policy_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

// Wave 50 / POL-005 policy-layer canaries (Track D):
//   - Hard: deny-only Document surfaces still present (Wave 35–49 list privacy source)
//   - Soft residual note: Wave 50 feature tracks A/B/C live in jenkins/tools/
//     diagnostics (MaxConcurrent resolve, absolute_max_concurrent + backoff ms,
//     origin pin residual) — no new policy Document symbols expected for Track D

// TestWave50_DenyListSurfacesStillOnDocument hard-asserts Document still carries
// all deny list fields used by tools-layer fingerprints/filters and remains
// deny-only (no elevation fields).
func TestWave50_DenyListSurfacesStillOnDocument(t *testing.T) {
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
		DenyNodeNames:     []string{"prod-agent-*"},
		DenyViewNames:     []string{"secret-view"},
		DenyJobPrefixes:   []string{"classified/"},
		DenyBranchNames:   []string{"release-*"},
	})
	if got := policy.DenyArtifactPathsFromEvaluator(ev); len(got) != 1 || got[0] != "secrets/**" {
		t.Fatalf("DenyArtifactPathsFromEvaluator: %v", got)
	}
	if got := policy.DenyNodeNamesFromEvaluator(ev); len(got) != 1 || got[0] != "prod-agent-*" {
		t.Fatalf("DenyNodeNamesFromEvaluator: %v", got)
	}
	if got := policy.DenyViewNamesFromEvaluator(ev); len(got) != 1 || got[0] != "secret-view" {
		t.Fatalf("DenyViewNamesFromEvaluator: %v", got)
	}
	if got := policy.DenyJobPrefixesFromEvaluator(ev); len(got) != 1 || got[0] != "classified/" {
		t.Fatalf("DenyJobPrefixesFromEvaluator: %v", got)
	}
	if got := policy.DenyBranchNamesFromEvaluator(ev); len(got) != 1 || got[0] != "release-*" {
		t.Fatalf("DenyBranchNamesFromEvaluator: %v", got)
	}
}

// TestWave50_SoftResidual_PolicyLayerNote records that Wave 50 residual tracks
// (ResolveMaxConcurrent, operator_caps absolute_max_concurrent + backoff ms,
// jenkins_origin_pin_residual) are jenkins/tools/diagnostics concerns — policy
// Document has no new symbols for them. Soft residual only; never fails for
// absence of those features.
func TestWave50_SoftResidual_PolicyLayerNote(t *testing.T) {
	t.Parallel()
	// Multi-sig lite env contract remains (Wave 42 Done* self-check uses MinSignatures).
	if policy.EnvPolicyMinSignatures == "" {
		t.Fatal("EnvPolicyMinSignatures must remain a public contract name")
	}
	t.Logf("Wave 50 soft residual (policy): EnvPolicyMinSignatures=%q present; "+
		"Track A ResolveMaxConcurrent + AbsoluteMax + serve flag / "+
		"Track B operator_caps absolute_max_concurrent + backoff ms keys / "+
		"Track C jenkins_origin_pin_residual self-check are "+
		"jenkins/tools/diagnostics residuals "+
		"(Wave 49 CircuitOpenDuration resolve + open-duration operator_caps + "+
		"ResolveMaintenanceInterval Done* in those packages)",
		policy.EnvPolicyMinSignatures)
}
