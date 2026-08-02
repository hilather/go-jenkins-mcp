package policy_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

// Wave 43 / POL-005 policy-layer canaries:
//   - Hard: deny-only Document surfaces still present (Wave 35–42 list privacy source)
//   - Soft residual note: Wave 43 feature tracks live in tools/diagnostics (no new policy symbols)

// TestWave43_DenyListSurfacesStillOnDocument hard-asserts Document still carries
// all deny list fields used by tools-layer fingerprints/filters (Wave 42 Done*
// artifacts hard-cap / nodes-views collect still read these via Deny*FromEvaluator).
func TestWave43_DenyListSurfacesStillOnDocument(t *testing.T) {
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
}

// TestWave43_SoftResidual_PolicyLayerNote records that Wave 43 residual tracks
// (artifact body-bytes resolve, operator_caps_snapshot, adapter_framework_residual)
// are tools/cmd/diagnostics concerns — policy Document has no new symbols for them.
// Soft residual only; never fails for absence of those features.
func TestWave43_SoftResidual_PolicyLayerNote(t *testing.T) {
	t.Parallel()
	// Multi-sig lite env contract remains (Wave 42 Done* self-check uses MinSignatures).
	if policy.EnvPolicyMinSignatures == "" {
		t.Fatal("EnvPolicyMinSignatures must remain a public contract name")
	}
	t.Logf("Wave 43 soft residual (policy): EnvPolicyMinSignatures=%q present; "+
		"body-bytes / operator_caps_snapshot / adapter_framework_residual are tools/diagnostics residuals",
		policy.EnvPolicyMinSignatures)
}
