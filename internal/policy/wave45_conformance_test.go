package policy_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

// Wave 45 / POL-005 policy-layer canaries (Track D):
//   - Hard: deny-only Document surfaces still present (Wave 35–44 list privacy source)
//   - Soft residual note: Wave 45 feature tracks A/B/C live in adapter/diagnostics/
//     tools/mcpserver/jenkins (no new policy Document symbols expected for Track D)

// TestWave45_DenyListSurfacesStillOnDocument hard-asserts Document still carries
// all deny list fields used by tools-layer fingerprints/filters and remains
// deny-only (no elevation fields).
func TestWave45_DenyListSurfacesStillOnDocument(t *testing.T) {
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

// TestWave45_SoftResidual_PolicyLayerNote records that Wave 45 residual tracks
// (allowlist MinSignatures dual-control, operator_caps HTTP body + identity
// reverify TTL, jenkins_resilience_residual) are adapter/diagnostics/tools/
// mcpserver/jenkins concerns — policy Document has no new symbols for them.
// Soft residual only; never fails for absence of those features.
func TestWave45_SoftResidual_PolicyLayerNote(t *testing.T) {
	t.Parallel()
	// Multi-sig lite env contract remains (Wave 42 Done* self-check uses MinSignatures).
	if policy.EnvPolicyMinSignatures == "" {
		t.Fatal("EnvPolicyMinSignatures must remain a public contract name")
	}
	t.Logf("Wave 45 soft residual (policy): EnvPolicyMinSignatures=%q present; "+
		"Track A adapter allowlist MinSignatures dual-control / Track B operator_caps "+
		"HTTP body + identity reverify TTL / Track C jenkins_resilience_residual are "+
		"adapter/diagnostics/tools/mcpserver/jenkins residuals "+
		"(Wave 44 operator_caps body-bytes + adapter_allowlist_provenance_lite + "+
		"ResolveHTTPMaxBodyBytes Done* in those packages)",
		policy.EnvPolicyMinSignatures)
}
