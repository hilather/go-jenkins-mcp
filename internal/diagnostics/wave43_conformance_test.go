package diagnostics_test

import (
	"context"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/diagnostics"
)

// TestWave43_OperatorCapsAndAdapter_Hard asserts Wave 43 Done* self-check items.
func TestWave43_OperatorCapsAndAdapter_Hard(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rep, err := diagnostics.RunSecuritySelfCheck(ctx, diagnostics.SelfCheckOptions{SkipSupportBundleCanary: true})
	if err != nil {
		t.Fatal(err)
	}
	need := map[string]bool{
		"operator_caps_snapshot":            false,
		"adapter_framework_residual":        false,
		"adapter_allowlist_provenance_lite": false,
		"policy_multisig_lite_residual":     false,
	}
	for _, item := range rep.Items {
		if _, ok := need[item.Name]; ok {
			need[item.Name] = true
			if item.Status != diagnostics.SelfCheckOK && item.Status != diagnostics.SelfCheckInfo {
				// operator caps ok; adapter ok; multisig ok
				if item.Name != "http_require_token_residual" && item.Status == diagnostics.SelfCheckFail {
					t.Fatalf("%s status=%s msg=%s", item.Name, item.Status, item.Message)
				}
			}
			if item.Name == "operator_caps_snapshot" && item.Status != diagnostics.SelfCheckOK {
				t.Fatalf("operator_caps_snapshot status=%s", item.Status)
			}
			if item.Name == "adapter_framework_residual" && item.Status != diagnostics.SelfCheckOK {
				t.Fatalf("adapter_framework_residual status=%s %s", item.Status, item.Message)
			}
			if item.Name == "adapter_allowlist_provenance_lite" && item.Status != diagnostics.SelfCheckOK {
				t.Fatalf("adapter_allowlist_provenance_lite status=%s %s", item.Status, item.Message)
			}
		}
	}
	for k, v := range need {
		if !v {
			t.Fatalf("missing self-check item %s", k)
		}
	}
}
