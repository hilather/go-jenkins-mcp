package diagnostics_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/diagnostics"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

const residualCanary = "residual-status-canary-token-NEVER"

// BuildGatewayResidualStatus is secret-free and always advertises Mode B residual id.
func TestBuildGatewayResidualStatus_SecretFreeAndModeBId(t *testing.T) {
	t.Setenv("HOST_RESIDUAL_CANARY", residualCanary)
	t.Setenv(gateway.EnvGatewayCredentialMode, string(gateway.CredentialModeJWTRSBearer))
	t.Setenv("JENKINS_MCP_GATEWAY_MULTI_USER", "1")
	t.Setenv("KUBERNETES_SERVICE_HOST", "")

	out := diagnostics.BuildGatewayResidualStatus(nil)
	blob, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	s := string(blob)
	for _, bad := range []string{residualCanary, "access_token=", "refresh_token=", "client_secret=", "Bearer " + residualCanary} {
		if strings.Contains(s, bad) {
			t.Fatalf("forbidden %q in residual-status", bad)
		}
	}
	if out["residual_id"] != "oauth009_offline" {
		t.Fatalf("residual_id=%v", out["residual_id"])
	}
	if out["oauth009_offline"] != true {
		t.Fatalf("oauth009_offline=%v", out["oauth009_offline"])
	}
	if out["mode_b_enabled"] != true {
		t.Fatalf("mode_b_enabled=%v", out["mode_b_enabled"])
	}
	if out["ha_multi_replica"] != false {
		t.Fatal("ha_multi_replica must be false")
	}
	if out["multi_user_enabled"] != true {
		t.Fatalf("multi_user_enabled=%v", out["multi_user_enabled"])
	}
	if out["multi_pod_vault_residual"] != true {
		t.Fatal("multi_pod_vault_residual always true")
	}
	if out["shared_principal_cache_file"] != false {
		t.Fatalf("shared_principal_cache_file default false: %+v", out["shared_principal_cache_file"])
	}
	if _, ok := out["principal_cache_entries"].(int); !ok {
		// Len() returns int
		if _, ok2 := out["principal_cache_entries"].(int64); !ok2 {
			// accept any numeric representation
			switch out["principal_cache_entries"].(type) {
			case int, int32, int64, float64:
			default:
				t.Fatalf("principal_cache_entries: %T %v", out["principal_cache_entries"], out["principal_cache_entries"])
			}
		}
	}
	note, _ := out["residual_note"].(string)
	doc, _ := out["doc"].(string)
	if !strings.Contains(note, "live-pin-blockers") && !strings.Contains(doc, "live-pin-blockers") {
		t.Fatalf("want live-pin-blockers pointer: note=%q doc=%q", note, doc)
	}
	if strings.Contains(strings.ToLower(s), "production go complete") {
		t.Fatal("must not claim production GO complete")
	}
}

func TestBuildGatewayResidualStatus_MultiPodFromK8s(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
	out := diagnostics.BuildGatewayResidualStatus(nil)
	if out["kubernetes_env_detected"] != true {
		t.Fatalf("kubernetes_env_detected: %v", out["kubernetes_env_detected"])
	}
	cl, _ := out["multi_pod_residual_checklist"].(string)
	if cl == "" || !strings.Contains(strings.ToLower(cl), "multi-pod") {
		t.Fatalf("want multi_pod_residual_checklist: %q", cl)
	}
	blob, _ := json.Marshal(out)
	if strings.Contains(string(blob), "10.96.0.1") {
		t.Fatal("must not embed KUBERNETES_SERVICE_HOST value")
	}
}

func TestBuildGatewayResidualStatus_ModeCConsentNote(t *testing.T) {
	t.Setenv(gateway.EnvGatewayCredentialMode, string(gateway.CredentialModeAgentCore))
	t.Setenv(gateway.EnvGatewayEnabledModes, "")
	out := diagnostics.BuildGatewayResidualStatus(nil)
	if out["mode_c_enabled"] != true {
		t.Fatalf("mode_c_enabled=%v", out["mode_c_enabled"])
	}
	if _, ok := out["progressive_consent_residual"].(string); !ok {
		t.Fatalf("want progressive_consent_residual when Mode C: %+v", out["progressive_consent_residual"])
	}
	pc, ok := out["progressive_consent"].(map[string]any)
	if !ok {
		t.Fatalf("progressive_consent: %+v", out["progressive_consent"])
	}
	if pc["browser_3lo_automated"] != false {
		t.Fatalf("browser_3lo_automated: %+v", pc)
	}
}
