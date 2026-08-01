package diagnostics_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/auth"
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
	// principal_cache_process_note: this-process honesty (CLI/admin ≠ remote serve).
	pcNote, _ := out["principal_cache_process_note"].(string)
	if pcNote == "" {
		t.Fatal("principal_cache_process_note must be present")
	}
	if pcNote != diagnostics.PrincipalCacheProcessNote {
		t.Fatalf("principal_cache_process_note: %q", pcNote)
	}
	if !strings.Contains(strings.ToLower(pcNote), "this process") {
		t.Fatalf("principal_cache_process_note must state process-local count: %q", pcNote)
	}
	// shared_subject_rate_file default false when path unset.
	if out["shared_subject_rate_file"] != false {
		t.Fatalf("shared_subject_rate_file default false: %+v", out["shared_subject_rate_file"])
	}
	// shared_jwks_file default false when JWKS cache path unset (HOST-001/HOST-008 lite).
	if out["shared_jwks_file"] != false {
		t.Fatalf("shared_jwks_file default false: %+v", out["shared_jwks_file"])
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

// shared_subject_rate_file=true when SUBJECT_RATE_PATH set; path never dumped.
func TestBuildGatewayResidualStatus_SharedSubjectRateFile(t *testing.T) {
	marker := "subject-rate-path-canary-NEVER-IN-JSON"
	path := t.TempDir() + "/" + marker + ".dat"
	t.Setenv(gateway.EnvGatewaySubjectRatePath, path)

	out := diagnostics.BuildGatewayResidualStatus(nil)
	if out["shared_subject_rate_file"] != true {
		t.Fatalf("shared_subject_rate_file want true when path set: %+v", out["shared_subject_rate_file"])
	}
	blob, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	s := string(blob)
	if strings.Contains(s, marker) || strings.Contains(s, path) {
		t.Fatal("Regression: SUBJECT_RATE_PATH leaked into residual-status JSON")
	}
	for _, bad := range []string{residualCanary, "access_token=", "refresh_token=", "client_secret="} {
		if strings.Contains(s, bad) {
			t.Fatalf("forbidden %q in residual-status with rate path", bad)
		}
	}
	// Process note still present alongside rate residual.
	if _, ok := out["principal_cache_process_note"].(string); !ok {
		t.Fatal("principal_cache_process_note required")
	}
}

// shared_principal_cache_file=true when PRINCIPAL_CACHE_PATH set; path never dumped.
// When file has entries, principal_cache_entries is secret-free Len only.
func TestBuildGatewayResidualStatus_SharedPrincipalCacheFile(t *testing.T) {
	marker := "principal-cache-path-canary-NEVER-IN-JSON"
	path := t.TempDir() + "/" + marker + ".json"
	// Seed secret-free file entries so residual Len is exercised (not only empty open).
	seedSK := "t1|residual-seed-sub|corp"
	seedJP := "residual-seed-jenkins-principal-CANARY"
	fpc, err := gateway.NewFilePrincipalCache(path)
	if err != nil {
		t.Fatal(err)
	}
	fpc.Set(seedSK, seedJP)
	fpc.Set(gateway.SubjectKeyParts("t1", "residual-seed-sub-2", "corp"), "seed-jp-2")
	if fpc.Len() != 2 {
		t.Fatalf("seed Len=%d want 2", fpc.Len())
	}

	t.Setenv(gateway.EnvGatewayPrincipalCachePath, path)
	t.Setenv("HOST_RESIDUAL_CANARY", residualCanary)

	out := diagnostics.BuildGatewayResidualStatus(nil)
	if out["shared_principal_cache_file"] != true {
		t.Fatalf("shared_principal_cache_file want true when path set: %+v", out["shared_principal_cache_file"])
	}
	// Default-path call without env must stay false.
	clear := diagnostics.BuildGatewayResidualStatus(func(string) string { return "" })
	if clear["shared_principal_cache_file"] != false {
		t.Fatalf("shared_principal_cache_file default false: %+v", clear["shared_principal_cache_file"])
	}

	entries, ok := out["principal_cache_entries"].(int)
	if !ok {
		// accept numeric float from some paths
		if f, okf := out["principal_cache_entries"].(float64); okf {
			entries = int(f)
			ok = true
		}
	}
	if !ok || entries != 2 {
		t.Fatalf("principal_cache_entries want 2 (file Len): %T %v", out["principal_cache_entries"], out["principal_cache_entries"])
	}

	blob, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	s := string(blob)
	if strings.Contains(s, marker) || strings.Contains(s, path) {
		t.Fatal("Regression: PRINCIPAL_CACHE_PATH leaked into residual-status JSON")
	}
	if strings.Contains(s, seedSK) {
		t.Fatal("Regression: subject key inventory leaked into residual-status JSON")
	}
	if strings.Contains(s, seedJP) || strings.Contains(s, "seed-jp-2") {
		t.Fatal("Regression: jenkins principal value leaked into residual-status JSON")
	}
	for _, bad := range []string{residualCanary, "access_token=", "refresh_token=", "client_secret=", "Bearer " + residualCanary} {
		if strings.Contains(s, bad) {
			t.Fatalf("forbidden %q in residual-status with principal path", bad)
		}
	}
	if _, ok := out["principal_cache_process_note"].(string); !ok {
		t.Fatal("principal_cache_process_note required")
	}
	// shared_subject_rate_file stays false when only principal path is set.
	if out["shared_subject_rate_file"] != false {
		t.Fatalf("shared_subject_rate_file must stay false without SUBJECT_RATE_PATH: %+v", out["shared_subject_rate_file"])
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

// shared_jwks_file=true when JWKS_CACHE_PATH set; path never dumped (HOST-001/HOST-008 lite).
func TestBuildGatewayResidualStatus_SharedJWKSFile(t *testing.T) {
	marker := "jwks-cache-path-canary-NEVER-IN-JSON"
	path := t.TempDir() + "/" + marker + ".json"
	t.Setenv(auth.EnvHTTPJWKSCachePath, path)

	out := diagnostics.BuildGatewayResidualStatus(nil)
	if out["shared_jwks_file"] != true {
		t.Fatalf("shared_jwks_file want true when path set: %+v", out["shared_jwks_file"])
	}
	blob, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	s := string(blob)
	if strings.Contains(s, marker) || strings.Contains(s, path) {
		t.Fatal("Regression: JWKS_CACHE_PATH leaked into residual-status JSON")
	}
	for _, bad := range []string{residualCanary, "access_token=", "refresh_token=", "client_secret="} {
		if strings.Contains(s, bad) {
			t.Fatalf("forbidden %q in residual-status with jwks path", bad)
		}
	}
	// Default getenv empty → false.
	clear := diagnostics.BuildGatewayResidualStatus(func(string) string { return "" })
	if clear["shared_jwks_file"] != false {
		t.Fatalf("shared_jwks_file default false: %+v", clear["shared_jwks_file"])
	}
}
