package diagnostics_test

import (
	"encoding/json"
	"os"
	"path/filepath"
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
	// Empty consent path → progressive_consent.file_backed default false.
	t.Setenv(gateway.EnvConsentSessionStorePath, "")

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
	// shared_token_cache_file default false when TOKEN_CACHE_PATH unset (HOST-008 lite).
	if out["shared_token_cache_file"] != false {
		t.Fatalf("shared_token_cache_file default false: %+v", out["shared_token_cache_file"])
	}
	// shared_api_token_vault_file / shared_jwt_vault_file default false when vault path env unset
	// (HOST-008 Mode A/B path residual lite; default XDG path does not count).
	if out["shared_api_token_vault_file"] != false {
		t.Fatalf("shared_api_token_vault_file default false: %+v", out["shared_api_token_vault_file"])
	}
	if out["shared_jwt_vault_file"] != false {
		t.Fatalf("shared_jwt_vault_file default false: %+v", out["shared_jwt_vault_file"])
	}
	// HOST-007 / HOST-008: concurrency slots always process-local (never multi-pod claim).
	if out["subject_slots_process_local"] != true {
		t.Fatalf("subject_slots_process_local must always be true: %+v", out["subject_slots_process_local"])
	}
	if _, ok := out["subject_limiter_max_subjects"]; ok {
		t.Fatalf("unlimited must omit subject_limiter_max_subjects: %+v", out["subject_limiter_max_subjects"])
	}
	// Progressive consent nest always present (empty environ: file_backed=false).
	pc, ok := out["progressive_consent"].(map[string]any)
	if !ok || pc == nil {
		t.Fatalf("progressive_consent object required: %+v", out["progressive_consent"])
	}
	if pc["browser_3lo_automated"] != false {
		t.Fatalf("browser_3lo_automated must be false: %+v", pc)
	}
	if pc["metadata_path_done_star"] != true {
		t.Fatalf("metadata_path_done_star must be true (Done*): %+v", pc)
	}
	if pc["stores_tokens"] != false {
		t.Fatalf("stores_tokens must be false: %+v", pc)
	}
	if pc["multi_replica_shared"] != false {
		t.Fatalf("multi_replica_shared must be false: %+v", pc)
	}
	if pc["file_backed"] != false {
		t.Fatalf("file_backed default false (empty environ): %+v", pc)
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
	// Explicitly clear consent path so default residual does not claim file_backed.
	t.Setenv(gateway.EnvConsentSessionStorePath, "")
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
	if pc["metadata_path_done_star"] != true {
		t.Fatalf("metadata_path_done_star must be true (Done*): %+v", pc)
	}
	// HOST-007 SPA progressive consent honesty (always on progressive_consent nest).
	if pc["stores_tokens"] != false {
		t.Fatalf("stores_tokens must be false: %+v", pc)
	}
	if pc["multi_replica_shared"] != false {
		t.Fatalf("multi_replica_shared must be false: %+v", pc)
	}
	if pc["file_backed"] != false {
		t.Fatalf("file_backed default false without CONSENT_STORE_PATH: %+v", pc)
	}
	if pc["same_host_reload_before_persist"] != false {
		t.Fatalf("same_host_reload_before_persist default false: %+v", pc)
	}
}

// HOST-007 / OAUTH-010: progressive_consent nests consent-store same_host_reload
// honesty when JENKINS_MCP_CONSENT_STORE_PATH set (path never dumped).
func TestBuildGatewayResidualStatus_ProgressiveConsentFileBacked(t *testing.T) {
	marker := "consent-path-canary-NEVER-IN-JSON"
	path := t.TempDir() + "/" + marker + ".json"
	t.Setenv(gateway.EnvConsentSessionStorePath, path)

	out := diagnostics.BuildGatewayResidualStatus(nil)
	pc, ok := out["progressive_consent"].(map[string]any)
	if !ok {
		t.Fatalf("progressive_consent: %+v", out["progressive_consent"])
	}
	if pc["file_backed"] != true {
		t.Fatalf("file_backed want true when path set: %+v", pc)
	}
	if pc["same_host_reload_before_persist"] != true {
		t.Fatalf("same_host_reload_before_persist want true: %+v", pc)
	}
	if pc["stores_tokens"] != false {
		t.Fatalf("stores_tokens: %+v", pc)
	}
	if pc["multi_replica_shared"] != false {
		t.Fatalf("multi_replica_shared: %+v", pc)
	}
	if pc["browser_3lo_automated"] != false {
		t.Fatalf("browser_3lo_automated: %+v", pc)
	}
	if pc["metadata_path_done_star"] != true {
		t.Fatalf("metadata_path_done_star: %+v", pc)
	}
	blob, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	s := string(blob)
	if strings.Contains(s, marker) || strings.Contains(s, path) {
		t.Fatal("Regression: CONSENT_STORE_PATH leaked into residual-status JSON")
	}
	for _, bad := range []string{residualCanary, "access_token=", "refresh_token=", "client_secret="} {
		if strings.Contains(s, bad) {
			t.Fatalf("forbidden %q in residual-status with consent path", bad)
		}
	}
	// getenv empty → file flags false.
	clear := diagnostics.BuildGatewayResidualStatus(func(string) string { return "" })
	cpc, _ := clear["progressive_consent"].(map[string]any)
	if cpc["file_backed"] != false || cpc["same_host_reload_before_persist"] != false {
		t.Fatalf("cleared getenv file flags: %+v", cpc)
	}
	if cpc["stores_tokens"] != false || cpc["multi_replica_shared"] != false {
		t.Fatalf("cleared getenv token/multi: %+v", cpc)
	}
	if cpc["metadata_path_done_star"] != true {
		t.Fatalf("cleared getenv metadata_path_done_star: %+v", cpc)
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
	// Concurrency honesty still true when other paths unset.
	if clear["subject_slots_process_local"] != true {
		t.Fatalf("subject_slots_process_local always true: %+v", clear["subject_slots_process_local"])
	}
}

// HOST-006/HOST-007 residual lite: subject_limiter_max_subjects when env set;
// subject_slots_process_local always true (process-local concurrency honesty).
func TestBuildGatewayResidualStatus_SubjectLimiterMaxSubjects(t *testing.T) {
	t.Setenv(gateway.EnvGatewaySubjectLimiterMaxSubjects, "")
	out := diagnostics.BuildGatewayResidualStatus(nil)
	if _, ok := out["subject_limiter_max_subjects"]; ok {
		t.Fatalf("unlimited must omit subject_limiter_max_subjects: %+v", out["subject_limiter_max_subjects"])
	}
	if out["subject_slots_process_local"] != true {
		t.Fatalf("subject_slots_process_local: %+v", out["subject_slots_process_local"])
	}

	t.Setenv(gateway.EnvGatewaySubjectLimiterMaxSubjects, "2048")
	out = diagnostics.BuildGatewayResidualStatus(nil)
	if out["subject_limiter_max_subjects"] != 2048 {
		t.Fatalf("subject_limiter_max_subjects: %+v", out["subject_limiter_max_subjects"])
	}
	if out["subject_slots_process_local"] != true {
		t.Fatalf("subject_slots_process_local with max set: %+v", out["subject_slots_process_local"])
	}
	blob, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	s := string(blob)
	for _, bad := range []string{residualCanary, "access_token=", "refresh_token=", "client_secret=", "Bearer "} {
		if strings.Contains(s, bad) {
			t.Fatalf("forbidden %q in residual-status with limiter max subjects", bad)
		}
	}
	// Never claim multi-pod shared concurrency Done.
	if strings.Contains(strings.ToLower(s), "multi-pod concurrency done") {
		t.Fatal("must not claim multi-pod concurrency Done")
	}
}

// Regression: LooksSecretKey must not treat residual honesty bool shared_token_cache_file
// or shared_api_token_vault_file or progressive_consent stores_tokens as a secret key
// (doctor/support-bundle sanitize + release-evidence scrub). Still drops real secret
// keys like access_token / client_secret.
func TestLooksSecretKey_SharedTokenCacheFileAllowlist(t *testing.T) {
	t.Parallel()
	if diagnostics.LooksSecretKey("shared_token_cache_file") {
		t.Fatal("Regression: shared_token_cache_file residual honesty bool must not look secret")
	}
	if diagnostics.LooksSecretKey("SHARED_TOKEN_CACHE_FILE") {
		t.Fatal("case-insensitive allowlist for shared_token_cache_file")
	}
	if diagnostics.LooksSecretKey("shared_api_token_vault_file") {
		t.Fatal("Regression: shared_api_token_vault_file residual honesty bool must not look secret")
	}
	if diagnostics.LooksSecretKey("SHARED_API_TOKEN_VAULT_FILE") {
		t.Fatal("case-insensitive allowlist for shared_api_token_vault_file")
	}
	// shared_jwt_vault_file has no secret-shaped substring; still must not look secret.
	if diagnostics.LooksSecretKey("shared_jwt_vault_file") {
		t.Fatal("shared_jwt_vault_file residual honesty bool must not look secret")
	}
	// Progressive consent nest honesty bool (contains "token"; always false).
	if diagnostics.LooksSecretKey("stores_tokens") {
		t.Fatal("Regression: stores_tokens residual honesty bool must not look secret (support-bundle sanitize)")
	}
	if diagnostics.LooksSecretKey("STORES_TOKENS") {
		t.Fatal("case-insensitive allowlist for stores_tokens")
	}
	for _, secret := range []string{
		"access_token", "refresh_token", "client_secret", "authorization",
		"password", "cookie", "private_key", "token_cache_path", "bearer_token",
		"api_token",
	} {
		if !diagnostics.LooksSecretKey(secret) {
			t.Fatalf("LooksSecretKey(%q) want true (still drop real secret keys)", secret)
		}
	}
}

// shared_token_cache_file=true when TOKEN_CACHE_PATH set; path never dumped (HOST-008 lite).
// Residual must not open the cache file (tokens on disk) — bool + path residual only.
func TestBuildGatewayResidualStatus_SharedTokenCacheFile(t *testing.T) {
	marker := "token-cache-path-canary-NEVER-IN-JSON"
	path := t.TempDir() + "/" + marker + ".json"
	// Plant a fake token file so open-leak would surface if residual ever read it.
	seedToken := "seed-access-token-CANARY-never-in-residual-json"
	if err := os.WriteFile(path, []byte(`{"version":1,"entries":{"k":{"access_token":"`+seedToken+`","expires_at":"2099-01-01T00:00:00Z"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(gateway.EnvGatewayTokenCachePath, path)
	t.Setenv("HOST_RESIDUAL_CANARY", residualCanary)

	out := diagnostics.BuildGatewayResidualStatus(nil)
	if out["shared_token_cache_file"] != true {
		t.Fatalf("shared_token_cache_file want true when path set: %+v", out["shared_token_cache_file"])
	}
	// Other shared_*_file flags stay false when only token path is set.
	if out["shared_subject_rate_file"] != false {
		t.Fatalf("shared_subject_rate_file must stay false: %+v", out["shared_subject_rate_file"])
	}
	if out["shared_principal_cache_file"] != false {
		t.Fatalf("shared_principal_cache_file must stay false: %+v", out["shared_principal_cache_file"])
	}
	if out["shared_jwks_file"] != false {
		t.Fatalf("shared_jwks_file must stay false: %+v", out["shared_jwks_file"])
	}
	if out["shared_api_token_vault_file"] != false {
		t.Fatalf("shared_api_token_vault_file must stay false: %+v", out["shared_api_token_vault_file"])
	}
	if out["shared_jwt_vault_file"] != false {
		t.Fatalf("shared_jwt_vault_file must stay false: %+v", out["shared_jwt_vault_file"])
	}
	clear := diagnostics.BuildGatewayResidualStatus(func(string) string { return "" })
	if clear["shared_token_cache_file"] != false {
		t.Fatalf("shared_token_cache_file default false: %+v", clear["shared_token_cache_file"])
	}

	blob, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	s := string(blob)
	if strings.Contains(s, marker) || strings.Contains(s, path) {
		t.Fatal("Regression: TOKEN_CACHE_PATH leaked into residual-status JSON")
	}
	if strings.Contains(s, seedToken) {
		t.Fatal("Regression: token cache file contents leaked into residual-status JSON")
	}
	for _, bad := range []string{residualCanary, "access_token=", "refresh_token=", "client_secret=", "Bearer " + residualCanary} {
		if strings.Contains(s, bad) {
			t.Fatalf("forbidden %q in residual-status with token cache path", bad)
		}
	}
}

// shared_api_token_vault_file=true when VAULT_PATH env set; path never dumped (HOST-008 lite).
// Residual must not open the vault file (tokens on disk). Default XDG path does not count.
func TestBuildGatewayResidualStatus_SharedAPITokenVaultFile(t *testing.T) {
	marker := "api-token-vault-path-canary-NEVER-IN-JSON"
	path := t.TempDir() + "/" + marker + ".json"
	seedToken := "seed-api-token-CANARY-never-in-residual-json"
	if err := os.WriteFile(path, []byte(`{"version":1,"entries":{"k":"`+seedToken+`"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(gateway.EnvGatewayVaultPath, path)
	t.Setenv("HOST_RESIDUAL_CANARY", residualCanary)

	out := diagnostics.BuildGatewayResidualStatus(nil)
	if out["shared_api_token_vault_file"] != true {
		t.Fatalf("shared_api_token_vault_file want true when VAULT_PATH set: %+v", out["shared_api_token_vault_file"])
	}
	if out["shared_jwt_vault_file"] != false {
		t.Fatalf("shared_jwt_vault_file must stay false: %+v", out["shared_jwt_vault_file"])
	}
	if out["shared_token_cache_file"] != false {
		t.Fatalf("shared_token_cache_file must stay false: %+v", out["shared_token_cache_file"])
	}
	// Empty getenv → false (default XDG path from VaultPathFromEnviron must not flip residual).
	clear := diagnostics.BuildGatewayResidualStatus(func(string) string { return "" })
	if clear["shared_api_token_vault_file"] != false {
		t.Fatalf("shared_api_token_vault_file default false: %+v", clear["shared_api_token_vault_file"])
	}

	blob, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	s := string(blob)
	if strings.Contains(s, marker) || strings.Contains(s, path) {
		t.Fatal("Regression: VAULT_PATH leaked into residual-status JSON")
	}
	if strings.Contains(s, seedToken) {
		t.Fatal("Regression: vault file contents leaked into residual-status JSON")
	}
	for _, bad := range []string{residualCanary, "access_token=", "refresh_token=", "client_secret=", "Bearer " + residualCanary} {
		if strings.Contains(s, bad) {
			t.Fatalf("forbidden %q in residual-status with vault path", bad)
		}
	}
}

// shared_jwt_vault_file=true when JWT_VAULT_PATH env set; path never dumped (HOST-008 lite).
// Residual must not open the vault file. Default XDG JWT path does not count.
func TestBuildGatewayResidualStatus_SharedJWTVaultFile(t *testing.T) {
	marker := "jwt-vault-path-canary-NEVER-IN-JSON"
	path := t.TempDir() + "/" + marker + ".json"
	seedToken := "seed-jwt-CANARY-never-in-residual-json.eyJhbGciOiJub25lIn0."
	if err := os.WriteFile(path, []byte(`{"version":1,"entries":{"k":"`+seedToken+`"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(gateway.EnvGatewayJWTVaultPath, path)
	t.Setenv("HOST_RESIDUAL_CANARY", residualCanary)

	out := diagnostics.BuildGatewayResidualStatus(nil)
	if out["shared_jwt_vault_file"] != true {
		t.Fatalf("shared_jwt_vault_file want true when JWT_VAULT_PATH set: %+v", out["shared_jwt_vault_file"])
	}
	if out["shared_api_token_vault_file"] != false {
		t.Fatalf("shared_api_token_vault_file must stay false: %+v", out["shared_api_token_vault_file"])
	}
	clear := diagnostics.BuildGatewayResidualStatus(func(string) string { return "" })
	if clear["shared_jwt_vault_file"] != false {
		t.Fatalf("shared_jwt_vault_file default false: %+v", clear["shared_jwt_vault_file"])
	}

	blob, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	s := string(blob)
	if strings.Contains(s, marker) || strings.Contains(s, path) {
		t.Fatal("Regression: JWT_VAULT_PATH leaked into residual-status JSON")
	}
	if strings.Contains(s, seedToken) {
		t.Fatal("Regression: JWT vault file contents leaked into residual-status JSON")
	}
	for _, bad := range []string{residualCanary, "access_token=", "refresh_token=", "client_secret=", "Bearer " + residualCanary} {
		if strings.Contains(s, bad) {
			t.Fatalf("forbidden %q in residual-status with jwt vault path", bad)
		}
	}
}

// Regression: ONLY default XDG vault paths (XDG_DATA_HOME / HOME set, no
// JENKINS_MCP_GATEWAY_VAULT_PATH / JWT_VAULT_PATH) must keep shared_api_token_vault_file
// and shared_jwt_vault_file false. Plant tokens at the resolved default paths so an
// accidental VaultPathFromEnviron + open would leak — residual must never open vaults.
// VaultPathConfiguredFromEnviron / JWTVaultPathConfiguredFromEnviron require explicit env.
func TestBuildGatewayResidualStatus_DefaultXDGVaultDoesNotCountOrOpen(t *testing.T) {
	xdg := t.TempDir()
	apiSeed := "xdg-default-api-token-CANARY-never-in-residual-json"
	jwtSeed := "xdg-default-jwt-CANARY-never-in-residual-json.eyJhbGciOiJub25lIn0."

	apiDefault := gateway.VaultPathFromEnviron(func(k string) string {
		if k == "XDG_DATA_HOME" {
			return xdg
		}
		return ""
	})
	jwtDefault := gateway.JWTVaultPathFromEnviron(func(k string) string {
		if k == "XDG_DATA_HOME" {
			return xdg
		}
		return ""
	})
	if apiDefault == "" || jwtDefault == "" {
		t.Fatal("default XDG vault paths must resolve non-empty")
	}
	if err := os.MkdirAll(filepath.Dir(apiDefault), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(jwtDefault), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(apiDefault, []byte(`{"version":1,"entries":{"k":"`+apiSeed+`"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jwtDefault, []byte(`{"version":1,"entries":{"k":"`+jwtSeed+`"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// getenv: XDG present, vault path env keys empty (and other residual path envs empty).
	getenv := func(k string) string {
		switch k {
		case "XDG_DATA_HOME":
			return xdg
		case "HOME":
			return t.TempDir() // must not be used when XDG_DATA_HOME set
		case gateway.EnvGatewayVaultPath, gateway.EnvGatewayJWTVaultPath,
			gateway.EnvGatewayTokenCachePath, gateway.EnvGatewaySubjectRatePath,
			gateway.EnvGatewayPrincipalCachePath, gateway.EnvConsentSessionStorePath,
			auth.EnvHTTPJWKSCachePath:
			return ""
		default:
			return ""
		}
	}

	// Configured helpers themselves: empty vault env → false even with XDG set.
	if gateway.VaultPathConfiguredFromEnviron(getenv) {
		t.Fatal("Regression: VaultPathConfiguredFromEnviron true with only default XDG (no VAULT_PATH env)")
	}
	if gateway.JWTVaultPathConfiguredFromEnviron(getenv) {
		t.Fatal("Regression: JWTVaultPathConfiguredFromEnviron true with only default XDG (no JWT_VAULT_PATH env)")
	}

	out := diagnostics.BuildGatewayResidualStatus(getenv)
	if out["shared_api_token_vault_file"] != false {
		t.Fatalf("Regression: shared_api_token_vault_file=true with only default XDG: %+v", out["shared_api_token_vault_file"])
	}
	if out["shared_jwt_vault_file"] != false {
		t.Fatalf("Regression: shared_jwt_vault_file=true with only default XDG: %+v", out["shared_jwt_vault_file"])
	}
	// Empty getenv (no XDG either) must also stay false — fail-closed canary.
	empty := diagnostics.BuildGatewayResidualStatus(func(string) string { return "" })
	if empty["shared_api_token_vault_file"] != false || empty["shared_jwt_vault_file"] != false {
		t.Fatalf("empty env vault shared_* must be false: api=%+v jwt=%+v",
			empty["shared_api_token_vault_file"], empty["shared_jwt_vault_file"])
	}

	blob, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	s := string(blob)
	if strings.Contains(s, apiSeed) {
		t.Fatal("Regression: default XDG Mode A vault contents leaked (residual must never open vault)")
	}
	if strings.Contains(s, jwtSeed) {
		t.Fatal("Regression: default XDG Mode B JWT vault contents leaked (residual must never open vault)")
	}
	if strings.Contains(s, apiDefault) || strings.Contains(s, jwtDefault) || strings.Contains(s, xdg) {
		t.Fatal("Regression: default XDG vault path leaked into residual-status JSON")
	}
	for _, bad := range []string{residualCanary, "access_token=", "refresh_token=", "client_secret=", "Bearer "} {
		if strings.Contains(s, bad) {
			t.Fatalf("forbidden %q in residual-status with default XDG vaults planted", bad)
		}
	}
	// Progressive consent honesty (stores_tokens-style secret canary).
	pc, _ := out["progressive_consent"].(map[string]any)
	if pc == nil {
		t.Fatal("progressive_consent required")
	}
	if pc["stores_tokens"] != false {
		t.Fatalf("progressive_consent.stores_tokens must be false: %+v", pc["stores_tokens"])
	}
}

// HOST-006 residual lite: subject_limiter_max_subjects surfaces when env set;
// omit when unlimited / unset. Path never involved.
