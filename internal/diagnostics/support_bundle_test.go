package diagnostics_test

import (
	"archive/zip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/config"
	"github.com/simonfxr/go-jenkins-mcp/internal/diagnostics"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
	"github.com/simonfxr/go-jenkins-mcp/internal/keyring"
	"github.com/simonfxr/go-jenkins-mcp/internal/profile"
	"github.com/simonfxr/go-jenkins-mcp/internal/telemetry"
)

const bundleCanary = "BUNDLE_CANARY_token_must_never_appear_xyz999"

func boolPtr(v bool) *bool { return &v }

func TestCreateSupportBundle_PreviewListsCategories(t *testing.T) {
	t.Parallel()
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com/",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	res, err := diagnostics.CreateSupportBundle(context.Background(), diagnostics.SupportBundleOptions{
		Profile:     p,
		PreviewOnly: true,
		Version:     "test",
		Commit:      "abc",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Plan.PreviewOnly {
		t.Fatal("preview")
	}
	if len(res.Plan.Included) == 0 || len(res.Plan.Excluded) == 0 {
		t.Fatalf("plan: %+v", res.Plan)
	}
	// Excluded must mention tokens / keyring / logs.
	joined := strings.Join(res.Plan.Excluded, ",")
	for _, want := range []string{"tokens", "keyring", "full_build_logs", "authorization"} {
		if !strings.Contains(joined, want) {
			t.Errorf("excluded missing %q: %s", want, joined)
		}
	}
	if res.Path != "" {
		t.Fatal("preview must not write path")
	}
}

func TestCreateSupportBundle_CanaryAbsent(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(root, "cfg"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
	_ = os.MkdirAll(paths.ProfilesDir(), 0o700)
	outDir := filepath.Join(root, "bundles")

	// Plant canary in keyring — bundle must never read/export the secret value.
	kr := keyring.NewStore(keyring.NewMemory())
	if err := kr.SetAPIToken(keyring.CredentialRef{
		ProfileID: "corp",
		Origin:    "https://jenkins.example.com",
		Method:    "api_token",
		Account:   "alice",
	}, bundleCanary); err != nil {
		t.Fatalf("plant keyring canary: %v", err)
	}
	// ARC-009: plant cache encryption key canary (32-byte test vector).
	cacheMat := make([]byte, 32)
	copy(cacheMat, []byte(bundleCanary))
	if err := kr.SetCacheKey("corp", 1, cacheMat); err != nil {
		t.Fatalf("plant cache key canary: %v", err)
	}

	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com/",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
		// Canary must not leak even if accidentally placed in a non-secret field path.
		DisplayName: "display-without-secret",
	}

	rep := diagnostics.Report{
		ProfileID: "corp",
		Overall:   diagnostics.StatusOK,
		Version:   "test",
		Checks: []diagnostics.Check{{
			Name:    "binary",
			Status:  diagnostics.StatusOK,
			Message: "ok",
			Details: map[string]any{
				// Secret-like keys must be dropped by SanitizeCheck when doctor runs;
				// also plant canary as a value that redact should scrub if token-shaped.
				"safe": "value",
			},
		}},
	}

	m := telemetry.NewMetrics()
	m.Inc(telemetry.MetricToolCalls, 3)

	res, err := diagnostics.CreateSupportBundle(context.Background(), diagnostics.SupportBundleOptions{
		Profile:      p,
		Paths:        &paths,
		OutputDir:    outDir,
		DoctorReport: &rep,
		Version:      "1.2.3",
		Commit:       "deadbeef",
		BuildTime:    "2026-01-01T00:00:00Z",
		Metrics:      m,
		CapabilitySummary: map[string]any{
			"jenkinsVersion":  "2.462.3",
			"hasPipelineREST": true,
			// Planted secret key must be dropped.
			"token": bundleCanary,
		},
		ErrorSignatures: []diagnostics.ErrorSignatureEntry{{
			Signature: "sig1",
			Pattern:   "error",
			Count:     2,
			Message:   "failed without secret",
		}},
		DoctorOpts: diagnostics.DoctorOptions{
			Keyring:     kr,
			SkipNetwork: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Path == "" || res.Bytes <= 0 {
		t.Fatalf("result: %+v", res)
	}
	// Mode 0600
	fi, err := os.Stat(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("bundle mode too open: %04o", fi.Mode().Perm())
	}

	// Scan entire zip for canary.
	zr, err := zip.OpenReader(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		size := int(f.UncompressedSize64) + 1
		if size < 64 {
			size = 64
		}
		buf := make([]byte, size)
		n, _ := rc.Read(buf)
		_ = rc.Close()
		body := string(buf[:n])
		if strings.Contains(body, bundleCanary) {
			t.Fatalf("canary leaked in %s", f.Name)
		}
		if strings.Contains(strings.ToLower(body), "authorization:") {
			t.Fatalf("authorization header-like content in %s", f.Name)
		}
	}
	for _, want := range []string{
		"manifest.json", "version.json", "runtime.json", "profile_effective.json",
		"doctor.json", "cache_status.json", "capability_summary.json",
		"metrics.json", "error_signatures.json", "README.txt",
		"security_self_check.json", "release_evidence_lite.json", "rs_qualification_summary.json",
		"gateway-residual-status.json",
	} {
		found := false
		for _, n := range names {
			if n == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing member %s in %v", want, names)
		}
	}

	// capability_summary must not retain token key.
	capBody, err := diagnostics.ReadBundleFile(res.Path, "capability_summary.json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(capBody), bundleCanary) || strings.Contains(string(capBody), `"token"`) {
		t.Fatalf("capability summary retained secret: %s", capBody)
	}

	// profile must not claim to embed token.
	profBody, err := diagnostics.ReadBundleFile(res.Path, "profile_effective.json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(profBody), bundleCanary) {
		t.Fatal("canary in profile")
	}

	// Wave 23 members: offline content, no canary.
	for _, mem := range []string{
		"security_self_check.json", "release_evidence_lite.json", "rs_qualification_summary.json",
	} {
		body, err := diagnostics.ReadBundleFile(res.Path, mem)
		if err != nil {
			t.Fatalf("%s: %v", mem, err)
		}
		if strings.Contains(string(body), bundleCanary) {
			t.Fatalf("canary in %s", mem)
		}
	}

	// release_evidence_lite is version/runtime only.
	relBody, err := diagnostics.ReadBundleFile(res.Path, "release_evidence_lite.json")
	if err != nil {
		t.Fatal(err)
	}
	var rel map[string]any
	if err := json.Unmarshal(relBody, &rel); err != nil {
		t.Fatal(err)
	}
	if rel["offline"] != true {
		t.Fatalf("release_evidence_lite offline: %+v", rel)
	}
	if _, ok := rel["version"].(map[string]any); !ok {
		t.Fatalf("release_evidence_lite missing version: %s", relBody)
	}

	// RS qualification has fallthrough contract.
	rsBody, err := diagnostics.ReadBundleFile(res.Path, "rs_qualification_summary.json")
	if err != nil {
		t.Fatal(err)
	}
	var rs map[string]any
	if err := json.Unmarshal(rsBody, &rs); err != nil {
		t.Fatal(err)
	}
	if rs["fallthrough_must_deny"] != true {
		t.Fatalf("rs summary: %+v", rs)
	}
}

func TestCreateSupportBundle_RequiresProfile(t *testing.T) {
	t.Parallel()
	_, err := diagnostics.CreateSupportBundle(context.Background(), diagnostics.SupportBundleOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCreateSupportBundle_Wave23SectionsDisableAndLogSample(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(root, "cfg"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
	outDir := filepath.Join(root, "bundles")
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com/",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	rep := diagnostics.Report{
		ProfileID: "corp",
		Overall:   diagnostics.StatusOK,
		Version:   "test",
		Checks: []diagnostics.Check{{
			Name: "binary", Status: diagnostics.StatusOK, Message: "ok",
		}},
	}

	// Disable optional Wave 23 sections; expand error_signatures from a log sample
	// that contains a canary-shaped token line — sample text must not appear in zip.
	logSample := "BUILD FAILURE\nError: Authorization: Bearer " + bundleCanary + "\nFATAL: boom\n"
	res, err := diagnostics.CreateSupportBundle(context.Background(), diagnostics.SupportBundleOptions{
		Profile:                    p,
		Paths:                      &paths,
		OutputDir:                  outDir,
		DoctorReport:               &rep,
		Version:                    "1.0.0",
		Commit:                     "cafebabe",
		BuildTime:                  "2026-08-01T00:00:00Z",
		IncludeSecuritySelfCheck:   boolPtr(false),
		IncludeReleaseEvidenceLite: boolPtr(false),
		IncludeRSQualification:     boolPtr(false),
		LogSample:                  logSample,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Preview categories should omit disabled sections.
	prev, err := diagnostics.CreateSupportBundle(context.Background(), diagnostics.SupportBundleOptions{
		Profile:                    p,
		PreviewOnly:                true,
		IncludeSecuritySelfCheck:   boolPtr(false),
		IncludeReleaseEvidenceLite: boolPtr(false),
		IncludeRSQualification:     boolPtr(false),
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(prev.Plan.Included, ",")
	for _, ban := range []string{
		diagnostics.BundleCatSecuritySelfCheck,
		diagnostics.BundleCatReleaseEvidenceLite,
		diagnostics.BundleCatRSQualification,
	} {
		if strings.Contains(joined, ban) {
			t.Errorf("disabled category still included: %s in %s", ban, joined)
		}
	}
	if !strings.Contains(strings.Join(prev.Plan.Excluded, ","), "raw_log_samples") {
		t.Errorf("excluded missing raw_log_samples: %v", prev.Plan.Excluded)
	}

	zr, err := zip.OpenReader(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		size := int(f.UncompressedSize64) + 1
		if size < 64 {
			size = 64
		}
		buf := make([]byte, size)
		n, _ := rc.Read(buf)
		_ = rc.Close()
		body := string(buf[:n])
		if strings.Contains(body, bundleCanary) {
			t.Fatalf("Regression: canary leaked from LogSample into %s", f.Name)
		}
		if strings.Contains(body, "Authorization: Bearer") {
			t.Fatalf("authorization material from log sample in %s", f.Name)
		}
	}
	for _, ban := range []string{
		"security_self_check.json", "release_evidence_lite.json", "rs_qualification_summary.json",
	} {
		for _, n := range names {
			if n == ban {
				t.Errorf("disabled member present: %s", ban)
			}
		}
	}

	sigBody, err := diagnostics.ReadBundleFile(res.Path, "error_signatures.json")
	if err != nil {
		t.Fatal(err)
	}
	var sigDoc map[string]any
	if err := json.Unmarshal(sigBody, &sigDoc); err != nil {
		t.Fatal(err)
	}
	if sigDoc["source"] != "log_sample_extract" {
		t.Fatalf("expected log_sample_extract source: %s", sigBody)
	}
	sigs, _ := sigDoc["signatures"].([]any)
	if len(sigs) == 0 {
		t.Fatalf("expected signatures from sample: %s", sigBody)
	}
	// Messages must be empty/absent for sample-derived rows.
	for _, raw := range sigs {
		m, _ := raw.(map[string]any)
		if msg, ok := m["message"].(string); ok && strings.TrimSpace(msg) != "" {
			t.Fatalf("sample-derived signature must not carry message: %+v", m)
		}
	}
}

func TestCreateSupportBundle_DefaultIncludesWave23Categories(t *testing.T) {
	t.Parallel()
	cats := diagnostics.DefaultBundleCategories()
	joined := strings.Join(cats, ",")
	for _, want := range []string{
		diagnostics.BundleCatSecuritySelfCheck,
		diagnostics.BundleCatReleaseEvidenceLite,
		diagnostics.BundleCatRSQualification,
		diagnostics.BundleCatErrorSigs,
		diagnostics.BundleCatGatewayResidualStatus,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("DefaultBundleCategories missing %s: %v", want, cats)
		}
	}
}

// OPS support-bundle residual lite: top-level gateway-residual-status.json is always
// present (even when DoctorReport omits gateway_residual_status), secret-free, and
// never claims HA multi-replica or live GO.
// Progressive consent nest honesty (OAUTH-010): browser 3LO not automated; metadata
// path Done*; stores_tokens=false (must survive sanitize — key contains "token");
// multi_replica_shared=false; file_backed=false when CONSENT_STORE_PATH unset.
func TestCreateSupportBundle_GatewayResidualStatusMember(t *testing.T) {
	// Not parallel: plants env canary for secret-free residual map.
	const residualCanary = "BUNDLE_GRS_CANARY_token_must_never_appear_xyz888"
	t.Setenv("HOST_BUNDLE_RESIDUAL_CANARY", residualCanary)
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("JENKINS_MCP_GATEWAY_REPLICAS", "")
	t.Setenv("REPLICAS", "")
	// Empty consent path → progressive_consent.file_backed default false.
	t.Setenv(gateway.EnvConsentSessionStorePath, "")

	root := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(root, "cfg"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
	outDir := filepath.Join(root, "bundles")
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com/",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	// Prebuilt doctor without GatewayResidualStatus — top-level member must still land.
	rep := diagnostics.Report{
		ProfileID: "corp",
		Overall:   diagnostics.StatusOK,
		Version:   "test",
		Checks: []diagnostics.Check{{
			Name: "binary", Status: diagnostics.StatusOK, Message: "ok",
		}},
	}

	res, err := diagnostics.CreateSupportBundle(context.Background(), diagnostics.SupportBundleOptions{
		Profile:      p,
		Paths:        &paths,
		OutputDir:    outDir,
		DoctorReport: &rep,
		Version:      "1.0.0",
		Commit:       "deadbeef",
		// Disable optional sections to keep zip small; residual member is not optional.
		IncludeSecuritySelfCheck:   boolPtr(false),
		IncludeReleaseEvidenceLite: boolPtr(false),
		IncludeRSQualification:     boolPtr(false),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Category plan advertises residual honesty.
	joined := strings.Join(res.Categories, ",")
	if !strings.Contains(joined, diagnostics.BundleCatGatewayResidualStatus) {
		t.Fatalf("categories missing gateway_residual_status: %v", res.Categories)
	}

	body, err := diagnostics.ReadBundleFile(res.Path, "gateway-residual-status.json")
	if err != nil {
		t.Fatalf("gateway-residual-status.json missing: %v", err)
	}
	if strings.Contains(string(body), residualCanary) {
		t.Fatal("Regression: residual canary leaked in gateway-residual-status.json")
	}
	var grs map[string]any
	if err := json.Unmarshal(body, &grs); err != nil {
		t.Fatal(err)
	}
	if grs["residual_id"] != "oauth009_offline" {
		t.Fatalf("residual_id=%v", grs["residual_id"])
	}
	if grs["oauth009_offline"] != true {
		t.Fatalf("oauth009_offline=%v", grs["oauth009_offline"])
	}
	if grs["ha_multi_replica"] != false {
		t.Fatalf("ha_multi_replica must be false, got %v", grs["ha_multi_replica"])
	}
	if grs["gateway_ready"] != false {
		t.Fatalf("gateway_ready must be false on residual surface, got %v", grs["gateway_ready"])
	}
	if grs["mode_a_live_obtain_qualified"] != false ||
		grs["mode_b_live_rs_qualified"] != false ||
		grs["mode_c_live_agentcore_qualified"] != false {
		t.Fatalf("live mode pins must stay false: %+v", grs)
	}
	if grs["multi_pod_vault_residual"] != true {
		t.Fatal("multi_pod_vault_residual always true")
	}
	doc, _ := grs["doc"].(string)
	note, _ := grs["residual_note"].(string)
	if !strings.Contains(doc, "live-pin-blockers") && !strings.Contains(note, "live-pin-blockers") {
		t.Fatalf("want live-pin-blockers pointer: doc=%q note=%q", doc, note)
	}

	// Progressive consent nest (always present on residual-status / support-bundle).
	pc, ok := grs["progressive_consent"].(map[string]any)
	if !ok || pc == nil {
		t.Fatalf("progressive_consent object required in gateway-residual-status.json: %+v", grs["progressive_consent"])
	}
	if pc["browser_3lo_automated"] != false {
		t.Fatalf("browser_3lo_automated must be false: %+v", pc)
	}
	if pc["metadata_path_done_star"] != true {
		t.Fatalf("metadata_path_done_star must be true (Done*): %+v", pc)
	}
	// Regression: stores_tokens must survive sanitize (key contains "token" substring).
	if pc["stores_tokens"] != false {
		t.Fatalf("stores_tokens must be false after sanitize: %+v", pc)
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

	for _, bad := range []string{
		residualCanary,
		"access_token=",
		"refresh_token=",
		"client_secret=",
		"Authorization: Bearer",
		"production go complete",
	} {
		if strings.Contains(strings.ToLower(string(body)), strings.ToLower(bad)) {
			t.Fatalf("forbidden %q in gateway-residual-status.json", bad)
		}
	}

	// README mentions residual member.
	readme, err := diagnostics.ReadBundleFile(res.Path, "README.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(readme), "gateway-residual-status") {
		t.Fatalf("README should mention gateway-residual-status: %s", readme)
	}
}

// OPS support-bundle residual lite: when JENKINS_MCP_CONSENT_STORE_PATH is set,
// gateway-residual-status.json progressive_consent reports file_backed=true and
// same_host_reload_before_persist=true; path marker never appears in the zip member.
func TestCreateSupportBundle_GatewayResidualStatus_ConsentStorePath(t *testing.T) {
	// Not parallel: sets CONSENT_STORE_PATH for residual honesty during BuildSupportBundle.
	const residualCanary = "BUNDLE_CONSENT_CANARY_token_must_never_appear_xyz777"
	marker := "consent-bundle-path-canary-NEVER-IN-JSON"
	path := filepath.Join(t.TempDir(), marker+".json")
	t.Setenv("HOST_BUNDLE_CONSENT_CANARY", residualCanary)
	t.Setenv(gateway.EnvConsentSessionStorePath, path)
	t.Setenv("KUBERNETES_SERVICE_HOST", "")

	root := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(root, "cfg"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
	outDir := filepath.Join(root, "bundles")
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com/",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	rep := diagnostics.Report{
		ProfileID: "corp",
		Overall:   diagnostics.StatusOK,
		Version:   "test",
		Checks: []diagnostics.Check{{
			Name: "binary", Status: diagnostics.StatusOK, Message: "ok",
		}},
	}

	res, err := diagnostics.CreateSupportBundle(context.Background(), diagnostics.SupportBundleOptions{
		Profile:                    p,
		Paths:                      &paths,
		OutputDir:                  outDir,
		DoctorReport:               &rep,
		Version:                    "1.0.0",
		Commit:                     "deadbeef",
		IncludeSecuritySelfCheck:   boolPtr(false),
		IncludeReleaseEvidenceLite: boolPtr(false),
		IncludeRSQualification:     boolPtr(false),
	})
	if err != nil {
		t.Fatal(err)
	}

	body, err := diagnostics.ReadBundleFile(res.Path, "gateway-residual-status.json")
	if err != nil {
		t.Fatalf("gateway-residual-status.json missing: %v", err)
	}
	var grs map[string]any
	if err := json.Unmarshal(body, &grs); err != nil {
		t.Fatal(err)
	}
	pc, ok := grs["progressive_consent"].(map[string]any)
	if !ok || pc == nil {
		t.Fatalf("progressive_consent object required: %+v", grs["progressive_consent"])
	}
	if pc["file_backed"] != true {
		t.Fatalf("file_backed want true when CONSENT_STORE_PATH set: %+v", pc)
	}
	if pc["same_host_reload_before_persist"] != true {
		t.Fatalf("same_host_reload_before_persist want true: %+v", pc)
	}
	if pc["stores_tokens"] != false {
		t.Fatalf("stores_tokens must stay false: %+v", pc)
	}
	if pc["multi_replica_shared"] != false {
		t.Fatalf("multi_replica_shared must stay false: %+v", pc)
	}
	if pc["browser_3lo_automated"] != false {
		t.Fatalf("browser_3lo_automated: %+v", pc)
	}
	if pc["metadata_path_done_star"] != true {
		t.Fatalf("metadata_path_done_star: %+v", pc)
	}

	s := string(body)
	if strings.Contains(s, marker) || strings.Contains(s, path) {
		t.Fatal("Regression: CONSENT_STORE_PATH leaked into gateway-residual-status.json")
	}
	for _, bad := range []string{
		residualCanary,
		"access_token=",
		"refresh_token=",
		"client_secret=",
		"Authorization: Bearer",
	} {
		if strings.Contains(s, bad) {
			t.Fatalf("forbidden %q in gateway-residual-status.json with consent path", bad)
		}
	}
}
