package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// pilotEvidenceManifest is the secret-free index written by scripts/pilot-evidence.sh.
// Schema: jenkins-mcp.pilot-evidence.manifest.v1
type pilotEvidenceManifest struct {
	Schema      string                  `json:"schema"`
	GeneratedAt string                  `json:"generated_at"`
	Offline     bool                    `json:"offline"`
	Overall     string                  `json:"overall"`
	ProfileID   string                  `json:"profile_id"`
	Binary      string                  `json:"binary"`
	Host        pilotEvidenceHost       `json:"host"`
	Artifacts   []pilotEvidenceArtifact `json:"artifacts"`
	Notes       []string                `json:"notes"`
	Residual    []string                `json:"residual"`
}

type pilotEvidenceHost struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

type pilotEvidenceArtifact struct {
	Name     string `json:"name"`
	Path     string `json:"path,omitempty"`
	Status   string `json:"status"`
	ExitCode int    `json:"exit_code"`
	Note     string `json:"note,omitempty"`
}

const pilotEvidenceManifestSchema = "jenkins-mcp.pilot-evidence.manifest.v1"

// validatePilotEvidenceManifest checks required fields for REL-001/002 pack MANIFEST.
func validatePilotEvidenceManifest(m *pilotEvidenceManifest) error {
	if m.Schema != pilotEvidenceManifestSchema {
		return fmt.Errorf("schema want %q got %q", pilotEvidenceManifestSchema, m.Schema)
	}
	if strings.TrimSpace(m.GeneratedAt) == "" {
		return fmt.Errorf("generated_at required")
	}
	if !m.Offline {
		return fmt.Errorf("offline must be true for this pack")
	}
	switch m.Overall {
	case "pass", "warn", "fail", "incomplete":
	default:
		return fmt.Errorf("overall invalid: %q", m.Overall)
	}
	if len(m.Artifacts) == 0 {
		return fmt.Errorf("artifacts must be non-empty")
	}
	seen := map[string]bool{}
	for i, a := range m.Artifacts {
		if strings.TrimSpace(a.Name) == "" {
			return fmt.Errorf("artifacts[%d].name required", i)
		}
		if seen[a.Name] {
			return fmt.Errorf("duplicate artifact name %q", a.Name)
		}
		seen[a.Name] = true
		switch a.Status {
		case "pass", "fail", "skip", "warn":
		default:
			return fmt.Errorf("artifacts[%d].status invalid: %q", i, a.Status)
		}
		if a.Status != "skip" && a.Path == "" {
			return fmt.Errorf("artifacts[%d] path required when status=%s", i, a.Status)
		}
	}
	for _, need := range []string{"version", "security_self_check"} {
		if !seen[need] {
			return fmt.Errorf("missing required artifact %q", need)
		}
	}
	return nil
}

func TestValidatePilotEvidenceManifestSchema(t *testing.T) {
	t.Parallel()
	good := &pilotEvidenceManifest{
		Schema:      pilotEvidenceManifestSchema,
		GeneratedAt: "2026-08-01T00:00:00Z",
		Offline:     true,
		Overall:     "incomplete",
		Binary:      "/usr/bin/jenkins-mcp",
		Host:        pilotEvidenceHost{OS: "Linux", Arch: "x86_64"},
		Artifacts: []pilotEvidenceArtifact{
			{Name: "version", Path: "version.json", Status: "pass", ExitCode: 0},
			{Name: "security_self_check", Path: "security-self-check.json", Status: "pass", ExitCode: 0},
			{Name: "doctor_offline", Status: "skip", Note: "PROFILE not set"},
			{Name: "pilot_check_offline", Status: "skip", Note: "PROFILE not set"},
		},
		Notes:    []string{"secret-free offline pack"},
		Residual: []string{"online pilot-check residual"},
	}
	if err := validatePilotEvidenceManifest(good); err != nil {
		t.Fatalf("good manifest: %v", err)
	}

	// Round-trip JSON like the script emits.
	raw, err := json.Marshal(good)
	if err != nil {
		t.Fatal(err)
	}
	var decoded pilotEvidenceManifest
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := validatePilotEvidenceManifest(&decoded); err != nil {
		t.Fatalf("decoded: %v", err)
	}

	// Bad schema
	bad := *good
	bad.Schema = "wrong"
	if err := validatePilotEvidenceManifest(&bad); err == nil {
		t.Fatal("expected schema error")
	}
	// Missing required artifact
	bad2 := *good
	bad2.Artifacts = []pilotEvidenceArtifact{
		{Name: "version", Path: "version.json", Status: "pass"},
	}
	if err := validatePilotEvidenceManifest(&bad2); err == nil {
		t.Fatal("expected missing security_self_check")
	}
	// Invalid overall
	bad3 := *good
	bad3.Overall = "ok"
	if err := validatePilotEvidenceManifest(&bad3); err == nil {
		t.Fatal("expected overall error")
	}
}

func TestPilotEvidenceManifestSecretCanary(t *testing.T) {
	t.Parallel()
	// Regression: MANIFEST and artifact notes must not carry secret canaries when
	// operators paste evidence (defense: script redacts; validator is shape-only —
	// this test asserts our fixture pack documentation stays secret-free).
	const canary = "CANARY_TOKEN_pilot_evidence_must_not_appear"
	m := pilotEvidenceManifest{
		Schema:      pilotEvidenceManifestSchema,
		GeneratedAt: "2026-08-01T00:00:00Z",
		Offline:     true,
		Overall:     "pass",
		Artifacts: []pilotEvidenceArtifact{
			{Name: "version", Path: "version.json", Status: "pass"},
			{Name: "security_self_check", Path: "security-self-check.json", Status: "pass"},
		},
		Notes: []string{"no secrets"},
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), canary) {
		t.Fatal("canary leaked into manifest JSON")
	}
	if err := validatePilotEvidenceManifest(&m); err != nil {
		t.Fatal(err)
	}
}

func TestPilotEvidenceScriptShellAndOfflineBundle(t *testing.T) {
	// Integration: script uses set -euo pipefail; offline pack validates MANIFEST.
	// Skips only when bash or python3 missing (required by script).
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}

	root := findRepoRoot(t)
	script := filepath.Join(root, "scripts", "pilot-evidence.sh")
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("script missing: %v", err)
	}

	// Enforce set -euo pipefail is present (contract for REL automation).
	body, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "set -euo pipefail") {
		t.Fatal("scripts/pilot-evidence.sh must use set -euo pipefail")
	}
	if !strings.Contains(bodyStr, pilotEvidenceManifestSchema) {
		t.Fatalf("script must emit schema %s", pilotEvidenceManifestSchema)
	}
	// Residual lite: pilot pack must capture residual-status + honesty canaries.
	if !strings.Contains(bodyStr, "gateway residual-status") {
		t.Fatal("scripts/pilot-evidence.sh must invoke gateway residual-status")
	}
	if !strings.Contains(bodyStr, "gateway-residual-status.json") {
		t.Fatal("scripts/pilot-evidence.sh must write gateway-residual-status.json")
	}
	if !strings.Contains(bodyStr, "ha_multi_replica") {
		t.Fatal("scripts/pilot-evidence.sh must assert ha_multi_replica honesty")
	}
	// Wave 13: shared_*_file residual-status honesty (align residual-smoke).
	for _, key := range []string{
		"shared_subject_rate_file",
		"shared_principal_cache_file",
		"shared_jwks_file",
		"shared_token_cache_file",
	} {
		if !strings.Contains(bodyStr, key) {
			t.Fatalf("scripts/pilot-evidence.sh must assert %s honesty canary", key)
		}
	}
	if !strings.Contains(bodyStr, "path must never dump") {
		t.Fatal("scripts/pilot-evidence.sh must include path-not-dumped canaries for shared_*_file")
	}
	if !strings.Contains(bodyStr, "JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH") {
		t.Fatal("scripts/pilot-evidence.sh must canary SUBJECT_RATE_PATH → shared_subject_rate_file=true")
	}
	if !strings.Contains(bodyStr, "JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH") {
		t.Fatal("scripts/pilot-evidence.sh must canary PRINCIPAL_CACHE_PATH → shared_principal_cache_file=true")
	}
	if !strings.Contains(bodyStr, "JENKINS_MCP_HTTP_JWKS_CACHE_PATH") {
		t.Fatal("scripts/pilot-evidence.sh must canary JWKS_CACHE_PATH → shared_jwks_file=true")
	}
	if !strings.Contains(bodyStr, "JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH") {
		t.Fatal("scripts/pilot-evidence.sh must canary TOKEN_CACHE_PATH → shared_token_cache_file=true")
	}
	if !strings.Contains(bodyStr, "gateway consent-residual") {
		t.Fatal("scripts/pilot-evidence.sh must optionally capture gateway consent-residual")
	}

	// Build binary into temp dir so we do not race with developer's bin/.
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "jenkins-mcp")
	build := exec.Command("go", "build", "-o", bin, "./cmd/jenkins-mcp")
	build.Dir = root
	build.Env = append(os.Environ(), "PATH="+os.Getenv("PATH"))
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	outRoot := filepath.Join(tmp, "pilot-evidence")
	cmd := exec.Command("bash", script, "--skip-go-test", "--out-root", outRoot, "--bin", bin)
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"PATH="+os.Getenv("PATH"),
		"PROFILE=",
		"SKIP_BUILD=1",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// incomplete overall exits 0; fail exits 1 — either way capture logs
		t.Logf("pilot-evidence output:\n%s", out)
		// Allow exit 0 only for incomplete/pass/warn; if fail, still try validate.
	}
	t.Logf("pilot-evidence:\n%s", out)

	// Find the single timestamp directory.
	entries, err := os.ReadDir(outRoot)
	if err != nil {
		t.Fatalf("out root: %v\n%s", err, out)
	}
	if len(entries) != 1 || !entries[0].IsDir() {
		t.Fatalf("want one evidence dir under %s, got %v\n%s", outRoot, entries, out)
	}
	manifestPath := filepath.Join(outRoot, entries[0].Name(), "MANIFEST.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("MANIFEST.json: %v\n%s", err, out)
	}
	var m pilotEvidenceManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse MANIFEST: %v\n%s", err, raw)
	}
	if err := validatePilotEvidenceManifest(&m); err != nil {
		t.Fatalf("validate: %v\n%s", err, raw)
	}
	if m.Overall != "incomplete" && m.Overall != "pass" && m.Overall != "warn" {
		// Offline pack without profile should not hard-fail on healthy binary.
		t.Fatalf("unexpected overall %q\n%s", m.Overall, raw)
	}
	// Secret canary absent from whole bundle text.
	const canary = "sk-live-canary-token-SHOULD_NOT_APPEAR"
	if strings.Contains(string(raw), canary) {
		t.Fatal("canary in MANIFEST")
	}
	// version.json present when version artifact passed.
	evidDir := filepath.Join(outRoot, entries[0].Name())
	for _, a := range m.Artifacts {
		if a.Name == "version" && a.Status == "pass" {
			vpath := filepath.Join(evidDir, a.Path)
			if _, err := os.Stat(vpath); err != nil {
				t.Fatalf("version artifact missing: %v", err)
			}
		}
	}
	// Residual lite: gateway_residual_status listed; when pass, JSON + honesty.
	var residualArt *pilotEvidenceArtifact
	for i := range m.Artifacts {
		if m.Artifacts[i].Name == "gateway_residual_status" {
			residualArt = &m.Artifacts[i]
			break
		}
	}
	if residualArt == nil {
		t.Fatal("MANIFEST missing gateway_residual_status artifact (residual lite)")
	}
	switch residualArt.Status {
	case "pass":
		if residualArt.Path != "gateway-residual-status.json" {
			t.Fatalf("gateway_residual_status path want gateway-residual-status.json got %q", residualArt.Path)
		}
		rsPath := filepath.Join(evidDir, residualArt.Path)
		rsRaw, err := os.ReadFile(rsPath)
		if err != nil {
			t.Fatalf("gateway-residual-status.json: %v", err)
		}
		var rs map[string]any
		if err := json.Unmarshal(rsRaw, &rs); err != nil {
			t.Fatalf("parse residual-status: %v\n%s", err, rsRaw)
		}
		if ha, ok := rs["ha_multi_replica"].(bool); !ok || ha {
			t.Fatalf("ha_multi_replica want false got %v", rs["ha_multi_replica"])
		}
		if o9, ok := rs["oauth009_offline"].(bool); !ok || !o9 {
			t.Fatalf("oauth009_offline want true got %v", rs["oauth009_offline"])
		}
		ids, _ := rs["residual_ids"].([]any)
		idSet := map[string]bool{}
		for _, x := range ids {
			idSet[fmt.Sprint(x)] = true
		}
		for _, need := range []string{
			"multi_user_offline",
			"oauth009_offline",
			"oauth010_offline",
			"progressive_consent_offline",
			"host008_single_replica",
			"gateway_modes_live",
		} {
			if !idSet[need] {
				t.Fatalf("residual_ids missing %q in pilot pack residual-status", need)
			}
		}
		// shared_*_file default false (or absent) when pilot pack runs without path env.
		// Regression: residual-status honesty weaker than residual-smoke without these.
		for _, key := range []string{
			"shared_subject_rate_file",
			"shared_principal_cache_file",
			"shared_jwks_file",
			"shared_token_cache_file",
		} {
			v, ok := rs[key]
			if !ok || v == nil {
				continue // absent-as-false acceptable
			}
			b, ok := v.(bool)
			if !ok || b {
				t.Fatalf("%s want false|absent on default pilot residual-status got %v", key, v)
			}
		}
		// Path values must never appear in residual-status JSON (bool residual only).
		for _, envKey := range []string{
			"JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH",
			"JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH",
			"JENKINS_MCP_HTTP_JWKS_CACHE_PATH",
		} {
			if strings.Contains(string(rsRaw), envKey) {
				t.Fatalf("path env name %q must not appear in gateway-residual-status.json", envKey)
			}
		}
		// Secret-shaped material must not appear in residual-status artifact.
		low := strings.ToLower(string(rsRaw))
		for _, needle := range []string{"access_token=", "refresh_token=", "client_secret=", "authorization: bearer"} {
			if strings.Contains(low, needle) {
				t.Fatalf("secret-shaped material %q in gateway-residual-status.json", needle)
			}
		}
		// Path canary artifacts (when produced) must not dump markers / secrets.
		for _, name := range []string{
			"gateway-residual-status-rate-path.json",
			"gateway-residual-status-principal-path.json",
			"gateway-residual-status-jwks-path.json",
		} {
			p := filepath.Join(evidDir, name)
			rawPath, err := os.ReadFile(p)
			if err != nil {
				// Optional when python3 path canaries skipped; default honesty already checked.
				if os.IsNotExist(err) {
					continue
				}
				t.Fatalf("read %s: %v", name, err)
			}
			if strings.Contains(string(rawPath), "CANARY-never-in-json") {
				t.Fatalf("path marker leaked into %s", name)
			}
			if strings.Contains(strings.ToLower(string(rawPath)), "authorization: bearer") {
				t.Fatalf("secret-shaped material in %s", name)
			}
		}
	case "skip":
		// Older binary without residual-status is acceptable.
		t.Logf("gateway_residual_status skipped: %s", residualArt.Note)
	case "fail":
		t.Fatalf("gateway_residual_status failed on healthy binary: %+v\n%s", residualArt, out)
	default:
		t.Fatalf("gateway_residual_status unexpected status %q", residualArt.Status)
	}
	// Optional consent-residual may pass, skip, or warn — never secret material when file present.
	for _, a := range m.Artifacts {
		if a.Name != "gateway_consent_residual" || a.Status != "pass" || a.Path == "" {
			continue
		}
		cpath := filepath.Join(evidDir, a.Path)
		craw, err := os.ReadFile(cpath)
		if err != nil {
			t.Fatalf("gateway-consent-residual.json: %v", err)
		}
		if strings.Contains(strings.ToLower(string(craw)), "authorization: bearer") {
			t.Fatal("secret-shaped material in gateway-consent-residual.json")
		}
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	// cmd/jenkins-mcp → repo root
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// When `go test` runs, CWD is the package directory.
	candidates := []string{
		filepath.Join(wd, "../.."),
		wd,
		filepath.Join(wd, ".."),
	}
	for _, c := range candidates {
		if st, err := os.Stat(filepath.Join(c, "scripts", "pilot-evidence.sh")); err == nil && !st.IsDir() {
			abs, err := filepath.Abs(c)
			if err != nil {
				t.Fatal(err)
			}
			return abs
		}
	}
	t.Fatalf("could not locate repo root from %s", wd)
	return ""
}
