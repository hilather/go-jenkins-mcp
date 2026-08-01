package diagnostics_test

import (
	"archive/zip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/audit"
	"github.com/simonfxr/go-jenkins-mcp/internal/config"
	"github.com/simonfxr/go-jenkins-mcp/internal/diagnostics"
	"github.com/simonfxr/go-jenkins-mcp/internal/keyring"
	"github.com/simonfxr/go-jenkins-mcp/internal/profile"
	"github.com/simonfxr/go-jenkins-mcp/internal/telemetry"
)

// privacyCanary is a planted secret for QA-006 combined support-bundle + audit paths.
// Regression: support-bundle and audit must never retain this value.
const privacyCanary = "QA006_PRIVACY_CANARY_token_must_never_export_7f3a9c"

// TestPrivacyRetention_SupportBundleAndAuditExcludeSecrets is the QA-006 automated
// canary: support-bundle zip and audit sink both exclude planted secrets.
func TestPrivacyRetention_SupportBundleAndAuditExcludeSecrets(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(root, "cfg"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
	_ = os.MkdirAll(paths.ProfilesDir(), 0o700)
	outDir := filepath.Join(root, "bundles")

	kr := keyring.NewStore(keyring.NewMemory())
	if err := kr.SetAPIToken(keyring.CredentialRef{
		ProfileID: "corp",
		Origin:    "https://jenkins.example.com",
		Method:    "api_token",
		Account:   "alice",
	}, privacyCanary); err != nil {
		t.Fatalf("plant keyring: %v", err)
	}

	// Audit path: attempt to inject canary into free-form-ish fields.
	mem := &audit.Memory{}
	if err := mem.Emit(context.Background(), audit.Event{
		Type:        audit.TypeLoginFail,
		ProfileID:   "corp",
		PrincipalID: "alice",
		Tool:        "jenkins_get_build_logs",
		Action:      "login",
		Decision:    audit.DecisionFail,
		ReasonCode:  "auth_failed",
		RequestID:   "Bearer " + privacyCanary,
	}); err != nil {
		t.Fatal(err)
	}
	auditJSON, err := json.Marshal(mem.Events())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(auditJSON), privacyCanary) {
		t.Fatalf("Regression: privacy canary leaked into audit events: %s", auditJSON)
	}

	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com/",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
		DisplayName:   "no-secret-here",
	}
	rep := diagnostics.Report{
		ProfileID: "corp",
		Overall:   diagnostics.StatusOK,
		Version:   "test",
		Checks: []diagnostics.Check{{
			Name:    "binary",
			Status:  diagnostics.StatusOK,
			Message: "ok",
		}},
	}
	m := telemetry.NewMetrics()
	m.Inc(telemetry.MetricToolCalls, 1)

	res, err := diagnostics.CreateSupportBundle(context.Background(), diagnostics.SupportBundleOptions{
		Profile:      p,
		Paths:        &paths,
		OutputDir:    outDir,
		DoctorReport: &rep,
		Version:      "test",
		Commit:       "deadbeef",
		Metrics:      m,
		CapabilitySummary: map[string]any{
			"jenkinsVersion": "2.462.3",
			"token":          privacyCanary, // secret-like key must be dropped
			"authorization":  "Bearer " + privacyCanary,
		},
		DoctorOpts: diagnostics.DoctorOptions{
			Keyring:     kr,
			SkipNetwork: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	zr, err := zip.OpenReader(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	for _, f := range zr.File {
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
		if strings.Contains(body, privacyCanary) {
			t.Fatalf("Regression: privacy canary leaked in support-bundle member %s", f.Name)
		}
	}

	// Preview plan still lists secret categories as excluded (REL-002 cache privacy gate).
	prev, err := diagnostics.CreateSupportBundle(context.Background(), diagnostics.SupportBundleOptions{
		Profile:     p,
		PreviewOnly: true,
		Version:     "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(prev.Plan.Excluded, ",")
	for _, want := range []string{"tokens", "keyring", "full_build_logs"} {
		if !strings.Contains(joined, want) {
			t.Errorf("preview excluded missing %q: %s", want, joined)
		}
	}
}
