package diagnostics_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/config"
	"github.com/simonfxr/go-jenkins-mcp/internal/diagnostics"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/keyring"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
	"github.com/simonfxr/go-jenkins-mcp/internal/profile"
	"github.com/simonfxr/go-jenkins-mcp/internal/telemetry"
	"github.com/simonfxr/go-jenkins-mcp/internal/update"
)

const doctorCanary = "DOCTOR_CANARY_token_must_never_appear_xyz789"

func TestRunDoctor_OfflineNoSecrets(t *testing.T) {
	// Not parallel with Setenv: isolate LKG path so update_lkg resolves under Paths.
	t.Setenv(update.EnvUpdateLKGPath, "")
	t.Setenv(gateway.EnvGatewayMultiUser, "")
	t.Setenv(gateway.EnvGatewayCredentialMode, string(gateway.CredentialModeAPITokenVault))
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(root, "cfg"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
	_ = os.MkdirAll(paths.ProfilesDir(), 0o700)

	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com/",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	// Inject canary into username only as a negative control for message scrubbing
	// is not needed; secret canary must not appear even if present in error paths.
	kr := keyring.NewStore(keyring.NewMemory())

	rep, err := diagnostics.RunDoctor(context.Background(), diagnostics.DoctorOptions{
		Profile:     p,
		Paths:       &paths,
		Keyring:     kr,
		Version:     "test",
		Commit:      "abc",
		SkipNetwork: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Overall == "" {
		t.Fatal("overall empty")
	}
	// Must have core checks.
	names := map[string]bool{}
	for _, c := range rep.Checks {
		names[c.Name] = true
		if strings.Contains(c.Message, doctorCanary) {
			t.Fatalf("canary in message: %s", c.Message)
		}
		for k, v := range c.Details {
			if diagnosticsLooksSecretKey(k) {
				t.Fatalf("secret-like detail key %q", k)
			}
			if s, ok := v.(string); ok && strings.Contains(s, doctorCanary) {
				t.Fatalf("canary in detail %s=%s", k, s)
			}
		}
	}
	for _, want := range []string{"binary", "profile", "keyring", "data_dir", "store", "policy", "read_only", "mutations", "identity", "rs_auth", "jenkins_as_as", "metrics", "circuit_breaker", "gateway_status", "update_lkg"} {
		if !names[want] {
			t.Errorf("missing check %q", want)
		}
	}
	// Offline identity is skip; api_token skips Jenkins-as-AS structural check.
	// Circuit without client is skip (offline-capable doctor).
	for _, c := range rep.Checks {
		if c.Name == "identity" && c.Status != diagnostics.StatusSkip {
			t.Fatalf("identity offline: %s %s", c.Status, c.Message)
		}
		if c.Name == "keyring" && c.Status != diagnostics.StatusFail {
			// No credential stored → fail (actionable).
			t.Fatalf("keyring without cred: %s %s", c.Status, c.Message)
		}
		if c.Name == "jenkins_as_as" && c.Status != diagnostics.StatusSkip {
			t.Fatalf("jenkins_as_as for api_token: %s %s", c.Status, c.Message)
		}
		if c.Name == "circuit_breaker" && c.Status != diagnostics.StatusSkip {
			t.Fatalf("circuit_breaker without client: %s %s", c.Status, c.Message)
		}
		if c.Name == "update_lkg" && c.Status != diagnostics.StatusSkip {
			// Isolated temp Paths with no LKG → skip.
			t.Fatalf("update_lkg without LKG: %s %s", c.Status, c.Message)
		}
		if c.Name == "gateway_status" {
			if c.Status != diagnostics.StatusOK {
				t.Fatalf("gateway_status multi_user off: %s %s", c.Status, c.Message)
			}
			if c.Details["multi_user_enabled"] != false {
				t.Fatalf("multi_user_enabled=%v", c.Details["multi_user_enabled"])
			}
			if c.Details["ha_multi_replica"] != false {
				t.Fatalf("HOST-008 residual must report ha_multi_replica=false: %+v", c.Details)
			}
			if c.Details["gateway_ready"] != false {
				t.Fatalf("offline gateway_ready must be false residual: %+v", c.Details)
			}
			if c.Details["credential_mode"] != string(gateway.CredentialModeAPITokenVault) {
				t.Fatalf("credential_mode=%v", c.Details["credential_mode"])
			}
			// Unified modes A/B/C residual honesty (Mode A only in this test).
			if c.Details["mode_a_enabled"] != true || c.Details["mode_b_enabled"] != false || c.Details["mode_c_enabled"] != false {
				t.Fatalf("modes A/B/C flags: %+v", c.Details)
			}
			if c.Details["mode_a_live_obtain_qualified"] != false ||
				c.Details["mode_b_live_rs_qualified"] != false ||
				c.Details["mode_c_live_agentcore_qualified"] != false {
				t.Fatalf("offline must never claim live mode pins: %+v", c.Details)
			}
			if c.Details["oauth009_offline_only"] != true {
				t.Fatalf("oauth009_offline_only residual: %+v", c.Details)
			}
			res, _ := c.Details["mode_matrix_residual"].(string)
			if !strings.Contains(res, "mode_a") {
				t.Fatalf("want mode_a residual honesty: %q", res)
			}
		}
	}

	var buf bytes.Buffer
	diagnostics.FormatReportText(&buf, rep)
	out := buf.String()
	if strings.Contains(out, doctorCanary) {
		t.Fatalf("canary in formatted report: %s", out)
	}
	if strings.Contains(strings.ToLower(out), "api_token:") || strings.Contains(out, "token:") {
		t.Fatalf("token field in doctor output: %s", out)
	}
}

// HOST-008 / multi-user residual: doctor surfaces multi_user_enabled warn + secret-free fields.
func TestRunDoctor_GatewayStatus_MultiUserResidual(t *testing.T) {
	t.Setenv(update.EnvUpdateLKGPath, "")
	t.Setenv(gateway.EnvGatewayMultiUser, "1")
	t.Setenv(gateway.EnvGatewayCredentialMode, string(gateway.CredentialModeAgentCore))
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(root, "cfg"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com/",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	rep, err := diagnostics.RunDoctor(context.Background(), diagnostics.DoctorOptions{
		Profile:     p,
		Paths:       &paths,
		Keyring:     keyring.NewStore(keyring.NewMemory()),
		Version:     "test",
		SkipNetwork: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var gs *diagnostics.Check
	for i := range rep.Checks {
		if rep.Checks[i].Name == "gateway_status" {
			gs = &rep.Checks[i]
			break
		}
	}
	if gs == nil {
		t.Fatal("missing gateway_status check")
	}
	if gs.Status != diagnostics.StatusWarn {
		t.Fatalf("multi_user env set → warn residual, got %s %s", gs.Status, gs.Message)
	}
	if gs.Details["multi_user_enabled"] != true {
		t.Fatalf("multi_user_enabled=%v", gs.Details["multi_user_enabled"])
	}
	if gs.Details["ha_multi_replica"] != false || gs.Details["gateway_ready"] != false {
		t.Fatalf("HOST-008 residual fields: %+v", gs.Details)
	}
	if gs.Details["credential_mode"] != string(gateway.CredentialModeAgentCore) {
		t.Fatalf("credential_mode=%v", gs.Details["credential_mode"])
	}
	if gs.Details["mode_c_enabled"] != true {
		t.Fatalf("mode_c_enabled=%v", gs.Details["mode_c_enabled"])
	}
	if gs.Details["mode_c_live_agentcore_qualified"] != false {
		t.Fatalf("must not claim live AgentCore pin offline: %+v", gs.Details)
	}
	res, _ := gs.Details["mode_matrix_residual"].(string)
	if !strings.Contains(res, "mode_c") {
		t.Fatalf("want mode_c residual honesty: %q", res)
	}
	// Canary: message/details never include vault tokens.
	blob := gs.Message
	for k, v := range gs.Details {
		blob += k
		if s, ok := v.(string); ok {
			blob += s
		}
	}
	if strings.Contains(blob, doctorCanary) {
		t.Fatal("canary in gateway_status")
	}
}

// Unified offline residual honesty for gateway Mode B (OAUTH-009).
func TestRunDoctor_GatewayStatus_ModeBResidualHonesty(t *testing.T) {
	t.Setenv(update.EnvUpdateLKGPath, "")
	t.Setenv(gateway.EnvGatewayMultiUser, "")
	t.Setenv(gateway.EnvGatewayCredentialMode, string(gateway.CredentialModeJWTRSBearer))
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(root, "cfg"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com/",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	rep, err := diagnostics.RunDoctor(context.Background(), diagnostics.DoctorOptions{
		Profile:     p,
		Paths:       &paths,
		Keyring:     keyring.NewStore(keyring.NewMemory()),
		Version:     "test",
		SkipNetwork: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var gs *diagnostics.Check
	for i := range rep.Checks {
		if rep.Checks[i].Name == "gateway_status" {
			gs = &rep.Checks[i]
			break
		}
	}
	if gs == nil {
		t.Fatal("missing gateway_status")
	}
	if gs.Status != diagnostics.StatusWarn {
		t.Fatalf("mode B residual should warn: %s %s", gs.Status, gs.Message)
	}
	if gs.Details["mode_b_enabled"] != true || gs.Details["mode_b_live_rs_qualified"] != false {
		t.Fatalf("mode B residual fields: %+v", gs.Details)
	}
	res, _ := gs.Details["mode_matrix_residual"].(string)
	if !strings.Contains(res, "OAUTH-009") || !strings.Contains(res, "mode_b") {
		t.Fatalf("mode B residual honesty: %q", res)
	}
	if !strings.Contains(gs.Message, "OAUTH-009") && !strings.Contains(gs.Message, "jwt-auth-filter") {
		t.Fatalf("message should note Mode B live residual: %s", gs.Message)
	}
}

// Wave 38 / POL-005: doctor policy check Details include deny_branch_names_count
// when the overlay has the field (StatusMap passthrough).
func TestRunDoctor_PolicyStatusMap_DenyBranchNamesCount(t *testing.T) {
	t.Setenv(update.EnvUpdateLKGPath, "")
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(root, "cfg"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
	_ = os.MkdirAll(paths.ProfilesDir(), 0o700)

	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com/",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	kr := keyring.NewStore(keyring.NewMemory())

	polRes := &policy.LoadResult{
		Present:        true,
		Path:           "/etc/jenkins-mcp/policy/overlay.json",
		SignatureState: "unverified_pilot",
		Overlay: &policy.Overlay{
			Version:           1,
			ForceReadOnly:     true,
			Mode:              policy.ModePilot,
			DenyTools:         []string{"jenkins_get_build_logs"},
			DenyJobPrefixes:   []string{"secret-folder"},
			DenyNodeNames:     []string{"prod-agent-*"},
			DenyViewNames:     []string{"secret-view"},
			DenyArtifactPaths: []string{"secrets/**"},
			DenyBranchNames:   []string{"release/*", "main"},
		},
	}

	rep, err := diagnostics.RunDoctor(context.Background(), diagnostics.DoctorOptions{
		Profile:      p,
		Paths:        &paths,
		Keyring:      kr,
		Version:      "test",
		Commit:       "abc",
		SkipNetwork:  true,
		PolicyResult: polRes,
	})
	if err != nil {
		t.Fatal(err)
	}
	var policyCheck *diagnostics.Check
	for i := range rep.Checks {
		if rep.Checks[i].Name == "policy" {
			policyCheck = &rep.Checks[i]
			break
		}
	}
	if policyCheck == nil {
		t.Fatal("missing policy check")
	}
	if policyCheck.Status != diagnostics.StatusOK {
		t.Fatalf("policy status=%s msg=%s", policyCheck.Status, policyCheck.Message)
	}
	if policyCheck.Details == nil {
		t.Fatal("policy Details nil")
	}
	if got := policyCheck.Details["deny_branch_names_count"]; got != 2 {
		t.Fatalf("deny_branch_names_count=%v want 2 details=%v", got, policyCheck.Details)
	}
	if got := policyCheck.Details["deny_artifact_paths_count"]; got != 1 {
		t.Fatalf("deny_artifact_paths_count=%v", got)
	}
	if got := policyCheck.Details["deny_node_names_count"]; got != 1 {
		t.Fatalf("deny_node_names_count=%v", got)
	}
	// Must not echo pattern bodies as secret-like free text keys.
	for k := range policyCheck.Details {
		if strings.Contains(strings.ToLower(k), "token") || strings.Contains(strings.ToLower(k), "password") {
			t.Fatalf("secret-like detail key %q", k)
		}
	}
}

func TestSanitizeCheck_DropsSecretKeys(t *testing.T) {
	t.Parallel()
	c := diagnostics.SanitizeCheck(diagnostics.Check{
		Name:    "x",
		Status:  diagnostics.StatusOK,
		Message: "Bearer " + doctorCanary,
		Details: map[string]any{
			"token":       doctorCanary,
			"password":    doctorCanary,
			"has_cred":    true,
			"safe_string": "ok",
		},
	})
	if strings.Contains(c.Message, doctorCanary) {
		// redact.Secrets should scrub Bearer tokens.
		t.Fatalf("canary survived redact in message: %q", c.Message)
	}
	if _, ok := c.Details["token"]; ok {
		t.Fatal("token detail key must be dropped")
	}
	if _, ok := c.Details["password"]; ok {
		t.Fatal("password detail key must be dropped")
	}
	if c.Details["has_cred"] != true {
		t.Fatal("safe detail dropped")
	}
}

func TestRunCacheStatus(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(root, "cfg"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com",
		AuthMethod:    profile.AuthMethodAPIToken,
	}
	st, err := diagnostics.RunCacheStatus(context.Background(), diagnostics.CacheStatusOptions{
		Profile: p,
		Paths:   &paths,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !st.DataDirOK || !st.StoreOpen || !st.SchemaOK {
		t.Fatalf("cache status: %+v", st)
	}
	if st.SchemaVersion == 0 {
		t.Fatal("schema version zero")
	}
	var buf bytes.Buffer
	diagnostics.FormatCacheStatusText(&buf, st)
	if strings.Contains(buf.String(), doctorCanary) {
		t.Fatal("canary in cache status")
	}
}

func TestOverallStatus(t *testing.T) {
	t.Parallel()
	if diagnostics.OverallStatus(nil) != diagnostics.StatusOK {
		t.Fatal("empty")
	}
	if diagnostics.OverallStatus([]diagnostics.Check{{Status: diagnostics.StatusWarn}, {Status: diagnostics.StatusOK}}) != diagnostics.StatusWarn {
		t.Fatal("warn")
	}
	if diagnostics.OverallStatus([]diagnostics.Check{{Status: diagnostics.StatusWarn}, {Status: diagnostics.StatusFail}}) != diagnostics.StatusFail {
		t.Fatal("fail wins")
	}
	// Skips must not demote ok (offline identity / absent metrics).
	if diagnostics.OverallStatus([]diagnostics.Check{
		{Status: diagnostics.StatusOK},
		{Status: diagnostics.StatusSkip},
	}) != diagnostics.StatusOK {
		t.Fatal("skip should not demote ok")
	}
}

func TestMetricsSnapshotInDoctor(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(root, "cfg"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
	m := telemetry.NewMetrics()
	m.Inc(telemetry.MetricToolCalls, 3)
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	rep, err := diagnostics.RunDoctor(context.Background(), diagnostics.DoctorOptions{
		Profile:     p,
		Paths:       &paths,
		Keyring:     keyring.NewStore(keyring.NewMemory()),
		SkipNetwork: true,
		Metrics:     m,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range rep.Checks {
		if c.Name == "metrics" {
			if c.Status != diagnostics.StatusOK {
				t.Fatalf("%+v", c)
			}
			return
		}
	}
	t.Fatal("metrics check missing")
}

// Regression JAS-001: doctor flags OIDC issuer co-hosted with Jenkins (offline).
func TestRunDoctor_JenkinsAsASStructuralFail(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(root, "cfg"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
	// Bypass Save/Validate — doctor must still surface the structural AS misconfig.
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "bad-as",
		JenkinsURL:    "https://jenkins.example.com",
		AuthMethod:    profile.AuthMethodOIDC,
		Username:      "alice",
		OIDC: &profile.OIDCConfig{
			Issuer:          "https://jenkins.example.com",
			ClientID:        "client",
			JenkinsAudience: "api://jenkins",
		},
	}
	rep, err := diagnostics.RunDoctor(context.Background(), diagnostics.DoctorOptions{
		Profile:     p,
		Paths:       &paths,
		Keyring:     keyring.NewStore(keyring.NewMemory()),
		SkipNetwork: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, c := range rep.Checks {
		if c.Name != "jenkins_as_as" {
			continue
		}
		found = true
		if c.Status != diagnostics.StatusFail {
			t.Fatalf("expected fail, got %s %s", c.Status, c.Message)
		}
		msg := strings.ToLower(c.Message)
		if !strings.Contains(msg, "jenkins") || !strings.Contains(msg, "authorization") {
			t.Fatalf("expected AS wording: %s", c.Message)
		}
	}
	if !found {
		t.Fatal("jenkins_as_as check missing")
	}
}

// JAS-001: external IdP issuer passes doctor structural AS check.
func TestRunDoctor_JenkinsAsASOKExternalIssuer(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(root, "cfg"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "good-oidc",
		JenkinsURL:    "https://jenkins.example.com",
		AuthMethod:    profile.AuthMethodOIDC,
		Username:      "alice",
		OIDC: &profile.OIDCConfig{
			Issuer:          "https://login.microsoftonline.com/tenant/v2.0",
			ClientID:        "public-client",
			JenkinsAudience: "api://jenkins-api",
			RedirectURIs:    []string{"http://127.0.0.1:9876/callback"},
		},
	}
	rep, err := diagnostics.RunDoctor(context.Background(), diagnostics.DoctorOptions{
		Profile:     p,
		Paths:       &paths,
		Keyring:     keyring.NewStore(keyring.NewMemory()),
		SkipNetwork: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range rep.Checks {
		if c.Name == "jenkins_as_as" {
			if c.Status != diagnostics.StatusOK {
				t.Fatalf("expected ok, got %s %s", c.Status, c.Message)
			}
			return
		}
	}
	t.Fatal("jenkins_as_as check missing")
}

func diagnosticsLooksSecretKey(k string) bool {
	lk := strings.ToLower(k)
	return strings.Contains(lk, "token") || strings.Contains(lk, "password") ||
		strings.Contains(lk, "secret") || strings.Contains(lk, "cookie") ||
		strings.Contains(lk, "authorization") || strings.Contains(lk, "private_key")
}

// OBS Wave 27: doctor reports CircuitState when a client is available (offline-capable).
func TestRunDoctor_CircuitStateWhenClientAvailable(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(root, "cfg"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
	_ = os.MkdirAll(paths.ProfilesDir(), 0o700)

	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com/",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	// Closed client with resilience defaults → circuit closed / OK.
	c := &jenkins.Client{URL: "https://jenkins.example.com/", User: "u", Token: "t"}
	c.WithResilience(jenkins.DefaultResilienceConfig())

	rep, err := diagnostics.RunDoctor(context.Background(), diagnostics.DoctorOptions{
		Profile:     p,
		Paths:       &paths,
		Keyring:     keyring.NewStore(keyring.NewMemory()),
		Version:     "test",
		SkipNetwork: true,
		Circuit:     c,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, ch := range rep.Checks {
		if ch.Name != "circuit_breaker" {
			continue
		}
		if ch.Status != diagnostics.StatusOK {
			t.Fatalf("closed circuit: %s %s", ch.Status, ch.Message)
		}
		if st, _ := ch.Details["state"].(string); st != "closed" {
			t.Fatalf("details.state=%v want closed", ch.Details["state"])
		}
		return
	}
	t.Fatal("circuit_breaker check missing")
}

// stubCircuit implements CircuitStateProvider for open-state doctor warn path.
type stubCircuit struct {
	st jenkins.CircuitState
}

func (s stubCircuit) CircuitState() jenkins.CircuitState { return s.st }

// Wave 32: mutations check — pilot default RO is skip (not registered).
func TestRunDoctor_MutationsDefaultROSkip(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(root, "cfg"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com/",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	rep, err := diagnostics.RunDoctor(context.Background(), diagnostics.DoctorOptions{
		Profile:     p,
		Paths:       &paths,
		Keyring:     keyring.NewStore(keyring.NewMemory()),
		SkipNetwork: true,
		// AllowMutations false: pilot default.
	})
	if err != nil {
		t.Fatal(err)
	}
	ch := findCheck(t, rep, "mutations")
	if ch.Status != diagnostics.StatusSkip {
		t.Fatalf("default RO mutations: %s %s", ch.Status, ch.Message)
	}
	assertMutDetailBool(t, ch, "read_only_effective", true)
	assertMutDetailBool(t, ch, "allow_mutations_opt_in", false)
	assertMutDetailBool(t, ch, "mutations_should_register", false)
	assertMutDetailBool(t, ch, "mutations_executable", false)
}

// Wave 32: allow-mutations + force RO → registered but not executable (warn).
func TestRunDoctor_MutationsRegisteredNotExecutableWarn(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(root, "cfg"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com/",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	force := policy.StaticForce{Force: true, Present: true}
	gate := policy.NewReadOnlyGate(policy.Inputs{
		AllowMutations: true,
		Force:          force,
	})
	rep, err := diagnostics.RunDoctor(context.Background(), diagnostics.DoctorOptions{
		Profile:        p,
		Paths:          &paths,
		Keyring:        keyring.NewStore(keyring.NewMemory()),
		SkipNetwork:    true,
		AllowMutations: true,
		Gate:           gate,
	})
	if err != nil {
		t.Fatal(err)
	}
	ch := findCheck(t, rep, "mutations")
	if ch.Status != diagnostics.StatusWarn {
		t.Fatalf("registered-not-executable: %s %s", ch.Status, ch.Message)
	}
	assertMutDetailBool(t, ch, "read_only_effective", true)
	assertMutDetailBool(t, ch, "allow_mutations_opt_in", true)
	assertMutDetailBool(t, ch, "mutations_should_register", true)
	assertMutDetailBool(t, ch, "mutations_executable", false)
	msg := strings.ToLower(ch.Message)
	if !strings.Contains(msg, "not executable") && !strings.Contains(msg, "registered") {
		t.Fatalf("expected registered/not-executable wording: %s", ch.Message)
	}
	// Secret-free: no token-like keys; tool names not required (count only).
	for k := range ch.Details {
		if diagnosticsLooksSecretKey(k) {
			t.Fatalf("secret-like key in mutations details: %q", k)
		}
	}
	if _, ok := ch.Details["mutation_tool_catalog_count"]; !ok {
		t.Fatal("expected mutation_tool_catalog_count")
	}
}

// Wave 32: allow-mutations without stronger RO → executable ok.
func TestRunDoctor_MutationsExecutableOK(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(root, "cfg"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com/",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	rep, err := diagnostics.RunDoctor(context.Background(), diagnostics.DoctorOptions{
		Profile:        p,
		Paths:          &paths,
		Keyring:        keyring.NewStore(keyring.NewMemory()),
		SkipNetwork:    true,
		AllowMutations: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ch := findCheck(t, rep, "mutations")
	if ch.Status != diagnostics.StatusOK {
		t.Fatalf("executable mutations: %s %s", ch.Status, ch.Message)
	}
	assertMutDetailBool(t, ch, "read_only_effective", false)
	assertMutDetailBool(t, ch, "allow_mutations_opt_in", true)
	assertMutDetailBool(t, ch, "mutations_should_register", true)
	assertMutDetailBool(t, ch, "mutations_executable", true)
}

// Wave 32: live Gate preferred over reconstructed Inputs (force clear mid-life).
func TestRunDoctor_MutationsUsesLiveGate(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(root, "cfg"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com/",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	dyn := policy.NewDynamicForce(true, true)
	gate := policy.NewReadOnlyGate(policy.Inputs{
		AllowMutations: true,
		Force:          dyn,
	})
	// DoctorOptions AllowMutations false would reconstruct pilot RO — Gate wins.
	rep, err := diagnostics.RunDoctor(context.Background(), diagnostics.DoctorOptions{
		Profile:        p,
		Paths:          &paths,
		Keyring:        keyring.NewStore(keyring.NewMemory()),
		SkipNetwork:    true,
		AllowMutations: false,
		Gate:           gate,
	})
	if err != nil {
		t.Fatal(err)
	}
	ch := findCheck(t, rep, "mutations")
	if ch.Status != diagnostics.StatusWarn {
		t.Fatalf("live gate force+allow: %s %s", ch.Status, ch.Message)
	}
	// Clear force → executable without re-building doctor options.
	dyn.Set(false, true)
	rep2, err := diagnostics.RunDoctor(context.Background(), diagnostics.DoctorOptions{
		Profile:     p,
		Paths:       &paths,
		Keyring:     keyring.NewStore(keyring.NewMemory()),
		SkipNetwork: true,
		Gate:        gate,
	})
	if err != nil {
		t.Fatal(err)
	}
	ch2 := findCheck(t, rep2, "mutations")
	if ch2.Status != diagnostics.StatusOK {
		t.Fatalf("after force clear: %s %s", ch2.Status, ch2.Message)
	}
	assertMutDetailBool(t, ch2, "mutations_executable", true)
}

func findCheck(t *testing.T, rep diagnostics.Report, name string) diagnostics.Check {
	t.Helper()
	for _, c := range rep.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("check %q missing", name)
	return diagnostics.Check{}
}

func assertMutDetailBool(t *testing.T, ch diagnostics.Check, key string, want bool) {
	t.Helper()
	v, ok := ch.Details[key]
	if !ok {
		t.Fatalf("missing detail %q in %+v", key, ch.Details)
	}
	got, ok := v.(bool)
	if !ok {
		t.Fatalf("detail %q type %T want bool", key, v)
	}
	if got != want {
		t.Fatalf("detail %q=%v want %v", key, got, want)
	}
}

func TestRunDoctor_CircuitOpenWarns(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(root, "cfg"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com/",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	rep, err := diagnostics.RunDoctor(context.Background(), diagnostics.DoctorOptions{
		Profile:     p,
		Paths:       &paths,
		Keyring:     keyring.NewStore(keyring.NewMemory()),
		SkipNetwork: true,
		Circuit: stubCircuit{st: jenkins.CircuitState{
			State:               "open",
			ConsecutiveFailures: 5,
			FailureThreshold:    5,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, ch := range rep.Checks {
		if ch.Name != "circuit_breaker" {
			continue
		}
		if ch.Status != diagnostics.StatusWarn {
			t.Fatalf("open circuit: %s %s", ch.Status, ch.Message)
		}
		return
	}
	t.Fatal("circuit_breaker check missing")
}

func TestCheckUpdateLKG_SkipAbsent(t *testing.T) {
	// Not parallel: clears LKG env so Paths-based resolution is deterministic.
	t.Setenv(update.EnvUpdateLKGPath, "")
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(root, "cfg"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
	_ = os.MkdirAll(paths.ProfilesDir(), 0o700)
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com/",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	rep, err := diagnostics.RunDoctor(context.Background(), diagnostics.DoctorOptions{
		Profile: p, Paths: &paths, Keyring: keyring.NewStore(keyring.NewMemory()),
		SkipNetwork: true, Version: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, ch := range rep.Checks {
		if ch.Name == "update_lkg" {
			if ch.Status != diagnostics.StatusSkip {
				t.Fatalf("want skip: %s %s", ch.Status, ch.Message)
			}
			return
		}
	}
	t.Fatal("update_lkg missing")
}

func TestCheckUpdateLKG_OKMatch(t *testing.T) {
	t.Setenv(update.EnvUpdateLKGPath, "")
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(root, "cfg"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
	_ = os.MkdirAll(paths.UpdateDataDir(), 0o700)
	payload := []byte("doctor-lkg-ok")
	// hash via write + update.StoreLKG / VerifyLKG path
	sum := sha256SumDoctor(payload)
	base := "doctor-art.bin"
	if err := os.WriteFile(filepath.Join(paths.UpdateDataDir(), base), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := update.StoreLKG(update.LKGWriteOptions{
		Path: paths.UpdateLKGFile(), Version: "1.2.3", Channel: "stable",
		ArtifactSHA256: sum, ArtifactPath: base,
	}); err != nil {
		t.Fatal(err)
	}
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com/",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	rep, err := diagnostics.RunDoctor(context.Background(), diagnostics.DoctorOptions{
		Profile: p, Paths: &paths, Keyring: keyring.NewStore(keyring.NewMemory()),
		SkipNetwork: true, Version: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, ch := range rep.Checks {
		if ch.Name == "update_lkg" {
			if ch.Status != diagnostics.StatusOK {
				t.Fatalf("want ok: %s %s", ch.Status, ch.Message)
			}
			if !strings.Contains(ch.Message, "1.2.3") {
				t.Fatalf("message: %s", ch.Message)
			}
			return
		}
	}
	t.Fatal("update_lkg missing")
}

func TestCheckUpdateLKG_WarnMissingArtifact(t *testing.T) {
	t.Setenv(update.EnvUpdateLKGPath, "")
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(root, "cfg"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
	_ = os.MkdirAll(paths.UpdateDataDir(), 0o700)
	if _, err := update.StoreLKG(update.LKGWriteOptions{
		Path: paths.UpdateLKGFile(), Version: "1.0.0", Channel: "stable",
		ArtifactSHA256: strings.Repeat("ab", 32), ArtifactPath: "missing.bin",
	}); err != nil {
		t.Fatal(err)
	}
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com/",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	rep, err := diagnostics.RunDoctor(context.Background(), diagnostics.DoctorOptions{
		Profile: p, Paths: &paths, Keyring: keyring.NewStore(keyring.NewMemory()),
		SkipNetwork: true, Version: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, ch := range rep.Checks {
		if ch.Name == "update_lkg" {
			if ch.Status != diagnostics.StatusWarn {
				t.Fatalf("want warn: %s %s", ch.Status, ch.Message)
			}
			return
		}
	}
	t.Fatal("update_lkg missing")
}

func TestCheckUpdateLKG_WarnMismatch(t *testing.T) {
	t.Setenv(update.EnvUpdateLKGPath, "")
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(root, "cfg"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
	_ = os.MkdirAll(paths.UpdateDataDir(), 0o700)
	base := "bad.bin"
	if err := os.WriteFile(filepath.Join(paths.UpdateDataDir(), base), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := update.StoreLKG(update.LKGWriteOptions{
		Path: paths.UpdateLKGFile(), Version: "1.0.0", Channel: "stable",
		ArtifactSHA256: strings.Repeat("cd", 32), ArtifactPath: base,
	}); err != nil {
		t.Fatal(err)
	}
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com/",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	rep, err := diagnostics.RunDoctor(context.Background(), diagnostics.DoctorOptions{
		Profile: p, Paths: &paths, Keyring: keyring.NewStore(keyring.NewMemory()),
		SkipNetwork: true, Version: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, ch := range rep.Checks {
		if ch.Name == "update_lkg" {
			if ch.Status != diagnostics.StatusWarn {
				t.Fatalf("want warn: %s %s", ch.Status, ch.Message)
			}
			if !strings.Contains(strings.ToLower(ch.Message), "mismatch") {
				t.Fatalf("message: %s", ch.Message)
			}
			return
		}
	}
	t.Fatal("update_lkg missing")
}

func sha256SumDoctor(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// OAUTH-010: when gateway Mode C (agentcore_3lo_obo) is explicitly enabled,
// doctor gateway_status must warn live AgentCore residual (offline matrix is not a pin).
func TestRunDoctor_ModeC_GatewayStatusResidual(t *testing.T) {
	t.Setenv(update.EnvUpdateLKGPath, "")
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(root, "cfg"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
	_ = os.MkdirAll(paths.ProfilesDir(), 0o700)
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com/",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	getenv := func(k string) string {
		if k == gateway.EnvGatewayCredentialMode {
			return string(gateway.CredentialModeAgentCore)
		}
		return ""
	}
	rep, err := diagnostics.RunDoctor(context.Background(), diagnostics.DoctorOptions{
		Profile:     p,
		Paths:       &paths,
		Keyring:     keyring.NewStore(keyring.NewMemory()),
		SkipNetwork: true,
		Version:     "test",
		Getenv:      getenv,
	})
	if err != nil {
		t.Fatal(err)
	}
	var gs diagnostics.Check
	for _, c := range rep.Checks {
		if c.Name == "gateway_status" {
			gs = c
			break
		}
	}
	if gs.Name == "" {
		t.Fatal("gateway_status missing")
	}
	if gs.Status != diagnostics.StatusWarn {
		t.Fatalf("Mode C gateway_status want warn got %s %s", gs.Status, gs.Message)
	}
	if !strings.Contains(gs.Message, "Mode C") && !strings.Contains(gs.Message, "agentcore") {
		t.Fatalf("message must note Mode C: %s", gs.Message)
	}
	if !strings.Contains(gs.Message, "OAUTH-010") {
		t.Fatalf("message must note OAUTH-010: %s", gs.Message)
	}
	if gs.Details["gateway_mode_c_enabled"] != true {
		t.Fatalf("gateway_mode_c_enabled: %+v", gs.Details)
	}
	if gs.Details["mode_c_live_agentcore_qualified"] != false {
		t.Fatalf("must not claim live AgentCore qualified: %+v", gs.Details)
	}
	if gs.Details["gateway_ready"] != false {
		t.Fatalf("offline gateway_ready must stay false: %+v", gs.Details)
	}
	// Progressive consent residual (OAUTH-010): browser 3LO not automated; metadata Done*.
	if gs.Details["progressive_consent_browser_3lo_automated"] != false {
		t.Fatalf("browser_3lo_automated: %+v", gs.Details)
	}
	if gs.Details["progressive_consent_metadata_path_done_star"] != true {
		t.Fatalf("metadata_path_done_star: %+v", gs.Details)
	}
	if gs.Details["progressive_consent_last_would_apply"] != true {
		t.Fatalf("last_would_apply: %+v", gs.Details)
	}
	resNote, _ := gs.Details["progressive_consent_residual"].(string)
	if !strings.Contains(resNote, "OAUTH-010") || !strings.Contains(strings.ToLower(resNote), "not automated") {
		t.Fatalf("progressive_consent_residual honesty: %q", resNote)
	}
	if !strings.Contains(gs.Message, "progressive consent") && !strings.Contains(gs.Message, "browser 3LO") {
		t.Fatalf("Mode C message should note progressive consent residual: %s", gs.Message)
	}
	// Residual text secret-free.
	if strings.Contains(gs.Message, doctorCanary) {
		t.Fatal("canary in message")
	}
	if strings.Contains(resNote, doctorCanary) {
		t.Fatal("canary in progressive residual")
	}
	// Mode A primary must not elevate Mode C warn.
	getenvA := func(k string) string {
		if k == gateway.EnvGatewayCredentialMode {
			return string(gateway.CredentialModeAPITokenVault)
		}
		return ""
	}
	repA, err := diagnostics.RunDoctor(context.Background(), diagnostics.DoctorOptions{
		Profile:     p,
		Paths:       &paths,
		Keyring:     keyring.NewStore(keyring.NewMemory()),
		SkipNetwork: true,
		Version:     "test",
		Getenv:      getenvA,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range repA.Checks {
		if c.Name == "gateway_status" {
			if c.Details["gateway_mode_c_enabled"] == true {
				t.Fatalf("Mode A must not report Mode C enabled: %+v", c.Details)
			}
			if c.Status == diagnostics.StatusWarn && strings.Contains(c.Message, "Mode C") {
				t.Fatalf("Mode A must not Mode C warn: %s", c.Message)
			}
			return
		}
	}
	t.Fatal("gateway_status missing on Mode A run")
}

// OAUTH-009: when gateway Mode B (jwt_rs_bearer) is enabled, doctor rs_auth
// must warn live RS residual (offline vault is not a production pin).
func TestRunDoctor_ModeB_RSAuthResidual(t *testing.T) {
	t.Setenv(update.EnvUpdateLKGPath, "")
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(root, "cfg"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
	_ = os.MkdirAll(paths.ProfilesDir(), 0o700)
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com/",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	getenv := func(k string) string {
		if k == "JENKINS_MCP_GATEWAY_CREDENTIAL_MODE" {
			return "jwt_rs_bearer"
		}
		return ""
	}
	rep, err := diagnostics.RunDoctor(context.Background(), diagnostics.DoctorOptions{
		Profile:     p,
		Paths:       &paths,
		Keyring:     keyring.NewStore(keyring.NewMemory()),
		SkipNetwork: true,
		Version:     "test",
		Getenv:      getenv,
	})
	if err != nil {
		t.Fatal(err)
	}
	var rs diagnostics.Check
	for _, c := range rep.Checks {
		if c.Name == "rs_auth" {
			rs = c
			break
		}
	}
	if rs.Name == "" {
		t.Fatal("rs_auth missing")
	}
	if rs.Status != diagnostics.StatusWarn {
		t.Fatalf("Mode B rs_auth want warn got %s %s", rs.Status, rs.Message)
	}
	if !strings.Contains(rs.Message, "Mode B") && !strings.Contains(rs.Message, "jwt_rs_bearer") {
		t.Fatalf("message must note Mode B: %s", rs.Message)
	}
	if rs.Details["gateway_mode_b_enabled"] != true {
		t.Fatalf("gateway_mode_b_enabled: %+v", rs.Details)
	}
	if rs.Details["mode_b_live_rs_qualified"] != false {
		t.Fatalf("must not claim live RS qualified: %+v", rs.Details)
	}
	if rs.Details["id_jwt_never_api_credential"] != true {
		t.Fatalf("id_jwt note: %+v", rs.Details)
	}
	if rs.Details["live_lab_still_required"] != true {
		t.Fatalf("live_lab_still_required: %+v", rs.Details)
	}
	// Residual text secret-free.
	if strings.Contains(rs.Message, doctorCanary) {
		t.Fatal("canary in message")
	}
}
