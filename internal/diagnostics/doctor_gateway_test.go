package diagnostics_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/config"
	"github.com/hilather/go-jenkins-mcp/internal/diagnostics"
	"github.com/hilather/go-jenkins-mcp/internal/gateway"
	"github.com/hilather/go-jenkins-mcp/internal/keyring"
	"github.com/hilather/go-jenkins-mcp/internal/profile"
	"github.com/hilather/go-jenkins-mcp/internal/update"
)

const multiPodCanary = "MULTI_POD_CANARY_token_must_never_appear_xyz"

// HOST-008: multi_pod_vault_residual is always true (honest residual, not multi-replica Done).
func TestMultiPodResidualFromEnviron_AlwaysVaultResidual(t *testing.T) {
	mp := diagnostics.MultiPodResidualFromEnviron(func(string) string { return "" })
	if !mp.MultiPodVaultResidual {
		t.Fatal("multi_pod_vault_residual must always be true")
	}
	if mp.KubernetesEnvDetected || mp.VaultEmptyDirHeuristic || mp.ReplicasEnvResidual {
		t.Fatalf("empty env should not set multi-pod signals: %+v", mp)
	}
	if mp.Checklist != "" {
		t.Fatalf("checklist only when signals present: %q", mp.Checklist)
	}
}

// HOST-008: KUBERNETES_SERVICE_HOST detection (getenv k8s residual).
func TestMultiPodResidualFromEnviron_KubernetesServiceHost(t *testing.T) {
	getenv := func(k string) string {
		if k == "KUBERNETES_SERVICE_HOST" {
			return "10.96.0.1"
		}
		return ""
	}
	mp := diagnostics.MultiPodResidualFromEnviron(getenv)
	if !mp.MultiPodVaultResidual {
		t.Fatal("multi_pod_vault_residual always true")
	}
	if !mp.KubernetesEnvDetected {
		t.Fatal("want kubernetes_env_detected when KUBERNETES_SERVICE_HOST set")
	}
	if mp.Checklist == "" {
		t.Fatal("want multi-pod residual checklist when k8s detected")
	}
	// Secret-free checklist: sticky / vault / rate / Obtain.
	for _, want := range []string{"sticky", "vault", "rate", "Obtain", "HOST-008"} {
		if !strings.Contains(mp.Checklist, want) {
			t.Fatalf("checklist missing %q: %s", want, mp.Checklist)
		}
	}
	if strings.Contains(mp.Checklist, multiPodCanary) {
		t.Fatal("canary in checklist")
	}
}

// HOST-008: emptyDir-ish vault path heuristic (path shape only; no secrets).
func TestMultiPodResidualFromEnviron_VaultEmptyDirHeuristic(t *testing.T) {
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"tmp", "/tmp/jenkins-mcp/vault.json", true},
		{"tmp_exact", "/tmp", true},
		{"tmp_not_prefix", "/tmpfoo/vault.json", false},
		{"var_run", "/var/run/secrets/vault.json", true},
		{"dev_shm", "/dev/shm/vault.json", true},
		{"emptydir_seg", "/data/emptydir/vault.json", true},
		{"home_ok", "/home/nonroot/.local/share/jenkins-mcp/gateway/apitoken_vault.json", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			getenv := func(k string) string {
				if k == gateway.EnvGatewayVaultPath {
					return tc.path
				}
				// Avoid default path under /tmp on some hosts by pinning HOME.
				if k == "HOME" {
					return "/home/nonroot"
				}
				if k == "XDG_DATA_HOME" {
					return "/home/nonroot/.local/share"
				}
				return ""
			}
			mp := diagnostics.MultiPodResidualFromEnviron(getenv)
			if mp.VaultEmptyDirHeuristic != tc.want {
				t.Fatalf("VaultEmptyDirHeuristic=%v want %v path=%q", mp.VaultEmptyDirHeuristic, tc.want, tc.path)
			}
			if tc.want && mp.Checklist == "" {
				t.Fatal("want checklist when emptyDir heuristic")
			}
			// Never embed vault path in checklist (secret-free residual).
			if tc.path != "" && strings.Contains(mp.Checklist, tc.path) {
				t.Fatalf("checklist must not embed vault path: %s", mp.Checklist)
			}
		})
	}
}

// HOST-008: residual replicas-like env > 1.
func TestMultiPodResidualFromEnviron_ReplicasEnvResidual(t *testing.T) {
	getenv := func(k string) string {
		if k == "JENKINS_MCP_GATEWAY_REPLICAS" {
			return "3"
		}
		if k == "HOME" {
			return "/home/nonroot"
		}
		return ""
	}
	mp := diagnostics.MultiPodResidualFromEnviron(getenv)
	if !mp.ReplicasEnvResidual {
		t.Fatal("want replicas_env_residual when REPLICAS>1")
	}
	if mp.Checklist == "" {
		t.Fatal("want checklist")
	}
	// replicas=1 must not fire.
	getenv1 := func(k string) string {
		if k == "REPLICAS" {
			return "1"
		}
		if k == "HOME" {
			return "/home/nonroot"
		}
		return ""
	}
	mp1 := diagnostics.MultiPodResidualFromEnviron(getenv1)
	if mp1.ReplicasEnvResidual {
		t.Fatal("replicas=1 must not set residual")
	}
}

// HOST-008: doctor gateway_status warns on k8s env + multi_pod fields (getenv).
func TestRunDoctor_GatewayStatus_KubernetesMultiPodResidual(t *testing.T) {
	t.Setenv(update.EnvUpdateLKGPath, "")
	// Isolate process env for modes; k8s comes from Getenv only.
	t.Setenv(gateway.EnvGatewayMultiUser, "")
	t.Setenv(gateway.EnvGatewayCredentialMode, string(gateway.CredentialModeAPITokenVault))
	t.Setenv(gateway.EnvGatewayVaultPath, filepath.Join("/home/nonroot/.local/share/jenkins-mcp", "vault.json"))
	t.Setenv("KUBERNETES_SERVICE_HOST", "") // process clear; inject via Getenv
	t.Setenv("JENKINS_MCP_GATEWAY_REPLICAS", "")
	t.Setenv("REPLICAS", "")

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
	// Plant canary in env that must never surface.
	t.Setenv("JENKINS_MCP_FAKE_TOKEN", multiPodCanary)

	getenv := func(k string) string {
		switch k {
		case "KUBERNETES_SERVICE_HOST":
			return "10.96.0.1"
		case gateway.EnvGatewayCredentialMode:
			return string(gateway.CredentialModeAPITokenVault)
		case gateway.EnvGatewayMultiUser:
			return ""
		case gateway.EnvGatewayVaultPath:
			return "/home/nonroot/.local/share/jenkins-mcp/gateway/apitoken_vault.json"
		case gateway.EnvGatewayJWTVaultPath:
			return ""
		case "HOME":
			return "/home/nonroot"
		case "XDG_DATA_HOME":
			return "/home/nonroot/.local/share"
		case "JENKINS_MCP_GATEWAY_REPLICAS", "REPLICAS":
			return ""
		default:
			return ""
		}
	}
	rep, err := diagnostics.RunDoctor(context.Background(), diagnostics.DoctorOptions{
		Profile:     p,
		Paths:       &paths,
		Keyring:     keyring.NewStore(keyring.NewMemory()),
		Version:     "test",
		SkipNetwork: true,
		Getenv:      getenv,
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
		t.Fatalf("k8s env → want warn residual, got %s %s", gs.Status, gs.Message)
	}
	if gs.Details["multi_pod_vault_residual"] != true {
		t.Fatalf("multi_pod_vault_residual: %+v", gs.Details)
	}
	if gs.Details["kubernetes_env_detected"] != true {
		t.Fatalf("kubernetes_env_detected: %+v", gs.Details)
	}
	if gs.Details["ha_multi_replica"] != false {
		t.Fatalf("ha_multi_replica must stay false: %+v", gs.Details)
	}
	checklist, _ := gs.Details["multi_pod_residual_checklist"].(string)
	if checklist == "" {
		t.Fatal("want multi_pod_residual_checklist in details")
	}
	if !strings.Contains(gs.Message, "KUBERNETES_SERVICE_HOST") && !strings.Contains(gs.Message, "multi-pod") {
		t.Fatalf("message should note multi-pod residual: %s", gs.Message)
	}
	// Checklist / message cover sticky, vault, rate, Obtain residual summary.
	blob := gs.Message + checklist
	for _, want := range []string{"sticky", "vault", "rate"} {
		if !strings.Contains(strings.ToLower(blob), strings.ToLower(want)) {
			t.Fatalf("want %q in residual message/checklist: %s", want, blob)
		}
	}
	if strings.Contains(blob, multiPodCanary) {
		t.Fatal("canary leaked in gateway_status")
	}
}

// HOST-008: doctor warns on emptyDir-ish vault path heuristic (no path leak).
func TestRunDoctor_GatewayStatus_EmptyDirVaultHeuristic(t *testing.T) {
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
	vaultPath := "/tmp/jenkins-mcp-lab/apitoken_vault.json"
	getenv := func(k string) string {
		switch k {
		case gateway.EnvGatewayVaultPath:
			return vaultPath
		case gateway.EnvGatewayCredentialMode:
			return string(gateway.CredentialModeAPITokenVault)
		case "KUBERNETES_SERVICE_HOST", "JENKINS_MCP_GATEWAY_REPLICAS", "REPLICAS":
			return ""
		default:
			return ""
		}
	}
	rep, err := diagnostics.RunDoctor(context.Background(), diagnostics.DoctorOptions{
		Profile:     p,
		Paths:       &paths,
		Keyring:     keyring.NewStore(keyring.NewMemory()),
		Version:     "test",
		SkipNetwork: true,
		Getenv:      getenv,
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
		t.Fatalf("emptyDir heuristic → want warn, got %s %s", gs.Status, gs.Message)
	}
	if gs.Details["vault_path_emptydir_heuristic"] != true {
		t.Fatalf("vault_path_emptydir_heuristic: %+v", gs.Details)
	}
	if gs.Details["multi_pod_vault_residual"] != true {
		t.Fatal("multi_pod_vault_residual always true")
	}
	// Never embed vault path in doctor message/details strings.
	blob := gs.Message
	for _, v := range gs.Details {
		if s, ok := v.(string); ok {
			blob += s
		}
	}
	if strings.Contains(blob, vaultPath) {
		t.Fatalf("vault path leaked in gateway_status residual: %s", blob)
	}
}

// HOST-008: non-k8s Mode A still reports multi_pod_vault_residual=true without multi-pod warn.
func TestRunDoctor_GatewayStatus_MultiPodResidualAlwaysTrueWithoutK8sWarn(t *testing.T) {
	t.Setenv(update.EnvUpdateLKGPath, "")
	t.Setenv(gateway.EnvGatewayMultiUser, "")
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("JENKINS_MCP_GATEWAY_REPLICAS", "")
	t.Setenv("REPLICAS", "")
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
		switch k {
		case gateway.EnvGatewayCredentialMode:
			return string(gateway.CredentialModeAPITokenVault)
		case gateway.EnvGatewayVaultPath:
			return "/home/nonroot/.local/share/jenkins-mcp/gateway/apitoken_vault.json"
		case "HOME":
			return "/home/nonroot"
		case "XDG_DATA_HOME":
			return "/home/nonroot/.local/share"
		case "KUBERNETES_SERVICE_HOST", "JENKINS_MCP_GATEWAY_REPLICAS", "REPLICAS", gateway.EnvGatewayMultiUser:
			return ""
		default:
			return ""
		}
	}
	rep, err := diagnostics.RunDoctor(context.Background(), diagnostics.DoctorOptions{
		Profile:     p,
		Paths:       &paths,
		Keyring:     keyring.NewStore(keyring.NewMemory()),
		Version:     "test",
		SkipNetwork: true,
		Getenv:      getenv,
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
	if gs.Details["multi_pod_vault_residual"] != true {
		t.Fatalf("always true: %+v", gs.Details)
	}
	if gs.Details["kubernetes_env_detected"] != false {
		t.Fatalf("k8s off: %+v", gs.Details)
	}
	if gs.Status != diagnostics.StatusOK {
		t.Fatalf("Mode A without multi-pod signals want ok, got %s %s", gs.Status, gs.Message)
	}
	if _, ok := gs.Details["multi_pod_residual_checklist"]; ok {
		t.Fatalf("checklist must be absent without multi-pod signals: %+v", gs.Details)
	}
}
