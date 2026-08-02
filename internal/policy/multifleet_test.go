package policy_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

// Regression: multi-fleet free-lab pack overlay loads and enforces user/group
// denials without elevating other subjects (real evaluator path).
func TestMultiFleet_PackOverlay_UserAndGroupDeny(t *testing.T) {
	root := findRepoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "testdata", "fleet-pack", "policy", "overlay.json"))
	if err != nil {
		t.Fatalf("read fleet-pack overlay: %v", err)
	}
	var ov policy.Overlay
	if err := json.Unmarshal(raw, &ov); err != nil {
		t.Fatal(err)
	}
	if err := ov.Validate(); err != nil {
		t.Fatal(err)
	}
	ev := policy.NewDenyOnlyFromOverlay(&ov)

	logs := policy.Action{ToolName: "jenkins_get_build_logs", Class: policy.EffectRead}
	alice := pol006Subject("alice")
	if d := ev.Evaluate(alice, logs, policy.Target{}); d.Allowed() {
		t.Fatalf("alice should be denied logs: %+v", d)
	}
	bob := pol006Subject("bob")
	if d := ev.Evaluate(bob, logs, policy.Target{}); d.Denied() {
		t.Fatalf("bob without user binding should not be tool-denied by alice rule: %+v", d)
	}
	contractor := pol006Subject("carol", "contractors")
	if d := ev.Evaluate(contractor, logs, policy.Target{}); d.Allowed() {
		t.Fatalf("contractors group should deny logs: %+v", d)
	}
	if d := ev.Evaluate(contractor, policy.Action{ToolName: "jenkins_get_job", Class: policy.EffectRead},
		policy.Target{JobName: "prod/payments"}); d.Allowed() {
		t.Fatalf("contractors should be denied prod/** jobs: %+v", d)
	}
	if d := ev.Evaluate(bob, policy.Action{ToolName: "jenkins_get_job", Class: policy.EffectRead},
		policy.Target{JobName: "prod/payments"}); d.Denied() {
		t.Fatalf("bob without contractors should not get group job deny: %+v", d)
	}
}

// Multi-fleet REQUIRE_SIGNED fail-closed without trusted keys (real LoadFromEnviron).
func TestMultiFleet_RequireSigned_FailClosedNoKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"force_read_only":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(policy.EnvPolicyFileVar, path)
	t.Setenv(policy.EnvPolicyTrustedKeysVar, "")
	t.Setenv(policy.EnvPolicyRequiredVar, "")
	t.Setenv(policy.EnvRequireSignedPolicyVar, "1")
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "cfg"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	t.Setenv("HOME", dir)

	_, err := policy.LoadFromEnviron()
	if err == nil {
		t.Fatal("expected fail closed when REQUIRE_SIGNED without trusted keys")
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "require") && !strings.Contains(msg, "trusted") && !strings.Contains(msg, "key") {
		t.Fatalf("want require-signed/key message, got %q", err.Error())
	}
}

// Signed multi-fleet bundle with subjects: LoadFromEnviron + evaluate group deny.
func TestMultiFleet_SignedBundle_LoadAndGroupDeny(t *testing.T) {
	pub, priv := testKeyPair(t)
	dir := t.TempDir()
	keysDir := writeTrustDir(t, dir, "fleet-lab", pub)

	ov := policy.Overlay{
		Version:       1,
		Mode:          policy.ModePilot,
		ForceReadOnly: true,
		Subjects: &policy.SubjectBindings{
			Groups: []policy.GroupBinding{{
				GroupID:   "contractors",
				DenyTools: []string{"jenkins_get_build_logs"},
			}},
			Users: []policy.UserBinding{{
				JenkinsUserID: "alice",
				DenyTools:     []string{"jenkins_get_console_log"},
			}},
		},
	}
	if err := ov.Validate(); err != nil {
		t.Fatal(err)
	}
	env := signOverlay(t, ov, priv, "fleet-lab", 42, time.Now().UTC().Add(24*time.Hour).Format(time.RFC3339))
	bundlePath := filepath.Join(dir, "overlay.bundle.json")
	writeBundle(t, bundlePath, env)

	t.Setenv(policy.EnvPolicyFileVar, bundlePath)
	t.Setenv(policy.EnvPolicyTrustedKeysVar, keysDir)
	t.Setenv(policy.EnvPolicyRequiredVar, "")
	t.Setenv(policy.EnvRequireSignedPolicyVar, "1")
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	t.Setenv("HOME", dir)

	res, err := policy.LoadFromEnviron()
	if err != nil {
		t.Fatalf("LoadFromEnviron signed: %v", err)
	}
	if res.SignatureState != policy.SigStateVerified {
		t.Fatalf("signature_state=%s", res.SignatureState)
	}
	if res.Overlay == nil || res.Overlay.Subjects == nil {
		t.Fatal("expected subjects on loaded overlay")
	}
	if len(res.Overlay.Subjects.Groups) != 1 || len(res.Overlay.Subjects.Users) != 1 {
		t.Fatalf("subjects not fully loaded: %+v", res.Overlay.Subjects)
	}

	ev := policy.NewDenyOnlyFromOverlay(res.Overlay)
	logs := policy.Action{ToolName: "jenkins_get_build_logs", Class: policy.EffectRead}
	if d := ev.Evaluate(pol006Subject("c1", "contractors"), logs, policy.Target{}); d.Allowed() {
		t.Fatalf("group deny after signed load: %+v", d)
	}
	if d := ev.Evaluate(pol006Subject("alice"), policy.Action{ToolName: "jenkins_get_console_log", Class: policy.EffectRead}, policy.Target{}); d.Allowed() {
		t.Fatalf("user deny after signed load: %+v", d)
	}
	// Unrelated subject not denied by those bindings
	if d := ev.Evaluate(pol006Subject("bob"), logs, policy.Target{}); d.Denied() {
		t.Fatalf("bob should not inherit alice/contractor denials: %+v", d)
	}

	// Missing file under REQUIRE_SIGNED fail closed
	t.Setenv(policy.EnvPolicyFileVar, filepath.Join(dir, "nope.bundle.json"))
	if _, err := policy.LoadFromEnviron(); err == nil {
		t.Fatal("expected fail closed missing policy file under REQUIRE_SIGNED")
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "testdata", "fleet-pack", "policy", "overlay.json")); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}
