package policy_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/config"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

func TestLoadValidOverlay(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.json")
	const body = `{
		"version": 1,
		"force_read_only": true,
		"mode": "pilot",
		"deny_tools": ["jenkins_get_build_logs", "jenkins_start_job"],
		"deny_job_prefixes": ["secret-folder"],
		"max_result_bytes": 4096
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := policy.LoadOverlay(policy.LoadOptions{Path: path})
	if err != nil {
		t.Fatalf("LoadOverlay: %v", err)
	}
	if !res.Present || res.Overlay == nil {
		t.Fatal("expected present overlay")
	}
	if !res.Overlay.ForceReadOnly {
		t.Fatal("force_read_only")
	}
	if res.Overlay.NormalizeMode() != policy.ModePilot {
		t.Fatalf("mode=%s", res.Overlay.NormalizeMode())
	}
	if len(res.Overlay.DenyTools) != 2 {
		t.Fatalf("deny_tools=%v", res.Overlay.DenyTools)
	}
	if len(res.Overlay.DenyJobPrefixes) != 1 || res.Overlay.DenyJobPrefixes[0] != "secret-folder" {
		t.Fatalf("deny_job_prefixes=%v", res.Overlay.DenyJobPrefixes)
	}
	if n, ok := res.Overlay.EffectiveMaxResultBytes(); !ok || n != 4096 {
		t.Fatalf("max_result_bytes=%d ok=%v", n, ok)
	}
	if res.SignatureState != "unverified_pilot" {
		t.Fatalf("signature_state=%s", res.SignatureState)
	}
	// Evaluator wired from overlay denies the job full name / children.
	ev := policy.NewDenyOnlyFromOverlay(res.Overlay)
	d := ev.Evaluate(
		policy.NewSubject("corp", "admin", true),
		policy.Action{ToolName: "jenkins_get_build", Class: policy.EffectRead},
		policy.Target{JobName: "secret-folder/job-a", BuildNumber: 1},
	)
	if !d.Denied() || d.ReasonCode != policy.ReasonJobPatternDeny {
		t.Fatalf("overlay job deny: %+v", d)
	}
	// EnterpriseForce wiring via adapter.
	force, ok := policy.AsEnterpriseForce(res.Overlay).ForceReadOnly()
	if !ok || !force {
		t.Fatalf("ForceReadOnly()=%v,%v", force, ok)
	}
}

func TestLoadAbsentOverlay(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "missing.json")
	res, err := policy.LoadOverlay(policy.LoadOptions{Path: path})
	if err != nil {
		t.Fatalf("absent optional: %v", err)
	}
	if res.Present || res.Overlay != nil {
		t.Fatal("expected no overlay")
	}
	if res.SignatureState != "absent" {
		t.Fatalf("state=%s", res.SignatureState)
	}
}

func TestLoadAbsentRequiredFailClosed(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "missing.json")
	_, err := policy.LoadOverlay(policy.LoadOptions{Path: path, Required: true})
	if err == nil {
		t.Fatal("expected fail closed when required and missing")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code=%s", apperr.CodeOf(err))
	}
}

func TestLoadInvalidJSONFailClosed(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte(`{not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := policy.LoadOverlay(policy.LoadOptions{Path: path})
	if err == nil {
		t.Fatal("invalid JSON must fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code=%s want policy_denial", apperr.CodeOf(err))
	}
	if strings.Contains(err.Error(), "token") {
		t.Fatalf("error leaked secret-ish text: %v", err)
	}
}

func TestLoadEmptyDenyJobPrefixFailClosed(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "empty-job.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"deny_job_prefixes":["  "]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := policy.LoadOverlay(policy.LoadOptions{Path: path})
	if err == nil {
		t.Fatal("empty deny_job_prefixes entry must fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial && apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code=%s", apperr.CodeOf(err))
	}
}

// Wave 35: deny_node_names / deny_view_names load + validate + evaluate.
func TestLoadDenyNodeAndViewNames(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.json")
	const body = `{
		"version": 1,
		"mode": "pilot",
		"deny_node_names": ["prod-agent-*", "secret-node"],
		"deny_view_names": ["hr/**", "secret-view"]
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := policy.LoadOverlay(policy.LoadOptions{Path: path})
	if err != nil {
		t.Fatalf("LoadOverlay: %v", err)
	}
	if len(res.Overlay.DenyNodeNames) != 2 || res.Overlay.DenyNodeNames[0] != "prod-agent-*" {
		t.Fatalf("deny_node_names=%v", res.Overlay.DenyNodeNames)
	}
	if len(res.Overlay.DenyViewNames) != 2 || res.Overlay.DenyViewNames[0] != "hr/**" {
		t.Fatalf("deny_view_names=%v", res.Overlay.DenyViewNames)
	}
	st := res.StatusMap()
	if st["deny_node_names_count"] != 2 || st["deny_view_names_count"] != 2 {
		t.Fatalf("status counts: %+v", st)
	}
	ex := policy.ExplainEffective("corp", res, policy.Inputs{})
	if len(ex.DenyNodeNames) != 2 || len(ex.DenyViewNames) != 2 {
		t.Fatalf("explain: nodes=%v views=%v", ex.DenyNodeNames, ex.DenyViewNames)
	}
	ev := policy.NewDenyOnlyFromOverlay(res.Overlay)
	d := ev.Evaluate(
		policy.NewSubject("corp", "admin", true),
		policy.Action{ToolName: "jenkins_get_nodes", Class: policy.EffectRead},
		policy.Target{NodeName: "prod-agent-01"},
	)
	if !d.Denied() || d.ReasonCode != policy.ReasonResourcePatternDeny {
		t.Fatalf("node deny from overlay: %+v", d)
	}
	dView := ev.Evaluate(
		policy.NewSubject("corp", "admin", true),
		policy.Action{ToolName: "jenkins_list_jobs", Class: policy.EffectRead},
		policy.Target{ViewName: "hr/payroll"},
	)
	if !dView.Denied() || dView.ReasonCode != policy.ReasonResourcePatternDeny {
		t.Fatalf("view deny from overlay: %+v", dView)
	}
}

func TestLoadEmptyDenyNodeNameFailClosed(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "empty-node.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"deny_node_names":["  "]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := policy.LoadOverlay(policy.LoadOptions{Path: path})
	if err == nil {
		t.Fatal("empty deny_node_names entry must fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial && apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code=%s", apperr.CodeOf(err))
	}
	// Full chain (apperr.Wrap keeps cause) should name the field.
	full := fmt.Sprintf("%v", err)
	if !strings.Contains(full, "deny_node_names") {
		// Also accept cause via %w chain stringification.
		if u := errors.Unwrap(err); u == nil || !strings.Contains(u.Error(), "deny_node_names") {
			t.Fatalf("error should name field: %v", err)
		}
	}
}

func TestLoadEmptyDenyViewNameFailClosed(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "empty-view.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"deny_view_names":["*"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := policy.LoadOverlay(policy.LoadOptions{Path: path})
	if err == nil {
		t.Fatal("overly broad deny_view_names entry must fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial && apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code=%s", apperr.CodeOf(err))
	}
	full := fmt.Sprintf("%v", err)
	if !strings.Contains(full, "deny_view_names") {
		if u := errors.Unwrap(err); u == nil || !strings.Contains(u.Error(), "deny_view_names") {
			t.Fatalf("error should name field: %v", err)
		}
	}
}

// Wave 36: deny_artifact_paths load + validate + evaluate.
func TestLoadDenyArtifactPaths(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.json")
	const body = `{
		"version": 1,
		"mode": "pilot",
		"deny_artifact_paths": ["secrets/**", "*.pem", "exact/creds.txt"]
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := policy.LoadOverlay(policy.LoadOptions{Path: path})
	if err != nil {
		t.Fatalf("LoadOverlay: %v", err)
	}
	if len(res.Overlay.DenyArtifactPaths) != 3 || res.Overlay.DenyArtifactPaths[0] != "secrets/**" {
		t.Fatalf("deny_artifact_paths=%v", res.Overlay.DenyArtifactPaths)
	}
	st := res.StatusMap()
	if st["deny_artifact_paths_count"] != 3 {
		t.Fatalf("status counts: %+v", st)
	}
	ex := policy.ExplainEffective("corp", res, policy.Inputs{})
	if len(ex.DenyArtifactPaths) != 3 {
		t.Fatalf("explain: artifacts=%v", ex.DenyArtifactPaths)
	}
	ev := policy.NewDenyOnlyFromOverlay(res.Overlay)
	d := ev.Evaluate(
		policy.NewSubject("corp", "admin", true),
		policy.Action{ToolName: "jenkins_get_artifact_text", Class: policy.EffectRead},
		policy.Target{ArtifactPath: "secrets/prod/key.pem"},
	)
	if !d.Denied() || d.ReasonCode != policy.ReasonResourcePatternDeny {
		t.Fatalf("artifact deny from overlay: %+v", d)
	}
	if d.MatchedRule != "deny_artifact_path:secrets/**" {
		t.Fatalf("matched rule: %q", d.MatchedRule)
	}
}

func TestLoadEmptyDenyArtifactPathFailClosed(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "empty-art.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"deny_artifact_paths":["  "]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := policy.LoadOverlay(policy.LoadOptions{Path: path})
	if err == nil {
		t.Fatal("empty deny_artifact_paths entry must fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial && apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code=%s", apperr.CodeOf(err))
	}
	full := fmt.Sprintf("%v", err)
	if !strings.Contains(full, "deny_artifact_paths") {
		if u := errors.Unwrap(err); u == nil || !strings.Contains(u.Error(), "deny_artifact_paths") {
			t.Fatalf("error should name field: %v", err)
		}
	}
}

func TestLoadBroadDenyArtifactPathFailClosed(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "broad-art.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"deny_artifact_paths":["**"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := policy.LoadOverlay(policy.LoadOptions{Path: path})
	if err == nil {
		t.Fatal("overly broad deny_artifact_paths entry must fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial && apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code=%s", apperr.CodeOf(err))
	}
	full := fmt.Sprintf("%v", err)
	if !strings.Contains(full, "deny_artifact_paths") {
		if u := errors.Unwrap(err); u == nil || !strings.Contains(u.Error(), "deny_artifact_paths") {
			t.Fatalf("error should name field: %v", err)
		}
	}
}

// Wave 37: deny_branch_names load + validate + evaluate.
func TestLoadDenyBranchNames(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.json")
	const body = `{
		"version": 1,
		"mode": "pilot",
		"deny_branch_names": ["release/*", "main", "hotfix/**"]
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := policy.LoadOverlay(policy.LoadOptions{Path: path})
	if err != nil {
		t.Fatalf("LoadOverlay: %v", err)
	}
	if len(res.Overlay.DenyBranchNames) != 3 || res.Overlay.DenyBranchNames[0] != "release/*" {
		t.Fatalf("deny_branch_names=%v", res.Overlay.DenyBranchNames)
	}
	st := res.StatusMap()
	if st["deny_branch_names_count"] != 3 {
		t.Fatalf("status counts: %+v", st)
	}
	ex := policy.ExplainEffective("corp", res, policy.Inputs{})
	if len(ex.DenyBranchNames) != 3 {
		t.Fatalf("explain: branches=%v", ex.DenyBranchNames)
	}
	ev := policy.NewDenyOnlyFromOverlay(res.Overlay)
	d := ev.Evaluate(
		policy.NewSubject("corp", "admin", true),
		policy.Action{ToolName: "jenkins_list_jobs", Class: policy.EffectRead},
		policy.Target{BranchName: "release/1.2"},
	)
	if !d.Denied() || d.ReasonCode != policy.ReasonResourcePatternDeny {
		t.Fatalf("branch deny from overlay: %+v", d)
	}
	if d.MatchedRule != "deny_branch_name:release/*" {
		t.Fatalf("matched rule: %q", d.MatchedRule)
	}
	if !strings.Contains(d.Explanation, "release/1.2") {
		t.Fatalf("explanation: %q", d.Explanation)
	}
}

func TestLoadEmptyDenyBranchNameFailClosed(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "empty-branch.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"deny_branch_names":["  "]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := policy.LoadOverlay(policy.LoadOptions{Path: path})
	if err == nil {
		t.Fatal("empty deny_branch_names entry must fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial && apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code=%s", apperr.CodeOf(err))
	}
	full := fmt.Sprintf("%v", err)
	if !strings.Contains(full, "deny_branch_names") {
		if u := errors.Unwrap(err); u == nil || !strings.Contains(u.Error(), "deny_branch_names") {
			t.Fatalf("error should name field: %v", err)
		}
	}
}

func TestLoadBroadDenyBranchNameFailClosed(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "broad-branch.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"deny_branch_names":["**"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := policy.LoadOverlay(policy.LoadOptions{Path: path})
	if err == nil {
		t.Fatal("overly broad deny_branch_names entry must fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial && apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code=%s", apperr.CodeOf(err))
	}
	full := fmt.Sprintf("%v", err)
	if !strings.Contains(full, "deny_branch_names") {
		if u := errors.Unwrap(err); u == nil || !strings.Contains(u.Error(), "deny_branch_names") {
			t.Fatalf("error should name field: %v", err)
		}
	}
}

func TestLoadInvalidVersionFailClosed(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "v99.json")
	if err := os.WriteFile(path, []byte(`{"version":99,"force_read_only":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := policy.LoadOverlay(policy.LoadOptions{Path: path})
	if err == nil {
		t.Fatal("bad version must fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code=%s", apperr.CodeOf(err))
	}
}

func TestLoadBadModeFailClosed(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "mode.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"mode":"elevate"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := policy.LoadOverlay(policy.LoadOptions{Path: path})
	if err == nil {
		t.Fatal("invalid mode must fail closed")
	}
}

func TestForceReadOnlyCannotBeDefeatedByAllowMutations(t *testing.T) {
	t.Parallel()
	// Regression: --allow-mutations must not defeat enterprise force_read_only (CFG-002).
	o := &policy.Overlay{Version: 1, ForceReadOnly: true}
	force := policy.AsEnterpriseForce(o)
	st := policy.ComputeEffectiveReadOnly(policy.Inputs{
		AllowMutations: true,
		Force:          force,
	})
	if !st.Effective {
		t.Fatal("force_read_only must win over --allow-mutations")
	}
	if !contains(st.Sources, policy.SourceEnterpriseForce) {
		t.Fatalf("sources=%v", st.Sources)
	}
	gate := policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true, Force: force})
	if gate.AllowMutationRegistration() {
		t.Fatal("AllowMutationRegistration (write-enabled) must be false under enterprise force")
	}
	if !gate.ShouldRegisterMutations() {
		t.Fatal("Wave 30: ShouldRegisterMutations under allow-mutations + force")
	}
}

func TestEnvPolicyFileAndDefaultPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"force_read_only":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(policy.EnvPolicyFileVar, path)
	t.Setenv(policy.EnvPolicyRequiredVar, "")
	t.Setenv(policy.EnvRequireSignedPolicyVar, "")
	t.Setenv(policy.EnvPolicyTrustedKeysVar, "")

	res, err := policy.LoadFromEnviron()
	if err != nil {
		t.Fatal(err)
	}
	if res.Overlay == nil {
		t.Fatal("expected overlay from env path")
	}
}

func TestDefaultXDGPolicyPath(t *testing.T) {
	t.Parallel()
	paths := config.Paths{ConfigDir: "/tmp/xdg-config/jenkins-mcp"}
	if paths.PolicyDir() != "/tmp/xdg-config/jenkins-mcp/policy" {
		t.Fatalf("PolicyDir=%s", paths.PolicyDir())
	}
	if paths.DefaultPolicyFile() != "/tmp/xdg-config/jenkins-mcp/policy/overlay.json" {
		t.Fatalf("DefaultPolicyFile=%s", paths.DefaultPolicyFile())
	}
	p, err := policy.ResolvePolicyPath(policy.LoadOptions{Paths: &paths})
	if err != nil {
		t.Fatal(err)
	}
	if p != paths.DefaultPolicyFile() {
		t.Fatalf("resolved=%s", p)
	}
}

func TestRequiringSignatureVerifier(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "sig.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"force_read_only":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := policy.LoadOverlay(policy.LoadOptions{
		Path:     path,
		Verifier: policy.RequiringSignatureVerifier{},
	})
	if err == nil {
		t.Fatal("unsigned overlay must fail with requiring verifier")
	}

	path2 := filepath.Join(t.TempDir(), "signed.json")
	if err := os.WriteFile(path2, []byte(`{"version":1,"force_read_only":true,"signature":"stub"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := policy.LoadOverlay(policy.LoadOptions{
		Path:     path2,
		Verifier: policy.RequiringSignatureVerifier{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.SignatureState != "present_field" {
		t.Fatalf("state=%s", res.SignatureState)
	}
}

func TestOverlayStatusMapNoSecrets(t *testing.T) {
	t.Parallel()
	o := &policy.Overlay{Version: 1, ForceReadOnly: true, DenyTools: []string{"jenkins_get_job"}}
	res := policy.LoadResult{
		Overlay:        o,
		Path:           "/home/alice/.config/jenkins-mcp/policy/overlay.json",
		Present:        true,
		SignatureState: "unverified_pilot",
	}
	m := res.StatusMap()
	for k, v := range m {
		s := strings.ToLower(k + " " + toString(v))
		if strings.Contains(s, "token") || strings.Contains(s, "password") {
			t.Fatalf("status leaked secret-ish field: %v=%v", k, v)
		}
	}
	// Path should be basenamed, not full home path.
	if m["policy_path_base"] != "overlay.json" {
		t.Fatalf("path_base=%v", m["policy_path_base"])
	}
}

func toString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	default:
		return ""
	}
}
