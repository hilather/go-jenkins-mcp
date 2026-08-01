package policy_test

import (
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

func TestMutationAllowlist_ToolsJobsModes(t *testing.T) {
	p := &policy.MutationPolicy{
		AllowTools:          []string{policy.ToolStartJob, policy.ToolInterruptBuild},
		AllowInterruptModes: []string{"stop"},
		AllowJobPrefixes:    []string{"team/"},
	}
	if !policy.MutationToolAllowed(p, policy.ToolStartJob) {
		t.Fatal("start allowed")
	}
	if policy.MutationToolAllowed(p, policy.ToolRebuildBuild) {
		t.Fatal("rebuild not allowlisted")
	}
	if err := policy.CheckInterruptModeAllowed(p, "stop"); err != nil {
		t.Fatal(err)
	}
	if err := policy.CheckInterruptModeAllowed(p, "kill"); err == nil {
		t.Fatal("kill not allowlisted")
	}
	if err := policy.CheckMutationJobAllowed(p, "team/foo"); err != nil {
		t.Fatal(err)
	}
	if err := policy.CheckMutationJobAllowed(p, "other/foo"); err == nil {
		t.Fatal("other job denied")
	}
	if !policy.MutationToolAllowed(nil, policy.ToolStopBuild) {
		t.Fatal("nil policy allows stop")
	}
	if err := policy.CheckInterruptModeAllowed(nil, "kill"); err != nil {
		t.Fatal(err)
	}
}

func TestMutationPolicyFromOverlay(t *testing.T) {
	o := &policy.Overlay{
		Version:             policy.CurrentOverlayVersion,
		AllowMutationTools:  []string{policy.ToolStartJob},
		AllowInterruptModes: []string{"term"},
	}
	p := policy.MutationPolicyFromOverlay(o)
	if p == nil || !policy.MutationToolAllowed(p, policy.ToolStartJob) {
		t.Fatalf("%+v", p)
	}
	if policy.MutationToolAllowed(p, policy.ToolStopBuild) {
		t.Fatal("stop not in allowlist")
	}
}
