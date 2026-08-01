package mutation_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/mutation"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

func TestPowerUser_InterruptPreviewConfirmBind(t *testing.T) {
	gate := policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true})
	mgr := mutation.NewManager(mutation.Config{
		Gate: gate, ProfileID: "p", PrincipalID: "u",
		ConfirmCooldown: -1, MaxPreviewsPerMinute: -1, TTL: time.Minute,
	})
	intent := mutation.Intent{
		Action: mutation.ActionInterruptBuild, JobName: "demo", BuildNumber: 3, Mode: "term",
	}
	prev, err := mgr.Preview(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if prev.Mode != "term" || prev.EndpointClass != mutation.EndpointTerm {
		t.Fatalf("preview: %+v", prev)
	}
	// Cross-mode must fail target match.
	_, err = mgr.Confirm(context.Background(), prev.ConfirmationToken, mutation.Intent{
		Action: mutation.ActionInterruptBuild, JobName: "demo", BuildNumber: 3, Mode: "kill",
	})
	if err == nil {
		t.Fatal("expected mode mismatch")
	}
	// Fresh preview for kill then confirm.
	prev2, err := mgr.Preview(context.Background(), mutation.Intent{
		Action: mutation.ActionInterruptBuild, JobName: "demo", BuildNumber: 3, Mode: "kill",
	})
	if err != nil {
		t.Fatal(err)
	}
	bound, err := mgr.Confirm(context.Background(), prev2.ConfirmationToken, mutation.Intent{
		Action: mutation.ActionInterruptBuild, JobName: "demo", BuildNumber: 3, Mode: "kill",
	})
	if err != nil {
		t.Fatal(err)
	}
	if bound.Mode != "kill" {
		t.Fatalf("mode=%s", bound.Mode)
	}
}

func TestPowerUser_DescriptionCapAndBulkQueueCap(t *testing.T) {
	gate := policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true})
	mgr := mutation.NewManager(mutation.Config{
		Gate: gate, ProfileID: "p", PrincipalID: "u",
		ConfirmCooldown: -1, MaxPreviewsPerMinute: -1, TTL: time.Minute,
	})
	long := strings.Repeat("x", mutation.MaxBuildDescriptionLen+1)
	_, err := mgr.Preview(context.Background(), mutation.Intent{
		Action: mutation.ActionSetBuildDescription, JobName: "j", BuildNumber: 1, Extra: long,
	})
	if err == nil {
		t.Fatal("expected description cap error")
	}
	ids := make([]int, mutation.MaxBulkQueueCancel+1)
	for i := range ids {
		ids[i] = i + 1
	}
	_, err = mgr.Preview(context.Background(), mutation.Intent{
		Action: mutation.ActionCancelQueueItemsForJob, JobName: "j", QueueIDs: ids,
	})
	if err == nil {
		t.Fatal("expected bulk cap error")
	}
	// Cap-ok path.
	okIDs := ids[:mutation.MaxBulkQueueCancel]
	prev, err := mgr.Preview(context.Background(), mutation.Intent{
		Action: mutation.ActionCancelQueueItemsForJob, JobName: "j", QueueIDs: okIDs,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(prev.QueueIDs) != mutation.MaxBulkQueueCancel {
		t.Fatalf("queueIds=%v", prev.QueueIDs)
	}
}

func TestPowerUser_ReplayRejectsScriptEditMode(t *testing.T) {
	gate := policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true})
	mgr := mutation.NewManager(mutation.Config{
		Gate: gate, ProfileID: "p", PrincipalID: "u",
		ConfirmCooldown: -1, MaxPreviewsPerMinute: -1, TTL: time.Minute,
	})
	_, err := mgr.Preview(context.Background(), mutation.Intent{
		Action: mutation.ActionReplayPipeline, JobName: "pipe", BuildNumber: 2, Mode: "edit",
	})
	if err == nil {
		t.Fatal("expected script-edit reject")
	}
	prev, err := mgr.Preview(context.Background(), mutation.Intent{
		Action: mutation.ActionReplayPipeline, JobName: "pipe", BuildNumber: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if prev.Mode != "same" {
		t.Fatalf("mode=%s", prev.Mode)
	}
}

func TestPowerUser_ROBlocksPreview(t *testing.T) {
	gate := policy.NewDefaultReadOnlyGate()
	mgr := mutation.NewManager(mutation.Config{Gate: gate, ProfileID: "p", PrincipalID: "u"})
	_, err := mgr.Preview(context.Background(), mutation.Intent{
		Action: mutation.ActionSetJobBuildable, JobName: "j", Mode: "disable",
	})
	if err == nil {
		t.Fatal("RO must block")
	}
}

func TestValidateRequiredParams(t *testing.T) {
	defs := []mutation.ParamDefinition{
		{Name: "BRANCH", Type: "StringParameterDefinition", Required: true},
		{Name: "OPT", Type: "StringParameterDefinition"},
	}
	if err := mutation.ValidateRequiredParams(map[string]any{"OPT": "x"}, defs); err == nil {
		t.Fatal("missing required BRANCH")
	}
	if err := mutation.ValidateRequiredParams(map[string]any{"BRANCH": "main"}, defs); err != nil {
		t.Fatal(err)
	}
}
