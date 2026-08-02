package tools_test

import (
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/contracts"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
	"github.com/hilather/go-jenkins-mcp/internal/tools"
)

// Regression: POL-006 per-subject max_result_bytes must lower dispatch hard max.
func TestPOL006_SubjectMaxResultBytes_LowersHardMax(t *testing.T) {
	capBytes := 64
	ov := &policy.Overlay{
		Version: 1,
		Subjects: &policy.SubjectBindings{
			Users: []policy.UserBinding{{
				JenkinsUserID:  "alice",
				MaxResultBytes: &capBytes,
			}},
		},
	}
	if err := ov.Validate(); err != nil {
		t.Fatal(err)
	}
	ev := policy.NewDenyOnlyFromOverlay(ov)
	subj := policy.NewSubject(contracts.ProfileID("corp"), "alice", true)
	doc := ev.EffectiveDocument(subj)
	if doc.MaxResultBytes != 64 {
		t.Fatalf("effective max: %d", doc.MaxResultBytes)
	}
	b := tools.Budgets{HardMaxBytes: 1 << 20, TargetBytes: 1 << 20}.Normalize()
	b = tools.LowerHardMax(b, doc.MaxResultBytes)
	if b.HardMaxBytes != 64 {
		t.Fatalf("hard max after lower: %d", b.HardMaxBytes)
	}
	big := map[string]string{"blob": strings.Repeat("x", 200)}
	_, _, err := tools.EnforceBudgetOrError(big, b, false)
	if err == nil {
		t.Fatal("expected budget denial for oversized result under subject cap")
	}
	// Non-matching subject keeps process budget path (no subject lower).
	bob := policy.NewSubject(contracts.ProfileID("corp"), "bob", true)
	if got := ev.EffectiveDocument(bob).MaxResultBytes; got != 0 {
		t.Fatalf("bob should not inherit alice cap: %d", got)
	}
}
