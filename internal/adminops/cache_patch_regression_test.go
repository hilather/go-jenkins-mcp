package adminops_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/adminops"
	"github.com/hilather/go-jenkins-mcp/internal/audit"
	"github.com/hilather/go-jenkins-mcp/internal/cachecontrol"
)

// Regression: CachePatchMode erased the typed failure reason — any Patch error
// (CAS conflict, runtime_mutations_disabled, type_unqualified) became
// invalid_argument "cache mode patch rejected" and the audit event recorded a
// policy-style "deny" for what was an operational failure. The typed reason
// must survive and the audit decision must be fail (deny only for the
// runtime-mutations policy gate).
func TestCachePatchMode_CASConflictPreservesReason(t *testing.T) {
	dir := t.TempDir()
	st, err := cachecontrol.OpenOverrideStore(filepath.Join(dir, "cc"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cc, err := cachecontrol.NewService(cachecontrol.ServiceConfig{
		OverrideStore: st,
		ProfileID:     "lab",
	})
	if err != nil {
		t.Fatal(err)
	}
	mem := &audit.Memory{}
	op := adminops.New(adminops.Config{
		Role:              adminops.RoleOperator,
		CacheControl:      cc,
		CacheControlStore: st,
		DefaultProfileID:  "lab",
		Audit:             mem,
	})

	// First patch succeeds (revision 0 → 1).
	if _, err := op.CachePatchMode(context.Background(), adminops.CachePatchModeArgs{
		TypeID: "artifact_blob", Mode: "off", ExpectedRevision: 0, Reason: "first",
	}); err != nil {
		t.Fatal(err)
	}
	// Second patch with the now-stale ExpectedRevision 0 → CAS conflict.
	_, err = op.CachePatchMode(context.Background(), adminops.CachePatchModeArgs{
		TypeID: "artifact_blob", Mode: "read_only", ExpectedRevision: 0, Reason: "stale",
	})
	if err == nil {
		t.Fatal("stale revision must fail")
	}
	if !strings.Contains(err.Error(), "cas_conflict") {
		t.Fatalf("typed reason erased: %v", err)
	}

	// Audit: the failed patch recorded with decision=fail and the real reason.
	var sawFail bool
	for _, ev := range mem.Events() {
		if ev.Action != "cache_mode_patch" {
			continue
		}
		if ev.Decision == audit.DecisionDeny {
			t.Fatalf("CAS race must not audit as policy denial: %+v", ev)
		}
		if ev.Decision == audit.DecisionFail && ev.ReasonCode == "cas_conflict" {
			sawFail = true
		}
	}
	if !sawFail {
		t.Fatalf("missing fail/cas_conflict audit event: %+v", mem.Events())
	}
}
