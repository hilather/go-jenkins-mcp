package audit_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/audit"
)

func TestKnownEventTypes_ContainsCoreAndMutation(t *testing.T) {
	t.Parallel()
	types := audit.KnownEventTypes()
	need := []string{
		audit.TypeLoginSuccess,
		audit.TypeLoginFail,
		audit.TypeServeStart,
		audit.TypeToolDeny,
		audit.TypeToolError,
		audit.TypeToolSuccess,
		audit.TypeAuthFail,
		audit.TypeAuditSettings,
		audit.TypePolicyValidate,
		audit.TypePolicyApply,
		audit.TypeAdminCacheEvict,
		audit.TypeAdminSupportBundle,
		audit.TypeAdminSubjectInvalid,
		audit.TypeAdminConsentPurge,
		audit.TypeAdminFleetCachePurge,
		"mutation_preview",
		"mutation_confirm",
		"mutation_deny",
	}
	for _, n := range need {
		if !audit.IsKnownEventType(n) {
			t.Fatalf("missing known type %q in %v", n, types)
		}
	}
	if len(types) != len(need) {
		t.Fatalf("catalog length %d want %d: %v", len(types), len(need), types)
	}
}

func TestDefaultTypeFilter_ToolSuccessOffUnlessEnv(t *testing.T) {
	t.Setenv("JENKINS_MCP_AUDIT_TOOL_OK", "")
	f := audit.DefaultTypeFilter()
	if f.Allows(audit.TypeToolDeny) != true {
		t.Fatal("tool_deny default on")
	}
	if f.Allows(audit.TypeToolSuccess) {
		t.Fatal("tool_success default off without env")
	}
	t.Setenv("JENKINS_MCP_AUDIT_TOOL_OK", "1")
	f2 := audit.DefaultTypeFilter()
	if !f2.Allows(audit.TypeToolSuccess) {
		t.Fatal("tool_success on when env set")
	}
}

func TestTypeFilter_SaveLoadRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	f := audit.DefaultTypeFilter()
	f.Enabled[audit.TypeLoginSuccess] = false
	f.Enabled[audit.TypeToolDeny] = true
	if err := audit.SaveTypeFilter(dir, f); err != nil {
		t.Fatal(err)
	}
	path := audit.TypeFilterPath(dir)
	if path == "" || filepath.Base(path) != audit.TypeFilterFileName {
		t.Fatalf("path %q", path)
	}
	loaded := audit.LoadTypeFilter(dir)
	if loaded.Allows(audit.TypeLoginSuccess) {
		t.Fatal("login_success should be disabled after load")
	}
	if !loaded.Allows(audit.TypeToolDeny) {
		t.Fatal("tool_deny should remain enabled")
	}
}

func TestReloadingFilterSink_DropsDisabled(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	mem := &audit.Memory{}
	// Disable tool_deny on disk before first emit.
	f := audit.DefaultTypeFilter()
	f.Enabled[audit.TypeToolDeny] = false
	if err := audit.SaveTypeFilter(dir, f); err != nil {
		t.Fatal(err)
	}
	sink := audit.NewReloadingFilterSink(dir, mem)
	ctx := context.Background()
	if err := sink.Emit(ctx, audit.Event{
		Type:     audit.TypeToolDeny,
		Decision: audit.DecisionDeny,
	}); err != nil {
		t.Fatal(err)
	}
	if err := sink.Emit(ctx, audit.Event{
		Type:     audit.TypeLoginSuccess,
		Decision: audit.DecisionSuccess,
	}); err != nil {
		t.Fatal(err)
	}
	evs := mem.Events()
	if len(evs) != 1 || evs[0].Type != audit.TypeLoginSuccess {
		t.Fatalf("want only login_success, got %+v", evs)
	}
	// Toggle tool_deny on and ensure reload picks it up.
	f.Enabled[audit.TypeToolDeny] = true
	if err := audit.SaveTypeFilter(dir, f); err != nil {
		t.Fatal(err)
	}
	// Bump mtime reliability: re-save after tiny change already renames.
	if err := sink.Emit(ctx, audit.Event{
		Type:     audit.TypeToolDeny,
		Decision: audit.DecisionDeny,
	}); err != nil {
		t.Fatal(err)
	}
	evs = mem.Events()
	if len(evs) != 2 {
		t.Fatalf("after re-enable want 2 events, got %d", len(evs))
	}
}

func TestNormalizeEnabled_IgnoresUnknownKeys(t *testing.T) {
	t.Parallel()
	f := audit.NormalizeEnabled(map[string]bool{
		audit.TypeAuthFail: true,
		"not_a_real_type":  true,
	})
	if f.Allows("not_a_real_type") {
		t.Fatal("unknown types must not be allowed")
	}
	if !f.Allows(audit.TypeAuthFail) {
		t.Fatal("auth_fail should be on")
	}
}

func TestReloadingFilterSink_EmptyDirUsesDefaultFilter(t *testing.T) {
	t.Parallel()
	mem := &audit.Memory{}
	// Empty profile data dir: DefaultTypeFilter only (serve no-profile fallback).
	sink := audit.NewReloadingFilterSink("", mem)
	ctx := context.Background()
	_ = sink.Emit(ctx, audit.Event{Type: audit.TypeToolSuccess, Decision: audit.DecisionSuccess})
	_ = sink.Emit(ctx, audit.Event{Type: audit.TypeToolDeny, Decision: audit.DecisionDeny})
	evs := mem.Events()
	if len(evs) != 1 || evs[0].Type != audit.TypeToolDeny {
		t.Fatalf("want only tool_deny under default filter, got %+v", evs)
	}
}
