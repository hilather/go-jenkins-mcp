package adminops_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/adminops"
	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/audit"
	"github.com/hilather/go-jenkins-mcp/internal/config"
	"github.com/hilather/go-jenkins-mcp/internal/profile"
)

func TestService_MeAndHealth_SecretFree(t *testing.T) {
	t.Parallel()
	svc := adminops.New(adminops.Config{
		Role:    adminops.RoleViewer,
		Version: "test",
		Commit:  "abc",
		Getenv:  func(string) string { return "" },
	})
	me, err := svc.Me(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if me.Role != "viewer" || len(me.Permissions) == 0 {
		t.Fatalf("%+v", me)
	}
	if strings.Contains(me.Residual, "token=") {
		t.Fatal("token material in residual")
	}
	h, err := svc.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h.Status != "ok" || h.GatewayReady {
		t.Fatalf("%+v", h)
	}
}

func TestService_WriteRequiresRole(t *testing.T) {
	t.Parallel()
	viewer := adminops.New(adminops.Config{Role: adminops.RoleViewer})
	_, err := viewer.CacheEvict(context.Background(), "corp", 0, adminops.ConfirmEVICT)
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthorization {
		t.Fatalf("viewer cache evict: %v", err)
	}
	_, err = viewer.AuditSettingsPut(context.Background(), "corp", map[string]bool{"tool_deny": true})
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthorization {
		t.Fatalf("viewer audit settings: %v", err)
	}
	_, err = viewer.PolicyValidate(context.Background(), nil, "corp")
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthorization {
		t.Fatalf("viewer policy validate: %v", err)
	}
}

func TestService_AuditSettings_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	// Isolated XDG-ish paths via ProfileStore data dir.
	paths := config.Paths{
		ConfigDir: filepath.Join(dir, "cfg"),
		DataDir:   filepath.Join(dir, "data"),
		CacheDir:  filepath.Join(dir, "cache"),
	}
	pstore := profile.NewStore(paths)
	p := &profile.Profile{
		ID:         "corp",
		JenkinsURL: "https://jenkins.example.com",
		AuthMethod: profile.AuthMethodAPIToken,
		Username:   "alice",
	}
	if err := pstore.Save(p); err != nil {
		t.Fatal(err)
	}
	mem := &audit.Memory{}
	svc := adminops.New(adminops.Config{
		Role:             adminops.RoleOperator,
		ProfileStore:     pstore,
		Paths:            &paths,
		Audit:            mem,
		DefaultProfileID: "corp",
	})
	got, err := svc.AuditSettingsGet(context.Background(), "corp")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Types) == 0 || got.Enabled == nil {
		t.Fatalf("%+v", got)
	}
	// Disable tool_deny
	after, err := svc.AuditSettingsPut(context.Background(), "corp", map[string]bool{
		audit.TypeToolDeny: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if after.Enabled[audit.TypeToolDeny] {
		t.Fatal("tool_deny should be off")
	}
	// Self-audit event
	var found bool
	for _, e := range mem.Events() {
		if e.Type == audit.TypeAuditSettings {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected audit_settings emit")
	}
}

func TestService_CacheEvict_Confirm(t *testing.T) {
	dir := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(dir, "cfg"),
		DataDir:   filepath.Join(dir, "data"),
		CacheDir:  filepath.Join(dir, "cache"),
	}
	pstore := profile.NewStore(paths)
	p := &profile.Profile{
		ID:         "corp",
		JenkinsURL: "https://jenkins.example.com",
		AuthMethod: profile.AuthMethodAPIToken,
		Username:   "alice",
	}
	if err := pstore.Save(p); err != nil {
		t.Fatal(err)
	}
	svc := adminops.New(adminops.Config{
		Role:         adminops.RoleOperator,
		ProfileStore: pstore,
		Paths:        &paths,
	})
	_, err := svc.CacheEvict(context.Background(), "corp", 0, "nope")
	if err == nil || apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("want confirm fail: %v", err)
	}
	// Plan (read) ok
	if _, err := svc.CacheEvictPlan(context.Background(), "corp", 0); err != nil {
		t.Fatal(err)
	}
	// Evict with confirm (empty cache ok)
	if _, err := svc.CacheEvict(context.Background(), "corp", 0, adminops.ConfirmEVICT); err != nil {
		t.Fatal(err)
	}
}

func TestToolCatalog_CoversP0(t *testing.T) {
	t.Parallel()
	cat := adminops.ToolCatalog()
	need := []string{
		"admin_health", "admin_version", "admin_me",
		"admin_gateway_residual_status", "admin_list_profiles", "admin_get_profile",
		"admin_policy_effective", "admin_metrics", "admin_audit_list",
		"admin_doctor", "admin_cache_status",
		// UI-011 / POL-006 multi-fleet bindings
		"admin_rbac_list_bindings", "admin_rbac_put_binding", "admin_rbac_delete_binding",
	}
	set := map[string]struct{}{}
	for _, n := range cat {
		set[n] = struct{}{}
	}
	for _, n := range need {
		if _, ok := set[n]; !ok {
			t.Fatalf("missing P0 tool %s", n)
		}
	}
	// POL-007 SAML MCP residual still documented
	res := adminops.ResidualTools()
	if res["admin_saml_status"] == "" {
		t.Fatal("POL-007 residual missing")
	}
}
