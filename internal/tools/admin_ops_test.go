package tools_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/adminops"
	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/audit"
	"github.com/hilather/go-jenkins-mcp/internal/config"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
	"github.com/hilather/go-jenkins-mcp/internal/profile"
	"github.com/hilather/go-jenkins-mcp/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestAdminOps_RegisterAndCall_SecretCanary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dir := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(dir, "cfg"),
		DataDir:   filepath.Join(dir, "data"),
		CacheDir:  filepath.Join(dir, "cache"),
	}
	ps := profile.NewStore(paths)
	if err := ps.Save(&profile.Profile{
		ID:         "corp",
		JenkinsURL: "https://jenkins.example.com",
		AuthMethod: profile.AuthMethodAPIToken,
		Username:   "alice",
	}); err != nil {
		t.Fatal(err)
	}
	canary := "CANARY_admin_mcp_token_never_in_result_zz99"
	svc := adminops.New(adminops.Config{
		Role:             adminops.RoleOperator,
		Version:          "v-test",
		ProfileStore:     ps,
		Paths:            &paths,
		DefaultProfileID: "corp",
		Audit:            &audit.Memory{},
		Getenv: func(k string) string {
			if k == "JENKINS_MCP_ADMIN_TOKEN" {
				return canary
			}
			return ""
		},
	})

	server := mcp.NewServer(&mcp.Implementation{Name: "admin-ops", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{
		Gate:           policy.NewDefaultReadOnlyGate(),
		EnableAdminOps: true,
		AdminOps:       svc,
	})

	client := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "test"}, nil)
	ct, st := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	// List tools includes admin_health
	listed, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, tool := range listed.Tools {
		if tool.Name == "admin_health" {
			found = true
		}
		if strings.Contains(tool.Name, "admin_") == false {
			continue
		}
		// Schema descriptions never contain canary
		if strings.Contains(tool.Description, canary) {
			t.Fatal("canary in tool description")
		}
	}
	if !found {
		t.Fatal("admin_health not registered")
	}

	// Call admin_me — never leak token
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "admin_me", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	blob := toolResultBlob(t, res)
	if strings.Contains(blob, canary) {
		t.Fatal("admin token canary leaked in me result")
	}
	if !strings.Contains(blob, "operator") {
		t.Fatalf("want role operator in %s", blob)
	}

	// Residual status
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "admin_gateway_residual_status", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	blob = toolResultBlob(t, res)
	if strings.Contains(blob, canary) {
		t.Fatal("canary in residual status")
	}

	// Viewer cannot put audit settings
	svcView := adminops.New(adminops.Config{
		Role:             adminops.RoleViewer,
		ProfileStore:     ps,
		Paths:            &paths,
		DefaultProfileID: "corp",
	})
	server2 := mcp.NewServer(&mcp.Implementation{Name: "admin-ops-v", Version: "test"}, nil)
	tools.Register(server2, &jenkins.Client{}, &tools.RegisterOptions{
		Gate:           policy.NewDefaultReadOnlyGate(),
		EnableAdminOps: true,
		AdminOps:       svcView,
	})
	ct2, st2 := mcp.NewInMemoryTransports()
	ss2, err := server2.Connect(ctx, st2, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss2.Close()
	cs2, err := client.Connect(ctx, ct2, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs2.Close()
	_, err = cs2.CallTool(ctx, &mcp.CallToolParams{
		Name: "admin_audit_settings_put",
		Arguments: map[string]any{
			"enabled": map[string]any{"tool_deny": false},
		},
	})
	// Tool may return error result rather than transport error.
	if err == nil {
		// Check structured error path via second call to service
		_, serr := svcView.AuditSettingsPut(ctx, "corp", map[string]bool{"tool_deny": false})
		if serr == nil || apperr.CodeOf(serr) != apperr.CodeAuthorization {
			t.Fatalf("viewer write: %v", serr)
		}
	}
}

func TestAdminOps_DisabledByDefault(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server := mcp.NewServer(&mcp.Implementation{Name: "no-admin", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{
		Gate: policy.NewDefaultReadOnlyGate(),
	})
	client := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "test"}, nil)
	ct, st := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	listed, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range listed.Tools {
		if strings.HasPrefix(tool.Name, "admin_") {
			t.Fatalf("admin tools must not register by default: %s", tool.Name)
		}
	}
}

func toolResultBlob(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if res == nil {
		return ""
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}
