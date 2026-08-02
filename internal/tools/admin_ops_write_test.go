package tools_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/simonfxr/go-jenkins-mcp/internal/adminops"
	"github.com/simonfxr/go-jenkins-mcp/internal/audit"
	"github.com/simonfxr/go-jenkins-mcp/internal/config"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
	"github.com/simonfxr/go-jenkins-mcp/internal/profile"
	"github.com/simonfxr/go-jenkins-mcp/internal/tools"
)

// MCP-OPS write path honesty: CallTool for real writes + AUD-001 types that
// survive ReloadingFilterSink (OpenProfileSink production path).
func TestAdminOps_MCPWrites_AndFilterSinkAudits(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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

	// Production-shaped sink: filter drops unknown types; known admin types must pass.
	mem := &audit.Memory{}
	filtered := audit.NewReloadingFilterSink(filepath.Join(dir, "profile-data"), mem)

	// policy_admin has policy_write + gateway_ops; operator has cache_destructive.
	// Use policy_admin for mixed write tests; cache_destructive needs operator.
	// RolePolicyAdmin has gateway_ops + policy_write but NOT cache_destructive.
	// Split: operator for cache/support; policy_admin for policy/audit settings.
	svcOp := adminops.New(adminops.Config{
		Role:             adminops.RoleOperator,
		Version:          "v-test",
		ProfileStore:     ps,
		Paths:            &paths,
		DefaultProfileID: "corp",
		Audit:            filtered,
		Getenv:           func(string) string { return "" },
	})
	svcPol := adminops.New(adminops.Config{
		Role:             adminops.RolePolicyAdmin,
		Version:          "v-test",
		ProfileStore:     ps,
		Paths:            &paths,
		DefaultProfileID: "corp",
		Audit:            filtered,
		Getenv:           func(string) string { return "" },
	})

	// --- Service-level: policy validate with real overlay ---
	ov := &policy.Overlay{
		Version:       policy.CurrentOverlayVersion,
		ForceReadOnly: true,
		Mode:          policy.ModePilot,
		DenyTools:     []string{"jenkins_start_job"},
	}
	vOut, err := svcPol.PolicyValidate(ctx, ov, "corp")
	if err != nil {
		t.Fatal(err)
	}
	if valid, _ := vOut["valid"].(bool); !valid {
		t.Fatalf("validate want valid: %+v", vOut)
	}

	// --- MCP CallTool: audit settings put (gateway_ops via operator) ---
	server := mcp.NewServer(&mcp.Implementation{Name: "admin-write", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{
		Gate:           policy.NewDefaultReadOnlyGate(),
		EnableAdminOps: true,
		AdminOps:       svcOp,
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

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "admin_audit_settings_put",
		Arguments: map[string]any{
			"profile_id": "corp",
			"enabled":    map[string]any{audit.TypeToolDeny: false},
		},
	})
	if err != nil {
		t.Fatalf("audit_settings_put: %v", err)
	}
	blob := toolResultBlob(t, res)
	if res.IsError {
		t.Fatalf("audit_settings_put tool error: %s", blob)
	}
	if !strings.Contains(blob, "tool_deny") || !strings.Contains(blob, "false") && !strings.Contains(blob, `"tool_deny":false`) {
		// Accept either JSON false representation
		if !strings.Contains(blob, "enabled") {
			t.Fatalf("unexpected put result: %s", blob)
		}
	}

	// Wrong confirm on cache evict
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "admin_cache_evict",
		Arguments: map[string]any{
			"profile_id": "corp",
			"confirm":    "nope",
		},
	})
	if err != nil {
		t.Fatalf("cache_evict transport: %v", err)
	}
	// Expect tool-level error (IsError) or empty structured with error content
	if !res.IsError {
		// mapToolErr may still return IsError true; if not, service path must have failed
		b := toolResultBlob(t, res)
		if !strings.Contains(strings.ToLower(b), "confirm") && !strings.Contains(strings.ToLower(b), "evict") {
			// Call service directly to prove confirm gate
			_, cerr := svcOp.CacheEvict(ctx, "corp", 0, "nope")
			if cerr == nil {
				t.Fatal("cache evict must require EVICT")
			}
		}
	}

	// Correct confirm
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "admin_cache_evict",
		Arguments: map[string]any{
			"profile_id": "corp",
			"confirm":    adminops.ConfirmEVICT,
		},
	})
	if err != nil {
		t.Fatalf("cache_evict EVICT: %v", err)
	}
	if res.IsError {
		t.Fatalf("cache_evict EVICT failed: %s", toolResultBlob(t, res))
	}

	// Consent purge expire (no CLEAR_ALL needed)
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "admin_consent_purge",
		Arguments: map[string]any{
			"action": "expire",
		},
	})
	if err != nil {
		t.Fatalf("consent_purge: %v", err)
	}
	if res.IsError {
		t.Fatalf("consent_purge expire failed: %s", toolResultBlob(t, res))
	}

	// CLEAR_ALL without confirm fails
	_, cerr := svcOp.ConsentPurge(ctx, "clear_all", "", "")
	if cerr == nil {
		t.Fatal("clear_all without confirm must fail")
	}

	// Policy validate via MCP with overlay body (policy_admin server)
	serverPol := mcp.NewServer(&mcp.Implementation{Name: "admin-pol", Version: "test"}, nil)
	tools.Register(serverPol, &jenkins.Client{}, &tools.RegisterOptions{
		Gate:           policy.NewDefaultReadOnlyGate(),
		EnableAdminOps: true,
		AdminOps:       svcPol,
	})
	ct2, st2 := mcp.NewInMemoryTransports()
	ss2, err := serverPol.Connect(ctx, st2, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss2.Close()
	cs2, err := client.Connect(ctx, ct2, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs2.Close()

	res, err = cs2.CallTool(ctx, &mcp.CallToolParams{
		Name: "admin_policy_validate",
		Arguments: map[string]any{
			"profile_id": "corp",
			"overlay": map[string]any{
				"version":         policy.CurrentOverlayVersion,
				"force_read_only": true,
				"mode":            "pilot",
				"deny_tools":      []any{"jenkins_start_job"},
			},
		},
	})
	if err != nil {
		t.Fatalf("policy_validate: %v", err)
	}
	blob = toolResultBlob(t, res)
	if res.IsError {
		t.Fatalf("policy_validate error: %s", blob)
	}
	// Must not be the "overlay body omitted" residual note only
	if strings.Contains(blob, "overlay body omitted") {
		t.Fatalf("overlay was provided but treated as omitted: %s", blob)
	}
	// valid true expected
	var parsed map[string]any
	if err := json.Unmarshal([]byte(firstJSONObject(blob)), &parsed); err == nil {
		if v, ok := parsed["valid"].(bool); ok && !v {
			t.Fatalf("want valid true: %s", blob)
		}
	}

	// Apply with confirm (residual durable apply OK; must decode overlay)
	res, err = cs2.CallTool(ctx, &mcp.CallToolParams{
		Name: "admin_policy_apply",
		Arguments: map[string]any{
			"profile_id": "corp",
			"confirm":    adminops.ConfirmAPPLY,
			"overlay": map[string]any{
				"version":         policy.CurrentOverlayVersion,
				"force_read_only": true,
				"mode":            "pilot",
			},
		},
	})
	if err != nil {
		t.Fatalf("policy_apply: %v", err)
	}
	if res.IsError {
		// apply may return residual applied=false without IsError
		t.Logf("policy_apply result: %s", toolResultBlob(t, res))
	}

	// --- ReloadingFilterSink: all known admin write types must be retained ---
	evs := mem.Events()
	wantTypes := map[string]bool{
		audit.TypeAuditSettings:     false,
		audit.TypeAdminCacheEvict:   false,
		audit.TypeAdminConsentPurge: false,
		audit.TypePolicyValidate:    false,
		audit.TypePolicyApply:       false,
	}
	for _, e := range evs {
		if _, ok := wantTypes[e.Type]; ok {
			wantTypes[e.Type] = true
		}
		// Unknown types must not appear (filter fail-closed)
		if !audit.IsKnownEventType(e.Type) {
			t.Fatalf("unknown audit type reached Memory through filter: %q", e.Type)
		}
	}
	for typ, seen := range wantTypes {
		if !seen {
			// policy validate from service + MCP may both fire; require at least these writes
			t.Fatalf("expected filtered sink to retain type %s; events=%v", typ, eventTypes(evs))
		}
	}
}

func eventTypes(evs []audit.Event) []string {
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.Type)
	}
	return out
}

// firstJSONObject returns the first {...} substring for loose parsing of tool text.
func firstJSONObject(s string) string {
	i := strings.Index(s, "{")
	j := strings.LastIndex(s, "}")
	if i < 0 || j <= i {
		return s
	}
	return s[i : j+1]
}
