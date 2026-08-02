package admin_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/admin"
	"github.com/hilather/go-jenkins-mcp/internal/config"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

func TestUI011_BindingsListPutPreview(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "cfg"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(dir, "data"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	t.Setenv("HOME", dir)
	t.Setenv(policy.EnvPolicyFileVar, "")
	t.Setenv(policy.EnvRequireSignedPolicyVar, "")
	t.Setenv(policy.EnvPolicyTrustedKeysVar, "")

	// Ensure policy dir exists for default overlay write
	paths, err := config.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(paths.DefaultPolicyFile()), 0o700); err != nil {
		t.Fatal(err)
	}

	h, err := admin.NewHandler(admin.Config{
		Addr:  "127.0.0.1:0",
		Role:  admin.RolePolicyAdmin,
		Paths: &paths,
	})
	if err != nil {
		t.Fatal(err)
	}

	// List empty-ish
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/policy/bindings", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET bindings status %d body=%s", rr.Code, rr.Body.String())
	}
	var list admin.BindingsGetResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if list.FleetSoT == "" {
		t.Fatal("expected fleet_sot honesty")
	}

	// Put bindings
	putBody := map[string]any{
		"users": []map[string]any{{
			"jenkins_user_id": "alice",
			"deny_tools":      []string{"jenkins_get_build_logs"},
		}},
		"groups": []map[string]any{{
			"group_id":   "contractors",
			"deny_tools": []string{"jenkins_get_console_log"},
		}},
	}
	raw, _ := json.Marshal(putBody)
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPut, "/admin/v1/policy/bindings", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT bindings status %d body=%s", rr.Code, rr.Body.String())
	}
	var put admin.BindingsPutResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &put); err != nil {
		t.Fatal(err)
	}
	if !put.Applied || len(put.Users) != 1 || len(put.Groups) != 1 {
		t.Fatalf("put response: %+v", put)
	}
	// Canary: no secret-looking tokens in response
	if strings.Contains(rr.Body.String(), "Bearer ") || strings.Contains(rr.Body.String(), "api_token") {
		t.Fatalf("secret-shaped material in bindings response: %s", rr.Body.String())
	}

	// Preview alice denied logs
	prevRaw, _ := json.Marshal(map[string]any{
		"jenkins_user_id": "alice",
		"tool_name":       "jenkins_get_build_logs",
		"profileId":       "corp",
	})
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/admin/v1/policy/bindings/preview", bytes.NewReader(prevRaw))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("preview status %d %s", rr.Code, rr.Body.String())
	}
	var prev admin.BindingsPreviewResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &prev); err != nil {
		t.Fatal(err)
	}
	if prev.Allowed {
		t.Fatalf("alice should be denied logs: %+v", prev)
	}

	// Viewer cannot PUT
	hView, err := admin.NewHandler(admin.Config{Addr: "127.0.0.1:0", Role: admin.RoleViewer, Paths: &paths})
	if err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPut, "/admin/v1/policy/bindings", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	hView.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden && rr.Code != http.StatusUnauthorized {
		t.Fatalf("viewer put want deny, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestUI011_BindingsRefuseRequireSigned(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "cfg"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(dir, "data"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	t.Setenv("HOME", dir)
	t.Setenv(policy.EnvRequireSignedPolicyVar, "1")
	// keys empty → plainApplyBlocked or require signed
	t.Setenv(policy.EnvPolicyTrustedKeysVar, "")
	t.Setenv(policy.EnvPolicyFileVar, filepath.Join(dir, "overlay.json"))

	paths, err := config.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	h, err := admin.NewHandler(admin.Config{Addr: "127.0.0.1:0", Role: admin.RolePolicyAdmin, Paths: &paths})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{
		"users": []map[string]any{{"jenkins_user_id": "alice", "deny_tools": []string{"jenkins_get_build_logs"}}},
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/policy/bindings", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rr, req)
	// Forbidden or bad request when require signed blocks plain write
	if rr.Code == http.StatusOK {
		var put admin.BindingsPutResponse
		_ = json.Unmarshal(rr.Body.Bytes(), &put)
		if put.Applied {
			t.Fatalf("must not apply under REQUIRE_SIGNED without signed path: %s", rr.Body.String())
		}
	}
}
