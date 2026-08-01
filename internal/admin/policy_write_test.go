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

	"github.com/simonfxr/go-jenkins-mcp/internal/admin"
	"github.com/simonfxr/go-jenkins-mcp/internal/config"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

const policyWriteCanary = "planted-admin-secret-token-NEVER-ECHO-ui004"

func testPaths(t *testing.T) config.Paths {
	t.Helper()
	root := t.TempDir()
	return config.Paths{
		ConfigDir: filepath.Join(root, "config"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
}

func writeTestOverlay(t *testing.T, paths config.Paths, o policy.Overlay) string {
	t.Helper()
	path := paths.DefaultPolicyFile()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	o.Signature = ""
	raw, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newPolicyAdminHandler(t *testing.T, role admin.Role, token string, paths config.Paths) http.Handler {
	t.Helper()
	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = role
	cfg.BearerToken = token
	cfg.Paths = &paths
	cfg.ProfileID = "corp"
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func doJSON(t *testing.T, h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestPolicyWrite_AuthzMatrix(t *testing.T) {
	// Clear POLICY_REQUIRED for pilot plain apply path.
	t.Setenv(policy.EnvPolicyRequiredVar, "")
	t.Setenv(policy.EnvPolicyFileVar, "")

	paths := testPaths(t)
	writeTestOverlay(t, paths, policy.Overlay{
		Version:       1,
		ForceReadOnly: true,
		Mode:          policy.ModePilot,
		DenyTools:     []string{"jenkins_get_build_logs"},
	})

	draft := map[string]any{
		"overlay": map[string]any{
			"version":         1,
			"force_read_only": true,
			"mode":            "pilot",
			"deny_tools":      []string{"jenkins_get_build_logs", "jenkins_get_console"},
		},
		"profileId": "corp",
	}

	cases := []struct {
		name       string
		role       admin.Role
		wantStatus int
	}{
		{"viewer_validate", admin.RoleViewer, http.StatusForbidden},
		{"operator_validate", admin.RoleOperator, http.StatusForbidden},
		{"policy_admin_validate", admin.RolePolicyAdmin, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newPolicyAdminHandler(t, tc.role, policyWriteCanary, paths)
			rr := doJSON(t, h, http.MethodPost, "/admin/v1/policy/validate", policyWriteCanary, draft)
			if rr.Code != tc.wantStatus {
				t.Fatalf("status=%d body=%s want %d", rr.Code, rr.Body.String(), tc.wantStatus)
			}
			if strings.Contains(rr.Body.String(), policyWriteCanary) {
				t.Fatal("response must never contain planted token")
			}
			if tc.wantStatus == http.StatusForbidden {
				var errBody map[string]string
				if err := json.Unmarshal(rr.Body.Bytes(), &errBody); err != nil {
					t.Fatal(err)
				}
				if errBody["code"] != "permission_denied" {
					t.Fatalf("code=%q", errBody["code"])
				}
			}
		})
	}

	// Apply: same matrix
	for _, role := range []admin.Role{admin.RoleViewer, admin.RoleOperator} {
		h := newPolicyAdminHandler(t, role, policyWriteCanary, paths)
		rr := doJSON(t, h, http.MethodPost, "/admin/v1/policy/apply", policyWriteCanary, draft)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("role %s apply want 403, got %d body=%s", role, rr.Code, rr.Body.String())
		}
		if strings.Contains(rr.Body.String(), policyWriteCanary) {
			t.Fatal("apply 403 must not contain token")
		}
	}
}

func TestPolicyWrite_Unauthenticated401(t *testing.T) {
	t.Setenv(policy.EnvPolicyRequiredVar, "")
	t.Setenv(policy.EnvPolicyFileVar, "")
	paths := testPaths(t)
	h := newPolicyAdminHandler(t, admin.RolePolicyAdmin, policyWriteCanary, paths)

	draft := map[string]any{
		"overlay": map[string]any{
			"version":         1,
			"force_read_only": true,
			"mode":            "pilot",
		},
	}
	for _, path := range []string{"/admin/v1/policy/validate", "/admin/v1/policy/apply"} {
		rr := doJSON(t, h, http.MethodPost, path, "", draft)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s want 401, got %d body=%s", path, rr.Code, rr.Body.String())
		}
		if strings.Contains(rr.Body.String(), policyWriteCanary) {
			t.Fatal("401 body must not echo token")
		}
	}
	// Overlay GET also gated when token configured
	rr := doJSON(t, h, http.MethodGet, "/admin/v1/policy/overlay", "", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("overlay GET want 401, got %d", rr.Code)
	}
}

func TestPolicyWrite_ForceReadOnlyWidenRejected(t *testing.T) {
	t.Setenv(policy.EnvPolicyRequiredVar, "")
	t.Setenv(policy.EnvPolicyFileVar, "")
	paths := testPaths(t)
	path := writeTestOverlay(t, paths, policy.Overlay{
		Version:       1,
		ForceReadOnly: true,
		Mode:          policy.ModePilot,
		DenyTools:     []string{"jenkins_get_build_logs"},
	})
	// Snapshot mtime/content for "never written" check.
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	h := newPolicyAdminHandler(t, admin.RolePolicyAdmin, policyWriteCanary, paths)
	draft := map[string]any{
		"overlay": map[string]any{
			"version":         1,
			"force_read_only": false, // widen attempt
			"mode":            "pilot",
			"deny_tools":      []string{"jenkins_get_build_logs"},
		},
		"profileId": "corp",
	}

	rr := doJSON(t, h, http.MethodPost, "/admin/v1/policy/validate", policyWriteCanary, draft)
	if rr.Code != http.StatusOK {
		t.Fatalf("validate status=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), policyWriteCanary) {
		t.Fatal("canary in validate body")
	}
	var vresp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &vresp); err != nil {
		t.Fatal(err)
	}
	if vresp["valid"] != false {
		t.Fatalf("valid=%v want false", vresp["valid"])
	}
	errs, _ := vresp["errors"].([]any)
	if len(errs) == 0 {
		t.Fatal("expected field errors for force_read_only widen")
	}
	found := false
	for _, e := range errs {
		m, _ := e.(map[string]any)
		if m["field"] == "force_read_only" {
			found = true
		}
	}
	if !found {
		t.Fatalf("errors=%v want force_read_only field", errs)
	}

	// Apply must not write
	rr2 := doJSON(t, h, http.MethodPost, "/admin/v1/policy/apply", policyWriteCanary, draft)
	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("apply widen want 400, got %d body=%s", rr2.Code, rr2.Body.String())
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("invalid apply must not rewrite overlay file")
	}
	if strings.Contains(rr2.Body.String(), policyWriteCanary) {
		t.Fatal("canary in apply body")
	}
}

func TestPolicyWrite_DenyListMustBeSuperset(t *testing.T) {
	t.Setenv(policy.EnvPolicyRequiredVar, "")
	t.Setenv(policy.EnvPolicyFileVar, "")
	paths := testPaths(t)
	writeTestOverlay(t, paths, policy.Overlay{
		Version:       1,
		ForceReadOnly: true,
		DenyTools:     []string{"tool_a", "tool_b"},
	})
	h := newPolicyAdminHandler(t, admin.RolePolicyAdmin, policyWriteCanary, paths)
	// Drop tool_b → widen
	draft := map[string]any{
		"overlay": map[string]any{
			"version":         1,
			"force_read_only": true,
			"deny_tools":      []string{"tool_a"},
		},
	}
	rr := doJSON(t, h, http.MethodPost, "/admin/v1/policy/validate", policyWriteCanary, draft)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	var vresp struct {
		Valid  bool `json:"valid"`
		Errors []struct {
			Field string `json:"field"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &vresp); err != nil {
		t.Fatal(err)
	}
	if vresp.Valid {
		t.Fatal("want invalid when deny list shrinks")
	}
	found := false
	for _, e := range vresp.Errors {
		if e.Field == "deny_tools" {
			found = true
		}
	}
	if !found {
		t.Fatalf("errors=%+v", vresp.Errors)
	}
}

func TestPolicyWrite_ApplyWritesFile(t *testing.T) {
	t.Setenv(policy.EnvPolicyRequiredVar, "")
	t.Setenv(policy.EnvPolicyFileVar, "")
	paths := testPaths(t)
	writeTestOverlay(t, paths, policy.Overlay{
		Version:       1,
		ForceReadOnly: true,
		Mode:          policy.ModePilot,
		DenyTools:     []string{"jenkins_get_build_logs"},
	})
	h := newPolicyAdminHandler(t, admin.RolePolicyAdmin, policyWriteCanary, paths)

	draft := map[string]any{
		"overlay": map[string]any{
			"version":          1,
			"force_read_only":  true,
			"mode":             "pilot",
			"deny_tools":       []string{"jenkins_get_build_logs", "extra_tool"},
			"max_result_bytes": 32768,
		},
		"profileId": "corp",
	}
	rr := doJSON(t, h, http.MethodPost, "/admin/v1/policy/apply", policyWriteCanary, draft)
	if rr.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), policyWriteCanary) {
		t.Fatal("canary in apply success body")
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["applied"] != true {
		t.Fatalf("applied=%v", resp["applied"])
	}

	path := paths.DefaultPolicyFile()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), policyWriteCanary) {
		t.Fatal("overlay file must not contain canary")
	}
	var got policy.Overlay
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if !got.ForceReadOnly {
		t.Fatal("written force_read_only")
	}
	if len(got.DenyTools) != 2 {
		t.Fatalf("deny_tools=%v", got.DenyTools)
	}
	if got.Signature != "" {
		t.Fatal("signature must not be written from browser")
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o want 0600", st.Mode().Perm())
	}

	// GET overlay returns the written plain doc
	rrGet := doJSON(t, h, http.MethodGet, "/admin/v1/policy/overlay", policyWriteCanary, nil)
	if rrGet.Code != http.StatusOK {
		t.Fatalf("get status=%d body=%s", rrGet.Code, rrGet.Body.String())
	}
	if strings.Contains(rrGet.Body.String(), policyWriteCanary) {
		t.Fatal("canary in GET overlay")
	}
	var og map[string]any
	if err := json.Unmarshal(rrGet.Body.Bytes(), &og); err != nil {
		t.Fatal(err)
	}
	if og["available"] != true {
		t.Fatalf("available=%v", og["available"])
	}
	// Never return PEM-like key material keys
	for _, forbidden := range []string{"BEGIN PRIVATE", "private_key", "ed25519_seed"} {
		if strings.Contains(rrGet.Body.String(), forbidden) {
			t.Fatalf("response contains forbidden %q", forbidden)
		}
	}
}

func TestPolicyWrite_InvalidNeverWrites(t *testing.T) {
	t.Setenv(policy.EnvPolicyRequiredVar, "")
	t.Setenv(policy.EnvPolicyFileVar, "")
	paths := testPaths(t)
	path := writeTestOverlay(t, paths, policy.Overlay{
		Version:       1,
		ForceReadOnly: true,
	})
	before, _ := os.ReadFile(path)
	h := newPolicyAdminHandler(t, admin.RolePolicyAdmin, policyWriteCanary, paths)

	// Invalid schema version
	draft := map[string]any{
		"overlay": map[string]any{
			"version":         99,
			"force_read_only": true,
		},
	}
	rr := doJSON(t, h, http.MethodPost, "/admin/v1/policy/apply", policyWriteCanary, draft)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d body=%s", rr.Code, rr.Body.String())
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("invalid apply rewrote file")
	}
}

func TestPolicyWrite_PolicyRequiredBlocksApply(t *testing.T) {
	t.Setenv(policy.EnvPolicyRequiredVar, "1")
	t.Setenv(policy.EnvPolicyFileVar, "")
	paths := testPaths(t)
	path := writeTestOverlay(t, paths, policy.Overlay{
		Version:       1,
		ForceReadOnly: true,
	})
	before, _ := os.ReadFile(path)
	h := newPolicyAdminHandler(t, admin.RolePolicyAdmin, policyWriteCanary, paths)

	draft := map[string]any{
		"overlay": map[string]any{
			"version":         1,
			"force_read_only": true,
			"deny_tools":      []string{"x"},
		},
	}
	rr := doJSON(t, h, http.MethodPost, "/admin/v1/policy/apply", policyWriteCanary, draft)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("POLICY_REQUIRED apply want 403, got %d body=%s", rr.Code, rr.Body.String())
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("require-signed mode must not write plain overlay")
	}
	if strings.Contains(rr.Body.String(), policyWriteCanary) {
		t.Fatal("canary leak")
	}
}

func TestPolicyWrite_OverlayMissingAvailableFalse(t *testing.T) {
	t.Setenv(policy.EnvPolicyRequiredVar, "")
	t.Setenv(policy.EnvPolicyFileVar, "")
	paths := testPaths(t)
	h := newPolicyAdminHandler(t, admin.RoleViewer, policyWriteCanary, paths)
	rr := doJSON(t, h, http.MethodGet, "/admin/v1/policy/overlay", policyWriteCanary, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var og map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &og); err != nil {
		t.Fatal(err)
	}
	if og["available"] != false {
		t.Fatalf("available=%v", og["available"])
	}
}

func TestCheckMonotonicRestrict_Unit(t *testing.T) {
	// Exported helpers are package-private; exercise via validate HTTP.
	// Covered by ForceReadOnlyWiden + DenyListMustBeSuperset above.
	t.Parallel()
}

func TestCanWidenForceReadOnly_StillAlwaysFalse(t *testing.T) {
	t.Parallel()
	if admin.CanWidenForceReadOnly(admin.RolePolicyAdmin) {
		t.Fatal("policy_admin still must not widen force RO")
	}
}
