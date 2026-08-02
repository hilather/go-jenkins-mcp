package admin_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/admin"
	"github.com/hilather/go-jenkins-mcp/internal/config"
	"github.com/hilather/go-jenkins-mcp/internal/keyring"
	"github.com/hilather/go-jenkins-mcp/internal/profile"
	"github.com/hilather/go-jenkins-mcp/internal/store"
)

const secretCanary = "planted-API-TOKEN-never-echo-UI007-9x7z"

func opsTestPaths(t *testing.T) config.Paths {
	t.Helper()
	tmp := t.TempDir()
	return config.Paths{
		ConfigDir: filepath.Join(tmp, "cfg"),
		DataDir:   filepath.Join(tmp, "data"),
		CacheDir:  filepath.Join(tmp, "cache"),
	}
}

func seedCorpProfile(t *testing.T, paths config.Paths) *profile.Profile {
	t.Helper()
	st := profile.NewStore(paths)
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		DisplayName:   "Corp Jenkins",
		JenkinsURL:    "https://jenkins.example.corp/",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	if err := st.Save(p); err != nil {
		t.Fatal(err)
	}
	return p
}

func ensureProfileData(t *testing.T, paths config.Paths, id string) string {
	t.Helper()
	dataDir, err := store.EnsureProfileDataDir(paths.ProfileDataDir(id), id)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := store.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := meta.Close(); err != nil {
		t.Fatal(err)
	}
	return dataDir
}

func newOpsHandler(t *testing.T, paths config.Paths, role admin.Role, token string, kr *keyring.Store) http.Handler {
	t.Helper()
	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Paths = &paths
	cfg.Role = role
	cfg.BearerToken = token
	cfg.Version = "dev"
	cfg.Commit = "test"
	cfg.BuildTime = "now"
	if kr != nil {
		cfg.Keyring = kr
	} else {
		cfg.Keyring = keyring.NewStore(keyring.NewMemory())
	}
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func withToken(req *http.Request, token string) *http.Request {
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func assertNoSecretCanary(t *testing.T, body string) {
	t.Helper()
	if strings.Contains(body, secretCanary) {
		t.Fatalf("response must not contain secret canary: %s", body)
	}
	lower := strings.ToLower(body)
	for _, bad := range []string{
		`"apitoken"`, `"api_token":"`, `"password":"`, `"client_secret"`,
		`"access_token"`, `"refresh_token"`,
	} {
		if strings.Contains(lower, bad) {
			t.Fatalf("response looks secret-bearing (%s): %s", bad, body)
		}
	}
}

func TestProfilesList_SecretFreeAndNoTokenFields(t *testing.T) {
	paths := opsTestPaths(t)
	seedCorpProfile(t, paths)
	// Plant a secret in keyring — must never appear in JSON.
	kr := keyring.NewStore(keyring.NewMemory())
	origin, err := profile.NormalizedOrigin("https://jenkins.example.corp/")
	if err != nil {
		t.Fatal(err)
	}
	if err := kr.SetAPIToken(keyring.CredentialRef{
		ProfileID: "corp",
		Origin:    origin,
		Method:    string(profile.AuthMethodAPIToken),
		Account:   "alice",
	}, secretCanary); err != nil {
		t.Fatal(err)
	}

	h := newOpsHandler(t, paths, admin.RoleViewer, "", kr)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/v1/profiles", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	assertNoSecretCanary(t, rr.Body.String())

	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	profiles, ok := body["profiles"].([]any)
	if !ok || len(profiles) != 1 {
		t.Fatalf("profiles=%v", body["profiles"])
	}
	row, ok := profiles[0].(map[string]any)
	if !ok {
		t.Fatalf("row=%T", profiles[0])
	}
	if row["id"] != "corp" {
		t.Fatalf("id=%v", row["id"])
	}
	if row["authMethod"] != "api_token" {
		t.Fatalf("authMethod=%v", row["authMethod"])
	}
	if row["hasCredential"] != true {
		t.Fatalf("hasCredential=%v want true", row["hasCredential"])
	}
	for _, k := range []string{"token", "apiToken", "password", "secret", "clientSecret"} {
		if _, present := row[k]; present {
			t.Fatalf("profile row must not contain key %q", k)
		}
	}
	raw, _ := json.Marshal(row)
	if strings.Contains(string(raw), secretCanary) {
		t.Fatal("profile row must not embed keyring token")
	}
}

func TestProfileGet_PathTraversalRejected(t *testing.T) {
	paths := opsTestPaths(t)
	seedCorpProfile(t, paths)
	h := newOpsHandler(t, paths, admin.RoleViewer, "", nil)

	for _, id := range []string{
		"..",
		"../etc/passwd",
		"corp/../../x",
		"/etc/passwd",
		"corp/../corp",
	} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/profiles/"+id, nil)
		h.ServeHTTP(rr, req)
		if rr.Code == http.StatusOK {
			t.Errorf("id %q should be rejected, got 200 body=%s", id, rr.Body.String())
		}
		if rr.Code == http.StatusInternalServerError {
			t.Errorf("id %q should fail closed client-side, got 500 body=%s", id, rr.Body.String())
		}
		assertNoSecretCanary(t, rr.Body.String())
	}
}

func TestProfileGet_OK(t *testing.T) {
	paths := opsTestPaths(t)
	seedCorpProfile(t, paths)
	h := newOpsHandler(t, paths, admin.RoleViewer, "", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/v1/profiles/corp", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	assertNoSecretCanary(t, rr.Body.String())
	var row map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &row); err != nil {
		t.Fatal(err)
	}
	if row["id"] != "corp" || row["jenkinsHost"] != "jenkins.example.corp" {
		t.Fatalf("row=%v", row)
	}
}

func TestCacheGet_UnavailableWhenNoStore(t *testing.T) {
	paths := opsTestPaths(t)
	seedCorpProfile(t, paths)
	// No data dir created → available:false, not 500.
	h := newOpsHandler(t, paths, admin.RoleViewer, "", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/v1/profiles/corp/cache", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	assertNoSecretCanary(t, rr.Body.String())
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["available"] != false {
		t.Fatalf("available=%v want false", body["available"])
	}
	if residual, _ := body["residual"].(string); residual == "" {
		t.Fatal("expected residual when store unavailable")
	}
}

func TestCacheGet_AvailableWithUsage(t *testing.T) {
	paths := opsTestPaths(t)
	p := seedCorpProfile(t, paths)
	_ = ensureProfileData(t, paths, string(p.ID))

	h := newOpsHandler(t, paths, admin.RoleViewer, "", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/v1/profiles/corp/cache", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	assertNoSecretCanary(t, rr.Body.String())
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["available"] != true {
		t.Fatalf("available=%v body=%v", body["available"], body)
	}
	usage, ok := body["usage"].(map[string]any)
	if !ok {
		t.Fatalf("usage missing: %v", body)
	}
	if _, ok := usage["total_physical_bytes"]; !ok {
		t.Fatalf("usage fields: %v", usage)
	}
}

func TestCacheEvict_ViewerForbidden_OperatorRequiresConfirm(t *testing.T) {
	paths := opsTestPaths(t)
	p := seedCorpProfile(t, paths)
	_ = ensureProfileData(t, paths, string(p.ID))

	// Viewer → 403
	hViewer := newOpsHandler(t, paths, admin.RoleViewer, "", nil)
	rr := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"confirm":"EVICT"}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/profiles/corp/cache/evict", body)
	req.Header.Set("Content-Type", "application/json")
	hViewer.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("viewer want 403, got %d body=%s", rr.Code, rr.Body.String())
	}
	assertNoSecretCanary(t, rr.Body.String())
	var errBody map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &errBody); err != nil {
		t.Fatal(err)
	}
	if errBody["code"] != "permission_denied" {
		t.Fatalf("code=%q", errBody["code"])
	}

	// Operator without confirm → 400
	hOp := newOpsHandler(t, paths, admin.RoleOperator, secretCanary, nil)
	rr2 := httptest.NewRecorder()
	req2 := withToken(httptest.NewRequest(http.MethodPost, "/admin/v1/profiles/corp/cache/evict",
		bytes.NewBufferString(`{"confirm":"yes"}`)), secretCanary)
	req2.Header.Set("Content-Type", "application/json")
	hOp.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("missing exact confirm want 400, got %d body=%s", rr2.Code, rr2.Body.String())
	}
	assertNoSecretCanary(t, rr2.Body.String())
	if strings.Contains(rr2.Body.String(), secretCanary) {
		t.Fatal("error body must not echo admin token")
	}

	// Empty confirm → 400
	rr3 := httptest.NewRecorder()
	req3 := withToken(httptest.NewRequest(http.MethodPost, "/admin/v1/profiles/corp/cache/evict",
		bytes.NewBufferString(`{}`)), secretCanary)
	req3.Header.Set("Content-Type", "application/json")
	hOp.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusBadRequest {
		t.Fatalf("empty confirm want 400, got %d", rr3.Code)
	}

	// Operator + EVICT → 200 (nothing to reclaim is fine)
	rr4 := httptest.NewRecorder()
	req4 := withToken(httptest.NewRequest(http.MethodPost, "/admin/v1/profiles/corp/cache/evict",
		bytes.NewBufferString(`{"confirm":"EVICT"}`)), secretCanary)
	req4.Header.Set("Content-Type", "application/json")
	hOp.ServeHTTP(rr4, req4)
	if rr4.Code != http.StatusOK {
		t.Fatalf("operator+EVICT want 200, got %d body=%s", rr4.Code, rr4.Body.String())
	}
	assertNoSecretCanary(t, rr4.Body.String())
	var plan map[string]any
	if err := json.Unmarshal(rr4.Body.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if plan["profileId"] != "corp" {
		t.Fatalf("plan=%v", plan)
	}
	if plan["dryRun"] != false {
		t.Fatalf("dryRun=%v want false", plan["dryRun"])
	}
	if plan["applied"] != true {
		t.Fatalf("applied=%v want true", plan["applied"])
	}
}

func TestCacheEvictPlan_AllRolesRead(t *testing.T) {
	paths := opsTestPaths(t)
	p := seedCorpProfile(t, paths)
	_ = ensureProfileData(t, paths, string(p.ID))

	for _, role := range []admin.Role{admin.RoleViewer, admin.RoleOperator, admin.RolePolicyAdmin} {
		h := newOpsHandler(t, paths, role, "", nil)
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/v1/profiles/corp/cache/evict-plan",
			bytes.NewBufferString(`{"targetBytes":0}`))
		req.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("role %s plan want 200, got %d body=%s", role, rr.Code, rr.Body.String())
		}
		assertNoSecretCanary(t, rr.Body.String())
		var plan map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &plan); err != nil {
			t.Fatal(err)
		}
		if plan["dryRun"] != true {
			t.Fatalf("role %s dryRun=%v", role, plan["dryRun"])
		}
		if _, ok := plan["candidates"]; !ok {
			t.Fatalf("role %s missing candidates", role)
		}
	}
}

func TestSupportBundle_ViewerForbidden_OperatorPreviewAndCreate(t *testing.T) {
	paths := opsTestPaths(t)
	seedCorpProfile(t, paths)

	// Viewer → 403
	hViewer := newOpsHandler(t, paths, admin.RoleViewer, "", nil)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/profiles/corp/support-bundle",
		bytes.NewBufferString(`{"preview":true,"offline":true}`))
	req.Header.Set("Content-Type", "application/json")
	hViewer.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("viewer support-bundle want 403, got %d body=%s", rr.Code, rr.Body.String())
	}
	assertNoSecretCanary(t, rr.Body.String())

	// Operator preview
	hOp := newOpsHandler(t, paths, admin.RoleOperator, secretCanary, nil)
	rr2 := httptest.NewRecorder()
	req2 := withToken(httptest.NewRequest(http.MethodPost, "/admin/v1/profiles/corp/support-bundle",
		bytes.NewBufferString(`{"preview":true}`)), secretCanary)
	req2.Header.Set("Content-Type", "application/json")
	hOp.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("operator preview want 200, got %d body=%s", rr2.Code, rr2.Body.String())
	}
	assertNoSecretCanary(t, rr2.Body.String())
	var prev map[string]any
	if err := json.Unmarshal(rr2.Body.Bytes(), &prev); err != nil {
		t.Fatal(err)
	}
	if prev["preview"] != true {
		t.Fatalf("preview=%v", prev["preview"])
	}
	if path, _ := prev["path"].(string); path != "" {
		t.Fatalf("preview must not set path: %v", prev["path"])
	}
	included, ok := prev["included"].([]any)
	if !ok || len(included) == 0 {
		t.Fatalf("included=%v", prev["included"])
	}

	// Operator create (writes zip under cache dir)
	rr3 := httptest.NewRecorder()
	req3 := withToken(httptest.NewRequest(http.MethodPost, "/admin/v1/profiles/corp/support-bundle",
		bytes.NewBufferString(`{"preview":false,"offline":true}`)), secretCanary)
	req3.Header.Set("Content-Type", "application/json")
	hOp.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Fatalf("operator create want 200, got %d body=%s", rr3.Code, rr3.Body.String())
	}
	assertNoSecretCanary(t, rr3.Body.String())
	var created map[string]any
	if err := json.Unmarshal(rr3.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	path, _ := created["path"].(string)
	if path == "" {
		t.Fatalf("create must return path: %v", created)
	}
	if _, ok := created["bytes"].(float64); !ok {
		t.Fatalf("create must return bytes: %v", created)
	}
	if strings.Contains(rr3.Body.String(), secretCanary) {
		t.Fatal("support-bundle response must not contain planted secret")
	}
}

func TestSecuritySelfCheck_SecretFree(t *testing.T) {
	paths := opsTestPaths(t)
	seedCorpProfile(t, paths)
	h := newOpsHandler(t, paths, admin.RoleViewer, "", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/v1/profiles/corp/security-selfcheck", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	assertNoSecretCanary(t, rr.Body.String())
	if strings.Contains(rr.Body.String(), "QA005_SELFCHECK_CANARY") {
		t.Fatal("security self-check canary leaked into response")
	}
	var rep map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if _, ok := rep["items"]; !ok {
		t.Fatalf("items missing: %v", rep)
	}
}

func TestOps_PathTraversal_OnWriteRoutes(t *testing.T) {
	paths := opsTestPaths(t)
	seedCorpProfile(t, paths)
	h := newOpsHandler(t, paths, admin.RoleOperator, "", nil)
	for _, path := range []string{
		"/admin/v1/profiles/../etc/cache/evict",
		"/admin/v1/profiles/foo/../bar/cache/evict",
	} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(`{"confirm":"EVICT"}`))
		req.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(rr, req)
		if rr.Code == http.StatusOK {
			t.Errorf("path %q should not succeed", path)
		}
		assertNoSecretCanary(t, rr.Body.String())
	}
}

func TestPolicyAdmin_CannotEvict(t *testing.T) {
	// policy_admin has policy_write but not cache_destructive
	paths := opsTestPaths(t)
	p := seedCorpProfile(t, paths)
	_ = ensureProfileData(t, paths, string(p.ID))

	h := newOpsHandler(t, paths, admin.RolePolicyAdmin, "", nil)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/profiles/corp/cache/evict",
		bytes.NewBufferString(`{"confirm":"EVICT"}`))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("policy_admin want 403 on evict, got %d", rr.Code)
	}
}
