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
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/admin"
	"github.com/simonfxr/go-jenkins-mcp/internal/audit"
	"github.com/simonfxr/go-jenkins-mcp/internal/config"
	"github.com/simonfxr/go-jenkins-mcp/internal/keyring"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
	"github.com/simonfxr/go-jenkins-mcp/internal/profile"
)

// UI-009 adversarial canaries — planted secrets and XSS payloads must never
// appear as executable HTML or echo back as secrets in API responses.
const (
	ui009SecretCanary = "planted-admin-secret-UI009-NEVER-ECHO-9x7zK"
	ui009XSSScript    = `<script>alert(1)</script>`
	ui009XSSJSURI     = `javascript:alert(1)`
	ui009XSSOnError   = `" onerror="alert(1)`
)

func ui009Paths(t *testing.T) config.Paths {
	t.Helper()
	root := t.TempDir()
	return config.Paths{
		ConfigDir: filepath.Join(root, "config"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
}

func ui009Handler(t *testing.T, cfg admin.Config) http.Handler {
	t.Helper()
	if strings.TrimSpace(cfg.Addr) == "" {
		cfg.Addr = "127.0.0.1:0"
	}
	if cfg.Keyring == nil {
		cfg.Keyring = keyring.NewStore(keyring.NewMemory())
	}
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func ui009Do(t *testing.T, h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
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

func ui009AssertNoSecret(t *testing.T, body string) {
	t.Helper()
	if strings.Contains(body, ui009SecretCanary) {
		t.Fatalf("response must never contain secret canary: %s", body)
	}
}

// ui009AssertJSONNotHTML checks Content-Type is application/json and that
// XSS payloads are JSON-escaped (encoding/json EscapeHTML → \u003c…) so the
// raw wire body is not treatable as executable HTML.
func ui009AssertJSONNotHTML(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type=%q want application/json", ct)
	}
	raw := rr.Body.String()
	// encoding/json with SetEscapeHTML(true) encodes < as \u003c — raw <script>
	// must not appear unescaped as HTML markup.
	if strings.Contains(raw, "<script>") {
		t.Fatalf("raw JSON body contains unescaped <script> (XSS risk): %s", raw)
	}
	if strings.Contains(raw, "</script>") {
		t.Fatalf("raw JSON body contains unescaped </script>: %s", raw)
	}
	// Must still be valid JSON (escaped payloads decode to text only).
	var v any
	if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
		t.Fatalf("response is not valid JSON: %v body=%s", err, raw)
	}
}

// --- AC: Auth gate + secret canary never in body ---

func TestUI009_AuthGate_WrongAndMissingToken(t *testing.T) {
	paths := ui009Paths(t)
	cfg := admin.DefaultConfig()
	cfg.BearerToken = ui009SecretCanary
	cfg.Role = admin.RoleViewer
	cfg.Paths = &paths
	h := ui009Handler(t, cfg)

	// Missing token → 401
	rr := ui009Do(t, h, http.MethodGet, "/admin/v1/health", "", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("missing token: status=%d body=%s want 401", rr.Code, rr.Body.String())
	}
	ui009AssertNoSecret(t, rr.Body.String())
	ui009AssertJSONNotHTML(t, rr)

	// Wrong token → 401
	rr2 := ui009Do(t, h, http.MethodGet, "/admin/v1/me", "wrong-token-not-canary", nil)
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: status=%d body=%s want 401", rr2.Code, rr2.Body.String())
	}
	ui009AssertNoSecret(t, rr2.Body.String())
	if strings.Contains(rr2.Body.String(), "wrong-token") {
		t.Fatal("401 body must not echo client token")
	}

	// Correct token → 200; canary still never in body
	rr3 := ui009Do(t, h, http.MethodGet, "/admin/v1/health", ui009SecretCanary, nil)
	if rr3.Code != http.StatusOK {
		t.Fatalf("good token: status=%d body=%s", rr3.Code, rr3.Body.String())
	}
	ui009AssertNoSecret(t, rr3.Body.String())
	ui009AssertJSONNotHTML(t, rr3)
}

// --- AC: viewer cannot apply policy (explicit name) ---

func TestUI009_ViewerCannotApplyPolicy(t *testing.T) {
	t.Setenv(policy.EnvPolicyRequiredVar, "")
	t.Setenv(policy.EnvPolicyFileVar, "")

	paths := ui009Paths(t)
	// Seed a baseline overlay so validate path has context.
	overlayPath := paths.DefaultPolicyFile()
	if err := os.MkdirAll(filepath.Dir(overlayPath), 0o700); err != nil {
		t.Fatal(err)
	}
	base := policy.Overlay{
		Version:       1,
		ForceReadOnly: true,
		Mode:          policy.ModePilot,
		DenyTools:     []string{"jenkins_get_build_logs"},
	}
	raw, err := json.MarshalIndent(base, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overlayPath, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	draft := map[string]any{
		"overlay": map[string]any{
			"version":         1,
			"force_read_only": true,
			"mode":            "pilot",
			"deny_tools":      []string{"jenkins_get_build_logs", "jenkins_get_console"},
		},
		"profileId": "corp",
	}

	// Viewer: both validate and apply → 403
	hViewer := ui009Handler(t, admin.Config{
		Addr:        "127.0.0.1:0",
		Role:        admin.RoleViewer,
		BearerToken: ui009SecretCanary,
		Paths:       &paths,
	})
	for _, path := range []string{"/admin/v1/policy/validate", "/admin/v1/policy/apply"} {
		rr := ui009Do(t, hViewer, http.MethodPost, path, ui009SecretCanary, draft)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("viewer %s: status=%d body=%s want 403", path, rr.Code, rr.Body.String())
		}
		var eb map[string]string
		if err := json.Unmarshal(rr.Body.Bytes(), &eb); err != nil {
			t.Fatal(err)
		}
		if eb["code"] != "permission_denied" {
			t.Fatalf("viewer %s code=%q", path, eb["code"])
		}
		ui009AssertNoSecret(t, rr.Body.String())
	}

	// Operator also blocked on policy write
	hOp := ui009Handler(t, admin.Config{
		Addr:        "127.0.0.1:0",
		Role:        admin.RoleOperator,
		BearerToken: ui009SecretCanary,
		Paths:       &paths,
	})
	for _, path := range []string{"/admin/v1/policy/validate", "/admin/v1/policy/apply"} {
		rr := ui009Do(t, hOp, http.MethodPost, path, ui009SecretCanary, draft)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("operator %s: status=%d want 403", path, rr.Code)
		}
		ui009AssertNoSecret(t, rr.Body.String())
	}

	// policy_admin: validate dry-run allowed
	hPA := ui009Handler(t, admin.Config{
		Addr:        "127.0.0.1:0",
		Role:        admin.RolePolicyAdmin,
		BearerToken: ui009SecretCanary,
		Paths:       &paths,
	})
	rrOK := ui009Do(t, hPA, http.MethodPost, "/admin/v1/policy/validate", ui009SecretCanary, draft)
	if rrOK.Code != http.StatusOK {
		t.Fatalf("policy_admin validate: status=%d body=%s", rrOK.Code, rrOK.Body.String())
	}
	ui009AssertNoSecret(t, rrOK.Body.String())
	var vresp map[string]any
	if err := json.Unmarshal(rrOK.Body.Bytes(), &vresp); err != nil {
		t.Fatal(err)
	}
	if vresp["valid"] != true {
		t.Fatalf("policy_admin validate valid=%v body=%v", vresp["valid"], vresp)
	}
}

// --- AC: XSS canaries in audit fields returned as JSON text only ---

func TestUI009_AuditXSSCanaries_JSONEscaped(t *testing.T) {
	paths := ui009Paths(t)
	// Write adversarial audit JSONL under default profile data path.
	auditDir := filepath.Join(paths.DataDir, "profiles", "corp", "audit")
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(auditDir, audit.DefaultFileName)
	t0 := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	events := []audit.Event{
		{
			Time:          t0,
			Type:          ui009XSSScript, // adversarial type field
			ProfileID:     "corp",
			Tool:          ui009XSSScript,
			ReasonCode:    ui009XSSJSURI,
			Action:        ui009XSSOnError,
			Decision:      audit.DecisionDeny,
			SchemaVersion: 1,
		},
		{
			Time:          t0.Add(time.Minute),
			Type:          audit.TypeToolDeny,
			ProfileID:     "corp",
			Tool:          `jenkins_<img src=x onerror=alert(1)>_tool`,
			ReasonCode:    `<script>document.cookie</script>`,
			Decision:      audit.DecisionDeny,
			SchemaVersion: 1,
		},
	}
	f, err := os.Create(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(f)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Paths = &paths
	cfg.BearerToken = ui009SecretCanary
	cfg.Role = admin.RoleViewer
	h := ui009Handler(t, cfg)

	rr := ui009Do(t, h, http.MethodGet, "/admin/v1/profiles/corp/audit?limit=50", ui009SecretCanary, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("audit status=%d body=%s", rr.Code, rr.Body.String())
	}
	ui009AssertNoSecret(t, rr.Body.String())
	ui009AssertJSONNotHTML(t, rr)

	// Wire body: EscapeHTML must have replaced angle brackets with \u003c…
	raw := rr.Body.String()
	if strings.Contains(raw, "<script>") || strings.Contains(raw, "<img") {
		t.Fatalf("raw audit response contains unescaped HTML tags: %s", raw)
	}
	if !strings.Contains(raw, `\u003c`) && !strings.Contains(raw, `\u003C`) {
		t.Fatalf("expected JSON HTML-escape (\\u003c) for XSS angle brackets; body=%s", raw)
	}

	// Decoded: values are text strings only (SPA must treat as text, not HTML).
	var page struct {
		ProfileID string        `json:"profileId"`
		Events    []audit.Event `json:"events"`
		Truncated bool          `json:"truncated"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.ProfileID != "corp" {
		t.Fatalf("profileId=%q", page.ProfileID)
	}
	if len(page.Events) == 0 {
		t.Fatal("expected XSS canary events returned as JSON objects")
	}
	// At least one event must carry a payload substring after decode (text only).
	foundPayload := false
	for _, e := range page.Events {
		blob := e.Type + e.Tool + e.ReasonCode + e.Action
		if strings.Contains(blob, "script") || strings.Contains(blob, "javascript:") ||
			strings.Contains(blob, "onerror") || strings.Contains(blob, "alert") {
			foundPayload = true
		}
	}
	if !foundPayload {
		t.Fatalf("decoded events lost XSS canary text (expected text-only fields): %+v", page.Events)
	}
}

// --- AC: policy apply XSS / path + token never echoed on errors ---

func TestUI009_PolicyApply_XSSAndPathTraversalRejected(t *testing.T) {
	t.Setenv(policy.EnvPolicyRequiredVar, "")
	t.Setenv(policy.EnvPolicyFileVar, "")

	paths := ui009Paths(t)
	overlayPath := paths.DefaultPolicyFile()
	if err := os.MkdirAll(filepath.Dir(overlayPath), 0o700); err != nil {
		t.Fatal(err)
	}
	base := policy.Overlay{Version: 1, ForceReadOnly: true, Mode: policy.ModePilot}
	raw, err := json.MarshalIndent(base, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overlayPath, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	h := ui009Handler(t, admin.Config{
		Addr:        "127.0.0.1:0",
		Role:        admin.RolePolicyAdmin,
		BearerToken: ui009SecretCanary,
		Paths:       &paths,
	})

	// XSS in profileId / deny tool names — validate must not echo token; JSON only.
	draft := map[string]any{
		"overlay": map[string]any{
			"version":         1,
			"force_read_only": true,
			"mode":            "pilot",
			"deny_tools":      []string{ui009XSSScript, "javascript:alert(1)"},
		},
		"profileId": "../etc/passwd",
	}
	rr := ui009Do(t, h, http.MethodPost, "/admin/v1/policy/validate", ui009SecretCanary, draft)
	// validate may accept draft structure (profileId is audit-only) or reject —
	// either way: never echo secret; body is JSON not HTML.
	if rr.Code != http.StatusOK && rr.Code != http.StatusBadRequest && rr.Code != http.StatusForbidden {
		t.Fatalf("unexpected status=%d body=%s", rr.Code, rr.Body.String())
	}
	ui009AssertNoSecret(t, rr.Body.String())
	ui009AssertJSONNotHTML(t, rr)
	if strings.Contains(rr.Body.String(), "<script>") {
		t.Fatal("validate body must not contain raw <script>")
	}

	// Malformed JSON with planted canary in body → error must not echo canary token
	// (client body may contain the string; response must not re-emit admin token).
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/policy/apply",
		bytes.NewBufferString(`{"overlay": not-json, "token":"`+ui009SecretCanary+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+ui009SecretCanary)
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req)
	if rr2.Code == http.StatusOK {
		t.Fatal("malformed apply must not succeed")
	}
	ui009AssertNoSecret(t, rr2.Body.String())
	ui009AssertJSONNotHTML(t, rr2)
}

// --- AC: CSP headers on / and health (ties UI-008) ---

func TestUI009_CSPHeaders_RootAndHealth(t *testing.T) {
	h := ui009Handler(t, admin.DefaultConfig())
	for _, path := range []string{"/", "/admin/v1/health"} {
		rr := ui009Do(t, h, http.MethodGet, path, "", nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", path, rr.Code, rr.Body.String())
		}
		csp := rr.Header().Get("Content-Security-Policy")
		if csp == "" {
			t.Fatalf("%s missing CSP", path)
		}
		if !strings.Contains(csp, "script-src 'self'") {
			t.Fatalf("%s CSP missing script-src 'self': %q", path, csp)
		}
		if strings.Contains(csp, "unsafe-eval") {
			t.Fatalf("%s CSP must not allow unsafe-eval", path)
		}
		if rr.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s missing nosniff", path)
		}
	}
}

// --- AC: online doctor without token still 403 ---

func TestUI009_OnlineDoctorWithoutToken_403(t *testing.T) {
	paths := ui009Paths(t)
	st := profile.NewStore(paths)
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.corp/",
		AuthMethod:    profile.AuthMethodAPIToken,
	}
	if err := st.Save(p); err != nil {
		t.Fatal(err)
	}

	// Loopback residual: no BearerToken configured.
	h := ui009Handler(t, admin.Config{
		Addr:    "127.0.0.1:0",
		Paths:   &paths,
		Role:    admin.RoleViewer,
		Keyring: keyring.NewStore(keyring.NewMemory()),
	})
	rr := ui009Do(t, h, http.MethodGet, "/admin/v1/profiles/corp/doctor?offline=0", "", nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("online doctor without token: status=%d body=%s want 403", rr.Code, rr.Body.String())
	}
	var eb map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &eb); err != nil {
		t.Fatal(err)
	}
	if eb["code"] != "permission_denied" {
		t.Fatalf("code=%q", eb["code"])
	}
	ui009AssertNoSecret(t, rr.Body.String())
}

// --- AC: SPA deep link still serves index shell ---

func TestUI009_SPADeepLink_ServesIndexShell(t *testing.T) {
	dir := t.TempDir()
	index := "<!DOCTYPE html><html><body data-ui009-shell>spa-shell-ui009</body></html>\n"
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte(index), 0o644); err != nil {
		t.Fatal(err)
	}
	h := ui009Handler(t, admin.Config{
		Addr:      "127.0.0.1:0",
		AssetsDir: dir,
	})
	for _, path := range []string{"/metrics", "/audit", "/policy", "/profiles"} {
		rr := ui009Do(t, h, http.MethodGet, path, "", nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", path, rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "spa-shell-ui009") {
			t.Fatalf("%s should serve SPA shell, got %q", path, rr.Body.String())
		}
		// SPA HTML still gets CSP (UI-008/UI-009).
		if rr.Header().Get("Content-Security-Policy") == "" {
			t.Fatalf("%s missing CSP on SPA shell", path)
		}
	}
}

// --- AC: cache evict viewer 403; operator missing confirm 400 ---

func TestUI009_CacheEvict_Viewer403_OperatorMissingConfirm400(t *testing.T) {
	paths := ui009Paths(t)
	st := profile.NewStore(paths)
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.corp/",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	if err := st.Save(p); err != nil {
		t.Fatal(err)
	}

	hViewer := ui009Handler(t, admin.Config{
		Addr:        "127.0.0.1:0",
		Paths:       &paths,
		Role:        admin.RoleViewer,
		BearerToken: ui009SecretCanary,
	})
	rr := ui009Do(t, hViewer, http.MethodPost, "/admin/v1/profiles/corp/cache/evict",
		ui009SecretCanary, map[string]any{"confirm": "EVICT"})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("viewer evict: status=%d body=%s want 403", rr.Code, rr.Body.String())
	}
	ui009AssertNoSecret(t, rr.Body.String())

	hOp := ui009Handler(t, admin.Config{
		Addr:        "127.0.0.1:0",
		Paths:       &paths,
		Role:        admin.RoleOperator,
		BearerToken: ui009SecretCanary,
	})
	rr2 := ui009Do(t, hOp, http.MethodPost, "/admin/v1/profiles/corp/cache/evict",
		ui009SecretCanary, map[string]any{"confirm": "yes"})
	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("operator missing exact confirm: status=%d body=%s want 400", rr2.Code, rr2.Body.String())
	}
	ui009AssertNoSecret(t, rr2.Body.String())
}

// --- AC umbrella: secret canary never in network/API responses across routes ---

func TestUI009_SecretCanaryAbsentAcrossRoutes(t *testing.T) {
	paths := ui009Paths(t)
	st := profile.NewStore(paths)
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.corp/",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	if err := st.Save(p); err != nil {
		t.Fatal(err)
	}
	// Plant API token in keyring — must never appear.
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
	}, ui009SecretCanary); err != nil {
		t.Fatal(err)
	}

	h := ui009Handler(t, admin.Config{
		Addr:        "127.0.0.1:0",
		Paths:       &paths,
		Role:        admin.RoleOperator,
		BearerToken: ui009SecretCanary,
		Keyring:     kr,
		Version:     "ui009",
		Commit:      "test",
	})

	routes := []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodGet, "/admin/v1/health", nil},
		{http.MethodGet, "/admin/v1/version", nil},
		{http.MethodGet, "/admin/v1/me", nil},
		{http.MethodGet, "/admin/v1/metrics", nil},
		{http.MethodGet, "/admin/v1/profiles", nil},
		{http.MethodGet, "/admin/v1/profiles/corp", nil},
		{http.MethodGet, "/admin/v1/profiles/corp/policy/effective", nil},
		{http.MethodGet, "/admin/v1/profiles/corp/audit", nil},
		{http.MethodGet, "/admin/v1/profiles/corp/doctor?offline=1", nil},
		{http.MethodGet, "/admin/v1/profiles/corp/security-selfcheck", nil},
		{http.MethodGet, "/admin/v1/profiles/corp/cache", nil},
		{http.MethodPost, "/admin/v1/profiles/corp/cache/evict-plan", map[string]any{}},
		// 401 path (wrong token) also scrubbed
	}
	for _, rt := range routes {
		rr := ui009Do(t, h, rt.method, rt.path, ui009SecretCanary, rt.body)
		// Allow non-200 for optional routes, but never secret leakage.
		ui009AssertNoSecret(t, rr.Body.String())
		if strings.HasPrefix(rt.path, "/admin/v1") && rr.Code == http.StatusOK {
			ct := rr.Header().Get("Content-Type")
			if !strings.HasPrefix(ct, "application/json") {
				t.Fatalf("%s Content-Type=%q", rt.path, ct)
			}
		}
	}

	// Wrong auth responses
	rr401 := ui009Do(t, h, http.MethodGet, "/admin/v1/me", "not-the-canary", nil)
	if rr401.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr401.Code)
	}
	ui009AssertNoSecret(t, rr401.Body.String())
}
