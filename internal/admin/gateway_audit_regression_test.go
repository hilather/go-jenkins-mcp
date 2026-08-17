package admin_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/admin"
	"github.com/hilather/go-jenkins-mcp/internal/saml"
)

// Regression (AUD-001): the BFF gateway mutation endpoints emitted no audit
// events at all — the MCP twins (admin_subject_invalidate /
// admin_consent_purge) record them. Both handlers must now write a
// secret-free event to the profile audit JSONL.
func TestGatewayMutations_EmitAuditEvents(t *testing.T) {
	paths := opsTestPaths(t)
	// emitAdminAudit only writes when the profile data root already exists.
	dataRoot := paths.ProfileDataDir("admin")
	if err := os.MkdirAll(dataRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	h := newOpsHandler(t, paths, admin.RoleOperator, "tok", nil)

	post := func(path string, body map[string]any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer tok")
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	rr := post("/admin/v1/gateway/subject-invalidate", map[string]any{
		"subject_key": "tenant|subject|corp",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("subject-invalidate: %d %s", rr.Code, rr.Body.String())
	}
	rr = post("/admin/v1/gateway/consent-purge", map[string]any{
		"action": "purge_expired",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("consent-purge: %d %s", rr.Code, rr.Body.String())
	}

	auditFile := filepath.Join(dataRoot, "audit", "audit.jsonl")
	data, err := os.ReadFile(auditFile)
	if err != nil {
		t.Fatalf("audit file missing after gateway mutations: %v", err)
	}
	body := string(data)
	if !strings.Contains(body, "admin_subject_invalidate") {
		t.Fatalf("missing admin_subject_invalidate event: %s", body)
	}
	if !strings.Contains(body, "admin_consent_purge") {
		t.Fatalf("missing admin_consent_purge event: %s", body)
	}
	// Canary: subject key material never in the clear (hash-only target).
	if strings.Contains(body, "tenant|subject|corp") {
		t.Fatal("audit leaked the raw subject key")
	}
}

// Regression (review follow-up): the BFF subject-invalidate audit derived the
// decision only from the validation error, but InvalidateSubjectKeyLocal
// reports partial cache failures via cleared flags (nil error) — a 200 with
// principal_cleared=false audited "success", understating failed
// invalidations. The decision now reflects the cleared flags.
func TestSubjectInvalidate_AuditFailOnPartialCacheFailure(t *testing.T) {
	paths := opsTestPaths(t)
	dataRoot := paths.ProfileDataDir("admin")
	if err := os.MkdirAll(dataRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	// Corrupt principal cache file → FilePrincipalCache.Delete fails at load.
	cachePath := filepath.Join(t.TempDir(), "principal.json")
	if err := os.WriteFile(cachePath, []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH", cachePath)

	h := newOpsHandler(t, paths, admin.RoleOperator, "tok", nil)
	body, _ := json.Marshal(map[string]any{"subject_key": "tenant|subject|corp"})
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/gateway/subject-invalidate", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	// The response honestly reports the partial failure...
	if !strings.Contains(rr.Body.String(), `"principal_cleared":false`) {
		t.Fatalf("expected principal_cleared=false: %s", rr.Body.String())
	}
	// ...and the audit decision must not claim success.
	data, err := os.ReadFile(filepath.Join(dataRoot, "audit", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "admin_subject_invalidate") {
		t.Fatalf("missing event: %s", data)
	}
	if strings.Contains(string(data), `"decision":"success"`) ||
		strings.Contains(string(data), `"decision": "success"`) {
		t.Fatalf("partial failure must not audit success: %s", data)
	}
}

// Regression: fleet-cache purge authorized against the static PROCESS role
// after CheckPermission passed with the SAML-aware REQUEST role — a
// SAML-mapped operator was 403'd whenever the process ran as viewer.
// The handler now authorizes against the request role.
func TestFleetCachePurge_SAMLMappedOperatorNotProcessRole(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	paths := opsTestPaths(t)
	cfg := admin.Config{
		Addr:        admin.DefaultAddr,
		Role:        admin.RoleViewer, // process role: viewer
		BearerToken: "secret",
		Paths:       &paths,
		SAML: admin.SAMLOptions{
			Config: saml.Config{
				SchemaVersion: 1,
				Enabled:       true,
				SPEntityID:    "https://mcp.example/sp",
				ACSURL:        "https://mcp.example/admin/v1/saml/acs",
				IdPEntityID:   "https://idp.example/metadata",
				AttributeMap:  saml.AttributeMap{GroupsAttribute: "groups"},
				GroupRoles:    map[string]string{"mcp-operators": "operator"},
			},
			Trust: saml.TrustMaterial{PublicKey: &priv.PublicKey},
			Now:   func() time.Time { return time.Now().UTC() },
		},
	}
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Establish an operator SAML session.
	raw := buildAdminSAMLAssertion(t, priv, "mcp-operators")
	form := url.Values{}
	form.Set("SAMLResponse", base64.StdEncoding.EncodeToString(raw))
	rrACS := httptest.NewRecorder()
	reqACS := httptest.NewRequest(http.MethodPost, "/admin/v1/saml/acs", strings.NewReader(form.Encode()))
	reqACS.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rrACS, reqACS)
	if rrACS.Code != http.StatusOK {
		t.Fatalf("acs: %d %s", rrACS.Code, rrACS.Body.String())
	}
	var cookie *http.Cookie
	for _, c := range rrACS.Result().Cookies() {
		if strings.Contains(c.Name, "saml") {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no SAML session cookie")
	}

	// Purge with the operator session: must pass BOTH role gates and reach the
	// fleet library (which errors on the unknown locator — any non-403-role
	// outcome proves the request role was honored).
	body, _ := json.Marshal(map[string]any{
		"confirm":      "PURGE",
		"locator_hash": strings.Repeat("ef", 32),
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/fleet-cache/purge", bytes.NewReader(body))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code == http.StatusForbidden &&
		strings.Contains(rr.Body.String(), "fleet-cache purge requires operator role") {
		t.Fatalf("SAML-mapped operator denied by process-role check: %d %s", rr.Code, rr.Body.String())
	}
}

// Regression: the request-body profile_id fed emitAdminAudit's filesystem
// path without ValidateProfileID. A traversal value must not escape the
// profiles root — the event falls back to the configured/default profile dir.
func TestFleetCachePurge_AuditProfileIDTraversalJailed(t *testing.T) {
	paths := opsTestPaths(t)
	// Default audit landing zone (profile_id falls back to "admin").
	defaultRoot := paths.ProfileDataDir("admin")
	if err := os.MkdirAll(defaultRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	// The traversal target: <DataDir>/escape (outside the profiles root).
	escapeRoot := filepath.Join(paths.DataDir, "escape")
	if err := os.MkdirAll(escapeRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	h := newOpsHandler(t, paths, admin.RoleOperator, "tok", nil)
	body, _ := json.Marshal(map[string]any{
		"confirm":      "PURGE",
		"locator_hash": strings.Repeat("ef", 32),
		"profile_id":   "../escape",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/fleet-cache/purge", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if _, err := os.Stat(filepath.Join(escapeRoot, "audit")); err == nil {
		t.Fatal("audit path escaped the profiles root via profile_id traversal")
	}
	if _, err := os.Stat(filepath.Join(defaultRoot, "audit", "audit.jsonl")); err != nil {
		t.Fatalf("audit event must land in the default profile dir: %v", err)
	}
}
