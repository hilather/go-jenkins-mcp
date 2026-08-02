package admin_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/admin"
	"github.com/simonfxr/go-jenkins-mcp/internal/audit"
)

func TestAuditSettings_GETAndPUT(t *testing.T) {
	paths := opsTestPaths(t)
	seedCorpProfile(t, paths)
	// operator can write
	h := newOpsHandler(t, paths, admin.RoleOperator, "tok", nil)

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/profiles/corp/audit/settings", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET status %d body %s", rr.Code, rr.Body.String())
	}
	var got admin.AuditSettingsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Types) == 0 || got.Enabled == nil {
		t.Fatalf("empty catalog: %+v", got)
	}
	if !got.Enabled[audit.TypeToolDeny] {
		t.Fatal("tool_deny should default enabled")
	}

	// Disable tool_deny
	body := map[string]any{
		"enabled": map[string]bool{audit.TypeToolDeny: false},
	}
	raw, _ := json.Marshal(body)
	req2 := httptest.NewRequest(http.MethodPut, "/admin/v1/profiles/corp/audit/settings", bytes.NewReader(raw))
	req2.Header.Set("Authorization", "Bearer tok")
	req2.Header.Set("Content-Type", "application/json")
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("PUT status %d body %s", rr2.Code, rr2.Body.String())
	}
	var after admin.AuditSettingsResponse
	if err := json.Unmarshal(rr2.Body.Bytes(), &after); err != nil {
		t.Fatal(err)
	}
	if after.Enabled[audit.TypeToolDeny] {
		t.Fatal("tool_deny should be disabled after PUT")
	}

	// Self-audit: type_filter update writes audit_settings via bare File sink.
	auditPath, err := admin.ProfileAuditPath(paths, "corp", "")
	if err != nil {
		t.Fatal(err)
	}
	page, err := admin.ReadAuditFile(auditPath, "corp", admin.AuditQuery{Type: audit.TypeAuditSettings, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) < 1 {
		t.Fatal("expected audit_settings event after PUT")
	}
	if page.Events[0].ReasonCode != "type_filter_updated" {
		t.Fatalf("reason %q", page.Events[0].ReasonCode)
	}
	if page.Events[0].TargetHash == "" {
		t.Fatal("expected TargetHash digest of enabled map")
	}

	// Unknown keys ignored; partial merge keeps other defaults.
	bodyMerge := map[string]any{
		"enabled": map[string]bool{
			"not_a_real_type":      true,
			audit.TypeLoginSuccess: false,
		},
	}
	rawMerge, _ := json.Marshal(bodyMerge)
	reqMerge := httptest.NewRequest(http.MethodPut, "/admin/v1/profiles/corp/audit/settings", bytes.NewReader(rawMerge))
	reqMerge.Header.Set("Authorization", "Bearer tok")
	reqMerge.Header.Set("Content-Type", "application/json")
	rrMerge := httptest.NewRecorder()
	h.ServeHTTP(rrMerge, reqMerge)
	if rrMerge.Code != http.StatusOK {
		t.Fatalf("merge PUT %d", rrMerge.Code)
	}
	var merged admin.AuditSettingsResponse
	if err := json.Unmarshal(rrMerge.Body.Bytes(), &merged); err != nil {
		t.Fatal(err)
	}
	if merged.Enabled["not_a_real_type"] {
		t.Fatal("unknown type must not appear enabled")
	}
	if merged.Enabled[audit.TypeLoginSuccess] {
		t.Fatal("login_success should be disabled after partial merge")
	}
	if merged.Enabled[audit.TypeToolDeny] {
		t.Fatal("tool_deny should remain disabled from earlier PUT")
	}

	// Viewer cannot PUT
	hView := newOpsHandler(t, paths, admin.RoleViewer, "tok", nil)
	req3 := httptest.NewRequest(http.MethodPut, "/admin/v1/profiles/corp/audit/settings", bytes.NewReader(raw))
	req3.Header.Set("Authorization", "Bearer tok")
	req3.Header.Set("Content-Type", "application/json")
	rr3 := httptest.NewRecorder()
	hView.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusForbidden {
		t.Fatalf("viewer PUT want 403 got %d", rr3.Code)
	}
}
