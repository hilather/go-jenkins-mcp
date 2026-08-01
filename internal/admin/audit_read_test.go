package admin_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/admin"
	"github.com/simonfxr/go-jenkins-mcp/internal/audit"
	"github.com/simonfxr/go-jenkins-mcp/internal/config"
)

func TestValidateProfileID_PathTraversal(t *testing.T) {
	bad := []string{
		"",
		"..",
		"../etc",
		"foo/../bar",
		"a/b",
		`a\b`,
		"/abs",
		"../../secret",
		"corp/../../etc",
		".",
		"bad id spaces",
	}
	for _, id := range bad {
		if err := admin.ValidateProfileID(id); err == nil {
			t.Errorf("ValidateProfileID(%q) should fail", id)
		}
	}
	if err := admin.ValidateProfileID("corp"); err != nil {
		t.Fatal(err)
	}
	if err := admin.ValidateProfileID("corp-prod_01"); err != nil {
		t.Fatal(err)
	}
}

func TestReadAuditFile_LimitAndTypeFilter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	events := []audit.Event{
		{Time: t0, Type: audit.TypeLoginSuccess, ProfileID: "corp", Decision: audit.DecisionSuccess, SchemaVersion: 1},
		{Time: t0.Add(time.Minute), Type: audit.TypeToolDeny, ProfileID: "corp", Tool: "jenkins_start_job", Decision: audit.DecisionDeny, SchemaVersion: 1},
		{Time: t0.Add(2 * time.Minute), Type: audit.TypeLoginFail, ProfileID: "corp", Decision: audit.DecisionFail, SchemaVersion: 1},
		{Time: t0.Add(3 * time.Minute), Type: audit.TypeToolDeny, ProfileID: "corp", Tool: "jenkins_start_job", Decision: audit.DecisionDeny, SchemaVersion: 1},
		{Time: t0.Add(4 * time.Minute), Type: audit.TypeServeStart, ProfileID: "corp", Decision: audit.DecisionSuccess, SchemaVersion: 1},
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(f)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			t.Fatal(err)
		}
	}
	_ = f.Close()

	// Limit 2 → truncated, newest first
	page, err := admin.ReadAuditFile(path, "corp", admin.AuditQuery{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 2 {
		t.Fatalf("len=%d want 2", len(page.Events))
	}
	if !page.Truncated {
		t.Fatal("expected truncated")
	}
	if page.Events[0].Type != audit.TypeServeStart {
		t.Fatalf("newest type=%s want serve_start", page.Events[0].Type)
	}

	// Type filter
	page2, err := admin.ReadAuditFile(path, "corp", admin.AuditQuery{Type: audit.TypeToolDeny, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(page2.Events) != 2 {
		t.Fatalf("type filter len=%d want 2", len(page2.Events))
	}
	for _, e := range page2.Events {
		if e.Type != audit.TypeToolDeny {
			t.Fatalf("unexpected type %s", e.Type)
		}
	}
	if page2.Truncated {
		t.Fatal("should not truncate when under limit")
	}

	// before exclusive upper bound
	before := t0.Add(2 * time.Minute)
	page3, err := admin.ReadAuditFile(path, "corp", admin.AuditQuery{
		Before: &before,
		Limit:  50,
	})
	if err != nil {
		t.Fatal(err)
	}
	// events at t0 and t0+1m only (t0+2m is not Before)
	if len(page3.Events) != 2 {
		t.Fatalf("before filter len=%d want 2", len(page3.Events))
	}

	// Missing file → empty
	page4, err := admin.ReadAuditFile(filepath.Join(dir, "missing.jsonl"), "corp", admin.AuditQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page4.Events) != 0 || page4.Truncated {
		t.Fatalf("missing file should be empty: %+v", page4)
	}

	// Cap at MaxAuditLimit
	q := admin.AuditQuery{Limit: 9999}.Normalize()
	if q.Limit != admin.MaxAuditLimit {
		t.Fatalf("cap limit=%d want %d", q.Limit, admin.MaxAuditLimit)
	}
}

func TestAuditHandler_PathTraversalRejected(t *testing.T) {
	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Version = "test"
	// Inject paths so we don't depend on real XDG
	tmp := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(tmp, "cfg"),
		DataDir:   filepath.Join(tmp, "data"),
		CacheDir:  filepath.Join(tmp, "cache"),
	}
	cfg.Paths = &paths
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Go ServeMux may not even route ".." as a path value the same way, but
	// try encoded traversal and invalid ids.
	for _, id := range []string{"..", "foo%2F..%2Fbar", "a/b"} {
		// Build URL carefully: use PathValue path pattern with raw id in path
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/profiles/"+id+"/audit", nil)
		h.ServeHTTP(rr, req)
		// 400 or 404 from mux — never 200 with filesystem escape
		if rr.Code == http.StatusOK {
			t.Fatalf("id %q must not succeed: body=%s", id, rr.Body.String())
		}
	}

	// Valid id, missing audit → empty events 200
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/profiles/corp/audit?limit=10", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200 empty audit, got %d body=%s", rr.Code, rr.Body.String())
	}
	var page admin.AuditPage
	if err := json.Unmarshal(rr.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.ProfileID != "corp" || len(page.Events) != 0 {
		t.Fatalf("unexpected page: %+v", page)
	}
}

func TestProfileAuditPath_SafeJoin(t *testing.T) {
	paths := config.Paths{DataDir: "/tmp/jenkins-mcp-data"}
	p, err := admin.ProfileAuditPath(paths, "corp", "")
	if err != nil {
		t.Fatal(err)
	}
	if p != filepath.Join("/tmp/jenkins-mcp-data", "profiles", "corp", "audit", audit.DefaultFileName) {
		t.Fatalf("path=%s", p)
	}
	if _, err := admin.ProfileAuditPath(paths, "../etc", ""); err == nil {
		t.Fatal("traversal must fail")
	}
}
