package admin_test

import (
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

func writeAuditJSONL(t *testing.T, path string, events []audit.Event, extraLines ...string) {
	t.Helper()
	f, err := os.Create(path)
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
	for _, line := range extraLines {
		if _, err := f.WriteString(line + "\n"); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestReadAuditFile_RotatedSiblingMerge covers same-host rotated merge lite:
// numbered File-sink siblings (audit.jsonl.N) + optional timestamped name.
func TestReadAuditFile_RotatedSiblingMerge(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.jsonl")
	rot1 := active + ".1"
	rot2 := active + ".2"
	t0 := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)

	// Oldest rotated (.2): two events
	writeAuditJSONL(t, rot2, []audit.Event{
		{Time: t0, Type: audit.TypeLoginSuccess, ProfileID: "corp", Decision: audit.DecisionSuccess, SchemaVersion: 1, RequestID: "old-a"},
		{Time: t0.Add(time.Minute), Type: audit.TypeToolDeny, ProfileID: "corp", Tool: "jenkins_start_job", Decision: audit.DecisionDeny, SchemaVersion: 1, RequestID: "old-b"},
	})
	// Mid rotated (.1)
	writeAuditJSONL(t, rot1, []audit.Event{
		{Time: t0.Add(10 * time.Minute), Type: audit.TypeLoginFail, ProfileID: "corp", Decision: audit.DecisionFail, SchemaVersion: 1, RequestID: "mid-a"},
		{Time: t0.Add(11 * time.Minute), Type: audit.TypeToolDeny, ProfileID: "corp", Tool: "jenkins_stop_job", Decision: audit.DecisionDeny, SchemaVersion: 1, RequestID: "mid-b"},
	})
	// Active (newest) + one corrupt line (skipped)
	writeAuditJSONL(t, active, []audit.Event{
		{Time: t0.Add(20 * time.Minute), Type: audit.TypeServeStart, ProfileID: "corp", Decision: audit.DecisionSuccess, SchemaVersion: 1, RequestID: "new-a"},
		{Time: t0.Add(21 * time.Minute), Type: audit.TypeToolError, ProfileID: "corp", Tool: "jenkins_get_log", Decision: audit.DecisionError, SchemaVersion: 1, RequestID: "new-b"},
	}, `{not-json`, `{"time":"bad"}`)

	paths := admin.ListAuditReadPaths(active)
	if len(paths) != 3 {
		t.Fatalf("ListAuditReadPaths len=%d want 3: %v", len(paths), paths)
	}
	if paths[0] != rot2 || paths[1] != rot1 || paths[2] != active {
		t.Fatalf("oldest-first order got %v want [%s %s %s]", paths, rot2, rot1, active)
	}

	// Full merge: 6 good events, newest first
	page, err := admin.ReadAuditFile(active, "corp", admin.AuditQuery{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if page.Truncated {
		t.Fatal("should not truncate under limit")
	}
	if len(page.Events) != 6 {
		t.Fatalf("merged len=%d want 6", len(page.Events))
	}
	if page.Events[0].RequestID != "new-b" || page.Events[5].RequestID != "old-a" {
		t.Fatalf("newest/oldest requestId: first=%q last=%q", page.Events[0].RequestID, page.Events[5].RequestID)
	}

	// Limit across files → newest from active + rot1; truncated
	page2, err := admin.ReadAuditFile(active, "corp", admin.AuditQuery{Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if !page2.Truncated || len(page2.Events) != 3 {
		t.Fatalf("limit merge truncated=%v len=%d", page2.Truncated, len(page2.Events))
	}
	wantIDs := []string{"new-b", "new-a", "mid-b"}
	for i, id := range wantIDs {
		if page2.Events[i].RequestID != id {
			t.Fatalf("events[%d]=%q want %q", i, page2.Events[i].RequestID, id)
		}
	}

	// Type filter spans rotated siblings
	page3, err := admin.ReadAuditFile(active, "corp", admin.AuditQuery{Type: audit.TypeToolDeny, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(page3.Events) != 2 {
		t.Fatalf("type filter across rotates len=%d want 2", len(page3.Events))
	}
	if page3.Events[0].RequestID != "mid-b" || page3.Events[1].RequestID != "old-b" {
		t.Fatalf("type order: %q %q", page3.Events[0].RequestID, page3.Events[1].RequestID)
	}

	// before exclusive: only events strictly before t0+10m (old-a, old-b)
	before := t0.Add(10 * time.Minute)
	page4, err := admin.ReadAuditFile(active, "corp", admin.AuditQuery{Before: &before, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(page4.Events) != 2 {
		t.Fatalf("before across rotates len=%d want 2", len(page4.Events))
	}

	// Extra numbered sibling .3 still merges (operator-retained beyond default keep).
	writeAuditJSONL(t, active+".3", []audit.Event{
		{Time: t0.Add(-time.Hour), Type: audit.TypeAuthFail, ProfileID: "corp", Decision: audit.DecisionFail, SchemaVersion: 1, RequestID: "older-3"},
	})
	page5, err := admin.ReadAuditFile(active, "corp", admin.AuditQuery{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(page5.Events) != 7 {
		t.Fatalf("expected .3 sibling merge len=7 got %d", len(page5.Events))
	}
	if page5.Events[len(page5.Events)-1].RequestID != "older-3" {
		t.Fatalf("oldest should be .3 event, got %q", page5.Events[len(page5.Events)-1].RequestID)
	}
}

// TestReadAuditFile_CorruptAndSecretShapedLinesSkipped ensures non-Event JSON
// (including secret-shaped keys) never becomes audit.Event identity fields.
func TestReadAuditFile_CorruptAndSecretShapedLinesSkipped(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.jsonl")
	rot1 := active + ".1"
	const canary = "super-secret-audit-token-xyz"
	t0 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	writeAuditJSONL(t, rot1, []audit.Event{
		{Time: t0, Type: audit.TypeLoginSuccess, ProfileID: "corp", Decision: audit.DecisionSuccess, SchemaVersion: 1, RequestID: "ok-rot"},
	},
		`{"password":"`+canary+`","authorization":"Bearer `+canary+`"}`,
		`not-json-at-all`,
		`{"time":"not-a-timestamp","type":"login_fail"}`,
	)
	writeAuditJSONL(t, active, []audit.Event{
		{Time: t0.Add(time.Minute), Type: audit.TypeServeStart, ProfileID: "corp", Decision: audit.DecisionSuccess, SchemaVersion: 1, RequestID: "ok-active"},
	})

	page, err := admin.ReadAuditFile(active, "corp", admin.AuditQuery{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 2 {
		t.Fatalf("len=%d want 2 good events only", len(page.Events))
	}
	// Regression: secret-shaped corrupt lines must not surface as identity fields.
	raw, _ := json.Marshal(page)
	if strings.Contains(string(raw), canary) {
		t.Fatalf("Regression: canary secret leaked into audit page JSON: %s", raw)
	}
	for _, e := range page.Events {
		if e.PrincipalID == canary || e.ReasonCode == canary || e.Decision == canary {
			t.Fatalf("Regression: canary in Event field: %+v", e)
		}
	}
}

func TestReadAuditFile_RotatedOnlyWhenActiveMissing(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.jsonl")
	rot1 := active + ".1"
	t0 := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	writeAuditJSONL(t, rot1, []audit.Event{
		{Time: t0, Type: audit.TypeLoginSuccess, ProfileID: "corp", Decision: audit.DecisionSuccess, SchemaVersion: 1, RequestID: "rot-only"},
	})
	// Active missing — still merge rotated siblings
	page, err := admin.ReadAuditFile(active, "corp", admin.AuditQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 1 || page.Events[0].RequestID != "rot-only" {
		t.Fatalf("rotated-only page: %+v", page)
	}
}

func TestReadAuditFile_TimestampedSibling(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.jsonl")
	// Timestamped archive (optional naming; not produced by default File sink)
	stamped := active + ".20260115T120000Z"
	t0 := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	writeAuditJSONL(t, stamped, []audit.Event{
		{Time: t0, Type: audit.TypeAuthFail, ProfileID: "corp", Decision: audit.DecisionFail, SchemaVersion: 1, RequestID: "stamp-a"},
	})
	writeAuditJSONL(t, active, []audit.Event{
		{Time: t0.Add(time.Hour), Type: audit.TypeServeStart, ProfileID: "corp", Decision: audit.DecisionSuccess, SchemaVersion: 1, RequestID: "active-a"},
	})

	paths := admin.ListAuditReadPaths(active)
	if len(paths) != 2 {
		t.Fatalf("paths=%v want stamped+active", paths)
	}
	page, err := admin.ReadAuditFile(active, "corp", admin.AuditQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 2 {
		t.Fatalf("len=%d want 2", len(page.Events))
	}
	if page.Events[0].RequestID != "active-a" || page.Events[1].RequestID != "stamp-a" {
		t.Fatalf("order: %q %q", page.Events[0].RequestID, page.Events[1].RequestID)
	}
}

func TestReadAuditFile_IgnoresUnrelatedSiblings(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.jsonl")
	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	writeAuditJSONL(t, active, []audit.Event{
		{Time: t0, Type: audit.TypeServeStart, ProfileID: "corp", Decision: audit.DecisionSuccess, SchemaVersion: 1, RequestID: "only"},
	})
	// Unrelated files must not be merged
	writeAuditJSONL(t, filepath.Join(dir, "other.jsonl"), []audit.Event{
		{Time: t0, Type: audit.TypeLoginFail, ProfileID: "corp", Decision: audit.DecisionFail, SchemaVersion: 1, RequestID: "nope"},
	})
	writeAuditJSONL(t, active+".bak", []audit.Event{
		{Time: t0, Type: audit.TypeLoginFail, ProfileID: "corp", Decision: audit.DecisionFail, SchemaVersion: 1, RequestID: "bak"},
	})
	_ = os.WriteFile(active+".txt", []byte("not audit\n"), 0o600)

	page, err := admin.ReadAuditFile(active, "corp", admin.AuditQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 1 || page.Events[0].RequestID != "only" {
		t.Fatalf("unrelated siblings leaked into page: %+v", page.Events)
	}
}

// TestReadAuditFile_ExternalSubjectExactFilter covers multi-user correlation:
// exact (case-sensitive) match on ExternalSubject; empty skips; works across
// rotated siblings. Residual: multi-pod aggregation not claimed.
func TestReadAuditFile_ExternalSubjectExactFilter(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.jsonl")
	rot1 := active + ".1"
	t0 := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	writeAuditJSONL(t, rot1, []audit.Event{
		{Time: t0, Type: audit.TypeToolDeny, ProfileID: "corp", ExternalSubject: "alice@idp", Decision: audit.DecisionDeny, SchemaVersion: 1, RequestID: "alice-old"},
		{Time: t0.Add(time.Minute), Type: audit.TypeToolDeny, ProfileID: "corp", ExternalSubject: "bob@idp", Decision: audit.DecisionDeny, SchemaVersion: 1, RequestID: "bob-old"},
	})
	writeAuditJSONL(t, active, []audit.Event{
		{Time: t0.Add(10 * time.Minute), Type: audit.TypeToolError, ProfileID: "corp", ExternalSubject: "alice@idp", Decision: audit.DecisionError, SchemaVersion: 1, RequestID: "alice-new"},
		{Time: t0.Add(11 * time.Minute), Type: audit.TypeToolDeny, ProfileID: "corp", ExternalSubject: "carol@idp", Decision: audit.DecisionDeny, SchemaVersion: 1, RequestID: "carol-new"},
		// No ExternalSubject (single-user residual)
		{Time: t0.Add(12 * time.Minute), Type: audit.TypeServeStart, ProfileID: "corp", Decision: audit.DecisionSuccess, SchemaVersion: 1, RequestID: "no-sub"},
	})

	// Empty filter → all events
	pageAll, err := admin.ReadAuditFile(active, "corp", admin.AuditQuery{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(pageAll.Events) != 5 {
		t.Fatalf("empty external_subject filter len=%d want 5", len(pageAll.Events))
	}

	// Exact match alice across rotate + active
	pageAlice, err := admin.ReadAuditFile(active, "corp", admin.AuditQuery{
		ExternalSubject: "alice@idp",
		Limit:           50,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pageAlice.Events) != 2 {
		t.Fatalf("alice exact len=%d want 2", len(pageAlice.Events))
	}
	if pageAlice.Events[0].RequestID != "alice-new" || pageAlice.Events[1].RequestID != "alice-old" {
		t.Fatalf("alice order: %q %q", pageAlice.Events[0].RequestID, pageAlice.Events[1].RequestID)
	}
	for _, e := range pageAlice.Events {
		if e.ExternalSubject != "alice@idp" {
			t.Fatalf("non-alice leaked: %+v", e)
		}
	}

	// Case-sensitive: wrong case must not match
	pageCase, err := admin.ReadAuditFile(active, "corp", admin.AuditQuery{
		ExternalSubject: "Alice@idp",
		Limit:           50,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pageCase.Events) != 0 {
		t.Fatalf("case-sensitive exact: want 0 got %d", len(pageCase.Events))
	}

	// Substring must not match (exact only)
	pageSub, err := admin.ReadAuditFile(active, "corp", admin.AuditQuery{
		ExternalSubject: "alice",
		Limit:           50,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pageSub.Events) != 0 {
		t.Fatalf("substring must not match exact filter: got %d", len(pageSub.Events))
	}

	// Combine type + external_subject across rotates
	pageCombo, err := admin.ReadAuditFile(active, "corp", admin.AuditQuery{
		Type:            audit.TypeToolDeny,
		ExternalSubject: "alice@idp",
		Limit:           50,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pageCombo.Events) != 1 || pageCombo.Events[0].RequestID != "alice-old" {
		t.Fatalf("type+external_subject: %+v", pageCombo.Events)
	}

	// Limit + truncated under external_subject filter
	pageLim, err := admin.ReadAuditFile(active, "corp", admin.AuditQuery{
		ExternalSubject: "alice@idp",
		Limit:           1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !pageLim.Truncated || len(pageLim.Events) != 1 || pageLim.Events[0].RequestID != "alice-new" {
		t.Fatalf("limit under subject filter: truncated=%v events=%+v", pageLim.Truncated, pageLim.Events)
	}
}

// TestAuditHandler_ExternalSubjectQueryParam wires external_subject through
// GET /admin/v1/profiles/{id}/audit and asserts secret-free responses.
func TestAuditHandler_ExternalSubjectQueryParam(t *testing.T) {
	tmp := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(tmp, "cfg"),
		DataDir:   filepath.Join(tmp, "data"),
		CacheDir:  filepath.Join(tmp, "cache"),
	}
	// Default ProfileAuditPath: data/profiles/<id>/audit/audit.jsonl
	auditDir := filepath.Join(paths.DataDir, "profiles", "corp", "audit")
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		t.Fatal(err)
	}
	active := filepath.Join(auditDir, audit.DefaultFileName)
	t0 := time.Date(2026, 6, 2, 9, 0, 0, 0, time.UTC)
	const canary = "CANARY_audit_ext_subj_token_must_not_echo"
	writeAuditJSONL(t, active, []audit.Event{
		{Time: t0, Type: audit.TypeToolDeny, ProfileID: "corp", ExternalSubject: "alice@idp", Decision: audit.DecisionDeny, SchemaVersion: 1, RequestID: "a1", ReasonCode: "policy_deny"},
		{Time: t0.Add(time.Minute), Type: audit.TypeToolDeny, ProfileID: "corp", ExternalSubject: "bob@idp", Decision: audit.DecisionDeny, SchemaVersion: 1, RequestID: "b1"},
	})

	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Version = "test"
	cfg.Paths = &paths
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Filter alice
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/admin/v1/profiles/corp/audit?limit=50&external_subject=alice%40idp", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var page admin.AuditPage
	if err := json.Unmarshal(rr.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 1 || page.Events[0].ExternalSubject != "alice@idp" {
		t.Fatalf("handler external_subject filter: %+v", page.Events)
	}
	// Secret canary: planted token never appears in response (filter or body).
	if strings.Contains(rr.Body.String(), canary) {
		t.Fatal("audit response must not contain canary token")
	}
	// Query with canary as external_subject must not invent it into events
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet,
		"/admin/v1/profiles/corp/audit?external_subject="+canary, nil)
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("canary filter status=%d", rr2.Code)
	}
	body2 := rr2.Body.String()
	// Response may echo query only if we put it in events — we must not.
	// JSON events should not carry the canary as a field value from our store.
	var page2 admin.AuditPage
	if err := json.Unmarshal(rr2.Body.Bytes(), &page2); err != nil {
		t.Fatal(err)
	}
	if len(page2.Events) != 0 {
		t.Fatalf("canary external_subject must match zero stored events, got %d", len(page2.Events))
	}
	// Fail closed: body is still schema-shaped; no token fields.
	if strings.Contains(strings.ToLower(body2), "password") ||
		strings.Contains(strings.ToLower(body2), "authorization") {
		t.Fatalf("secret-shaped keys in empty audit page: %s", body2)
	}

	// Whitespace-only external_subject = no filter
	rr3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodGet,
		"/admin/v1/profiles/corp/audit?external_subject=%20%20", nil)
	h.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Fatalf("blank external_subject status=%d", rr3.Code)
	}
	var page3 admin.AuditPage
	if err := json.Unmarshal(rr3.Body.Bytes(), &page3); err != nil {
		t.Fatal(err)
	}
	if len(page3.Events) != 2 {
		t.Fatalf("blank external_subject should skip filter, got %d", len(page3.Events))
	}
}

func TestAuditQuery_NormalizeExternalSubject(t *testing.T) {
	q := admin.AuditQuery{ExternalSubject: "  alice@idp  "}.Normalize()
	if q.ExternalSubject != "alice@idp" {
		t.Fatalf("trim: %q", q.ExternalSubject)
	}
	// Oversize clipped to MaxExternalSubjectFilterLen
	long := strings.Repeat("x", admin.MaxExternalSubjectFilterLen+40)
	q2 := admin.AuditQuery{ExternalSubject: long}.Normalize()
	if len([]rune(q2.ExternalSubject)) != admin.MaxExternalSubjectFilterLen {
		t.Fatalf("cap len=%d want %d", len([]rune(q2.ExternalSubject)), admin.MaxExternalSubjectFilterLen)
	}
}
