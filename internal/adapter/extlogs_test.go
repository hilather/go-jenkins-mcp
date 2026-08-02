package adapter_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/adapter"
)

func TestExtLogs_DisabledByDefault(t *testing.T) {
	t.Parallel()
	r := adapter.NewRegistry(adapter.Config{})
	if err := r.RegisterEnabled(); err != nil {
		t.Fatal(err)
	}
	if r.Get(adapter.IDExtLogs) != nil {
		t.Fatal("ext-logs must not register by default")
	}
}

func TestExtLogs_EnableNoop(t *testing.T) {
	t.Parallel()
	r := adapter.NewRegistry(adapter.Config{
		EnabledIDs: []string{adapter.IDExtLogs},
	})
	if err := r.RegisterEnabled(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := r.StartAll(ctx); err != nil {
		t.Fatal(err)
	}
	h := r.Health(ctx, adapter.IDExtLogs)
	if h.Status != adapter.HealthHealthy {
		t.Fatalf("health=%+v", h)
	}
	entry := r.Get(adapter.IDExtLogs)
	if entry == nil {
		t.Fatal("missing")
	}
	q, ok := entry.Adapter.(adapter.ExternalLogQuery)
	if !ok {
		t.Fatalf("type %T", entry.Adapter)
	}
	res, err := q.QueryExternalLogs(ctx, adapter.ExternalLogQueryRequest{
		Job:   "demo",
		Build: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entries) != 0 {
		t.Fatalf("noop should be empty: %+v", res)
	}
	if res.SourceLabel != "noop" {
		t.Fatalf("source=%s", res.SourceLabel)
	}
	if res.EvidenceSource != adapter.EvidenceSourceExternalLogs {
		t.Fatalf("evidence=%s", res.EvidenceSource)
	}
	found := false
	for _, r := range res.Residuals {
		if strings.Contains(r, "residual") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected SaaS residual: %+v", res.Residuals)
	}
}

func TestExtLogs_MockBoundsAndIdentity(t *testing.T) {
	t.Parallel()
	r := adapter.NewRegistry(adapter.Config{
		EnabledIDs: []string{adapter.IDExtLogs},
		Catalog: map[string]adapter.Factory{
			adapter.IDExtLogs: adapter.ExtLogsFactory(adapter.ExtLogsConfig{
				Backend: adapter.ExtLogsBackendMock,
			}),
		},
	})
	if err := r.RegisterEnabled(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := r.StartAll(ctx); err != nil {
		t.Fatal(err)
	}
	q := r.Get(adapter.IDExtLogs).Adapter.(adapter.ExternalLogQuery)

	// Invalid identity
	if _, err := q.QueryExternalLogs(ctx, adapter.ExternalLogQueryRequest{}); err == nil {
		t.Fatal("expected job required")
	}
	if _, err := q.QueryExternalLogs(ctx, adapter.ExternalLogQueryRequest{
		Job: "https://evil.example/job", Build: 1,
	}); err == nil {
		t.Fatal("expected URL rejection")
	}

	// Query too long
	longQ := strings.Repeat("a", adapter.MaxLogQueryLen+1)
	if _, err := q.QueryExternalLogs(ctx, adapter.ExternalLogQueryRequest{
		Job: "demo", Build: 3, Query: longQ,
	}); err == nil {
		t.Fatal("expected query length error")
	}

	res, err := q.QueryExternalLogs(ctx, adapter.ExternalLogQueryRequest{
		Job:        "folder/job",
		Build:      9,
		Query:      "error",
		MaxEntries: 100, // hard-capped
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.MaxEntries > adapter.HardMaxLogEntries {
		t.Fatalf("max=%d", res.MaxEntries)
	}
	if len(res.Entries) == 0 {
		t.Fatal("mock should return entries")
	}
	for _, e := range res.Entries {
		if e.RefID == "" {
			t.Fatal("empty ref")
		}
		if len(e.Excerpt) > adapter.MaxLogExcerptBytes {
			t.Fatalf("excerpt too long: %d", len(e.Excerpt))
		}
		if e.EvidenceSource != adapter.EvidenceSourceExternalLogs {
			t.Fatalf("evidence=%s", e.EvidenceSource)
		}
	}
}

func TestExtLogs_NotStarted(t *testing.T) {
	t.Parallel()
	a, err := adapter.NewExtLogs(adapter.Host{}, adapter.ExtLogsConfig{Backend: adapter.ExtLogsBackendMock})
	if err != nil {
		t.Fatal(err)
	}
	q := a.(adapter.ExternalLogQuery)
	_, err = q.QueryExternalLogs(context.Background(), adapter.ExternalLogQueryRequest{
		Job: "j", Build: 1,
	})
	if err == nil || !strings.Contains(err.Error(), "not started") {
		t.Fatalf("err=%v", err)
	}
}

func TestExtLogs_TimeRangeClamp(t *testing.T) {
	t.Parallel()
	a, err := adapter.NewExtLogs(adapter.Host{}, adapter.ExtLogsConfig{
		Backend:      adapter.ExtLogsBackendMock,
		MaxTimeRange: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	q := a.(adapter.ExternalLogQuery)
	end := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	start := end.Add(-48 * time.Hour)
	res, err := q.QueryExternalLogs(context.Background(), adapter.ExternalLogQueryRequest{
		Job: "j", Build: 1, Start: start, End: end,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Mock ignores times but normalize must accept clamped range.
	if res.Count == 0 {
		t.Fatal("expected mock hits")
	}
}

func TestExtLogs_HTTPBackend_HTTPSOnlyAndPin(t *testing.T) {
	t.Parallel()
	// http:// must fail at factory.
	_, err := adapter.NewExtLogs(adapter.Host{}, adapter.ExtLogsConfig{
		Backend: adapter.ExtLogsBackendHTTP,
		BaseURL: "http://example.com/logs",
	})
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("err=%v", err)
	}

	// userinfo forbidden
	_, err = adapter.NewExtLogs(adapter.Host{}, adapter.ExtLogsConfig{
		Backend: adapter.ExtLogsBackendHTTP,
		BaseURL: "https://user:pass@example.com/logs",
	})
	if err == nil || !strings.Contains(err.Error(), "userinfo") {
		t.Fatalf("err=%v", err)
	}
}

func TestExtLogs_HTTPBackend_Query(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", 405)
			return
		}
		// Ensure no Authorization leaked.
		if r.Header.Get("Authorization") != "" {
			http.Error(w, "auth not allowed", 400)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "json", 400)
			return
		}
		if body["job"] != "demo" || int(body["build"].(float64)) != 5 {
			http.Error(w, "identity", 400)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"entries": []map[string]string{
				{"ref_id": "evt-1", "excerpt": "error boom token=ghp_LEAKEDSECRETVALUE001", "timestamp": "2024-01-01T00:00:00Z"},
			},
		})
	}))
	defer srv.Close()

	a, err := adapter.NewExtLogs(adapter.Host{}, adapter.ExtLogsConfig{
		Backend: adapter.ExtLogsBackendHTTP,
		BaseURL: srv.URL + "/query",
		HTTP:    srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	q := a.(adapter.ExternalLogQuery)
	res, err := q.QueryExternalLogs(context.Background(), adapter.ExternalLogQueryRequest{
		Job: "demo", Build: 5, Query: "error",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Count != 1 || res.Entries[0].RefID != "evt-1" {
		t.Fatalf("res=%+v", res)
	}
	// Adapter may still carry secret-like excerpt; tools layer redacts.
	// Here we only assert bounds and identity.
	if res.Freshness != "live" || res.SourceLabel != "http" {
		t.Fatalf("meta=%+v", res)
	}
}

func TestExtLogs_PanicIsolationOnQuery(t *testing.T) {
	t.Parallel()
	// Call recovers panics so a bad backend cannot crash the core process.
	entry := &adapter.Entry{
		ID:      "panic-query",
		Adapter: &adapter.Noop{},
	}
	err := adapter.Call(entry, func() error {
		panic("boom in query")
	})
	if err == nil || !strings.Contains(err.Error(), "panic") {
		t.Fatalf("err=%v", err)
	}
}

func TestWorkItems_StubLookup(t *testing.T) {
	t.Parallel()
	r := adapter.NewRegistry(adapter.Config{
		EnabledIDs: []string{adapter.IDWorkItems},
	})
	if err := r.RegisterEnabled(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := r.StartAll(ctx); err != nil {
		t.Fatal(err)
	}
	entry := r.Get(adapter.IDWorkItems)
	lookup, ok := entry.Adapter.(adapter.WorkItemLookup)
	if !ok {
		t.Fatalf("type %T", entry.Adapter)
	}
	res, err := lookup.LookupWorkItems(ctx, adapter.WorkItemLookupRequest{
		Refs: []string{"PROJ-1", "PROJ-1", "acme/demo#2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Refs) != 2 {
		t.Fatalf("dedupe failed: %+v", res.Refs)
	}
	for _, ref := range res.Refs {
		if ref.Freshness != "stub" {
			t.Fatalf("freshness=%s", ref.Freshness)
		}
		if strings.Contains(strings.ToLower(ref.Note), "password") {
			t.Fatal("unexpected")
		}
	}
	found := false
	for _, r := range res.Residuals {
		if strings.Contains(r, "residual") {
			found = true
		}
	}
	if !found {
		t.Fatalf("residuals=%v", res.Residuals)
	}
}

func TestBuiltinIDsIncludeExtLogsAndWorkItems(t *testing.T) {
	t.Parallel()
	if !adapter.IsBuiltin(adapter.IDExtLogs) || !adapter.IsBuiltin(adapter.IDWorkItems) ||
		!adapter.IsBuiltin(adapter.IDOtelExport) {
		t.Fatal("builtins")
	}
	cat := adapter.DefaultCatalog()
	if _, ok := cat[adapter.IDExtLogs]; !ok {
		t.Fatal("catalog missing ext-logs")
	}
	if _, ok := cat[adapter.IDWorkItems]; !ok {
		t.Fatal("catalog missing work-items")
	}
	if _, ok := cat[adapter.IDOtelExport]; !ok {
		t.Fatal("catalog missing otel-export")
	}
}
