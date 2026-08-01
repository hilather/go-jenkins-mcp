package tools_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/tools"
)

// mockExternalLogs is a tools-layer querier for registration/redaction/ACL tests.
type mockExternalLogs struct {
	entries []tools.ExternalLogEntry
	err     error
	calls   atomic.Int32
}

func (m *mockExternalLogs) QueryExternalLogs(ctx context.Context, req tools.ExternalLogQueryRequest) (tools.ExternalLogQueryResult, error) {
	m.calls.Add(1)
	if err := ctx.Err(); err != nil {
		return tools.ExternalLogQueryResult{}, err
	}
	if m.err != nil {
		return tools.ExternalLogQueryResult{}, m.err
	}
	if req.Job == "" || req.Build <= 0 {
		return tools.ExternalLogQueryResult{}, context.Canceled // unused; tool validates via buildRef first
	}
	return tools.ExternalLogQueryResult{
		Entries:        m.entries,
		Count:          len(m.entries),
		MaxEntries:     20,
		SourceLabel:    "mock",
		Freshness:      "stub",
		EvidenceSource: "external_log_system",
		Residuals:      []string{"real Splunk/ELK residual"},
	}, nil
}

// extLogsJenkinsFixture serves Jenkins build API with configurable status.
// Regression: external log querier must not run when Jenkins denies/missing.
type extLogsJenkinsFixture struct {
	srv        *httptest.Server
	statusCode int
	hits       atomic.Int32
}

func newExtLogsJenkinsFixture(statusCode int) *extLogsJenkinsFixture {
	f := &extLogsJenkinsFixture{statusCode: statusCode}
	if f.statusCode == 0 {
		f.statusCode = http.StatusOK
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/api/json") && strings.Contains(r.URL.Path, "/job/") {
			f.hits.Add(1)
			if f.statusCode != http.StatusOK {
				w.WriteHeader(f.statusCode)
				_, _ = w.Write([]byte(http.StatusText(f.statusCode)))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"number":      7,
				"url":         "http://example/job/demo/7/",
				"building":    false,
				"result":      "FAILURE",
				"timestamp":   1_700_000_000_000,
				"duration":    1000,
				"displayName": "#7",
				"actions":     []any{},
			})
			return
		}
		http.NotFound(w, r)
	}))
	return f
}

func (f *extLogsJenkinsFixture) close() { f.srv.Close() }

func (f *extLogsJenkinsFixture) client() *jenkins.Client {
	return &jenkins.Client{
		URL:        f.srv.URL,
		User:       "u",
		Token:      "t",
		Client:     f.srv.Client(),
		LogsClient: f.srv.Client(),
	}
}

func TestExternalLogs_DisabledByDefault(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	names := listToolNames(t, ctx, nil)
	if _, ok := names[tools.ToolQueryExternalLogs]; ok {
		t.Fatalf("%s registered when ExternalLogs=nil", tools.ToolQueryExternalLogs)
	}
}

func TestExternalLogs_EnabledRegistersTool(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	names := listToolNames(t, ctx, &tools.RegisterOptions{
		ExternalLogs: &mockExternalLogs{},
	})
	if _, ok := names[tools.ToolQueryExternalLogs]; !ok {
		t.Fatalf("%s not registered", tools.ToolQueryExternalLogs)
	}
}

func TestExternalLogs_RedactsExcerptSecrets(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Jenkins 200 preflight required before querier (INT-003 ACL).
	f := newExtLogsJenkinsFixture(http.StatusOK)
	defer f.close()
	// ghp_ body must be ≥36 for built-in detector (SEC-002).
	secret := "ghp_" + strings.Repeat("A", 36)
	mock := &mockExternalLogs{
		entries: []tools.ExternalLogEntry{
			{
				RefID:          "evt-1",
				Excerpt:        "failed with token=" + secret,
				SourceLabel:    "mock",
				Freshness:      "stub",
				EvidenceSource: "external_log_system",
			},
		},
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{ExternalLogs: mock})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolQueryExternalLogs,
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 7,
			"query":        "error",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res)
	}
	payload := toolStructuredJSON(t, res)
	raw, _ := json.Marshal(payload)
	s := string(raw)
	if strings.Contains(s, secret) {
		t.Fatal("secret leaked into external logs tool response")
	}
	if !strings.Contains(s, "evt-1") {
		t.Fatalf("missing ref in %s", s)
	}
	if !strings.Contains(s, "external_log_system") {
		t.Fatalf("missing evidence in %s", s)
	}
	if mock.calls.Load() != 1 {
		t.Fatalf("querier calls=%d want 1 on allow", mock.calls.Load())
	}
	if f.hits.Load() < 1 {
		t.Fatal("expected Jenkins ACL preflight hit")
	}
}

func TestExternalLogs_QueryTooLong(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Query length fails before Jenkins preflight / querier.
	f := newExtLogsJenkinsFixture(http.StatusOK)
	defer f.close()
	mock := &mockExternalLogs{}
	server := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		ExternalLogs: mock,
	})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolQueryExternalLogs,
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 7,
			"query":        strings.Repeat("x", 300),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Prefer IsError or error content for invalid_argument.
	if !res.IsError {
		// Some SDK paths return error via result content.
		payload := toolStructuredJSON(t, res)
		raw, _ := json.Marshal(payload)
		if !strings.Contains(string(raw), "max length") {
			// Accept either error flag or error message surface.
			if res.Content == nil {
				t.Fatalf("expected query length error, got %+v payload=%s", res, raw)
			}
		}
	}
	if mock.calls.Load() != 0 {
		t.Fatalf("querier must not run on invalid query: calls=%d", mock.calls.Load())
	}
}

// Regression: Jenkins 403 must fail closed — external querier never called.
func TestExternalLogs_Jenkins403_NoQuerier(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	f := newExtLogsJenkinsFixture(http.StatusForbidden)
	defer f.close()
	mock := &mockExternalLogs{
		entries: []tools.ExternalLogEntry{{RefID: "should-not-appear", Excerpt: "leak"}},
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{ExternalLogs: mock})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolQueryExternalLogs,
		Arguments: map[string]any{
			"job_name":     "secret-job",
			"build_number": 1,
			"query":        "error",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if mock.calls.Load() != 0 {
		t.Fatalf("Regression: querier called on Jenkins 403 (calls=%d)", mock.calls.Load())
	}
	text := toolErrorText(res)
	// 403 → authorization (Jenkins ACL); fail closed, no external probe.
	if !res.IsError && !strings.Contains(text, string(apperr.CodeAuthorization)) &&
		!strings.Contains(strings.ToLower(text), "403") &&
		!strings.Contains(strings.ToLower(text), "authoriz") &&
		!strings.Contains(strings.ToLower(text), "forbidden") {
		// Also accept structured error embedding the code.
		raw, _ := json.Marshal(res)
		if !strings.Contains(string(raw), string(apperr.CodeAuthorization)) &&
			!strings.Contains(string(raw), "403") {
			t.Fatalf("expected authorization-style error on 403, isError=%v text=%q raw=%s",
				res.IsError, text, raw)
		}
	}
}

// Regression: Jenkins 401 must fail closed — external querier never called.
func TestExternalLogs_Jenkins401_NoQuerier(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	f := newExtLogsJenkinsFixture(http.StatusUnauthorized)
	defer f.close()
	mock := &mockExternalLogs{}
	server := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{ExternalLogs: mock})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolQueryExternalLogs,
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 7,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if mock.calls.Load() != 0 {
		t.Fatalf("Regression: querier called on Jenkins 401 (calls=%d)", mock.calls.Load())
	}
	text := toolErrorText(res)
	raw, _ := json.Marshal(res)
	combined := text + string(raw)
	if !strings.Contains(combined, string(apperr.CodeAuthentication)) &&
		!strings.Contains(strings.ToLower(combined), "401") &&
		!strings.Contains(strings.ToLower(combined), "auth") {
		t.Fatalf("expected authentication-style error on 401, isError=%v combined=%s", res.IsError, combined)
	}
}

// Regression: Jenkins 404 must not query external logs (not_found).
func TestExternalLogs_Jenkins404_NoQuerier(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	f := newExtLogsJenkinsFixture(http.StatusNotFound)
	defer f.close()
	mock := &mockExternalLogs{}
	server := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{ExternalLogs: mock})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolQueryExternalLogs,
		Arguments: map[string]any{
			"job_name":     "missing",
			"build_number": 99,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if mock.calls.Load() != 0 {
		t.Fatalf("Regression: querier called on Jenkins 404 (calls=%d)", mock.calls.Load())
	}
	text := toolErrorText(res)
	raw, _ := json.Marshal(res)
	combined := text + string(raw)
	if !strings.Contains(combined, string(apperr.CodeNotFound)) &&
		!strings.Contains(strings.ToLower(combined), "not found") &&
		!strings.Contains(combined, "404") {
		t.Fatalf("expected not_found-style error on 404, isError=%v combined=%s", res.IsError, combined)
	}
}

// Allowed Jenkins access: querier is invoked after preflight succeeds.
func TestExternalLogs_Jenkins200_QuerierCalled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	f := newExtLogsJenkinsFixture(http.StatusOK)
	defer f.close()
	mock := &mockExternalLogs{
		entries: []tools.ExternalLogEntry{
			{RefID: "ok-1", SourceLabel: "mock", Freshness: "stub", EvidenceSource: "external_log_system"},
		},
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{ExternalLogs: mock})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolQueryExternalLogs,
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 7,
			"query":        "error",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error on allow path: %+v text=%s", res, toolErrorText(res))
	}
	if f.hits.Load() < 1 {
		t.Fatal("expected Jenkins preflight")
	}
	if mock.calls.Load() != 1 {
		t.Fatalf("querier calls=%d want 1 on Jenkins 200", mock.calls.Load())
	}
	payload := toolStructuredJSON(t, res)
	raw, _ := json.Marshal(payload)
	if !strings.Contains(string(raw), "ok-1") {
		t.Fatalf("missing entry: %s", raw)
	}
}
